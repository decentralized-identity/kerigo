package log

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"time"

	"github.com/decentralized-identity/kerigo/pkg/db"
	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
)

// Log contains the Key Event Log for a given identifier
type Log struct {
	db          db.DB
	prefix      string
	Receipts    Register // receipts for Events
	Pending     Escrow   // pending events
	Duplicitous Escrow   // escrow of duplicitous events
}

// BySequence implements the sort.Inteface for log events
type BySequence []*event.Message

func (a BySequence) Len() int      { return len(a) }
func (a BySequence) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a BySequence) Less(i, j int) bool {
	iS, _ := strconv.ParseInt(a[i].Event.Sequence, 16, 64)
	jS, _ := strconv.ParseInt(a[j].Event.Sequence, 16, 64)
	return iS < jS
}

// ByDate implements the sort.Interface for log events
type ByDate []*event.Message

func (a ByDate) Len() int      { return len(a) }
func (a ByDate) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByDate) Less(i, j int) bool {
	return a[i].Seen.Before(a[j].Seen)
}

func New(prefix string, db db.DB) *Log {
	return &Log{
		db:          db,
		prefix:      prefix,
		Pending:     map[string]*event.Message{},
		Duplicitous: map[string]*event.Message{},
		Receipts:    Register{},
	}
}

// Inception returns the inception event for this log
func (l *Log) Inception() *event.Event {

	evt, err := l.db.Inception(l.prefix)
	if err != nil {
		return nil
	}

	return evt.Event
}

// Current returns the current event in the log
func (l *Log) Current() *event.Event {
	evt, err := l.db.CurrentEvent(l.prefix)
	if err != nil {
		return nil
	}

	return evt.Event
}

func (l *Log) EventAt(sequence int) *event.Message {
	evt, err := l.db.EventAt(l.prefix, sequence)
	if err != nil {
		return nil
	}

	return evt
}

// CurrentEstablishment returns the most current establishment event
// These differ from other events in that they contain key commitments
// and are used to verify the signatures for all subsequent events
func (l *Log) CurrentEstablishment() *event.Event {
	evt, err := l.db.CurrentEstablishmentEvent(l.prefix)
	if err != nil {
		return nil
	}

	return evt.Event
}

// EstablishmentEvents returns a slice of the establishment event messages
// in the log, order by serial number
func (l *Log) EstablishmentEvents() []*event.Event {
	var est []*event.Event

	err := l.db.StreamEstablisment(l.prefix, func(evt *event.Message) {
		est = append(est, evt.Event)
	})

	if err != nil {
		return nil
	}

	return est
}

func (l *Log) Size() int {
	return l.db.LogSize(l.prefix)
}

// KeyState returns a key state event (kst) that contains the
// current state of the identifier. This is essentially
// compressing all the establishment events to give a current
// view of keys, next, witnesses, and thresholds, along with
// a digest seal of the last received events
func (l *Log) KeyState() (*event.Event, error) {
	var kst *event.Event
	var last *event.Event

	err := l.db.StreamEstablisment(l.prefix, func(msg *event.Message) {
		e := msg.Event
		if kst == nil {
			kst = e
		}

		// Assumption: these will always be provided in the messages
		kst.SigThreshold = e.SigThreshold
		kst.Keys = e.Keys
		kst.Next = e.Next
		kst.WitnessThreshold = e.WitnessThreshold

		// if you are adding or cutting witnesses, we ignore the witness list
		if len(e.AddWitness) != 0 || len(e.RemoveWitness) != 0 {
			for _, w := range e.RemoveWitness {
				for ci, cw := range kst.Witnesses {
					if w == cw {
						kst.Witnesses = append(kst.Witnesses[:ci], kst.Witnesses[ci+1:]...)
					}
				}
			}

			// de-duping...not sure if this is really necessary?
			for _, w := range e.AddWitness {
				found := false
				for _, cw := range kst.Witnesses {
					if cw == w {
						found = true
						break
					}
				}
				if !found {
					kst.Witnesses = append(kst.Witnesses, w)
				}
			}

		} else if len(e.Witnesses) != 0 {
			// otherwise if we have an included list of witnesses
			kst.Witnesses = e.Witnesses
		}

		last = e
	})

	// key state events don't need the sequence number
	kst.Sequence = ""
	kst.EventType = event.KST.String()

	// digest the last event
	current := l.Current()
	seal, err := event.SealEstablishment(current)
	if err != nil {
		return nil, fmt.Errorf("unable to create seal for last event (%s)", err.Error())
	}

	// we don't need the prefix but do need the event type
	seal.Prefix = ""
	seal.EventType = current.EventType
	kst.LastEvent = seal

	// digest the last establishment event
	seal, err = event.SealEstablishment(last)
	if err != nil {
		return nil, fmt.Errorf("unable to create seal for last establishment event (%s)", err.Error())
	}

	// we dont' need the prefix for this
	seal.Prefix = ""
	kst.LastEstablishment = seal

	return kst, nil
}

// Apply the provided event to the log
// Apply will confirm the sequence number and digest for the new log
// entry are correct before applying. If the event message is for an
// event that has already been added to the log it will attempt to
// add the provided signature. If the event is out of order (in the future)
// it will escrow it.
func (l *Log) Apply(e *event.Message) error {
	if e.Event.Prefix != l.prefix {
		return errors.New("invalid event for this log")
	}

	// mark the event as seen
	if e.Seen.IsZero() {
		e.Seen = time.Now().UTC()
	}

	if l.db.LogSize(l.prefix) == 0 {
		if e.Event.EventType != event.ICP.String() {
			return errors.New("first event in an empty log must be an inception event")
		}

		l.prefix = e.Event.Prefix
		err := l.db.LogEvent(e)
		if err != nil {
			return err
		}
		//l.Events = append(l.Events, e)
		return nil
	}

	state, err := l.KeyState()
	if err != nil {
		return fmt.Errorf("unable to build key state (%s)", err.Error())
	}

	// add the signature to already applied event
	if e.Event.SequenceInt() <= state.LastEvent.SequenceInt() {
		// TODO: an edge case - you will need to validate
		// the signatures AS OF the key state that was valid for this event seq
		// so, for example, if this is for seq 7, then 8 was a valid ROT, you could still
		// collect valid sigs for seq 7, but the would no longer be valid as of the current
		// key state message (since it takes into account ROT at 8)

		return l.AddSignatures(e)
	} else if e.Event.SequenceInt() != state.LastEstablishment.SequenceInt()+1 {
		// if there are no attached signatures to the event, we do not escrow
		// DOS prevention - flooding an escrow with unverifiable events
		// TODO: currently we are not considering this an error condition, is it?
		if len(e.Signatures) == 0 {
			return nil
		}

		// We just add the event to the pending escrow: we cannot validate the signtures
		// until we get caught up since any of the previous missing events could be
		// ROT
		err := l.Pending.Add(e)
		if err != nil {
			return fmt.Errorf("unable to escrow event (%s)", err)
		}

		return nil
	}

	// verify the signatures for this event
	// Two paths: if this is a ROT event, we use the current keys
	// if this is any other type, we use the key state
	if e.Event.EventType == event.ROT.String() {
		err = VerifySigs(e.Event, e)
	} else {
		err = VerifySigs(state, e)
	}

	if err != nil {
		return err
	}

	// if this is a rotation event, we must validate the next keys
	if e.Event.ILK() == event.ROT {
		keyPre := []prefix.Prefix{}
		for _, k := range e.Event.Keys {
			kp, err := prefix.FromString(k)
			if err != nil {
				return fmt.Errorf("unable to verify next digest (%s)", err.Error())
			}
			keyPre = append(keyPre, kp)
		}

		lastEstablisment := l.EventAt(state.LastEstablishment.SequenceInt())
		lastNextDig, err := derivation.FromPrefix(lastEstablisment.Event.Next)
		if err != nil {
			return fmt.Errorf("unable to parse next digest from last establishment event (%s)", err.Error())
		}

		// calculate the next digest based on the current keys/signing threshold
		currentNextDig, err := e.Event.NextDigest(lastNextDig.Code)
		if err != nil {
			return fmt.Errorf("unable to parse next digest event (%s)", err.Error())
		}

		// this should match what was stored in the last establishment
		if currentNextDig != lastNextDig.AsPrefix() {
			return errors.New("next digest invalid")
		}
	}

	// to support digest agility, we allow the current event to dictate what
	// digest they want to use for the prior event
	inDerivation, err := derivation.FromPrefix(e.Event.PriorEventDigest)
	if err != nil {
		return fmt.Errorf("unable to determine digest derivation (%s)", err)
	}

	current := l.Current()
	curSerialized, err := current.Serialize()
	if err != nil {
		return fmt.Errorf("unable to serialize current event (%s)", err)
	}

	curDigest, err := event.Digest(curSerialized, inDerivation.Code)
	if err != nil {
		return fmt.Errorf("unable to digest current event (%s)", err)
	}

	if !bytes.Equal(curDigest, inDerivation.Raw) {
		// someone has tried to add an invalid event to the log
		_ = l.Duplicitous.Add(e)
		return errors.New("invalid digest for new event")
	}

	// if the sig threshold is not met escrow
	escrowed, err := l.Pending.Get(e.Event)
	if err != nil {
		return fmt.Errorf("unable to retrieve escrowed messages (%s)", err)
	}
	sigs := mergeSignatures(escrowed.Signatures, e.Signatures)

	if current.SigThreshold != nil && !current.SigThreshold.Satisfied(sigs) {
		err = l.Pending.Add(e)
		if err != nil {
			return fmt.Errorf("unable to escrow event (%s)", err)
		}

		return nil
	}

	err = l.db.LogEvent(&event.Message{Event: e.Event, Signatures: sigs})
	if err != nil {
		return err
	}

	dups, err := l.Pending.Clear(*e.Event)
	// we currently do not consider any of these errors that need to be addressed
	// TODO: handle
	if err == nil {
		for i := range dups {
			_ = l.Duplicitous.Add(dups[i])
		}
	}

	// go through the pending events and apply any that are now "current"
	current = l.Current()
	next := l.Pending.ForSequence(current.SequenceInt() + 1)
	if len(next) > 0 {
		sort.Sort(ByDate(next))
		// we iterate over the events, sorted by first received.
		// if an event is applied any others are moved to the
		// duplicitous escrow, so we can just return
		// if the event is still waiting for additional signatures
		// it will remain in escrow, and we can return (since it was)
		// first seen,
		// If there is an error, for example the
		for i := range next {
			err = l.Apply(next[i])
			if err == nil {
				return nil
			}

			// there as some other error applying the event to the log
			// at this point we dump from escrow and continue on
			l.Pending.Remove(next[i])
		}
	}

	b, _ := json.Marshal(e.Event)
	log.Print("Added valid event to KEL event = ", string(b), "\n\n")

	return nil
}

func (l *Log) ApplyReceipt(vrc *event.Message) error {
	err := l.Receipts.Add(vrc)
	if err != nil {
		return err
	}

	return nil
}

// VerifySigs takes the current log key state and an event message
// and validates the attached signatures
func VerifySigs(state *event.Event, m *event.Message) error {
	mRaw, err := m.Event.Serialize()
	if err != nil {
		return err
	}

	if len(m.Signatures) == 0 {
		return errors.New("no attached signatures to verify")
	}

	for _, sig := range m.Signatures {
		keyD, err := state.KeyDerivation(int(sig.KeyIndex))
		if err != nil {
			return fmt.Errorf("unable to get key derivation for signing key at index %d (%s)", sig.KeyIndex, err)
		}

		err = derivation.VerifyWithAttachedSignature(keyD, &sig, mRaw)
		if err != nil {
			return fmt.Errorf("Invalid signature for key at index %d", sig.KeyIndex)
		}
	}

	return nil
}

// Verify the event signatures against the current log
// establishment event
// TODO: do we need this?
func (l *Log) Verify(m *event.Message) error {
	if l.db.LogSize(l.prefix) == 0 {
		if m.Event.EventType != event.ICP.String() {
			return errors.New("first event in an empty log must be an inception event")
		}
		// If this is the first event in a log there is nothing to verify
		return nil
	}

	state, err := l.KeyState()
	if err != nil {
		return fmt.Errorf("unable to build state (%s)", err.Error())
	}

	if m.Event.EventType == event.ROT.String() {
		state = m.Event
	}

	return VerifySigs(state, m)
}

func (l *Log) ReceiptsForEvent(evt *event.Event) []*event.Message {
	dig, _ := evt.GetDigest()
	rcpts := l.Receipts[dig]
	return rcpts
}

// AddSignatures takes an event message (event + attached signatures) and attempts
// to merge the signatures into the log for the event. If the provided event does
// not match the event already in the KEL it is escrowed as a duplicitous event
func (l *Log) AddSignatures(e *event.Message) error {
	ext := l.EventAt(e.Event.SequenceInt())
	if ext == nil {
		return fmt.Errorf("unable to locate existing event for sequence %s", e.Event.Sequence)
	}

	extSerialized, err := ext.Event.Serialize()
	if err != nil {
		return fmt.Errorf("unable to add signature to existing event (could not serialize existing event: %s)", err)
	}

	extDigest, err := event.DigestString(extSerialized, derivation.Blake3256)
	if err != nil {
		return fmt.Errorf("unable to add signature to existing event (could not digest existing event: %s)", err)
	}

	newSerialized, err := e.Event.Serialize()
	if err != nil {
		return fmt.Errorf("unable to add signature to existing event (could not serialize new event: %s)", err)
	}

	newDigest, err := event.DigestString(newSerialized, derivation.Blake3256)
	if err != nil {
		return fmt.Errorf("unable to add signature to existing event (could not digest new event: %s)", err)
	}

	if newDigest != extDigest {
		// likely duplicitous Event!
		// if adding to the duplicitous escrow fails do not consider an error (at this point)
		_ = l.Duplicitous.Add(e)
		return errors.New("unable to add signature to existing event (new event digest does not match)")
	}

	ext.Signatures = mergeSignatures(ext.Signatures, e.Signatures)

	return nil
}

// mergeSignatures takes incoming signatures and merges them into a list
// of existing signatures. The purpose is to make sure we don't accept
// multiple signatures for the same key
func mergeSignatures(current, new []derivation.Derivation) []derivation.Derivation {
	for _, sig := range new {
		found := false
		for _, currentSig := range current {
			if currentSig.KeyIndex == sig.KeyIndex {
				found = true
				break
			}
		}
		if !found {
			current = append(current, sig)
		}
	}

	return current
}
