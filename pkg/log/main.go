package log

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

// Log contains the Key Event Log for a given identifier
type Log struct {
	Events      []*event.Message // ordered Key events
	Receipts    Register         // receipts for Events
	Pending     Escrow           // pending events
	Duplicitous Escrow           // escrow of duplicitous events
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

func New() *Log {
	return &Log{
		Events:      []*event.Message{},
		Pending:     map[string]*event.Message{},
		Duplicitous: map[string]*event.Message{},
		Receipts:    Register{},
	}
}

// Inception returns the inception event for this log
func (l *Log) Inception() *event.Event {
	for _, e := range l.Events {
		if e.Event.EventType == event.ICP.String() {
			return e.Event
		}
	}
	return nil
}

// Current returns the current event in the log
func (l *Log) Current() *event.Event {
	if len(l.Events) == 0 {
		return nil
	}

	sort.Sort(BySequence(l.Events))

	return l.Events[len(l.Events)-1].Event
}

func (l *Log) EventAt(sequence int) *event.Message {
	if sequence > len(l.Events)-1 || sequence < 0 {
		return nil
	}

	sort.Sort(BySequence(l.Events))
	return l.Events[sequence]
}

// CurrentEstablishment returns the most current establishment event
// These differ from other events in that they contain key commitments
// and are used to verify the signatures for all subsequent events
func (l *Log) CurrentEstablishment() *event.Event {
	sort.Sort(BySequence(l.Events))

	for i := len(l.Events) - 1; i >= 0; i-- {
		if l.Events[i].Event.ILK().Establishment() {
			return l.Events[i].Event
		}
	}

	return nil
}

// EstablishmentEvents returns a slice of the establishment event messages
// in the log, order by serial number
func (l *Log) EstablishmentEvents() []*event.Event {
	sort.Sort(BySequence(l.Events))

	est := []*event.Event{}

	for i, e := range l.Events {
		if e.Event.ILK().Establishment() {
			est = append(est, l.Events[i].Event)
		}
	}

	return est
}

// KeyState returns a key state event (kst) that contains the
// current state of the identifier. This is essentially
// compressing all the establishment events to give a current
// view of keys, next, witnesses, and thresholds, along with
// a digest seal of the last received events
func (l *Log) KeyState() (*event.Event, error) {
	var kst *event.Event

	evnts := l.EstablishmentEvents()

	if len(evnts) == 0 {
		// nothing in the log!
		return nil, nil
	}

	for i, e := range evnts {
		// start with the inception event
		if i == 0 {
			kst = evnts[i]
			continue
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
	}

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
	seal, err = event.SealEstablishment(evnts[len(evnts)-1])
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
	// mark the event as seen
	e.Seen = time.Now().UTC()

	if len(l.Events) == 0 {
		if e.Event.EventType != event.ICP.String() {
			return errors.New("first event in an empty log must be an inception event")
		}
		l.Events = append(l.Events, e)
		return nil
	}

	current := l.Current()

	// add the signature to already applied event
	if e.Event.SequenceInt() <= current.SequenceInt() {
		return l.AddSignatures(e)
	} else if e.Event.SequenceInt() != current.SequenceInt()+1 {
		err := l.Pending.Add(e)
		if err != nil {
			return fmt.Errorf("unable to escrow event (%s)", err)
		}

		return nil
	}

	inDerivation, err := derivation.FromPrefix(e.Event.Digest)
	if err != nil {
		return fmt.Errorf("unable to determin digest derivation (%s)", err)
	}

	curSerialized, err := current.Serialize()
	if err != nil {
		return fmt.Errorf("unable to serialize current event (%s)", err)
	}

	curDigest, err := event.Digest(curSerialized, inDerivation.Code)
	if err != nil {
		return fmt.Errorf("unable to digest current event (%s)", err)
	}

	if !bytes.Equal(curDigest, inDerivation.Raw) {
		return errors.New("invalid digest for new event")
	}

	// if the sig threshold is not met escrow
	escrowed, err := l.Pending.Get(e.Event)
	if err != nil {
		return fmt.Errorf("Unable to retrieve escrowed messages (%s)", err)
	}
	sigs := mergeSignatures(escrowed.Signatures, e.Signatures)

	if !current.SigThreshold.Satisfied(sigs) {
		err = l.Pending.Add(e)
		if err != nil {
			return fmt.Errorf("unable to escrow event (%s)", err)
		}

		return nil
	}

	l.Events = append(l.Events, &event.Message{Event: e.Event, Signatures: sigs})
	dups, err := l.Pending.Clear(*e.Event)
	// we currently do not consider any of these errors that need to be addressed
	// TODO: handle
	if err == nil {
		for i, _ := range dups {
			l.Duplicitous.Add(dups[i])
		}
	}

	// go through the pending events and apply any that are now "current"
	current = l.Current()
	next := l.Pending.ForSequence(current.SequenceInt() + 1)
	if len(next) > 0 {
		sort.Sort(ByDate(next))
		// return nil
		return l.Apply(next[0])
	}

	return nil
}

func (l *Log) ApplyReceipt(vrc *event.Message) error {
	err := l.Receipts.Add(vrc)
	if err != nil {
		return err
	}

	return nil
}

func (l *Log) ReceiptsForEvent(evt *event.Event) []*event.Message {
	dig, _ := evt.GetDigest()
	fmt.Println(dig)
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
		l.Duplicitous.Add(e)
		return errors.New("unable to add signature to existing event (new event digest does not match)")
	}

	ext.Signatures = mergeSignatures(ext.Signatures, e.Signatures)

	return nil
}

// Verify the event signatures against the current log
// establishment event
func (l *Log) Verify(m *event.Message) error {
	var currentEvent *event.Event
	if len(l.Events) == 0 {
		if m.Event.EventType != event.ICP.String() {
			return errors.New("first event in an empty log must be an inception event")
		}
		currentEvent = m.Event
	} else {
		if m.Event.ILK() == event.ROT {
			currentEvent = m.Event
		} else {
			currentEvent = l.CurrentEstablishment()
		}
	}

	mRaw, err := m.Event.Serialize()
	if err != nil {
		return err
	}

	if len(m.Signatures) == 0 {
		return errors.New("no attached signatures to verify")
	}

	for _, sig := range m.Signatures {
		keyD, err := currentEvent.KeyDerivation(int(sig.KeyIndex))
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
