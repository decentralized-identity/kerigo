package log

import (
	"bytes"
	"fmt"
	"log"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/db"
	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

// Log contains the Key Event Log for a given identifier
type Log struct {
	db     db.DB
	prefix string
}

func New(prefix string, db db.DB) *Log {
	return &Log{
		db:     db,
		prefix: prefix,
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

	err := l.db.StreamEstablisment(l.prefix, func(evt *event.Message) error {
		est = append(est, evt.Event)
		return nil
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

	err := l.db.StreamEstablisment(l.prefix, func(msg *event.Message) error {
		e := msg.Event
		if kst == nil {
			kst = &event.Event{}
			*kst = *e
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
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error processing log stream (%s)", err.Error())
	}

	if kst == nil {
		return &event.Event{}, nil
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

	// if there are no attached signatures to the event ignore
	// DOS prevention - flooding an escrow with unverifiable events
	// TODO: currently we are not considering this an error condition, is it?
	if len(e.Signatures) == 0 {
		return nil
	}

	ilk := e.Event.ILK()
	state, err := l.KeyState()
	if err != nil {
		return fmt.Errorf("unable to build key state (%s)", err.Error())
	}

	if l.db.LogSize(l.prefix) == 0 {
		if ilk == event.ICP || ilk == event.DIP {
			l.prefix = e.Event.Prefix

			err := l.validateSigs(e.Event, e)
			if err != nil {
				return err
			}

			return l.db.LogEvent(e, true)
		} else {
			return l.db.EscrowOutOfOrderEvent(e)
		}
	}

	sn := e.Event.SequenceInt()
	dig, _ := e.Event.GetDigest()
	lastsn := state.LastEvent.SequenceInt()
	nextsn := lastsn + 1

	if ilk == event.ICP || ilk == event.DIP {
		if sn != 0 {
			return fmt.Errorf("invalid sequence number %d for ICP event", sn)
		}

		latestEst, err := l.db.CurrentEstablishmentEvent(l.prefix)
		if err != nil {
			return err
		}

		latestDig, _ := latestEst.Event.GetDigest()

		if dig != latestDig {
			_ = l.db.EscrowLikelyDuplicitiousEvent(e)
			return errors.New("likely duplictious ICP event")
		}

		err = l.VerifySigs(state, e)
		if err != nil {
			return err
		}

		//duplicate inception we've already seen, add any additional signatures
		return l.db.LogEvent(e, true)
	}

	// ROT, DRT or IXN
	if sn > nextsn {
		//Our of order event
		return l.db.EscrowOutOfOrderEvent(e)
	} else if sn == nextsn || ((ilk == event.ROT || ilk == event.DRT) && (lastsn < sn || lastsn <= nextsn)) {
		// In order event or recovery event
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
			_ = l.db.EscrowLikelyDuplicitiousEvent(e)
			return errors.New("invalid digest for new event")
		}

		err = l.updateState(state, e)
		if err != nil {
			return err
		}

	} else {
		// possibly duplilcate
		latestDig, err := l.db.LastAcceptedDigest(l.prefix, sn)
		if err != nil {
			return err
		}

		if dig != string(latestDig) {
			_ = l.db.EscrowLikelyDuplicitiousEvent(e)
			return errors.New("likely duplictious event")
		}

		err = l.VerifySigs(state, e)
		if err != nil {
			return err
		}

		//Already seen, log any additional signatures
		err = l.db.LogEvent(e, true)
		if err != nil {
			return err
		}

	}

	err = l.db.StreamPending(l.prefix, func(esc *event.Message) error {
		dig, _ := esc.Event.GetDigest()
		sn := esc.Event.SequenceInt()

		err = l.Apply(esc)
		if err != nil {
			log.Println("error processing escrowed event", dig)
			return nil
		}

		err = l.db.RemovePendingEscrow(l.prefix, sn, dig)
		if err != nil {
			log.Println("error removing pending escrowed item", dig)
			return nil
		}

		return nil
	})

	//b, _ := json.Marshal(e.Event)
	//log.Print("Added valid event to KEL event = ", string(b), "\n\n")

	return nil
}

func (l *Log) ApplyReceipt(vrc *event.Message) error {

	for _, sig := range vrc.Signatures {

		//TODO:  Verify receipt sig
		//err = receiptorKEL.Verify(vrc)
		//if err != nil {
		//	return errors.Wrap(err, "unable to verify vrc signatures")
		//}

		err := l.db.LogTransferableReceipt(vrc.Event, sig)
		if err != nil {
			return err
		}
	}

	return nil
}

// VerifySigs takes the current log key state and an event message
// and validates the attached signatures
func (l *Log) VerifySigs(state *event.Event, m *event.Message) error {
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
			panic(fmt.Errorf("invalid signature for key at index %d", sig.KeyIndex))
		}
	}

	return nil
}

func (l *Log) validateSigs(state *event.Event, m *event.Message) error {
	err := l.VerifySigs(state, m)
	if err != nil {
		return err
	}

	if state.SigThreshold != nil && !state.SigThreshold.Satisfied(m.Signatures) {
		err := l.db.EscrowPendingEvent(m)
		if err != nil {
			return fmt.Errorf("unable to escrow event (%s)", err)
		}

		return errors.New("signature threshold not met, event added to pending escrow")
	}

	return nil
}

func (l *Log) ReceiptsForEvent(evt *event.Event) [][]byte {
	out := [][]byte{}

	_ = l.db.StreamTransferableReceipts(evt.Prefix, evt.SequenceInt(), func(q []byte) error {
		out = append(out, q)
		return nil
	})

	return out
}

func (l *Log) updateState(state *event.Event, e *event.Message) error {
	ilk := e.Event.ILK()

	if ilk == event.ROT || ilk == event.DRT {
		// the latest establishment event has the current Next digest
		lastEstablisment := l.EventAt(state.LastEstablishment.SequenceInt())
		lastNextDig, err := derivation.FromPrefix(lastEstablisment.Event.Next)
		if err != nil {
			return fmt.Errorf("unable to parse next digest from last establishment event (%s)", err.Error())
		}

		// calculate the next digest based on the current keys/signing threshold
		nextDig, err := e.Event.NextDigest(lastNextDig.Code)
		if err != nil {
			return fmt.Errorf("unable to parse next digest event (%s)", err.Error())
		}

		// this should match what was stored in the last establishment
		if nextDig != lastNextDig.AsPrefix() {
			return errors.New("next digest invalid")
		}

		err = l.validateSigs(e.Event, e)
		if err != nil {
			return err
		}

	} else {
		err := l.validateSigs(state, e)
		if err != nil {
			return err
		}
	}

	return l.db.LogEvent(e, true)
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
