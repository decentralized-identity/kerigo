package log

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type Escrow map[string]*event.Message

// Get returns the event message with all collected signatures
// for the given event
func (e Escrow) Get(evnt *event.Event) (*event.Message, error) {
	serialized, err := evnt.Serialize()
	if err != nil {
		return nil, err
	}

	digest, err := event.DigestString(serialized, derivation.Blake3256)
	if err != nil {
		return nil, err
	}

	escrowed := &event.Message{Event: evnt}

	if esc, ok := e[digest]; ok {
		escrowed = esc
	}

	return escrowed, nil
}

// Add a message to the escrow
func (e Escrow) Add(m *event.Message) error {
	serialized, err := m.Event.Serialize()
	if err != nil {
		return err
	}

	digest, err := event.DigestString(serialized, derivation.Blake3256)
	if err != nil {
		return err
	}

	if _, ok := e[digest]; !ok {
		e[digest] = m
	} else {
		e[digest].Signatures = mergeSignatures(e[digest].Signatures, m.Signatures)
	}

	return nil
}

// Clear all escrowed messages with the same sequence number
// Escrowed events are indexed by the digest of their event - there could be
// competeing versions of events if the prefix owner is being duplicitous, but
// the first valid seen event always wins
// Thus, this goes through and drops all competing events
// TODO: this is an assumption - there are times where having a record of duplicitous
// events is a good thing
func (e Escrow) Clear(evnt event.Event) {
	sequence := evnt.SequenceInt()
	for i, messages := range e {
		if messages.Event.SequenceInt() == sequence {
			delete(e, i)
		}
	}
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

// Log contains the Key Event Log for a given identifier
type Log struct {
	Events []*event.Message // ordered Key events
	Escrow                  // pending events
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

func New() *Log {
	return &Log{Events: []*event.Message{}, Escrow: map[string]*event.Message{}}
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

// Apply the provided event to the log
// This function will confirm the sequence number and digest
// for the new log are correct before applying
func (l *Log) Apply(e *event.Message) error {
	if len(l.Events) == 0 {
		if e.Event.EventType != event.ICP.String() {
			return errors.New("first event in an empty log must be an inception event")
		}
		l.Events = append(l.Events, e)
		return nil
	}

	current := l.Current()
	if e.Event.SequenceInt() != current.SequenceInt()+1 {
		return errors.New("invalid sequence for new event")
	}

	incomingDerivation, err := derivation.FromPrefix(e.Event.Digest)
	if err != nil {
		return fmt.Errorf("unable to determin digest derivation (%s)", err)
	}

	cSerialized, err := current.Serialize()
	if err != nil {
		return fmt.Errorf("unable to serialize current event (%s)", err)
	}

	currentDigest, err := event.Digest(cSerialized, incomingDerivation.Code)
	if err != nil {
		return fmt.Errorf("unable to digest current event (%s)", err)
	}

	if !bytes.Equal(currentDigest, incomingDerivation.Raw) {
		return errors.New("invalid digest for new event")
	}

	// if the sig threshold is not met escrow
	escrowed, err := l.Escrow.Get(e.Event)
	if err != nil {
		return fmt.Errorf("Unable to retrieve escrowed messages (%s)", err)
	}

	sigs := mergeSignatures(escrowed.Signatures, e.Signatures)

	if len(sigs) < current.SigningThresholdInt() {
		err = l.Escrow.Add(e)
		if err != nil {
			return fmt.Errorf("unable to escrow event (%s)", err)
		}
	} else {
		l.Events = append(l.Events, &event.Message{Event: e.Event, Signatures: sigs})
		l.Escrow.Clear(*e.Event)
	}

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
