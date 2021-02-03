package log

import (
	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type Escrow map[string]*event.Message

// Get returns the event message with all collected signatures
// for the given event
func (e Escrow) Get(evnt *event.Event) (*event.Message, error) {
	digest, err := digestEvent(evnt)
	if err != nil {
		return nil, err
	}

	escrowed := &event.Message{Event: evnt}

	if esc, ok := e[digest]; ok {
		escrowed = esc
	}

	return escrowed, nil
}

// ForSequence returns all of the messages currently in escrow for the given sequence number
func (e Escrow) ForSequence(sequence int) []*event.Message {
	msgs := []*event.Message{}
	for k, msg := range e {
		if msg.Event.SequenceInt() == sequence {
			msgs = append(msgs, e[k])
		}
	}

	return msgs
}

// Add a message to the escrow
func (e Escrow) Add(m *event.Message) error {
	digest, err := digestEvent(m.Event)
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
// Thus, this goes through and drops all competing events from the escrow
// and returns them
func (e Escrow) Clear(evnt event.Event) ([]*event.Message, error) {
	sequence := evnt.SequenceInt()
	digest, err := digestEvent(&evnt)
	if err != nil {
		return nil, err
	}

	delete(e, digest)

	dups := []*event.Message{}
	for i, msg := range e {
		if msg.Event.SequenceInt() == sequence {
			dups = append(dups, e[i])
			delete(e, i)
		}
	}

	return dups, nil
}

// digestEvent creates a standard digest of events to use as their index in
// the escrow
func digestEvent(evnt *event.Event) (string, error) {
	serialized, err := evnt.Serialize()
	if err != nil {
		return "", err
	}

	return event.DigestString(serialized, derivation.Blake3256)
}
