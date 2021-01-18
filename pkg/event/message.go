package event

import "github.com/decentralized-identity/kerigo/pkg/derivation"

// an event message holds the deserialized event
// along with the provided signature
type Message struct {
	Event      *Event
	Signatures []derivation.Derivation
}

func (m Message) Serialize() ([]byte, error) {
	evt, err := m.Event.Serialize()
	if err != nil {
		return nil, err
	}

	//TODO: correct attached signature count code
	for _, sig := range m.Signatures {
		evt = append(evt, sig.AsPrefix()...)
	}

	return evt, nil
}
