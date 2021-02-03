package event

import (
	"time"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

// an event message holds the deserialized event
// along with the provided signature
type Message struct {
	Event      *Event
	Signatures []derivation.Derivation
	Seen       time.Time
}

func (m Message) Serialize() ([]byte, error) {
	evt, err := m.Event.Serialize()
	if err != nil {
		return nil, err
	}

	sc, err := derivation.NewSigCounter(derivation.WithCount(len(m.Signatures)))
	if err != nil {
		return nil, err
	}

	cntCode, err := sc.String()
	if err != nil {
		return nil, err
	}

	evt = append(evt, cntCode...)
	for _, sig := range m.Signatures {
		evt = append(evt, sig.AsPrefix()...)
	}

	return evt, nil
}
