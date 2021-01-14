package event

import "github.com/decentralized-identity/kerigo/pkg/derivation"

// an event message holds the deserialized event
// along with the provided signature
type Message struct {
	Event      *Event
	Signatures []derivation.Derivation
}
