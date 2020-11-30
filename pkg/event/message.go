package event

// an event message holds the deserialized event
// along with the provided signature
type Message struct {
	Event      *Event
	Signatures []string
}

func ValidateMessage(event *Event, sig []byte) error {
	return nil
}
