package io

import (
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type InboundTransport interface {
	// Start starts the inbound transport.  It returns a channel of event.Messages or an error
	Start() (<-chan *event.Message, error)

	// Write writes the serialized bytes of the message
	Write(msg *event.Message) error

	// Stop halts the inbound transport
	Stop()
}
