package io

import (
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type Conn interface {
	Msgs() chan *event.Message
	Write(msg *event.Message) error
}

type Transport interface {
	// Start starts the inbound transport.  It returns a channel of event.Messages or an error
	Start() (<-chan Conn, error)

	// Write writes to all connections current active for the transport
	Write(msg *event.Message) error

	// Stop halts the inbound transport
	Stop()
}
