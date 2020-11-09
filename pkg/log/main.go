package log

import "github.com/decentralized-identity/kerigo/pkg/event"

type Log struct {
	Events []*event.Event
}
