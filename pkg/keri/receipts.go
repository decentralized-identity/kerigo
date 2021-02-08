package keri

import (
	"sync"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/event"
)

// Message thread-safe message register structure.
type Receipts struct {
	mu     sync.RWMutex
	events []chan<- *event.Event
}

// RcptChans returns receipt channels.
func (r *Receipts) RcptChans() []chan<- *event.Event {
	r.mu.RLock()
	events := append(r.events[:0:0], r.events...)
	r.mu.RUnlock()

	return events
}

// RegisterMsgEvent on protocol messages. The message events are triggered for incoming messages. Event
// will not expect any callback on these events unlike Action events.
func (r *Receipts) RegisterRcptChan(ch chan<- *event.Event) error {
	if ch == nil {
		return errors.New("nil channel")
	}

	r.mu.Lock()
	r.events = append(r.events, ch)
	r.mu.Unlock()

	return nil
}

// UnregisterMsgEvent on protocol messages. Refer RegisterMsgEvent().
func (r *Receipts) UnregisterRcptChan(ch chan<- *event.Event) error {
	r.mu.Lock()
	for i := 0; i < len(r.events); i++ {
		if r.events[i] == ch {
			r.events = append(r.events[:i], r.events[i+1:]...)
			i--
		}
	}
	r.mu.Unlock()

	return nil
}
