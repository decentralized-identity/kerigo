package log

import (
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type Register map[string][]*event.Message

func (r Register) Add(vrc *event.Message) error {
	dig := vrc.Event.EventDigest
	r[dig] = append(r[dig], vrc)
	return nil
}
