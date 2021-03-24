package encoding

import (
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type Writer interface {
	Write(msg *event.Message) error
	WriteAll(msg []*event.Message) error
}
