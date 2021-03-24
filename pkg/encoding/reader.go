package encoding

import (
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type Reader interface {
	Read() (*event.Message, error)
	ReadAll() ([]*event.Message, error)
}
