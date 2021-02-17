package db

import (
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type DB interface {
	Put(k string, v []byte) error
	Get(k string) ([]byte, error)

	LogEvent(e *event.Message) error
	ForkEvent(e *event.Message) error

	LogSize(pre string) int
	StreamLog(pre string, handler func(*event.Message)) error
	StreamForks(pre string, handler func(*event.Message)) error
	StreamEstablisment(pre string, handler func(*event.Message)) error

	Seen(pre string) bool
	Inception(pre string) (*event.Message, error)
	CurrentEvent(pre string) (*event.Message, error)
	CurrentEstablishmentEvent(pre string) (*event.Message, error)
	EventAt(prefix string, sequence int) (*event.Message, error)

	Close() error
}
