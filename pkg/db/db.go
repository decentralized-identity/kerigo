package db

import (
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type DB interface {
	Put(k string, v []byte) error
	Get(k string) ([]byte, error)

	LogEvent(e *event.Message, first bool) error
	LogTransferableReceipt(vrc *event.Receipt) error
	LogNonTransferableReceipt(rct *event.Receipt) error

	EscrowPendingEvent(e *event.Message) error
	RemovePendingEscrow(prefix string, sn int, dig string) error

	EscrowOutOfOrderEvent(e *event.Message) error
	EscrowLikelyDuplicitiousEvent(e *event.Message) error

	LogSize(pre string) int
	StreamEstablisment(pre string, handler func(*event.Message) error) error
	StreamAsFirstSeen(pre string, handler func(*event.Message) error) error
	StreamBySequenceNo(pre string, handler func(*event.Message) error) error
	StreamPending(pre string, handler func(*event.Message) error) error
	StreamTransferableReceipts(pre string, sn int, handler func(quadlet []byte) error) error

	Seen(pre string) bool
	Inception(pre string) (*event.Message, error)
	CurrentEvent(pre string) (*event.Message, error)
	CurrentEstablishmentEvent(pre string) (*event.Message, error)
	EventAt(prefix string, sequence int) (*event.Message, error)

	LastAcceptedDigest(pre string, seq int) ([]byte, error)

	Close() error
}
