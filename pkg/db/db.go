package db

import (
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type DB interface {
	Put(k string, v []byte) error
	Get(k string) ([]byte, error)

	AddVRCs(key string, vrcs []*event.Event) error
	AddVRC(key string, vrcs *event.Event) error
	GetVRCs(key string) ([]*event.Event, error)
	ListVCRs(key string) (Iterator, error)
	VCRCount(key string) (int, error)
	DeleteVRCs(key string) error
}

type Iterator interface {
}
