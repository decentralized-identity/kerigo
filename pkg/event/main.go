package event

import (
	"errors"
	"fmt"

	"github.com/decentralized-identity/kerigo/pkg/prefix"
)

type EventOption func(*Event) error

func WithKeys(keys ...prefix.Prefix) EventOption {
	return func(e *Event) error {
		for i := 0; i < len(keys); i++ {
			k := keys[i].String()
			e.Keys = append(e.Keys, k)
		}
		return nil
	}
}

func WithWitnesses(keys ...prefix.Prefix) EventOption {
	return func(e *Event) error {
		for i := 0; i < len(keys); i++ {
			k := keys[i].String()
			e.Witnesses = append(e.Keys, k)
		}
		return nil
	}
}

// WithNext key must be a self dressing prefix. Do not use a basic prefix
// otherwise the public key data will be exposed in the log
func WithNext(key prefix.Prefix) EventOption {
	return func(e *Event) error {
		if !key.Derivation().Code.SelfAddressing() {
			return errors.New("next keys must be self-addressing")
		}
		k := key.String()
		e.Next = k
		return nil
	}
}

// WithThreshold sets the key threshold
func WithThreshold(threshold int) EventOption {
	return func(e *Event) error {
		e.SigningThreshold = fmt.Sprintf("%x", threshold)
		return nil
	}
}

func WithAccountableDuplicityThreshold(threshold int) EventOption {
	return func(e *Event) error {
		e.AccountableDuplicityThreshold = fmt.Sprintf("%x", threshold)
		return nil
	}
}

// NewInceptionEvent returns and incpetion configured with the provided parameters
// New Inception Events will have empty 'vs' and 'pre' strings
func NewInceptionEvent(opts ...EventOption) (*Event, error) {
	e := &Event{
		EventType:                     ilkString[ICP],
		Sequence:                      "0",
		SigningThreshold:              "1",
		AccountableDuplicityThreshold: "1",
		Witnesses:                     []string{},
		Config:                        []string{},
	}
	for _, o := range opts {
		err := o(e)
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}
