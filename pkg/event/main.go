package event

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
)

type EventOption func(*Event) error

// WithKeys sets the keys that are applicable for the event
func WithKeys(keys ...prefix.Prefix) EventOption {
	return func(e *Event) error {
		for i := 0; i < len(keys); i++ {
			k := keys[i].String()
			e.Keys = append(e.Keys, k)
		}
		return nil
	}
}

// WithWitnesses sets the witness keys for the event
func WithWitnesses(keys ...prefix.Prefix) EventOption {
	return func(e *Event) error {
		for i := 0; i < len(keys); i++ {
			k := keys[i].String()
			e.Witnesses = append(e.Keys, k)
		}
		return nil
	}
}

// WithNext keys must be self adressing prefixs. Do not use a basic prefix
// otherwise the public key data will be exposed in the log breaking post-quantum
// security.
// To support multi-sig, next is a prefix of the commitment to a signing threshold
// along with all of the keys to be rotated to, combined using XOR.
// Each of the provided keys, along with the derivation to use for the next,
// must use the same derivaiton code.
func WithNext(threshold int, code derivation.Code, keys ...prefix.Prefix) EventOption {
	return func(e *Event) error {
		if !code.SelfAddressing() {
			return errors.New("next keys must be self-addressing")
		}

		// digest the threshold
		der, err := derivation.New(derivation.WithCode(code))
		if err != nil {
			return err
		}

		_, err = der.Derive([]byte(fmt.Sprintf("%x", threshold)))
		if err != nil {
			return err
		}

		sint := new(big.Int)
		sint.SetBytes(der.Raw)
		for ki := range keys {
			keyRaw, _ := der.Derive([]byte(keys[ki].String()))
			kint := new(big.Int)
			kint.SetBytes(keyRaw)
			_ = sint.Xor(sint, kint)
		}

		nextDig, err := derivation.New(derivation.WithCode(code), derivation.WithRaw(sint.Bytes()))
		if err != nil {
			return err
		}

		e.Next = nextDig.AsPrefix()
		return nil
	}
}

// WithThreshold sets the key threshold
func WithThreshold(threshold int64) EventOption {
	return func(e *Event) error {
		st, err := NewSigThreshold(threshold)
		if err != nil {
			return err
		}
		e.SigThreshold = st
		return nil
	}
}

// WithWeightedTheshold sets a weighted signing threshold using provided
// string int or fraction values. The total for all conditions must be
// >= 1 otherwise the threshold can not be met. The order in which
// the conditions are provided is important: they map to the specific
// key index in the keys list, e.g, the second condition provided to this
// configuration function would be the weight of a signature by the second key
// in the keys list.
func WithWeightedTheshold(conditions ...string) EventOption {
	return func(e *Event) error {
		st, err := NewWeighted(conditions...)
		if err != nil {
			return err
		}

		e.SigThreshold = st

		return nil
	}
}

// WithMultiWeightedThesholds sets multiple weighted signing thresholds using provided
// string values.
func WithMultiWeightedThesholds(thresholds ...[]string) EventOption {
	return func(e *Event) error {
		st, err := NewMultiWeighted(thresholds...)
		if err != nil {
			return err
		}

		e.SigThreshold = st

		return nil
	}
}

// WithWitnessThreshold sets the witness duplicity threshold for the event
func WithWitnessThreshold(threshold int) EventOption {
	return func(e *Event) error {
		e.WitnessThreshold = fmt.Sprintf("%x", threshold)
		return nil
	}
}

// WithType specifies the event type
func WithType(eventType ILK) EventOption {
	return func(e *Event) error {
		e.EventType = ilkString[eventType]
		return nil
	}
}

/// WithSequence sets the sequence number for this event
func WithSequence(sequence int) EventOption {
	return func(e *Event) error {
		e.Sequence = fmt.Sprintf("%x", sequence)
		return nil
	}
}

// WithDigest sets the digest for the event
func WithDigest(digest string) EventOption {
	return func(e *Event) error {
		e.Digest = digest
		return nil
	}
}

func WithDefaultVersion(in FORMAT) EventOption {
	return func(e *Event) error {
		e.Version = DefaultVersionString(in)
		return nil
	}
}

func WithPrefix(prefix string) EventOption {
	return func(e *Event) error {
		e.Prefix = prefix
		return nil
	}
}

func WithSeal(seal *Seal) EventOption {
	return func(e *Event) error {
		e.Seals = []*Seal{seal}
		return nil
	}
}

// NewInceptionEvent returns and incpetion configured with the provided parameters
// New Inception Events will have empty 'v' and 'i' strings
func NewInceptionEvent(opts ...EventOption) (*Event, error) {
	st, _ := NewSigThreshold(1)
	e := &Event{
		EventType:        ilkString[ICP],
		Sequence:         "0",
		SigThreshold:     st,
		WitnessThreshold: "0",
		Witnesses:        []string{},
		Config:           []prefix.Trait{},
	}
	for _, o := range opts {
		err := o(e)
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}

// NewEvent returns a new event with the specified options applied
func NewEvent(opts ...EventOption) (*Event, error) {
	st, _ := NewSigThreshold(1)
	e := &Event{
		Sequence:         "0",
		SigThreshold:     st,
		WitnessThreshold: "0",
		Witnesses:        []string{},
		Config:           []prefix.Trait{},
	}

	for _, o := range opts {
		err := o(e)
		if err != nil {
			return nil, err
		}
	}

	if e.EventType == "" {
		return nil, errors.New("must sepcify an event type")
	}

	if (e.EventType != ilkString[ICP] && e.EventType != ilkString[VRC]) && e.Sequence == "0" {
		return nil, errors.New("only inception events may have a sequence of 0")
	}

	return e, nil
}
