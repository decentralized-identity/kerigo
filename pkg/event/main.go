package event

import (
	"errors"
	"fmt"

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
		sithDig, err := derivation.New(derivation.WithCode(code))
		if err != nil {
			return err
		}

		_, err = sithDig.Derive([]byte(fmt.Sprintf("%x", threshold)))
		if err != nil {
			return err
		}

		xorRaw := sithDig.Raw
		for ki := range keys {
			var keyRaw []byte
			if keys[ki].Derivation().Code.Basic() {
				// we can convert to the correct derivation
				der, _ := derivation.New(derivation.WithCode(code))
				_, err := der.Derive(keys[ki].Raw())
				if err != nil {
					return fmt.Errorf("unable to conver basic key derivation (%s)", err)
				}
				keyRaw = der.Raw
			} else {
				if keys[ki].Derivation().Code != code {
					return errors.New("all key derivations must be the same")
				}
				keyRaw = keys[ki].Raw()
			}

			buf := make([]byte, len(xorRaw))
			for ri := range keyRaw {
				buf[ri] = xorRaw[ri] ^ keyRaw[ri]
			}

			xorRaw = buf
		}

		nextDig, err := derivation.New(derivation.WithCode(code), derivation.WithRaw(xorRaw))
		if err != nil {
			return err
		}

		e.Next = nextDig.AsPrefix()
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

// WithAccountableDuplicityThreshold sets the witness duplicity threshold for the event
func WithAccountableDuplicityThreshold(threshold int) EventOption {
	return func(e *Event) error {
		e.AccountableDuplicityThreshold = fmt.Sprintf("%x", threshold)
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

// NewInceptionEvent returns and incpetion configured with the provided parameters
// New Inception Events will have empty 'vs' and 'pre' strings
func NewInceptionEvent(opts ...EventOption) (*Event, error) {
	e := &Event{
		EventType:                     ilkString[ICP],
		Sequence:                      "0",
		SigningThreshold:              "1",
		AccountableDuplicityThreshold: "0",
		Witnesses:                     []string{},
		Config:                        []prefix.Trait{},
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
	e := &Event{
		Sequence:                      "0",
		SigningThreshold:              "1",
		AccountableDuplicityThreshold: "0",
		Witnesses:                     []string{},
		Config:                        []prefix.Trait{},
	}

	for _, o := range opts {
		err := o(e)
		if err != nil {
			return nil, err
		}
	}

	if e.EventType == "" {
		return nil, errors.New("must sepcify and event type")
	}

	if e.EventType != ilkString[ICP] && e.Sequence == "0" {
		return nil, errors.New("only inception events may have a sequence of 0")
	}

	return e, nil
}
