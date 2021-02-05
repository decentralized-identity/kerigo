package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

type SealType int

const (
	DigestSeal SealType = iota
	RootSeal
	EventSeal
	EventLocationSeal
)

type SealOption func(*Seal) error

// Seal is used to anchor particular data to an event
// There are multiple types of seals, each with
// a different combination of data points.
type Seal struct {
	Type      SealType `json:"-"`
	Root      string   `json:"rd,omitempty"`
	Prefix    string   `json:"i,omitempty"`
	Sequence  string   `json:"s,omitempty"`
	EventType string   `json:"t,omitempty"`
	Digest    string   `json:"d,omitempty"`
}

func NewSeal(typ SealType, opts ...SealOption) (*Seal, error) {
	s := &Seal{
		Type: typ,
	}

	for _, o := range opts {
		err := o(s)
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

func NewDigestSeal(dig string) (*Seal, error) {
	return NewSeal(DigestSeal, WithSealDigest(dig))
}

func NewRootSeal(rt string) (*Seal, error) {
	return NewSeal(RootSeal, WithRoot(rt))
}

func NewEventSeal(dig, pre, sn string) (*Seal, error) {
	return NewSeal(EventSeal, WithSealDigest(dig), WithSealPrefix(pre), WithSealSequence(sn))
}

func SealEstablishment(evt *Event) (*Seal, error) {
	ser, err := evt.Serialize()
	if err != nil {
		return nil, fmt.Errorf("error serializing establshment event to extracted data set: %v", err)
	}

	sealDigest, err := DigestString(ser, derivation.Blake3256)
	if err != nil {
		return nil, fmt.Errorf("unable to digest establishment event: %v", err)
	}

	s, err := NewEventSeal(sealDigest, evt.Prefix, evt.Sequence)
	if err != nil {
		return nil, fmt.Errorf("unable to create last est evt seal for receipt: %v", err)
	}

	return s, nil
}

func NewEventLocationSeal(dig, pre, sn string, ilk ILK) (*Seal, error) {
	return NewSeal(EventLocationSeal,
		WithSealDigest(dig),
		WithSealPrefix(pre),
		WithSealSequence(sn),
		WithSealEventType(ilk),
	)
}

func WithSealDigest(dig string) SealOption {
	return func(s *Seal) error {
		s.Digest = dig
		return nil
	}
}

func WithRoot(rt string) SealOption {
	return func(s *Seal) error {
		s.Root = rt
		return nil
	}
}

func WithSealPrefix(pre string) SealOption {
	return func(s *Seal) error {
		s.Prefix = pre
		return nil
	}
}

func WithSealEventType(eventType ILK) SealOption {
	return func(e *Seal) error {
		e.EventType = ilkString[eventType]
		return nil
	}
}

func WithSealSequence(sn string) SealOption {
	return func(s *Seal) error {
		s.Sequence = sn
		return nil
	}
}

type SealArray []*Seal

func (r *SealArray) UnmarshalJSON(b []byte) error {
	a := []*Seal(*r)
	if len(b) == 0 {
		*r = nil
		return nil
	}

	if b[0] == '[' {
		err := json.Unmarshal(b, &a)
		if err != nil {
			return err
		}

		*r = a
		return nil
	} else if b[0] == '{' {
		s := &Seal{}
		err := json.Unmarshal(b, s)
		if err != nil {
			return err
		}

		*r = []*Seal{s}

		return nil
	} else {
		return errors.New("unmarshal of Seal Array")
	}
}

func (r *SealArray) MarshalJSON() ([]byte, error) {
	a := []*Seal(*r)
	if len(a) == 1 {
		return json.Marshal(a[0])
	}

	return json.Marshal(a)
}

// SequenceInt returns an integer representation of the
// hex sequence string
func (r *Seal) SequenceInt() int {
	eInt, err := strconv.ParseInt(r.Sequence, 16, 64)
	if err != nil {
		return -1
	}
	return int(eInt)
}
