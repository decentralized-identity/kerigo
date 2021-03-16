package event

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/version"
)

type Receipt struct {
	Prefix   string
	Digest   string
	Sequence int

	RctType   ILK
	Signature *derivation.Derivation //The Signature of the receipted event

	EstPrefix   string // The Witness Identifier Prefix for Receipt Signatures (Transferable and Non-Transferable)
	EstSequence int    // The sn of Latest Establishment Event for Transferable Receipt signatures
	EstDigest   string // The dig of Latest Establishment Event for Transferable Receipt signatures

	txt []byte
	bin []byte
}

type ReceiptOpt func(r *Receipt) error

func NewReceipt(evt *Event, opts ...ReceiptOpt) (*Receipt, error) {
	dig, err := evt.GetDigest()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get digest to create event")
	}
	r := &Receipt{
		RctType:  RCT,
		Prefix:   evt.Prefix,
		Digest:   dig,
		Sequence: evt.SequenceInt(),
	}

	for _, opt := range opts {
		err := opt(r)
		if err != nil {
			return nil, err
		}
	}

	if r.RctType == RCT && (len(r.EstPrefix) > 0 && r.EstSequence >= 0 && r.Signature != nil) {
		return r, nil
	}

	if r.RctType == VRC && (len(r.EstPrefix) > 0 && r.EstSequence >= 0 && len(r.EstDigest) > 0 && r.Signature != nil) {
		return r, nil
	}

	return nil, errors.New("invalid receipt")
}

func WithEstablishmentEvent(est *Event) ReceiptOpt {
	return func(r *Receipt) error {
		s, err := SealEstablishment(est)
		if err != nil {
			return errors.Wrap(err, "error sealing establishment event for receipt")
		}

		r.RctType = VRC
		r.EstPrefix = s.Prefix
		r.EstSequence = s.SequenceInt()
		r.EstDigest = s.Digest

		return nil
	}
}

func WithEstablishmentSeal(s *Seal) ReceiptOpt {
	return func(r *Receipt) error {
		r.RctType = VRC
		r.EstPrefix = s.Prefix
		r.EstSequence = s.SequenceInt()
		r.EstDigest = s.Digest

		return nil
	}
}

func WithQB64(qb64 []byte) ReceiptOpt {
	return func(r *Receipt) error {
		r.txt = qb64

		return nil
	}
}

func WithSignature(der *derivation.Derivation) ReceiptOpt {
	return func(r *Receipt) error {
		r.Signature = der
		return nil
	}
}

func WithSignerPrefix(pre string) ReceiptOpt {
	return func(r *Receipt) error {
		r.EstPrefix = pre
		return nil
	}
}

func (r *Receipt) Text() []byte {
	if r.txt == nil {
		switch r.RctType {
		case VRC:
			o := derivation.NewOrdinal(uint16(r.EstSequence))
			quadlet := strings.Join([]string{r.EstPrefix, string(o.Base64()), r.EstDigest, r.Signature.AsPrefix()}, "")
			r.txt = []byte(quadlet)
		case RCT:
			couplet := strings.Join([]string{r.EstPrefix, r.Signature.AsPrefix()}, "")
			r.txt = []byte(couplet)
		}
	}

	return r.txt
}

func (r *Receipt) Bin() []byte {
	if r.bin == nil {
		pre, _ := derivation.FromPrefix(r.EstPrefix)

		switch r.RctType {
		case VRC:
			dig, _ := derivation.FromPrefix(r.EstDigest)
			o := derivation.NewOrdinal(uint16(r.EstSequence))
			quadlet := bytes.Join([][]byte{pre.Raw, o.Base64(), dig.Raw, r.Signature.Raw}, []byte{})
			r.bin = quadlet
		case RCT:
			couplet := bytes.Join([][]byte{pre.Raw, r.Signature.Raw}, []byte{})
			r.bin = couplet
		}
	}

	return r.bin
}

func (r *Receipt) Message() (*Message, error) {

	opts := []EventOption{
		WithType(r.RctType),
		WithSequence(r.Sequence),
		WithPrefix(r.Prefix),
		WithDefaultVersion(JSON),
	}

	switch r.RctType {
	case VRC:
		s, _ := NewEventSeal(r.EstDigest, r.EstPrefix, strconv.Itoa(r.EstSequence))
		opts = append(opts, WithSeals([]*Seal{s}))
	case RCT:
		s, _ := NewSeal(EventSeal, WithSealPrefix(r.EstPrefix))
		opts = append(opts, WithSeals([]*Seal{s}))
	}

	receipt, err := NewEvent(
		opts...,
	)

	if err != nil {
		return nil, errors.Wrap(err, "unable to create new event")
	}

	receipt.EventDigest = r.Digest

	eventBytes, err := Serialize(receipt, JSON)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error serializing receipt")
	}

	receipt.Version = VersionString(JSON, version.Code(), len(eventBytes))

	msg := &Message{
		Event:      receipt,
		Signatures: []derivation.Derivation{*r.Signature},
	}

	return msg, nil
}
