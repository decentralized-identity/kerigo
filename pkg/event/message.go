package event

import (
	"strconv"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

// an event message holds the deserialized event
// along with the provided signature
type Message struct {
	Event                   *Event
	Signatures              []derivation.Derivation
	TransferableReceipts    []*Receipt
	NonTransferableReceipts []*Receipt
	WitnessReceipts         []*Receipt
}

type MessageOption func(*Message) error

func NewMessage(evt *Event, opts ...MessageOption) (*Message, error) {
	msg := &Message{Event: evt}

	for _, opt := range opts {
		err := opt(msg)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

func WithSignatures(sigs []derivation.Derivation) MessageOption {
	return func(msg *Message) error {
		msg.Signatures = append(msg.Signatures, sigs...)
		return nil
	}
}

func WithTransferableReceipts(quads []*Quadlet) MessageOption {
	return func(msg *Message) error {
		rcts := make([]*Receipt, len(quads))
		for i, quad := range quads {
			rct, err := NewReceipt(msg.Event,
				WithSignature(quad.Signature),
				WithEstablishmentSeal(&Seal{
					Prefix:   quad.Prefix.AsPrefix(),
					Sequence: strconv.Itoa(quad.Sequence),
					Digest:   quad.Digest.AsPrefix(),
				}),
			)
			if err != nil {
				return err
			}

			rcts[i] = rct
		}
		msg.TransferableReceipts = append(msg.TransferableReceipts, rcts...)
		return nil
	}
}

func WithNonTransferableReceipts(couples []*Couplet) MessageOption {
	return func(msg *Message) error {
		rcts := make([]*Receipt, len(couples))
		for i, couple := range couples {
			rct, err := NewReceipt(msg.Event, WithSignerPrefix(couple.Prefix.AsPrefix()),
				WithSignature(couple.Signature))
			if err != nil {
				return err
			}

			rcts[i] = rct
		}
		msg.NonTransferableReceipts = append(msg.NonTransferableReceipts, rcts...)
		return nil
	}
}

func WithWitnessReceipts(couples []*Couplet) MessageOption {
	return func(msg *Message) error {
		rcts := make([]*Receipt, len(couples))
		for i, couple := range couples {
			rct, err := NewReceipt(msg.Event, WithSignerPrefix(couple.Prefix.AsPrefix()),
				WithSignature(couple.Signature))
			if err != nil {
				return err
			}

			rcts[i] = rct
		}
		msg.WitnessReceipts = append(msg.WitnessReceipts, rcts...)
		return nil
	}
}
