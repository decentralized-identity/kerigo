package event

import (
	"fmt"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

// Recipt generates a receipt for the provided event
func TransferableReceipt(event *Event, estEvent *Event, code derivation.Code) (*Event, error) {
	s, err := SealEstablishment(estEvent)
	if err != nil {
		return nil, fmt.Errorf("unable to create last est evt seal for receipt: %v", err)
	}

	receipt, err := NewEvent(
		WithType(VRC),
		WithSequence(event.SequenceInt()),
		WithPrefix(event.Prefix),
		WithDefaultVersion(JSON),
		WithSeal(s),
	)

	if err != nil {
		return nil, err
	}

	ser, err := event.Serialize()
	if err != nil {
		return nil, err
	}

	eventDigest, err := DigestString(ser, code)
	if err != nil {
		return nil, err
	}
	receipt.Digest = eventDigest

	return receipt, nil
}

// Recipt generates a receipt for the provided event
func NonTransferableReceipt(event *Event, code derivation.Code) (*Event, error) {
	evtSeal, err := NewEventSeal("dig", "pre", "0")
	receipt, err := NewEvent(
		WithType(VRC),
		WithSequence(event.SequenceInt()),
		WithPrefix(event.Prefix),
		WithDefaultVersion(JSON),
		WithSeal(evtSeal),
	)

	if err != nil {
		return nil, err
	}

	ser, err := event.Serialize()
	if err != nil {
		return nil, err
	}

	eventDigest, err := DigestString(ser, code)
	if err != nil {
		return nil, err
	}
	receipt.Digest = eventDigest

	return receipt, nil
}
