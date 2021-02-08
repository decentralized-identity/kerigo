package event

import (
	"fmt"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/version"
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
		WithSeals([]*Seal{s}),
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
	receipt.EventDigest = eventDigest

	eventBytes, err := Serialize(receipt, JSON)
	if err != nil {
		return nil, err
	}

	receipt.Version = VersionString(JSON, version.Code(), len(eventBytes))

	return receipt, nil
}

// Recipt generates a receipt for the provided event
func NonTransferableReceipt(event *Event, code derivation.Code) (*Event, error) {
	receipt, err := NewEvent(
		WithType(RCT),
		WithSequence(event.SequenceInt()),
		WithPrefix(event.Prefix),
		WithDefaultVersion(JSON),
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
	receipt.EventDigest = eventDigest

	return receipt, nil
}
