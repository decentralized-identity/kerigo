package stream

import (
	"fmt"
	"strings"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type ReplayMode int

const (
	DisjointMode ReplayMode = iota
	ConjointMode
)

func ToDisjoint(m *event.Message) ([]byte, error) {
	evt, err := m.Event.Serialize()
	if err != nil {
		return nil, err
	}

	sc, err := derivation.NewSigCounter(derivation.ControllerSigCountCode, derivation.WithCount(len(m.Signatures)))
	if err != nil {
		return nil, err
	}

	cntCode, err := sc.String()
	if err != nil {
		return nil, err
	}

	evt = append(evt, cntCode...)
	for _, sig := range m.Signatures {
		evt = append(evt, sig.AsPrefix()...)
	}

	for _, rcpt := range m.TransferableReceipts {
		msg, err := rcpt.Message()
		if err != nil {
			return nil, err
		}

		d, err := ToDisjoint(msg)
		if err != nil {
			return nil, err
		}

		evt = append(evt, d...)
	}

	for _, rcpt := range m.NonTransferableReceipts {
		msg, err := rcpt.Message()
		if err != nil {
			return nil, err
		}

		d, err := ToDisjoint(msg)
		if err != nil {
			return nil, err
		}

		evt = append(evt, d...)
	}

	for _, rcpt := range m.WitnessReceipts {
		msg, err := rcpt.Message()
		if err != nil {
			return nil, err
		}

		d, err := ToDisjoint(msg)
		if err != nil {
			return nil, err
		}

		evt = append(evt, d...)
	}

	return evt, nil
}

func ToConjoint(m *event.Message) ([]byte, error) {

	switch m.Event.ILK() {
	case event.VRC:
		return conjointVRC(m)
	case event.RCT:
		return conjointRCT(m)
	default:
		return conjoint(m)
	}
}

func conjoint(m *event.Message) ([]byte, error) {

	evt, err := m.Event.Serialize()
	if err != nil {
		return nil, err
	}

	sc, err := derivation.NewSigCounter(derivation.ControllerSigCountCode, derivation.WithCount(len(m.Signatures)))
	if err != nil {
		return nil, err
	}

	cntCode, err := sc.String()
	if err != nil {
		return nil, err
	}

	evt = append(evt, cntCode...)
	for _, sig := range m.Signatures {
		evt = append(evt, sig.AsPrefix()...)
	}

	if len(m.TransferableReceipts) > 0 {
		sc, err = derivation.NewSigCounter(derivation.TransferableRctCountCode, derivation.WithCount(len(m.TransferableReceipts)))
		if err != nil {
			return nil, err
		}

		cntCode, err = sc.String()
		if err != nil {
			return nil, err
		}

		evt = append(evt, cntCode...)
		for _, rcpt := range m.TransferableReceipts {
			evt = append(evt, rcpt.Text()...)
		}
	}

	if len(m.NonTransferableReceipts) > 0 {
		sc, err = derivation.NewSigCounter(derivation.NonTransferableRctCountCode, derivation.WithCount(len(m.TransferableReceipts)))
		if err != nil {
			return nil, err
		}

		cntCode, err = sc.String()
		if err != nil {
			return nil, err
		}

		evt = append(evt, cntCode...)
		for _, rcpt := range m.NonTransferableReceipts {
			evt = append(evt, rcpt.Text()...)
		}
	}
	return evt, nil
}

func conjointVRC(m *event.Message) ([]byte, error) {
	//Transferable identifier prefix, the latest establishment event sequence number,
	// the latest establishment event digest and the associated signature
	// Those are the validator prefix and the signature attached to the RCT

	seal := m.Event.Seals[0]
	sig := m.Signatures[0]

	quadlet := strings.Join([]string{seal.Prefix, fmt.Sprintf("%024d", seal.SequenceInt()), seal.Digest, sig.AsPrefix()}, "")

	return []byte(quadlet), nil
}

func conjointRCT(m *event.Message) ([]byte, error) {
	// Witness identifier prefix and the associated signature
	// Those are the validator prefix and the signature attached to the RCT
	pre := m.Event.Prefix
	sig := m.Signatures[0]

	couplet := strings.Join([]string{pre, sig.AsPrefix()}, "")

	return []byte(couplet), nil
}
