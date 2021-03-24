package event

import (
	"bufio"
	"io"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

type AttachmentParser func(buf io.Reader) ([]derivation.Derivation, error)

type Attachment struct {
	Code                    derivation.CountCode
	Signatures              []derivation.Derivation
	TransferableReceipts    []*Quadlet
	NonTransferableReceipts []*Couplet
	WitnessReceipts         []*Couplet
}

type Couplet struct {
	Prefix    *derivation.Derivation
	Signature *derivation.Derivation
}

type Quadlet struct {
	Prefix    *derivation.Derivation
	Signature *derivation.Derivation
	Digest    *derivation.Derivation
	Sequence  int
}

func ParseAttachment(rd io.Reader) (*Attachment, error) {
	buf := bufio.NewReader(rd)

	f, err := buf.Peek(5)
	if err != nil {
		return nil, errors.Wrap(err, "error peeking")
	}

	if f[0] != '-' && f[0] != '_' {
		return nil, errors.New("invalid text attachment code")
	}

	c := string(f[:2])
	countCode, ok := derivation.CountCodes[c]
	if ok {
		att, err := ParseAttached(countCode, buf)
		if err != nil {
			return nil, err
		}

		return att, nil
	}

	return nil, errors.New("invalid attachment code")
}

func ParseAttached(c derivation.CountCode, buf io.Reader) (*Attachment, error) {
	switch c {
	case derivation.ControllerSigCountCode:
		ders, err := derivation.ParseAttachedSignatures(buf)
		if err != nil {
			return nil, errors.Wrap(err, "error reading attached signatures")
		}

		return &Attachment{
			Code:       derivation.ControllerSigCountCode,
			Signatures: ders,
		}, nil
	case derivation.WitnessSigCountCode:
		rcpts, err := ParseAttachedCouplets(buf)
		if err != nil {
			return nil, errors.Wrap(err, "error reading attached signatures")
		}

		return &Attachment{
			Code:            derivation.WitnessSigCountCode,
			WitnessReceipts: rcpts,
		}, nil
	case derivation.NonTransferableRctCountCode:
		rcpts, err := ParseAttachedCouplets(buf)
		if err != nil {
			return nil, errors.Wrap(err, "error reading attached signatures")
		}

		return &Attachment{
			Code:                    derivation.NonTransferableRctCountCode,
			NonTransferableReceipts: rcpts,
		}, nil
	case derivation.TransferableRctCountCode:
		rcpts, err := ParseAttachedQuadlets(buf)
		if err != nil {
			return nil, errors.Wrap(err, "error reading attached signatures")
		}

		return &Attachment{
			Code:                 derivation.TransferableRctCountCode,
			TransferableReceipts: rcpts,
		}, nil
	}

	return nil, errors.New("not implemented")
}
