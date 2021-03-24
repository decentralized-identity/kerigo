package event

import (
	"bufio"
	"fmt"
	"io"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

func ParseAttachedCouplets(buf io.Reader) ([]*Couplet, error) {
	out := []*Couplet{}

	rctCountBytes := make([]byte, 4)
	read, err := buf.Read(rctCountBytes)
	if read != 4 || err != nil {
		return nil, errors.New("invalid receipt count")
	}

	rctCount, err := derivation.Base64ToIndex(string(rctCountBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid receipt count (%s)", err)
	}

	// iterate over the receipt bytes for each receipt
	current := uint16(0)
	for current < rctCount {
		rct, err := ParseAttachedCouplet(buf)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing receipt %d", current)
		}

		out = append(out, rct)
		current++
	}

	return out, nil
}

func ParseAttachedCouplet(r io.Reader) (*Couplet, error) {
	pre, err := derivation.ParsePrefix(r)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read prefix from beginning of receipt")
	}

	sig, err := derivation.ParsePrefix(r) //This is a RCT, parse only the Signature remains
	if err != nil {
		return nil, errors.Wrap(err, "unable to read signature")
	}

	return &Couplet{
		Prefix:    pre,
		Signature: sig,
	}, nil

}

func ParseAttachedQuadlets(buf io.Reader) ([]*Quadlet, error) {
	out := []*Quadlet{}

	rctCountBytes := make([]byte, 4)
	read, err := buf.Read(rctCountBytes)
	if read != 4 || err != nil {
		return nil, errors.New("invalid receipt count")
	}

	rctCount, err := derivation.Base64ToIndex(string(rctCountBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid receipt count (%s)", err)
	}

	// iterate over the receipt bytes for each receipt
	current := uint16(0)
	for current < rctCount {
		rct, err := ParseAttachedQuadlet(buf)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing receipt %d", current)
		}

		out = append(out, rct)
		current++
	}

	return out, nil
}

func ParseAttachedQuadlet(r io.Reader) (*Quadlet, error) {
	buf := bufio.NewReader(r)
	pre, err := derivation.ParsePrefix(buf)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read prefix from beginning of receipt")
	}

	o, err := derivation.ParseOrdinal(buf)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read establishment sequence number")
	}

	dig, err := derivation.ParsePrefix(buf) //This is a RCT, parse only the Signature remains
	if err != nil {
		return nil, errors.Wrap(err, "unable to read establishment digest")
	}

	sig, err := derivation.ParsePrefix(buf)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read signature for receipt")
	}

	return &Quadlet{
		Prefix:    pre,
		Signature: sig,
		Digest:    dig,
		Sequence:  o.Num(),
	}, nil

}
