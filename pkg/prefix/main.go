package prefix

import (
	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

type Type int

const (
	Basic Type = iota
	SelfAddressing
)

type Prefix interface {
	String() string
	Derivation() *derivation.Derivation
	Raw() []byte // Returns the RAW derived data
}

func New(derivation *derivation.Derivation) Prefix {
	// d, err := derivation.New(derivation.WithCode(dc), derivation.WithRaw(data))
	// if err != nil {
	// 	return nil, err
	// }
	return &base{derivation: derivation}
	// data, err = bp.Derivation().Derive(data)
	// if err != nil {
	// 	return nil, err
	// }

	// bp.data = data

	// return bp, nil
}

func FromString(data string) (Prefix, error) {
	d, err := derivation.FromPrefix(data)
	if err != nil {
		return nil, err
	}

	return &base{derivation: d}, nil
}
