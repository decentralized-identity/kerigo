package prefix

import (
	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

type Type int

const (
	Basic Type = iota
	SelfAddressing
)

// Traits are configuration options that indicate certain restrictions
// on how the prefix is intended to be used. They are contained in the
// "c" field of an event.
type Trait int

const (
	EstablishmentOnly = iota
	DoNotDelegate
)

var (
	traitToString = map[Trait]string{
		EstablishmentOnly: "EO",
		DoNotDelegate:     "DND",
	}
)

func (t Trait) String() string {
	return traitToString[t]
}

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
