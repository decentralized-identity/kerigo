// Package derivation provides the derivation logic for KERI
//
// Derivaitons are data blobs that have been hashed or encrypted using a
// pre-defined set of algorithms. These data blobs are used to as the
// foundation of a variety functionality (for example prefixes)
// within KERI. Derivaitons are typically represented as Base64 encoded
// strings with a specific 1, 2 or 4 character prefix, making them self describing.
// This packages provides an accessible way to encode/decode the data bytes
// to a given KERI defined derivaiton.
package derivation

import (
	"encoding/base64"
	"fmt"
)

// DerivationOption is a genric configuration function for derivations
type DerivationOption func(*Derivation) error

// WithCode allows you to provide a derviation code for the derivation
func WithCode(code Code) DerivationOption {
	return func(d *Derivation) error {
		d.Code = code
		if d.Code.Basic() {
			d.deriver = basicDeriver()
		}
		if d.Code.SelfAddressing() {
			d.deriver = selfAddressingDeriver(code)
		}
		if d.Code.SelfSigning() {
			d.deriver = selfSigningDeriver(code)
		}
		if d.Code.AttachedSignature() {
			d.deriver = attachedSignatureDeriver(code)
		}
		return nil
	}
}

// WithSigner uses the provided signing function to do the derivation
func WithSigner(signer Signer) DerivationOption {
	return func(d *Derivation) error {
		d.deriver = deriver(signer)
		return nil
	}
}

// WithRaw allows you to provide raw derivation data
func WithRaw(data []byte) DerivationOption {
	return func(d *Derivation) error {
		d.Raw = data
		return nil
	}
}

// deriver is the function responsible for actually processing the
// raw data and returing the derived value
type deriver func([]byte) ([]byte, error)

// Derivation
type Derivation struct {
	Code     Code    // The code for this derivation
	deriver  deriver // return the derived data of the input
	Raw      []byte  // The Raw derived data
	KeyIndex uint16  // For Attached Signature Derivation - the index of the key for the signature
}

// Derive runs the derivation algorithm over the provided bytes
// returning the derived data
func (d *Derivation) Derive(data []byte) ([]byte, error) {
	raw, err := d.deriver(data)
	if err != nil {
		return nil, err
	}

	d.Raw = raw

	return raw, nil
}

// AsPrefix returns the derivation's raw data as a base 64 encoded string with
// the correct derivation code prepended
func (d *Derivation) AsPrefix() string {
	dcode := []byte(d.Code.String())
	if d.Code.AttachedSignature() {
		indexBase64, _ := IndexToBase64(d.KeyIndex)
		dcode = append(dcode[:1], indexBase64...)
	}
	return string(append(dcode, base64.RawURLEncoding.EncodeToString(d.Raw)...))
}

// New returns a derivation of the provided Code
func New(options ...DerivationOption) (*Derivation, error) {
	d := &Derivation{}
	for _, option := range options {
		err := option(d)
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}

// FromPrefix takes a prefix as input and returns the appropriate drivation
// and raw (base64 unencoded) data represented by the prefix.
func FromPrefix(data string) (*Derivation, error) {
	// Assumption: any valid prefix data will be over 4 bytes long, and if we know
	// that the data is at least that long, we can reference up to [:3] in the prefix
	// without going out of bounds
	if len(data) < 4 {
		return nil, fmt.Errorf("unable to determine derivation (%s)", "invalid prefix length")
	}

	var d *Derivation

	switch data[:1] {
	case "0":
		if dc, ok := codeValue[data[:2]]; ok {
			d, _ = New(WithCode(dc))
			if len(data) != d.Code.PrefixBase64Length() {
				return nil, fmt.Errorf("invalid prefix length (%d) for derevation %s", len(data), d.Code.Name())
			}
		} else {
			return nil, fmt.Errorf("unable to determin derevation from code %s", data[:1])
		}
	default:
		// we are dealing with a single Letter prefix
		if dc, ok := codeValue[data[:1]]; ok {
			d, _ = New(WithCode(dc))
			if len(data) != d.Code.PrefixBase64Length() {
				return nil, fmt.Errorf("invalid prefix length (%d) for derevation %s", len(data), d.Code.Name())
			}
		} else {
			return nil, fmt.Errorf("unable to determin derevation from code %s", data[:1])
		}
	}

	if d == nil {
		return nil, fmt.Errorf("unable to determin derevation")
	}

	raw, err := base64.RawURLEncoding.DecodeString(data[d.Code.Length():])
	if err != nil || len(raw) != d.Code.DataLength() {
		return nil, fmt.Errorf("unable to parse prefix (%s)", err)
	}

	d.Raw = raw

	return d, nil
}
