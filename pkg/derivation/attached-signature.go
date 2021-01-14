package derivation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// Attahced Signature derivations must provide a signer function
func attachedSignatureDeriver(c Code) (d deriver) {
	return func(data []byte) ([]byte, error) {
		return nil, errors.New("For attached signature derivations must provide Signer function")
	}
}

// IndexToBase64 takes the provided index int and converts it to the correct 2 character base64 representation
// Currently the index has to be less than 4095, which is the max encdoed value for a two character
// base64 representation
func IndexToBase64(index uint16) (string, error) {
	if index < 4096 {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, index)
		encoded := base64.RawURLEncoding.EncodeToString(append([]byte{0}, buf...))[1:]
		if index < 64 {
			return encoded[2:], nil
		} else {
			return encoded[1:], nil
		}
	}
	return "", errors.New("index must be less than 4095")
}

// Base64ToIndex converts a 2 character base64 index string into an int
// Currently it only supports index strings up to 2 characters long
func Base64ToIndex(index string) (uint16, error) {
	var convert string
	switch len(index) {
	case 1:
		convert = "AAA" + index
	case 2:
		convert = "AA" + index
	default:
		return 0, errors.New("index string can only be 2 characters long")
	}

	bytes, err := base64.RawURLEncoding.DecodeString(convert)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint16(bytes[1:]), nil
}

// ParseSignatureCount takes a well formated 4 character signature derivation code
// and returns the decoded count
func ParseSignatureCount(count string) (uint16, error) {
	if len(count) != 4 {
		return 0, errors.New("signature count string must be 4 characters long")
	}

	if count[:1] != "-" || count[1:2] != "A" {
		return 0, errors.New("invalid count format. String must start with '-A'")
	}

	return Base64ToIndex(count[2:])
}

// FromAttachedSignature parses an attached signature and returns
// the appropriate type. These derivation codes are similar to
// prefix derivation codes (i.e. they start with similar letters)
// but are handled differently in the context of an attached signature
// (namely they are two letter derivation codes but do not start with a "0" like
// the prefix derivation codes do)
func FromAttachedSignature(sig string) (*Derivation, error) {
	if len(sig) < 2 {
		return nil, errors.New("invalid signature string length")
	}
	var code Code
	switch sig[:1] {
	case "A":
		code = Ed25519Attached
	case "B":
		code = EcDSAAttached
	}

	if len(sig) != code.PrefixBase64Length() {
		return nil, errors.New("invalid signature string length")
	}

	der, err := New(WithCode(code))
	if err != nil {
		return nil, fmt.Errorf("unable to parse attahced signature (%s)", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(sig[2:])
	if err != nil {
		return nil, fmt.Errorf("unable to parse attahced signature (%s)", err)
	}

	if len(raw) != code.DataLength() {
		return nil, errors.New("invalid signature string length")
	}

	der.Raw = raw

	index, err := Base64ToIndex(sig[1:2])
	if err != nil {
		return nil, fmt.Errorf("unable to parse signature key index (%s)", err)
	}

	der.KeyIndex = index

	return der, nil
}

// ParseAttachedSignatures takes an attached signatures string and parses
// into individual derivations. This will return any unused bytes that remain
// after parsing the the number of signatures indicated in the sig count. It
// will error if there are not enough bytes for the number of signatures, or
// if any individual signature is not sucessfully parsed.
func ParseAttachedSignatures(signatures []byte) ([]Derivation, []byte, error) {
	buf := bytes.NewBuffer(signatures)
	derivations := []Derivation{}

	sigCountBytes := make([]byte, 4)
	read, err := buf.Read(sigCountBytes)
	if read != 4 || err != nil {
		return nil, nil, errors.New("invalid signature count")
	}

	sigCount, err := ParseSignatureCount(string(sigCountBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature count (%s)", err)
	}

	// iterate over the signatures bytes for each signature
	current := uint16(0)
	for current < sigCount {
		dCode, err := buf.ReadByte()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read signature (%s)", err)
		}

		// get expected b64 length
		var sigString []byte
		if c, ok := codeValue[string(dCode)+"X"]; ok {
			sigString = make([]byte, c.PrefixBase64Length()-1)
			read, err := buf.Read(sigString)
			if read != c.PrefixBase64Length()-1 || err != nil {
				return nil, nil, errors.New("invalid signature string length")
			}
		} else {
			return nil, nil, fmt.Errorf("unable to determin signature derivation from code (%s)", string(dCode))
		}

		der, err := FromAttachedSignature(string(append([]byte{dCode}, sigString...)))
		if err != nil {
			return nil, nil, err
		}

		derivations = append(derivations, *der)

		current++
	}

	return derivations, buf.Bytes(), nil
}

// VerifyWithAttachedSignature takes the key and signature derivations
// and verifies the provided message bytes using the correct sig alg.
func VerifyWithAttachedSignature(key, signature *Derivation, msg []byte) error {
	switch signature.Code {
	case Ed25519Attached:
		if !ed25519.Verify(key.Raw, msg, signature.Raw) {
			return errors.New("invalid message signature")
		}
		return nil
	}

	return errors.New("unknown or unsupported signature derivation")
}
