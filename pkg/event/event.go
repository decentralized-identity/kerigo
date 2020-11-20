package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/decentralized-identity/kerigo/pkg/version"
)

type ILK int

const (
	ICP ILK = iota
	ROT
	IXN
	DIP
	RCT
	VRC
)

var (
	ilkValue = map[string]ILK{
		"ICP": ICP,
		"ROT": ROT,
		"IXN": IXN,
		"DIP": DIP,
		"RCT": RCT,
		"VRC": VRC,
	}

	ilkString = map[ILK]string{
		ICP: "icp",
		ROT: "rot",
		IXN: "ixn",
		DIP: "dip",
		RCT: "rct",
		VRC: "vrc",
	}
)

func (i ILK) String() string {
	return ilkString[i]
}

type FORMAT int

const (
	JSON FORMAT = iota
	CBOR
	MSGPK
)

var (
	formatString = map[FORMAT]string{
		JSON:  "JSON",
		CBOR:  "CBOR",
		MSGPK: "MSGPK",
	}
)

type Event struct {
	Version                       string   `json:"vs"`
	Prefix                        string   `json:"pre,omitempty"`
	Sequence                      string   `json:"sn"`
	EventType                     string   `json:"ilk"`
	Digest                        string   `json:"dig,omitempty"`
	SigningThreshold              string   `json:"sith"`
	Keys                          []string `json:"keys"`
	Next                          string   `json:"nxt"`
	AccountableDuplicityThreshold string   `json:"toad"`
	Witnesses                     []string `json:"wits"`
	Config                        []string `json:"cnfg"`
	Seal                          []Seal   `json:"seal,omitempty"`
}

// SequenceInt returns an integer representation of the
// hex sequence string
func (e *Event) SequenceInt() int {
	eInt, err := strconv.ParseInt(e.Sequence, 16, 64)
	if err != nil {
		return -1
	}
	return int(eInt)
}

// KeyDerivation returns a dervation for the key prefix at the
// provided index
func (e *Event) KeyDerivation(index int) (*derivation.Derivation, error) {
	if index > len(e.Keys)-1 {
		return nil, errors.New("requested key index out of range")
	}

	return derivation.FromPrefix(e.Keys[index])
}

// WitnessDerivation returns a dervation for the key prefix at
// the provided index
func (e *Event) WitnessDerivation(index int) (*derivation.Derivation, error) {
	if index > len(e.Witnesses)-1 {
		return nil, errors.New("requested key index out of range")
	}

	return derivation.FromPrefix(e.Witnesses[index])
}

// DefaultVersionString returns a well formated version string
// for the provided format, with 0s for size
func DefaultVersionString(in FORMAT) string {
	switch in {
	case JSON:
		return fmt.Sprintf("KERI%sJSON000000_", version.Code())
	}
	return ""
}

// VersionString returns a well formated version string populated
// with the provide KERI version and message size
func VersionString(in FORMAT, keriVer string, size int) string {
	return fmt.Sprintf("KERI%s%s%06x_", keriVer, formatString[in], size)
}

// FormatFromVersion returns the message format parsed
// from the given version string
func FormatFromVersion(vs string) (FORMAT, error) {
	switch vs[6:9] {
	case "JSO":
		return JSON, nil
	case "CBO":
		return CBOR, nil
	case "MSG":
		return MSGPK, nil
	}

	return -1, errors.New("unable to determin format from version string")
}

// Serialize the provided event to the format specifeid
func Serialize(e *Event, to FORMAT) ([]byte, error) {
	switch to {
	case JSON:
		return json.Marshal(e)
	case CBOR, MSGPK:
		// unimplemented
		// TODO: implement!
		return nil, errors.New("unimplemented")
	}

	return nil, errors.New("unrecognized format")
}

// Digest returns the raw derived data of code for provided data
func Digest(data []byte, code derivation.Code) ([]byte, error) {
	if !code.SelfAddressing() {
		return nil, errors.New("must use self-adddressing derivation")
	}

	d, err := derivation.New(derivation.WithCode(code))
	if err != nil {
		return nil, err
	}

	return d.Derive(data)
}

// DigestString returns a prefix for the provided data
func DigestString(data []byte, code derivation.Code) (string, error) {
	raw, err := Digest(data, code)
	if err != nil {
		return "", err
	}

	d, _ := derivation.New(derivation.WithCode(code), derivation.WithRaw(raw))

	pre := prefix.New(d)
	return pre.String(), nil
}

// Serialize returns a byte array of the current event serialized according to its Version
func (e *Event) Serialize() ([]byte, error) {
	format, err := FormatFromVersion(e.Version)
	if err != nil {
		return nil, err
	}

	return Serialize(e, format)
}

// Recipt generates a receipt for the provided event
func Receipt(event *Event, code derivation.Code) (*Event, error) {
	receipt, _ := NewEvent(
		WithType(VRC),
		WithSequence(event.SequenceInt()),
		WithPrefix(event.Prefix),
		WithDefaultVersion(JSON),
	)

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
