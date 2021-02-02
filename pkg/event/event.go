package event

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"

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
	DRT
)

var (
	ilkValue = map[string]ILK{
		"icp": ICP,
		"rot": ROT,
		"ixn": IXN,
		"dip": DIP,
		"rct": RCT,
		"vrc": VRC,
		"drt": DRT,
	}

	ilkString = map[ILK]string{
		ICP: "icp",
		ROT: "rot",
		IXN: "ixn",
		DIP: "dip",
		RCT: "rct",
		VRC: "vrc",
		DRT: "drt",
	}

	serFields = map[ILK][]string{
		ICP: {"v", "s", "t", "kt", "k", "n", "wt", "c"},
		DIP: {"v", "s", "t", "kt", "k", "n", "wt", "c"},
	}
)

func (i ILK) String() string {
	return ilkString[i]
}

// Establishment returns true if the ILK is an establishment
// event type
func (i ILK) Establishment() bool {
	return i == ICP || i == ROT
}

type FORMAT int

// EDS stands for Extracted Data Set format that is used to create cryptographic digests
//     and signatures for Events but does not have to be deserialized therefore does not
//     have to preserve symantic structure.
const (
	JSON FORMAT = iota
	CBOR
	MSGPK
	EDS
)

var (
	formatString = map[FORMAT]string{
		JSON:  "JSON",
		CBOR:  "CBOR",
		MSGPK: "MSGPK",
		EDS:   "ExtractedDataSet",
	}

	formatValue = map[string]FORMAT{
		"JSON":  JSON,
		"CBOR":  CBOR,
		"MSGPK": MSGPK,
	}
)

type Event struct {
	Version                       string         `json:"v"`
	Prefix                        string         `json:"i,omitempty"`
	Sequence                      string         `json:"s"`
	EventType                     string         `json:"t"`
	Digest                        string         `json:"p,omitempty"`
	SigThreshold                  *SigThreshold  `json:"kt,omitempty"`
	Keys                          []string       `json:"k,omitempty"`
	Next                          string         `json:"n,omitempty"`
	AccountableDuplicityThreshold string         `json:"wt,omitempty"`
	Witnesses                     []string       `json:"w,omitempty"`
	Add                           []string       `json:"wa,omitempty"`
	Cut                           []string       `json:"wr,omitempty"`
	Config                        []prefix.Trait `json:"c,omitempty"`
	Permissions                   []interface{}  `json:"perm,omitempty"`
	Seals                         []*Seal        `json:"a,omitempty"`
	DelegatorSeal                 *Seal          `json:"da,omitempty"`
}

// ILK returns the ILK iota value for the event
func (e *Event) ILK() ILK {
	return ilkValue[e.EventType]
}

// MarshalJSON interface implementation.
// not all events requrie all fields, and some event types
// requrie empty arrays in place of null values. This allows
// us to correctly marhsal the Event data to JSON
func (e *Event) MarshalJSON() ([]byte, error) {
	type EventAlias Event

	switch e.EventType {

	case ROT.String(), DRT.String():
		// roation events need cuts, adds, and data
		if e.Cut == nil {
			e.Cut = []string{}
		}
		if e.Add == nil {
			e.Add = []string{}
		}
		if e.Seals == nil {
			e.Seals = []*Seal{}
		}

		return json.Marshal(&struct {
			*EventAlias
			Cut   []string `json:"wr"`
			Add   []string `json:"wa"`
			Seals []*Seal  `json:"a"`
		}{
			EventAlias: (*EventAlias)(e),
			Cut:        e.Cut,
			Add:        e.Add,
			Seals:      e.Seals,
		})

	case IXN.String():
		// IXN events need data
		if e.Seals == nil {
			e.Seals = []*Seal{}
		}
		return json.Marshal(&struct {
			*EventAlias
			Seals []*Seal `json:"a"`
		}{
			EventAlias: (*EventAlias)(e),
			Seals:      e.Seals,
		})

	case ICP.String():
		// Inception events need cnfg
		if e.Config == nil {
			e.Config = []prefix.Trait{}
		}
		if e.Witnesses == nil {
			e.Witnesses = []string{}
		}

		return json.Marshal(&struct {
			*EventAlias
			Witnesses []string       `json:"w"`
			Config    []prefix.Trait `json:"c"`
		}{
			EventAlias: (*EventAlias)(e),
			Witnesses:  e.Witnesses,
			Config:     e.Config,
		})
	case VRC.String():
		// Receipt news single Seal
		if e.Seals == nil || len(e.Seals) != 1 {
			return nil, errors.New("unable to serialize a receipt without a seal")
		}

		return json.Marshal(&struct {
			Version   string `json:"v"`
			Prefix    string `json:"i,omitempty"`
			Sequence  string `json:"s"`
			EventType string `json:"t"`
			Digest    string `json:"d,omitempty"`
			Data      *Seal  `json:"a"`
		}{
			Version:   e.Version,
			Prefix:    e.Prefix,
			Sequence:  e.Sequence,
			EventType: e.EventType,
			Digest:    e.Digest,
			Data:      e.Seals[0],
		})
	}

	// Default - just return the encoded struct
	return json.Marshal(&struct {
		*EventAlias
	}{
		EventAlias: (*EventAlias)(e),
	})
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

func (e *Event) GetDigest() (string, error) {
	ser, err := Serialize(e, EDS)

	der, err := derivation.New(derivation.WithCode(derivation.Blake3256))
	if err != nil {
		return "", err
	}

	_, err = der.Derive(ser)
	if err != nil {
		return "", err
	}

	pre := prefix.New(der)
	return pre.String(), nil
}

// DefaultVersionString returns a weGetDigestll formated version string
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

func Format(f string) (FORMAT, error) {
	out, ok := formatValue[f]
	if !ok {
		return -1, errors.New("unrecognized format")
	}

	return out, nil
}

// Serialize the provided event to the format specifeid
func Serialize(e *Event, to FORMAT) ([]byte, error) {
	switch to {
	case JSON:
		return json.Marshal(e)
	case EDS:
		return e.extractDataSet()
	case CBOR, MSGPK:
		// unimplemented
		// TODO: implement!
		return nil, errors.New("unimplemented")
	}

	return nil, errors.New("unrecognized format")
}

func Deserialize(data []byte, from FORMAT) (*Event, error) {
	switch from {
	case JSON:
		evt := &Event{}
		err := json.Unmarshal(data, evt)
		if err != nil {
			return nil, errors.Wrap(err, "unable to unmarshal event from JSON")
		}
		return evt, nil
	case CBOR, MSGPK:
		// unimplemented
		// TODO: implement!
		return nil, errors.New("unimplemented")
	}

	return nil, errors.New("unrecognized format")
}

func (e *Event) extractDataSet() ([]byte, error) {
	labels, ok := serFields[e.ILK()]
	if !ok {
		return nil, fmt.Errorf("invalid Ilk %s to derive pre", e.EventType)
	}

	m := map[string]interface{}{}
	config := &mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &m,
		TagName:  "json",
	}

	dec, err := mapstructure.NewDecoder(config)
	if err != nil {
		return nil, err
	}

	err = dec.Decode(e)
	if err != nil {
		return nil, err
	}

	var ser []byte
	for _, l := range labels {
		val, ok := m[l]
		if !ok {
			continue
		}

		switch t := val.(type) {
		case string:
			ser = append(ser, t...)
		case []string:
			for _, elem := range t {
				ser = append(ser, elem...)
			}
		}
	}

	return ser, nil
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
