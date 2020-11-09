package event

import (
	"encoding/json"
	"errors"
	"fmt"

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
}

func DefaultVersionString(in FORMAT) string {
	switch in {
	case JSON:
		return fmt.Sprintf("KERI%sJSON000000_", version.Code())
	}
	return ""
}

func VersionString(in FORMAT, keriVer string, size int) string {
	return fmt.Sprintf("KERI%s%s%06x_", keriVer, formatString[in], size)
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
