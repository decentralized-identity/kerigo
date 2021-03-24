package stream

type FrameType int

const (
	FrameMask = 0b11100000

	CBORFrame FrameType = iota
	MsgPackFrame
	JSONFrame
	QB64Frame
	QB2Frame

	CBORPrefix    = byte(0b10100000)
	MsgPackPrefix = byte(0b10000000)
	JSONPrefix    = byte(0b01100000)
	QB64Prefix    = byte(0b00100000)
	QB2Prefix     = byte(0b01000000)
)

var (
	FrameTypePrefixes = map[FrameType]byte{
		CBORFrame:    CBORPrefix,
		MsgPackFrame: MsgPackPrefix,
		JSONFrame:    JSONPrefix,
		QB64Frame:    QB64Prefix,
		QB2Frame:     QB2Prefix,
	}

	FrameTypes = map[byte]FrameType{
		CBORPrefix:    CBORFrame,
		MsgPackPrefix: MsgPackFrame,
		JSONPrefix:    JSONFrame,
		QB64Prefix:    QB64Frame,
		QB2Prefix:     QB2Frame,
	}

	frameTypeNames = map[FrameType]string{
		CBORFrame:    "CBOR",
		MsgPackFrame: "MsgPack",
		JSONFrame:    "JSON",
		QB64Frame:    "QB64",
		QB2Frame:     "QB2",
	}
)

func DetectFrameType(d []byte) FrameType {
	m := d[0] & FrameMask
	frameType, ok := FrameTypes[m]
	if !ok {
		return -1
	}

	return frameType
}
