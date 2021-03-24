package derivation

import (
	"fmt"
)

type CountCode int

const (
	ControllerSigCountCode CountCode = iota
	WitnessSigCountCode
	NonTransferableRctCountCode
	TransferableRctCountCode
	FirstSeenReplayCountCode
	MessageDataGroupCountCode
	AttachedMaterialCountCode
	MessageDataMaterialCountCode
	CombinedMaterialCountCode
	MaterialGroupCountCode
	MaterialCountCode

	SigCountLen = 2
)

var (
	countCodeString = map[CountCode]string{
		ControllerSigCountCode:       "-A",
		WitnessSigCountCode:          "-B",
		NonTransferableRctCountCode:  "-C",
		TransferableRctCountCode:     "-D",
		FirstSeenReplayCountCode:     "-E",
		MessageDataGroupCountCode:    "-U",
		AttachedMaterialCountCode:    "-V",
		MessageDataMaterialCountCode: "-W",
		CombinedMaterialCountCode:    "-X",
		MaterialGroupCountCode:       "-Y",
		MaterialCountCode:            "-Z",
	}

	CountCodes = map[string]CountCode{
		"-A": ControllerSigCountCode,
		"-B": WitnessSigCountCode,
		"-C": NonTransferableRctCountCode,
		"-D": TransferableRctCountCode,
		"-E": FirstSeenReplayCountCode,
		"-U": MessageDataGroupCountCode,
		"-V": AttachedMaterialCountCode,
		"-W": MessageDataMaterialCountCode,
		"-X": CombinedMaterialCountCode,
		"-Y": MaterialGroupCountCode,
		"-Z": MaterialCountCode,
	}
)

type CountOpt func(*Counter) error

type Counter struct {
	code   CountCode
	count  uint16
	length int
}

func NewSigCounter(code CountCode, opts ...CountOpt) (*Counter, error) {
	s := &Counter{
		code:  code,
		count: 1,
	}

	for _, o := range opts {
		err := o(s)
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (r *Counter) Incr() uint16 {
	r.count++
	return r.count
}

func (r *Counter) IncrBy(i uint16) uint16 {
	r.count += i
	return r.count
}

func (r *Counter) String() (string, error) {
	b64, err := IndexToBase64(r.count)
	if err != nil {
		return "", fmt.Errorf("unable to base64 encode signature count: %v", err)
	}

	cs := countCodeString[r.code]

	pad := SigCountLen - len(b64)
	return fmt.Sprintf("%s%.*s%s", cs, pad, "A", b64), nil
}

func WithCount(count int) CountOpt {
	return func(s *Counter) error {
		s.count = uint16(count)
		return nil
	}
}
