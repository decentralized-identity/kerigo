package derivation

import (
	"fmt"
)

const (
	SigCountCodeBase64 = "-A"
	SigCountCodeBase2  = "-B"

	SigCountLen = 2
)

var (
	MaxPad = []string{"AAAAAAAAAA"}
)

type SigCountOpt func(*SigCounter) error

type SigCounter struct {
	code   string
	count  uint16
	length int
}

func NewSigCounter(opts ...SigCountOpt) (*SigCounter, error) {
	s := &SigCounter{
		code:  SigCountCodeBase64,
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

func (r *SigCounter) String() (string, error) {
	b64, err := IndexToBase64(r.count)
	if err != nil {
		return "", fmt.Errorf("unable to base64 encode signature count: %v", err)
	}
	pad := SigCountLen - len(b64)
	return fmt.Sprintf("%s%.*s%s", r.code, pad, "A", b64), nil
}

func WithCount(count int) SigCountOpt {
	return func(s *SigCounter) error {
		s.count = uint16(count)
		return nil
	}
}

func WithSigCntCode(code string) SigCountOpt {
	return func(s *SigCounter) error {
		s.code = code
		return nil
	}
}
