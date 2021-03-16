package stream

import (
	"errors"
	"fmt"
	"io"

	"github.com/decentralized-identity/kerigo/pkg/event"
)

type Writer struct {
	writ io.Writer
	mode ReplayMode
}

type EncodeOption func(*Writer)

func NewWriter(w io.Writer, opts ...EncodeOption) *Writer {
	enc := &Writer{
		writ: w,
		mode: DisjointMode,
	}

	for _, opt := range opts {
		opt(enc)
	}

	return enc
}

func (r *Writer) WriteAll(msgs []*event.Message) error {

	for _, msg := range msgs {
		err := r.Write(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Writer) Write(msg *event.Message) error {
	var err error
	var d []byte

	switch r.mode {
	case DisjointMode:
		d, err = ToDisjoint(msg)
	case ConjointMode:
		d, err = ToConjoint(msg)
	default:
		return errors.New("invalid stream mode")
	}

	if err != nil {
		return err
	}

	_, err = r.writ.Write(d)
	if err != nil {
		return fmt.Errorf("error writing message (%v)", err)
	}

	return nil
}

func WithSerializationMode(sm ReplayMode) EncodeOption {
	return func(e *Writer) {
		e.mode = sm
	}
}
