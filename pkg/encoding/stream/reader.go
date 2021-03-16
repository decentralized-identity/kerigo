package stream

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

const (
	FullVerSize = 17

	MinSniffSize = 12 + FullVerSize

	Verex = `KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_`
)

var (
	Rever = regexp.MustCompile(Verex)
	EOA   = errors.New("EOA")
)

type Reader struct {
	buf *bufio.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{
		buf: bufio.NewReader(r),
	}
}

func (r *Reader) Read() (*event.Message, error) {

	// read a min sized buffer which contains the message length
	h, err := r.buf.Peek(MinSniffSize)
	if err != nil {
		return nil, err
	}

	submatches := Rever.FindStringSubmatch(string(h))
	if len(submatches) != 5 {
		return nil, errors.New("invalid version string")
	}

	ser := strings.TrimSpace(submatches[3])
	hex := submatches[4]

	size, err := strconv.ParseInt(hex, 16, 64)
	if err != nil {
		return nil, errors.Wrap(err, "invalid message size hex")
	}

	f, err := event.Format(ser)
	if err != nil {
		return nil, err
	}

	buff := make([]byte, size)
	_, err = io.ReadFull(r.buf, buff)
	if err != nil {
		return nil, err
	}

	evt, err := event.Deserialize(buff, f)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal event: (%v)", err)
	}

	opts := []event.MessageOption{}
	for {
		att, err := r.nextAttachment()
		if err == EOA {
			break
		}

		if err != nil {
			return nil, err
		}

		switch att.Code {
		case derivation.ControllerSigCountCode:
			opts = append(opts, event.WithSignatures(att.Signatures))
			return event.NewMessage(evt, opts...)
		case derivation.WitnessSigCountCode:
			opts = append(opts, event.WithWitnessReceipts(att.WitnessReceipts))
		case derivation.NonTransferableRctCountCode:
			opts = append(opts, event.WithNonTransferableReceipts(att.NonTransferableReceipts))
		case derivation.TransferableRctCountCode:
			opts = append(opts, event.WithTransferableReceipts(att.TransferableReceipts))
		}

	}

	return event.NewMessage(evt, opts...)
}

func (r *Reader) ReadAll() ([]*event.Message, error) {
	out := []*event.Message{}

	for {
		msg, err := r.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		out = append(out, msg)
	}

	return out, nil
}

func (r *Reader) nextAttachment() (*event.Attachment, error) {
	f, err := r.buf.Peek(1)
	if err == io.EOF {
		return nil, EOA
	}

	if err != nil {
		return nil, errors.Wrap(err, "error peeking")
	}

	typ := DetectFrameType(f)
	switch typ {
	case JSONFrame, MsgPackFrame, CBORFrame:
		return nil, EOA
	case QB64Frame:
		return event.ParseAttachment(r.buf)
	case QB2Frame:
		//TODO:  apply binary translation here
		return event.ParseAttachment(r.buf)
	}

	return nil, errors.New("invalid stream state")
}
