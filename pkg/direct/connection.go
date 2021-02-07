package direct

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/keri"
)

const (
	FullVerSize = 17

	MinSniffSize = 12 + FullVerSize

	Verex = `KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_`
)

var (
	Rever = regexp.MustCompile(Verex)
)

type conn struct {
	conn net.Conn
}

func (r *conn) Write(msg *event.Message) error {
	data, err := msg.Serialize()
	if err != nil {
		return errors.Wrap(err, "unable to serialize message for stream outbound")
	}

	_, err = r.conn.Write(data)
	if err != nil {
		return errors.Wrap(err, "unable to right message to stream outbound")
	}

	return nil
}

func handleConnection(ioc *conn, id *keri.Keri) error {

	for {
		msg, err := readMessage(ioc.conn)
		if err != nil {
			return err
		}

		outmsgs, err := id.ProcessEvents(msg)
		if err != nil {
			return errors.Wrap(err, "error reading message on connection")
		}

		for _, msg := range outmsgs {
			err := ioc.Write(msg)
			if err != nil {
				return errors.Wrap(err, "error writing initial message to connection")
			}
		}
	}
}

func readMessage(reader io.Reader) (*event.Message, error) {
	c := bufio.NewReader(reader)

	// read a min sized buffer which contains the message length
	h, err := c.Peek(MinSniffSize)
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
	_, err = io.ReadFull(c, buff)
	if err != nil {
		return nil, err
	}

	msg := &event.Message{}
	msg.Event, err = event.Deserialize(buff, f)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal event: (%v)", err)
	}

	sigs, err := derivation.ParseAttachedSignatures(c)
	if err != nil {
		return nil, fmt.Errorf("error parsing sigs: %v", err)
	}

	msg.Signatures = sigs

	return msg, nil
}
