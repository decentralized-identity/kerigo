package direct

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	reader *bufio.Reader
	conn   net.Conn
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

	b, _ := json.Marshal(msg)
	log.Print(msg.Event.Prefix, "sent event:\n", string(b), "\n\n")

	return nil
}

func handleConnection(ioc *conn, id *keri.Keri) error {

	for {
		msg, err := readMessage(ioc.reader)
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

func readMessage(reader *bufio.Reader) (*event.Message, error) {

	// read a min sized buffer which contains the message length
	h, err := reader.Peek(MinSniffSize)
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
	_, err = io.ReadFull(reader, buff)
	if err != nil {
		return nil, err
	}

	msg := &event.Message{}
	msg.Event, err = event.Deserialize(buff, f)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal event: (%v)", err)
	}

	sigs, err := derivation.ParseAttachedSignatures(reader)
	if err != nil {
		return nil, fmt.Errorf("error parsing sigs: %v", err)
	}

	msg.Signatures = sigs

	return msg, nil
}
