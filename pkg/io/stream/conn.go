package stream

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

func handleConnection(conn io.Reader, ch chan *event.Message) error {
	c := bufio.NewReader(conn)

	for {
		// read a min sized buffer which contains the message length
		h, err := c.Peek(MinSniffSize)
		if err != nil {
			return fmt.Errorf("short peek: (%v)", err)
		}

		submatches := Rever.FindStringSubmatch(string(h))
		if len(submatches) != 5 {
			return errors.New("invalid version string")
		}

		ser := strings.TrimSpace(submatches[3])
		hex := submatches[4]

		size, err := strconv.ParseInt(hex, 16, 64)
		if err != nil {
			return errors.Wrap(err, "invalid message size hex")
		}

		f, err := event.Format(ser)
		if err != nil {
			return err
		}

		buff := make([]byte, size)
		_, err = io.ReadFull(c, buff)
		if err != nil {
			return err
		}

		msg := &event.Message{}
		msg.Event, err = event.Deserialize(buff, f)
		if err != nil {
			return fmt.Errorf("unable to unmarshal event: (%v)", err)
		}

		sigs, err := derivation.ParseAttachedSignatures(c)
		if err != nil {
			return fmt.Errorf("error parsing sigs: %v", err)
		}

		msg.Signatures = sigs

		ch <- msg
	}
}
