package direct

import (
	"encoding/json"
	"log"
	"net"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/encoding"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/keri"
)

type conn struct {
	reader encoding.Reader
	conn   net.Conn
	writer encoding.Writer
}

func (r *conn) Write(msg *event.Message) error {
	err := r.writer.Write(msg)
	if err != nil {
		return errors.Wrap(err, "unable to right message to stream outbound")
	}

	b, _ := json.Marshal(msg)
	log.Print(msg.Event.Prefix, "sent event:\n", string(b), "\n\n")

	return nil
}

func handleConnection(ioc *conn, id *keri.Keri) error {

	for {
		msg, err := ioc.reader.Read()
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
