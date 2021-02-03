package stream

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

const (
	FullVerSize = 17

	MinSniffSize = 12 + FullVerSize

	Verex = `KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_`

	MessageBufferSize = 5
)

var (
	Rever = regexp.MustCompile(Verex)
)

type Inbound struct {
	addr string

	connLock sync.Mutex
	conns    []net.Conn

	ch chan *event.Message
}

func NewStreamInbound(addr string) (*Inbound, error) {
	return &Inbound{
		addr: addr,
		ch:   make(chan *event.Message, MessageBufferSize),
	}, nil
}

func (r *Inbound) Start() (<-chan *event.Message, error) {
	ln, err := net.Listen("tcp", r.addr)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to listen on %s", r.addr)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("unexpected error accepting connection: %v", err)
				continue
			}

			r.addConnection(conn)
			go func() {
				err := r.handleConnection(conn)
				r.removeConnection(conn)
				log.Printf("connection closed with err: %v\n", err)
			}()
		}
	}()

	return r.ch, nil
}

func (r *Inbound) Stop() {
	r.connLock.Lock()
	defer r.connLock.Unlock()

	for _, conn := range r.conns {
		_ = conn.Close()
	}

	close(r.ch)
}

func (r *Inbound) handleConnection(conn io.Reader) error {
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

		r.ch <- msg
	}
}

func (r *Inbound) addConnection(conn net.Conn) {
	r.connLock.Lock()
	defer r.connLock.Unlock()

	r.conns = append(r.conns, conn)
}

func (r *Inbound) removeConnection(conn net.Conn) {
	r.connLock.Lock()
	defer r.connLock.Unlock()

	idx := -1
	for i, c := range r.conns {
		if c == conn {
			idx = i
			break
		}
	}

	if idx != -1 {
		r.conns = append(r.conns[:idx], r.conns[idx+1:]...)
	}
}

func (r *Inbound) Write(msg *event.Message) error {
	data, err := msg.Serialize()
	if err != nil {
		return errors.Wrap(err, "unable to serialize message for stream outbound")
	}

	_, err = r.conns[0].Write(data)
	if err != nil {
		return errors.Wrap(err, "unable to right message to stream outbound")
	}

	return nil
}
