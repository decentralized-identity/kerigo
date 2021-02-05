package stream

import (
	"log"
	"net"
	"regexp"
	"sync"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/io"
)

const (
	FullVerSize = 17

	MinSniffSize = 12 + FullVerSize

	Verex = `KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_`

	MessageBufferSize = 5
)

type conn struct {
	ch   chan *event.Message
	conn net.Conn
}

var (
	Rever = regexp.MustCompile(Verex)
)

type Inbound struct {
	addr string

	connLock sync.Mutex
	conns    []*conn

	ch chan io.Conn
}

func NewStreamInbound(addr string) (*Inbound, error) {
	return &Inbound{
		addr: addr,
		ch:   make(chan io.Conn, 1),
	}, nil
}

func (r *Inbound) Start() (<-chan io.Conn, error) {
	ln, err := net.Listen("tcp", r.addr)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to listen on %s", r.addr)
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Printf("unexpected error accepting connection: %v", err)
				continue
			}

			ioc := &conn{
				conn: c,
				ch:   make(chan *event.Message, MessageBufferSize),
			}

			r.addConnection(ioc)
			r.ch <- ioc
			go func() {
				err := handleConnection(ioc.conn, ioc.ch)
				r.removeConnection(ioc)
				log.Printf("inbound connection closed with err: %v\n", err)
			}()
		}
	}()

	return r.ch, nil
}

func (r *Inbound) Stop() {
	r.connLock.Lock()
	defer r.connLock.Unlock()

	for _, conn := range r.conns {
		_ = conn.conn.Close()
		close(conn.ch)
	}

	close(r.ch)
}

func (r *Inbound) addConnection(conn *conn) {
	r.connLock.Lock()
	defer r.connLock.Unlock()

	r.conns = append(r.conns, conn)
}

func (r *Inbound) removeConnection(conn *conn) {
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

// Write the message to all currently active connections
func (r *Inbound) Write(msg *event.Message) error {
	for _, c := range r.conns {
		err := c.Write(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *conn) Msgs() chan *event.Message {
	return r.ch
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
