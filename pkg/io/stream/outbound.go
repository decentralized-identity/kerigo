package stream

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/event"
	kio "github.com/decentralized-identity/kerigo/pkg/io"
)

type Outbound struct {
	ioc     *conn
	addr    string
	timeout time.Duration
}

func NewStreamOutbound(addr string, timeout time.Duration) (*Outbound, error) {

	o := &Outbound{
		addr:    addr,
		timeout: timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err := backoff.Retry(func() error {
		var err error
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return errors.Wrap(err, "unable to connect")
		}

		o.ioc = &conn{
			ch:   make(chan *event.Message, MessageBufferSize),
			conn: c,
		}
		return nil
	}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))

	if err != nil {
		return nil, errors.Wrap(err, "unable to connect after timeout")
	}

	return o, nil
}

func (r *Outbound) Start() (<-chan kio.Conn, error) {
	ch := make(chan kio.Conn, 1)
	ch <- r.ioc
	go func() {
		err := handleConnection(r.ioc.conn, r.ioc.ch)
		log.Printf("outbound connection closed with err: %v\n", err)
	}()

	return ch, nil
}

func (r *Outbound) Write(msg *event.Message) error {
	err := r.ioc.Write(msg)
	if err != nil {
		return errors.Wrap(err, "unable to right message to stream outbound")
	}

	return nil
}

func (r *Outbound) Stop() {
	_ = r.ioc.conn.Close()
	close(r.ioc.ch)
}
