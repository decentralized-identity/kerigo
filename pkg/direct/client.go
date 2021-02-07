package direct

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/keri"
)

type Client struct {
	addr string
	ioc  *conn
	id   *keri.Keri
}

func Dial(id *keri.Keri, addr string) (*Client, error) {
	return DialTimeout(id, addr, 0)
}

func DialTimeout(id *keri.Keri, addr string, timeout time.Duration) (*Client, error) {

	o := &Client{
		addr: addr,
		id:   id,
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
			conn: c,
		}
		return nil
	}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx))

	if err != nil {
		return nil, errors.Wrap(err, "unable to connect after timeout")
	}

	go func() {
		err := handleConnection(o.ioc, o.id)
		log.Printf("client connection closed with (%v)\n", err)
	}()

	return o, nil

}

func (r *Client) Write(msg *event.Message) error {
	err := r.ioc.Write(msg)
	if err != nil {
		return errors.Wrap(err, "unable to right message to stream outbound")
	}

	return nil
}

func (r *Client) Close() error {
	return r.ioc.conn.Close()
}
