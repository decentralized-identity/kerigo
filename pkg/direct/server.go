package direct

import (
	"log"
	"net"
	"sync"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/keri"
	"github.com/decentralized-identity/kerigo/pkg/keymanager"
)

const (
	DefaultDirectModeAddr = ":5620"
)

type Server struct {
	Addr string

	KMS *keymanager.KeyManager

	// BaseIdentity optionally specifies a function that returns
	// the base context for incoming requests on this server.
	// The provided Listener is the specific Listener that's
	// about to start accepting requests.
	// If BaseContext is nil, the default is keri.New().
	// If non-nil, it must return a non-nil context.
	BaseIdentity func(net.Listener) *keri.Keri

	// ConnIdentity optionally specifies a function that modifies
	// the context used for a new connection c. The provided ctx
	// is derived from the base context and has a ServerContextKey
	// value.
	ConnIdentity func(base *keri.Keri, prefix string, c net.Conn) *keri.Keri

	connLock sync.Mutex
	conns    []*conn
	reg      keri.Registry
}

func (r *Server) ListenAndServer() error {

	if r.Addr == "" {
		r.Addr = DefaultDirectModeAddr
	}

	ln, err := net.Listen("tcp", r.Addr)
	if err != nil {
		return errors.Wrapf(err, "unable to listen on %s", r.Addr)
	}

	return r.Serve(ln)
}

func (r *Server) Serve(l net.Listener) error {

	if r.KMS == nil {
		r.KMS = defaultKMS()
	}

	baseID, err := keri.New(r.KMS)
	if err != nil {
		return err
	}

	if r.BaseIdentity != nil {
		baseID = r.BaseIdentity(l)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			return errors.Wrap(err, "unexpected error accepting connection")
		}

		firstMsg, err := readMessage(c)
		if err != nil {
			log.Println("error reading initial message on connection", err)
			c.Close()
			continue
		}

		ioc := &conn{
			conn: c,
		}

		r.addConnection(ioc)

		connID := baseID
		pre := firstMsg.Event.Prefix

		if cc := r.ConnIdentity; cc != nil {
			connID = cc(connID, pre, c)
			if connID == nil {
				panic("ConnIdentity returned nil")
			}
		}

		if firstMsg.Event.ILK() == event.ICP || firstMsg.Event.ILK() == event.DIP {
			_, err := connID.FindConnection(pre)
			if err != nil {
				err = sendOwnInception(connID, ioc)
				if err != nil {
					log.Println("error sending own icp to connection", err)
					c.Close()
					continue
				}
			}
		}
		//TODO:  I have the Keri instance to use for this connection, I need to check for the ICP.

		outmsgs, err := connID.ProcessEvents(firstMsg)
		if err != nil {
			log.Println("error reading initial message on connection", err)
			c.Close()
			continue
		}

		for _, msg := range outmsgs {
			err := ioc.Write(msg)
			if err != nil {
				log.Println("error writing initial message to connection", err)
				c.Close()
				continue
			}
		}

		go func() {
			err := handleConnection(ioc, connID)
			r.removeConnection(ioc)
			log.Printf("server connection closed with : (%v)\n", err)
		}()
	}
}

func (r *Server) addConnection(conn *conn) {
	r.connLock.Lock()
	defer r.connLock.Unlock()

	r.conns = append(r.conns, conn)
}

func (r *Server) removeConnection(conn *conn) {
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

func defaultKMS() *keymanager.KeyManager {
	kms, _ := keymanager.NewKeyManager()
	return kms
}

func sendOwnInception(id *keri.Keri, ioc *conn) error {
	icp, _ := id.Inception()

	err := ioc.Write(icp)
	if err != nil {
		return errors.Wrap(err, "unable to write inception event")
	}

	return nil

}
