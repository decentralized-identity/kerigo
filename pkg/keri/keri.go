package keri

import (
	"encoding/json"
	"log"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/io"
	"github.com/decentralized-identity/kerigo/pkg/keymanager"
)

type Option func(*Keri) error

type Keri struct {
	pre    string
	kms    *keymanager.KeyManager
	reg    *Registry
	direct []*directConn
}

type directConn struct {
	in io.InboundTransport
}

func New(kms *keymanager.KeyManager, opts ...Option) (*Keri, error) {
	k := &Keri{
		kms: kms,
	}

	reg, err := NewRegistry()
	if err != nil {
		return nil, errors.Wrap(err, "unable to create Keri registry")
	}

	k.reg = reg

	for _, o := range opts {
		err := o(k)
		if err != nil {
			return nil, err
		}
	}

	icp, err := event.Incept(kms.PublicKey(), kms.Next())
	if err != nil {
		return nil, errors.Wrap(err, "unable to create my own inception event")
	}

	k.pre = icp.Prefix

	sig, err := k.sign(icp)
	if err != nil {
		return nil, errors.Wrap(err, "unable to sign my inception event")
	}

	msg := &event.Message{
		Event:      icp,
		Signatures: []derivation.Derivation{*sig},
	}

	err = k.reg.ProcessMessage(msg, nil)
	if err != nil {
		return nil, errors.Wrap(err, "unable to process my own inception event")
	}

	return k, nil
}

func (r *Keri) Prefix() string {
	return r.pre
}

func (r *Keri) Sign(data []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (r *Keri) Rotate() (*event.Event, error) {
	return nil, errors.New("not implemented")
}

func (r *Keri) Interaction(payload []byte) (*event.Event, error) {
	return nil, errors.New("not implemented")
}

func (r *Keri) HandleInboundDirect(in io.InboundTransport) error {
	ch, err := in.Start()
	if err != nil {
		return errors.Wrap(err, "unable to start Keri transport")
	}

	rcpts, err := r.reg.Process(ch)
	if err != nil {
		return errors.Wrap(err, "unable to start process loop for direct connection")
	}

	go r.generateReceipts(rcpts, in)

	conn := &directConn{
		in: in,
	}

	r.direct = append(r.direct, conn)
	return nil
}

func (r *Keri) generateReceipts(rcpts <-chan *event.Event, in io.InboundTransport) {
	for evt := range rcpts {
		kel, err := r.reg.KEL(r.pre)
		if err != nil {
			log.Println("unexpected error getting current KEL", err)
			continue
		}

		if evt.ILK() == event.ICP {

			err := r.sendOwnInception(in)
			if err != nil {
				log.Println("Unable to send ICP to outbound", err)
				continue
			}
		}

		latestEst := kel.CurrentEstablishment()
		rec, err := event.TransferableReceipt(evt, latestEst, derivation.Blake3256)
		if err != nil {
			log.Println("unable to generate receipt:", err)
			continue
		}

		sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(r.kms.Signer()))
		if err != nil {
			log.Println("unexpected error getting new derivation", err)
			continue
		}

		//Sign the receipted event, not the receipt
		evtData, err := json.Marshal(evt)
		if err != nil {
			log.Println("unexpected error marshalling receipted event", err)
			continue
		}

		_, err = sig.Derive(evtData)
		if err != nil {
			log.Println("unable to derive signature", err)
			continue
		}

		msg := &event.Message{
			Event:      rec,
			Signatures: []derivation.Derivation{*sig},
		}

		err = in.Write(msg)
		if err != nil {
			log.Println("unable to write receipt data", err)
		}
	}

}

func (r *Keri) Close() {
	for _, conn := range r.direct {
		conn.in.Stop()
	}
}

func (r *Keri) sendOwnInception(in io.InboundTransport) error {
	kel, err := r.reg.KEL(r.pre)
	if err != nil {
		return errors.Wrap(err, "unexpected error getting current KEL")
	}

	icp := kel.Inception()
	sig, err := r.sign(icp)
	if err != nil {
		return err
	}

	msg := &event.Message{
		Event:      icp,
		Signatures: []derivation.Derivation{*sig},
	}

	err = in.Write(msg)
	if err != nil {
		return errors.Wrap(err, "unable to write inception event")
	}

	return nil
}

func (r *Keri) sign(evt *event.Event) (*derivation.Derivation, error) {
	sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(r.kms.Signer()))
	if err != nil {
		return nil, errors.Wrap(err, "unable to create signer derivation")
	}

	evtData, err := json.Marshal(evt)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error marshaling event")
	}

	_, err = sig.Derive(evtData)
	if err != nil {
		return nil, errors.Wrap(err, "unable to sign event")
	}

	return sig, nil
}
