package keri

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/db"
	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/keymanager"
	klog "github.com/decentralized-identity/kerigo/pkg/log"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/decentralized-identity/kerigo/pkg/version"
)

type Option func(*Keri) error

type Keri struct {
	pre   string
	kms   *keymanager.KeyManager
	db    db.DB
	rcpts *Receipts
}

func New(kms *keymanager.KeyManager, db db.DB, opts ...Option) (*Keri, error) {
	k := &Keri{
		db:    db,
		kms:   kms,
		rcpts: &Receipts{},
	}

	for _, o := range opts {
		err := o(k)
		if err != nil {
			return nil, err
		}
	}

	icp, err := createInception(kms.PublicKey(), kms.Next())
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

	_, err = k.ProcessEvents(msg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to process my own inception event")
	}

	return k, nil
}

func (r *Keri) KEL() *klog.Log {
	return klog.New(r.pre, r.db)
}

func (r *Keri) ProcessEvents(msgs ...*event.Message) ([]*event.Message, error) {

	out := make([]*event.Message, 0)
	for _, msg := range msgs {
		switch msg.Event.ILK() {
		case event.ICP, event.ROT, event.DIP, event.IXN, event.DRT:
			err := r.ProcessEvent(msg)
			if err != nil {
				return nil, err
			}

			if msg.Event.Prefix == r.pre {
				continue
			}

			vrc, err := r.generateReceipt(msg.Event)
			if err != nil {
				return nil, errors.Wrap(err, "unable to generate single vrc")
			}

			out = append(out, vrc)

		case event.VRC:
			err := r.ProcessReceipt(msg)
			if err != nil {
				return nil, err
			}
		case event.RCT:
			log.Println(event.RCT, "not supported, yet")
		}

	}

	return out, nil
}

func (r *Keri) Prefix() string {
	return r.pre
}

func (r *Keri) Sign(data []byte) ([]byte, error) {
	return r.kms.Signer()(data)
}

func (r *Keri) Inception() (*event.Message, error) {
	icp, err := r.db.Inception(r.pre)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error getting own inception")
	}

	return icp, nil
}

func (r *Keri) Rotate() (*event.Message, error) {
	err := r.kms.Rotate()

	cur, err := r.db.CurrentEvent(r.pre)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error getting my KEL")
	}

	dig, err := cur.Event.GetDigest()
	sn := cur.Event.SequenceInt() + 1

	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(r.kms.PublicKey()))
	if err != nil {
		return nil, err
	}
	keyPre := prefix.New(keyDer)

	nextKeyPre := prefix.New(r.kms.Next())

	rot, err := event.NewRotationEvent(
		event.WithPrefix(cur.Event.Prefix),
		event.WithDigest(dig),
		event.WithKeys(keyPre),
		event.WithDefaultVersion(event.JSON),
		event.WithSequence(sn),
		event.WithNext("1", derivation.Blake3256, nextKeyPre),
	)

	if err != nil {
		return nil, err
	}

	sig, err := r.sign(rot)
	if err != nil {
		return nil, errors.Wrap(err, "unable to sign my inception event")
	}

	msg := &event.Message{
		Event:      rot,
		Signatures: []derivation.Derivation{*sig},
	}

	err = r.ProcessEvent(msg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to process my own rotation event")
	}

	return msg, nil
}

func (r *Keri) Interaction(payload event.SealArray) (*event.Message, error) {
	cur, err := r.db.CurrentEvent(r.pre)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error getting my KEL")
	}

	dig, err := cur.Event.GetDigest()
	sn := cur.Event.SequenceInt() + 1

	ixn, err := event.NewInteractionEvent(
		event.WithPrefix(cur.Event.Prefix),
		event.WithDigest(dig),
		event.WithDefaultVersion(event.JSON),
		event.WithSequence(sn),
		event.WithSeals(payload),
	)
	if err != nil {
		return nil, err
	}

	sig, err := r.sign(ixn)
	if err != nil {
		return nil, errors.Wrap(err, "unable to sign my ixn event")
	}

	msg := &event.Message{
		Event:      ixn,
		Signatures: []derivation.Derivation{*sig},
	}

	err = r.ProcessEvent(msg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to process my own ixn event")
	}

	return msg, nil

}

func (r *Keri) FindConnection(prefix string) (*klog.Log, error) {
	if !r.db.Seen(prefix) {
		return nil, errors.New("not found")
	}

	return klog.New(prefix, r.db), nil
}

func (r *Keri) WaitForReceipt(evt *event.Event, timeout time.Duration) (chan *event.Event, chan error) {
	rcptCh := make(chan *event.Event, 1)
	_ = r.rcpts.RegisterRcptChan(rcptCh)

	out := make(chan *event.Event, 1)
	errOut := make(chan error, 1)

	go func() {
		defer func() {
			_ = r.rcpts.UnregisterRcptChan(rcptCh)
		}()

		for {
			select {
			case rcpt := <-rcptCh:
				dig, err := evt.GetDigest()
				if err != nil {
					continue
				}

				if rcpt.EventDigest == dig {
					out <- rcpt
					return
				}
			case <-time.After(timeout):
				errOut <- errors.New("receipt timeout")
			}
		}
	}()

	return out, errOut
}

func (r *Keri) generateReceipt(evt *event.Event) (*event.Message, error) {
	latestEst, err := r.db.CurrentEstablishmentEvent(r.pre)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error getting current KEL")
	}

	rec, err := event.TransferableReceipt(evt, latestEst.Event, derivation.Blake3256)
	if err != nil {
		return nil, errors.Wrap(err, "unable to generate receipt:")
	}

	sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(r.kms.Signer()))
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error getting new derivation")
	}

	//Sign the receipted event, not the receipt
	evtData, err := json.Marshal(evt)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error marshalling receipted event")
	}

	_, err = sig.Derive(evtData)
	if err != nil {
		return nil, errors.Wrap(err, "unable to derive signature")
	}

	msg := &event.Message{
		Event:      rec,
		Signatures: []derivation.Derivation{*sig},
	}

	return msg, nil
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

func (r *Keri) ProcessEvent(msg *event.Message) error {

	evt := msg.Event

	var kel *klog.Log
	kel = klog.New(evt.Prefix, r.db)

	err := kel.Apply(msg)
	if err != nil {
		return fmt.Errorf("unable to apply message: (%v)", err)
	}

	return nil
}

func (r *Keri) ProcessReceipt(vrc *event.Message) error {
	seal := vrc.Event.Seals[0]
	if !r.db.Seen(vrc.Event.Prefix) {
		return errors.New("unexpected error, received a receipt for an unknown prefix")
	}

	kel := klog.New(vrc.Event.Prefix, r.db)

	evt := kel.EventAt(vrc.Event.SequenceInt())
	if evt == nil {
		//TODO: Haven't seen the target event yet, add to vrc escrow
		return errors.New("unverified transferable receipt")
	}

	if !r.db.Seen(seal.Prefix) {
		//TODO: Haven't seen the receipter kel yet, add to vrc escrow
		return errors.New("unverified transferable receipt")
	}

	receiptorKEL := klog.New(seal.Prefix, r.db)

	estEvt := receiptorKEL.EventAt(seal.SequenceInt())
	if estEvt == nil {
		//TODO: Haven't seen the establishment event yet, add to vrc escrow
		return errors.New("unverified transferable receipt")
	}

	dig, err := estEvt.Event.GetDigest()
	if err != nil {
		return err
	}

	if dig != seal.Digest {
		return errors.New("invalid vrc seal")
	}

	err = kel.ApplyReceipt(vrc)
	if err != nil {
		return errors.Wrap(err, "unable to apply vrc")
	}

	for _, ch := range r.rcpts.RcptChans() {
		ch <- vrc.Event
	}

	return nil
}

func createInception(signing ed25519.PublicKey, next *derivation.Derivation) (*event.Event, error) {
	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(signing))
	if err != nil {
		return nil, err
	}

	keyPre := prefix.New(keyDer)

	nextKeyPre := prefix.New(next)

	icp, err := event.NewInceptionEvent(event.WithKeys(keyPre), event.WithDefaultVersion(event.JSON), event.WithNext("1", derivation.Blake3256, nextKeyPre))
	if err != nil {
		return nil, err
	}

	// Serialize with defaults to get correct length for version string
	icp.Prefix = derivation.Blake3256.Default()
	icp.Version = event.DefaultVersionString(event.JSON)
	eventBytes, err := event.Serialize(icp, event.JSON)
	if err != nil {
		return nil, err
	}

	icp.Version = event.VersionString(event.JSON, version.Code(), len(eventBytes))

	ser, err := event.Serialize(icp, event.JSON)
	if err != nil {
		return nil, err
	}

	saDerivation, err := derivation.New(derivation.WithCode(derivation.Blake3256))
	if err != nil {
		return nil, err
	}

	_, err = saDerivation.Derive(ser)
	if err != nil {
		return nil, err
	}

	selfAdd := prefix.New(saDerivation)
	selfAddAID := selfAdd.String()

	// Set as the prefix for the inception event
	icp.Prefix = selfAddAID

	return icp, nil
}
