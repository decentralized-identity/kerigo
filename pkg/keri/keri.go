package keri

import (
	"encoding/json"
	"log"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/keymanager"
	klog "github.com/decentralized-identity/kerigo/pkg/log"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
)

type Option func(*Keri) error

type Keri struct {
	pre string
	kms *keymanager.KeyManager
	reg *Registry
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

	_, err = k.ProcessEvents(msg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to process my own inception event")
	}

	return k, nil
}

func (r *Keri) KEL() *klog.Log {
	l, _ := r.reg.KEL(r.pre)
	return l
}

func (r *Keri) ProcessEvents(msgs ...*event.Message) ([]*event.Message, error) {

	out := make([]*event.Message, 0)
	for _, msg := range msgs {
		switch msg.Event.ILK() {
		case event.ICP, event.ROT, event.DIP, event.IXN, event.DRT:
			err := r.reg.ProcessEvent(msg)
			if err != nil {
				return nil, err
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
	kel, _ := r.reg.KEL(r.pre)
	icp := kel.Inception()

	sig, err := r.sign(icp)
	if err != nil {
		return nil, err
	}

	msg := &event.Message{
		Event:      icp,
		Signatures: []derivation.Derivation{*sig},
	}

	return msg, nil
}

func (r *Keri) Rotate() (*event.Message, error) {
	err := r.kms.Rotate()

	kel, err := r.reg.KEL(r.pre)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error getting my KEL")
	}

	cur := kel.Current()
	dig, err := cur.GetDigest()
	sn := cur.SequenceInt() + 1

	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(r.kms.PublicKey()))
	if err != nil {
		return nil, err
	}
	keyPre := prefix.New(keyDer)

	nextKeyPre := prefix.New(r.kms.Next())

	rot, err := event.NewRotationEvent(
		event.WithPrefix(cur.Prefix),
		event.WithDigest(dig),
		event.WithKeys(keyPre),
		event.WithDefaultVersion(event.JSON),
		event.WithSequence(sn),
		event.WithNext(1, derivation.Blake3256, nextKeyPre),
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

	err = r.reg.ProcessEvent(msg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to process my own rotation event")
	}

	return msg, nil
}

func (r *Keri) Interaction(_ []byte) (*event.Event, error) {
	return nil, errors.New("not implemented")
}

func (r *Keri) FindConnection(prefix string) (*klog.Log, error) {
	l, err := r.reg.KEL(prefix)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func (r *Keri) generateReceipt(evt *event.Event) (*event.Message, error) {
	kel, err := r.reg.KEL(r.pre)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error getting current KEL")
	}

	latestEst := kel.CurrentEstablishment()
	rec, err := event.TransferableReceipt(evt, latestEst, derivation.Blake3256)
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

func (r *Keri) ProcessReceipt(vrc *event.Message) error {
	seal := vrc.Event.Seals[0]
	kel, err := r.reg.KEL(vrc.Event.Prefix)
	if err != nil {
		return errors.New("unexpected error, received a receipt for an unknown prefix")
	}

	evt := kel.EventAt(vrc.Event.SequenceInt())
	if evt == nil {
		//TODO: Haven't seen the target event yet, add to vrc escrow
		return errors.New("unverified transferable receipt")
	}

	receiptorKEL, err := r.reg.KEL(seal.Prefix)
	if err != nil {
		//TODO: Haven't seen the receipter kel yet, add to vrc escrow
		return errors.New("unverified transferable receipt")
	}

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

	//TODO:  Verify receipt sigs
	//err = receiptorKEL.Verify(vrc)
	//if err != nil {
	//	return errors.Wrap(err, "unable to verify vrc signatures")
	//}

	err = kel.ApplyReceipt(vrc)
	if err != nil {
		return errors.Wrap(err, "unable to apply vrc")
	}

	return nil
}
