package keri

import (
	"fmt"
	"log"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/db"
	"github.com/decentralized-identity/kerigo/pkg/event"
	klog "github.com/decentralized-identity/kerigo/pkg/log"
)

type Registry struct {
	kels  map[string]*klog.Log
	store db.DB
}

func NewRegistry(d db.DB) (*Registry, error) {
	r := &Registry{
		store: d,
		kels:  map[string]*klog.Log{},
	}

	return r, nil
}

func (r *Registry) KEL(pre string) (*klog.Log, error) {
	kel, ok := r.kels[pre]
	if !ok {
		return nil, errors.New("not found")
	}

	return kel, nil
}

// Process takes a channel of messages for this registry to process and returns a channel
// of messages that need to be receipted
func (r *Registry) Process(msgs <-chan *event.Message) (<-chan *event.Event, error) {

	rcpts := make(chan *event.Event)

	go func() {
		for msg := range msgs {
			err := r.ProcessMessage(msg, rcpts)
			if err != nil {
				log.Printf("registry error processing message: (%+v)\n", err)
			}
		}
	}()

	return rcpts, nil
}

func (r *Registry) ProcessMessage(msg *event.Message, rcpts chan *event.Event) error {

	switch msg.Event.ILK() {
	case event.ICP, event.ROT, event.DIP, event.IXN, event.DRT:
		err := r.processEvent(msg)
		if err != nil {
			return err
		}

		if rcpts != nil {
			rcpts <- msg.Event
		}
	case event.VRC:
		return r.processReceipt(msg)
	case event.RCT:
		log.Println(event.RCT, "not supported, yet")
	}

	return nil
}

func (r *Registry) processEvent(msg *event.Message) error {

	evt := msg.Event
	ilk := evt.ILK()

	kel, ok := r.kels[evt.Prefix]
	if !ok {
		if ilk != event.ICP && ilk != event.DIP {
			//TODO: Handle out-of-order events
			return errors.New("out of order events not currently handled")
		}

		kel = klog.New()
		r.kels[evt.Prefix] = kel
	} else {
		if ilk == event.ICP || ilk == event.DIP {
			//TODO: Handle duplicitious events
			return errors.New("duplicitious events not currently handled")
		}
	}

	err := kel.Verify(msg)
	if err != nil {
		return fmt.Errorf("unable to verify message: (%v)", err)
	}

	err = kel.Apply(msg)
	if err != nil {
		return fmt.Errorf("unable to apply message: (%v)", err)
	}

	return nil
}

func (r *Registry) processReceipt(vrc *event.Message) error {
	seal := vrc.Event.Seals[0]
	kel, ok := r.kels[vrc.Event.Prefix]
	if !ok {
		return errors.New("unexpected error, received a receipt for an unknown prefix")
	}

	evt := kel.EventAt(vrc.Event.SequenceInt())
	if evt == nil {
		//TODO: Haven't seen the target event yet, add to vrc escrow
		return errors.New("unverified transferable receipt")
	}

	receiptorKEL, ok := r.kels[seal.Prefix]
	if !ok {
		//TODO: Haven't seen the receipter kel yet, add to vrc escrow
		return errors.New("unverified transferable receipt")
	}

	estEvt := receiptorKEL.EventAt(seal.SequenceInt())
	if !ok {
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
