package keri

import (
	"fmt"
	"sync"

	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/event"
	klog "github.com/decentralized-identity/kerigo/pkg/log"
)

type Registry struct {
	lock sync.RWMutex
	kels map[string]*klog.Log
}

func NewRegistry() (*Registry, error) {
	r := &Registry{
		kels: map[string]*klog.Log{},
	}

	return r, nil
}

func (r *Registry) KEL(pre string) (*klog.Log, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	kel, ok := r.kels[pre]
	if !ok {
		return nil, errors.New("not found")
	}

	return kel, nil
}

func (r *Registry) ProcessEvent(msg *event.Message) error {

	evt := msg.Event
	ilk := evt.ILK()

	kel, ok := r.kels[evt.Prefix]
	if !ok {
		if ilk != event.ICP && ilk != event.DIP {
			//TODO: Handle out-of-order events
			return errors.New("out of order events not currently handled")
		}

		kel = klog.New()
		r.lock.Lock()
		r.kels[evt.Prefix] = kel
		r.lock.Unlock()
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
