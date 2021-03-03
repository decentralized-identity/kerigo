package mem

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type DB struct {
	valueLock sync.RWMutex
	values    map[string][]byte

	logLock sync.RWMutex
	logs    map[string][][]*event.Message
	seen    map[string][]*event.Message

	pendLock sync.RWMutex
	pending  map[string][][]*event.Message

	dupLock    sync.RWMutex
	likelyDups map[string][][]*event.Message

	rcptLock sync.RWMutex
	rcpts    map[string][]string
}

func New() *DB {
	return &DB{
		valueLock: sync.RWMutex{},
		values:    map[string][]byte{},

		logLock: sync.RWMutex{},
		logs:    map[string][][]*event.Message{},
		seen:    map[string][]*event.Message{},

		pendLock: sync.RWMutex{},
		pending:  map[string][][]*event.Message{},

		dupLock:    sync.RWMutex{},
		likelyDups: map[string][][]*event.Message{},

		rcptLock: sync.RWMutex{},
		rcpts:    map[string][]string{},
	}
}

func (r *DB) Put(k string, v []byte) error {
	r.valueLock.Lock()
	defer r.valueLock.Unlock()

	r.values[k] = v
	return nil
}

func (r *DB) Get(k string) ([]byte, error) {
	r.valueLock.RLock()
	defer r.valueLock.RUnlock()

	v, ok := r.values[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (r *DB) LogSize(pre string) int {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	l, ok := r.logs[pre]
	if !ok {
		return 0
	}

	return len(l)
}

func (r *DB) Seen(pre string) bool {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	_, ok := r.logs[pre]
	return ok
}

func (r *DB) Inception(pre string) (*event.Message, error) {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	l, ok := r.logs[pre]
	if !ok || len(l) == 0 {
		return nil, errors.New("not found")
	}

	return l[0][0], nil
}

func (r *DB) CurrentEvent(pre string) (*event.Message, error) {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	l, ok := r.logs[pre]
	if !ok || len(l) == 0 {
		return nil, errors.New("not found")
	}

	evts := l[len(l)-1]

	return evts[len(evts)-1], nil
}

func (r *DB) CurrentEstablishmentEvent(pre string) (*event.Message, error) {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	var out *event.Message
	l := r.logs[pre]
	for _, evts := range l {
		msg := evts[len(evts)-1]
		if msg.Event.IsEstablishment() {
			out = msg
		}
	}

	if out == nil {
		return nil, errors.New("not found")
	}

	return out, nil
}

func (r *DB) EventAt(pre string, sequence int) (*event.Message, error) {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	l, ok := r.logs[pre]
	if !ok || len(l) < sequence-1 || sequence < 0 {
		return nil, errors.New("not found")
	}

	evts := l[sequence]
	return evts[len(evts)-1], nil
}

func (r *DB) LogEvent(e *event.Message, first bool) error {
	r.logLock.Lock()
	defer r.logLock.Unlock()

	pre := e.Event.Prefix
	l, ok := r.logs[pre]
	if !ok {
		l := [][]*event.Message{{e}}
		r.logs[pre] = l
	} else {
		sn := e.Event.SequenceInt()
		if sn < len(l) {
			l[sn] = append(l[sn], e)
		} else {
			r.logs[pre] = append(l, []*event.Message{e})
		}
	}

	s, ok := r.seen[pre]
	if !ok {
		r.seen[pre] = []*event.Message{e}
	} else {
		r.seen[pre] = append(s, e)
	}

	return nil
}

func (r *DB) StreamEstablisment(pre string, handler func(*event.Message) error) error {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	l, ok := r.logs[pre]
	if !ok {
		return nil
	}

	for _, msg := range l {
		evt := msg[len(msg)-1]
		if evt.Event.IsEstablishment() {
			err := handler(evt)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *DB) Close() error {
	return nil
}

//TODO:  implement
func (r *DB) StreamAsFirstSeen(pre string, handler func(*event.Message) error) error {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	log, ok := r.seen[pre]
	if !ok {
		return errors.New("not found")
	}

	for _, evt := range log {
		err := handler(evt)
		if err != nil {
			return err
		}
	}

	return nil
}

//TODO:  implement
func (r *DB) StreamBySequenceNo(pre string, handler func(*event.Message) error) error {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	log, ok := r.logs[pre]
	if !ok {
		return errors.New("not found")
	}

	fork := []byte{}
	for _, evts := range log {
		evt := evts[len(evts)-1]

		if len(fork) != 0 {
			if bytes.Compare([]byte(evt.Event.PriorEventDigest), fork) != 0 {
				break
			}
		}

		if len(evts) > 1 {
			dig, _ := evt.Event.GetDigest()
			fork = []byte(dig)
		} else {
			fork = []byte{}
		}

		err := handler(evt)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *DB) LastAcceptedDigest(pre string, seq int) ([]byte, error) {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	log, ok := r.logs[pre]
	if !ok {
		return nil, errors.New("not found")
	}

	last := log[len(log)-1]
	evt := last[len(last)-1]
	dig, err := evt.Event.GetDigest()
	if err != nil {
		return nil, err
	}

	return []byte(dig), nil
}

func (r *DB) EscrowOutOfOrderEvent(e *event.Message) error {
	return nil
}

func (r *DB) EscrowLikelyDuplicitiousEvent(e *event.Message) error {
	r.dupLock.Lock()
	defer r.dupLock.Unlock()

	pre := e.Event.Prefix
	l, ok := r.likelyDups[pre]
	if !ok {
		l := [][]*event.Message{{e}}
		r.likelyDups[pre] = l
	} else {
		sn := e.Event.SequenceInt()
		if sn < len(l) {
			l[sn] = append(l[sn], e)
		} else {
			r.likelyDups[pre] = append(l, []*event.Message{e})
		}
	}

	return nil
}

func (r *DB) EscrowPendingEvent(e *event.Message) error {
	r.pendLock.Lock()
	defer r.pendLock.Unlock()

	pre := e.Event.Prefix
	l, ok := r.pending[pre]
	if !ok {
		l := [][]*event.Message{{e}}
		r.pending[pre] = l
	} else {
		sn := e.Event.SequenceInt()
		if sn < len(l) {
			l[sn] = append(l[sn], e)
		} else {
			r.pending[pre] = append(l, []*event.Message{e})
		}
	}

	return nil
}

func (r *DB) RemovePendingEscrow(prefix string, sn int, dig string) error {
	r.pendLock.Lock()
	defer r.pendLock.Unlock()

	l, ok := r.pending[prefix]
	if ok {
		if sn < len(l) {
			digs := l[sn]
			n := 0
			for _, x := range digs {
				xdig, _ := x.Event.GetDigest()
				if xdig != dig {
					digs[n] = x
					n++
				}
			}
			digs = digs[:n]
		}
	}

	return nil
}

func (r *DB) StreamPending(pre string, handler func(*event.Message) error) error {
	r.pendLock.RLock()
	defer r.pendLock.RUnlock()

	log, ok := r.pending[pre]
	if !ok {
		return errors.New("not found")
	}

	for _, evts := range log {
		for _, evt := range evts {
			err := handler(evt)
			if err != nil {
				return err
			}
		}
	}

	return nil

}

func (r *DB) LogTransferableReceipt(vrc *event.Event, sig derivation.Derivation) error {
	r.rcptLock.Lock()
	defer r.rcptLock.Unlock()

	pre := vrc.Prefix
	seal := vrc.Seals[0]
	quadlet := strings.Join([]string{seal.Prefix, fmt.Sprintf("%024d", seal.SequenceInt()), seal.Digest, sig.AsPrefix()}, "")

	_, ok := r.rcpts[pre]
	if !ok {
		r.rcpts[pre] = []string{}
	}

	r.rcpts[pre] = append(r.rcpts[pre], quadlet)

	return nil
}

func (r *DB) StreamTransferableReceipts(pre string, sn int, handler func(quadlet []byte) error) error {
	r.rcptLock.Lock()
	defer r.rcptLock.Unlock()

	log, ok := r.rcpts[pre]
	if !ok {
		return nil
	}

	for _, quad := range log {
		err := handler([]byte(quad))
		if err != nil {
			return err
		}
	}

	return nil
}
