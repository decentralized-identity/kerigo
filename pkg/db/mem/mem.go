package mem

import (
	"errors"
	"sync"

	"github.com/decentralized-identity/kerigo/pkg/event"
)

type DB struct {
	valueLock sync.RWMutex
	values    map[string][]byte

	logLock sync.RWMutex
	logs    map[string][]*event.Message

	forkLock sync.RWMutex
	forks    map[string][]*event.Message
}

func New() *DB {
	return &DB{
		valueLock: sync.RWMutex{},
		values:    map[string][]byte{},

		logLock: sync.RWMutex{},
		logs:    map[string][]*event.Message{},

		forkLock: sync.RWMutex{},
		forks:    map[string][]*event.Message{},
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

	return l[0], nil
}

func (r *DB) CurrentEvent(pre string) (*event.Message, error) {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	l, ok := r.logs[pre]
	if !ok || len(l) == 0 {
		return nil, errors.New("not found")
	}

	return l[len(l)-1], nil
}

func (r *DB) CurrentEstablishmentEvent(pre string) (*event.Message, error) {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	var out *event.Message
	l := r.logs[pre]
	for _, msg := range l {
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

	return l[sequence], nil
}

func (r *DB) LogEvent(e *event.Message) error {
	r.logLock.Lock()
	defer r.logLock.Unlock()

	pre := e.Event.Prefix
	l, ok := r.logs[pre]
	if !ok {
		l := []*event.Message{e}
		r.logs[pre] = l
	} else {
		r.logs[pre] = append(l, e)
	}

	return nil
}

func (r *DB) ForkEvent(e *event.Message) error {
	r.forkLock.Lock()
	defer r.forkLock.Unlock()

	pre := e.Event.Prefix
	l, ok := r.forks[pre]
	if !ok {
		l := []*event.Message{e}
		r.forks[pre] = l
	} else {
		l = append(l, e)
	}

	return nil
}

func (r *DB) StreamLog(pre string, handler func(*event.Message)) error {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	l, ok := r.logs[pre]
	if !ok {
		return errors.New("not found")
	}

	for _, msg := range l {
		handler(msg)
	}

	return nil
}

func (r *DB) StreamForks(pre string, handler func(*event.Message)) error {
	r.forkLock.RLock()
	defer r.forkLock.RUnlock()

	l, ok := r.forks[pre]
	if !ok {
		return errors.New("not found")
	}

	for _, msg := range l {
		handler(msg)
	}

	return nil
}

func (r *DB) StreamEstablisment(pre string, handler func(*event.Message)) error {
	r.logLock.RLock()
	defer r.logLock.RUnlock()

	l, ok := r.logs[pre]
	if !ok {
		return errors.New("not found")
	}

	for _, msg := range l {
		if msg.Event.IsEstablishment() {
			handler(msg)
		}
	}

	return nil
}

func (r *DB) Close() error {
	return nil
}
