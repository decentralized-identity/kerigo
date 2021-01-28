package mem

import (
	"errors"
	"sync"
)

type DB struct {
	values map[string][]byte
	lock   sync.RWMutex
}

func NewMemDB() *DB {
	return &DB{
		values: map[string][]byte{},
		lock:   sync.RWMutex{},
	}
}

func (r *DB) Put(k string, v []byte) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.values[k] = v
	return nil
}

func (r *DB) Get(k string) ([]byte, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	v, ok := r.values[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}
