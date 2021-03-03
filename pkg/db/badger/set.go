package badger

import (
	"fmt"
	"strings"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
)

type Set struct {
	keyspace string
	keyCode  string
	iterator string
}

func NewSet(ns, key string) *Set {
	k := strings.Join([]string{"/", ns, key}, "")
	return &Set{
		keyspace: ns,
		keyCode:  k,
		iterator: iteratorFromKeyCode(k),
	}
}

func (r *Set) Get(txn *badger.Txn, keyvals ...interface{}) ([][]byte, error) {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return getVals(txn, key)
}

func (r *Set) Put(txn *badger.Txn, vals [][]byte, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return addVals(txn, key, vals)
}

func (r *Set) Add(txn *badger.Txn, val []byte, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return addVals(txn, key, [][]byte{val})
}

func (r *Set) Count(txn *badger.Txn, keyvals ...interface{}) int {
	key := fmt.Sprintf(r.iterator, keyvals...)
	return countVals(txn, key)
}

func (r *Set) Delete(txn *badger.Txn, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return delVals(txn, key)
}

func (r *Set) Iterator(txn *badger.Txn, keyvals ...interface{}) *SetIterator {
	seek := []byte(fmt.Sprintf(r.iterator, keyvals...))
	return NewSetIterator(txn, seek)
}

func (r *Set) First(txn *badger.Txn, keyvals ...interface{}) ([][]byte, error) {
	seek := []byte(fmt.Sprintf(r.iterator, keyvals...))
	it := NewSetIterator(txn, seek)
	defer it.Close()

	if !it.Next() {
		return nil, errors.New("not found")
	}

	return it.Value(), nil
}

func (r *Set) Last(txn *badger.Txn, keyvals ...interface{}) ([][]byte, error) {
	seek := []byte(fmt.Sprintf(r.iterator, keyvals...))
	it := NewSetIterator(txn, seek)
	defer it.Close()

	for it.Next() {
	}

	return it.Value(), nil
}
