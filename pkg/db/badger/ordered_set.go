package badger

import (
	"fmt"
	"strings"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
)

type OrderedSet struct {
	keyspace string
	keyCode  string
	iterator string
}

func NewOrderedSet(ns, key string) *OrderedSet {
	k := strings.Join([]string{"/", ns, key}, "")
	return &OrderedSet{
		keyspace: ns,
		keyCode:  k,
		iterator: iteratorFromKeyCode(k),
	}
}

func (r *OrderedSet) Get(txn *badger.Txn, keyvals ...interface{}) ([][]byte, error) {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return getOrderedVals(txn, key)
}

func (r *OrderedSet) Put(txn *badger.Txn, vals [][]byte, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return addOrderedVals(txn, key, vals)
}

func (r *OrderedSet) Add(txn *badger.Txn, val []byte, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return addOrderedVals(txn, key, [][]byte{val})
}

func (r *OrderedSet) Count(txn *badger.Txn, keyvals ...interface{}) int {
	key := fmt.Sprintf(r.iterator, keyvals...)
	return countVals(txn, key)
}

func (r *OrderedSet) Delete(txn *badger.Txn, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return delVals(txn, key)
}

func (r *OrderedSet) RemoveFromSet(txn *badger.Txn, val []byte, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return removeFromVals(txn, key, val)
}

func (r *OrderedSet) Iterator(txn *badger.Txn, keyvals ...interface{}) *SetIterator {
	seek := []byte(fmt.Sprintf(r.iterator, keyvals...))
	return NewSetIterator(txn, seek)
}

func (r *OrderedSet) First(txn *badger.Txn, keyvals ...interface{}) ([][]byte, error) {
	seek := []byte(fmt.Sprintf(r.iterator, keyvals...))
	it := NewSetIterator(txn, seek)
	defer it.Close()

	if !it.Next() {
		return nil, errors.New("not found")
	}

	return it.Value(), nil
}

func (r *OrderedSet) Last(txn *badger.Txn, keyvals ...interface{}) ([][]byte, error) {
	seek := []byte(fmt.Sprintf(r.iterator, keyvals...))
	it := NewSetIterator(txn, seek)
	defer it.Close()

	for it.Next() {
	}

	return it.Value(), nil
}
