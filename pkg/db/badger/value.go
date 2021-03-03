package badger

import (
	"fmt"
	"strings"

	"github.com/dgraph-io/badger"
)

type Value struct {
	keyspace string
	keyCode  string
	iterator string
}

func NewValue(ns, key string) *Value {
	k := strings.Join([]string{"/", ns, key}, "")
	return &Value{
		keyspace: ns,
		keyCode:  k,
		iterator: iteratorFromKeyCode(k),
	}
}

func (r *Value) Exists(txn *badger.Txn, keyvals ...interface{}) bool {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	_, err := txn.Get([]byte(key))

	return err == nil
}

func (r *Value) Get(txn *badger.Txn, keyvals ...interface{}) ([]byte, error) {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	item, err := txn.Get([]byte(key))
	if err != nil {
		return nil, err
	}

	out, err := item.ValueCopy(nil)
	return out, err
}

// Set writes value at key, overwrites if it already exists
func (r *Value) Set(txn *badger.Txn, val []byte, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)

	err := txn.Set([]byte(key), val)
	if err != nil {
		return err
	}

	return nil
}

// Put writes value at key, does not change value if it already exsits
func (r *Value) Put(txn *badger.Txn, val []byte, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)

	_, err := txn.Get([]byte(key))
	if err == nil {
		return nil
	}

	err = txn.Set([]byte(key), val)
	if err != nil {
		return err
	}

	return nil
}

func (r *Value) Iterator(txn *badger.Txn, keyvals ...interface{}) *Iterator {
	seek := []byte(fmt.Sprintf(r.iterator, keyvals...))
	return NewIterator(txn, seek)
}

func (r *Value) Count(txn *badger.Txn, keyvals ...interface{}) int {
	key := fmt.Sprintf(r.iterator, keyvals...)
	return countVals(txn, key)
}

func (r *Value) First(txn *badger.Txn, keyvals ...interface{}) ([]byte, error) {
	seek := fmt.Sprintf(r.iterator, keyvals...)
	val, err := distalVal(txn, seek, false)
	if err != nil {
		return nil, err
	}

	return val, nil
}

func (r *Value) Last(txn *badger.Txn, keyvals ...interface{}) ([]byte, error) {
	seek := fmt.Sprintf(r.iterator, keyvals...)
	val, err := distalVal(txn, seek, true)
	if err != nil {
		return nil, err
	}

	return val, nil
}

func (r *Value) Delete(txn *badger.Txn, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.keyCode, keyvals...)
	return txn.Delete([]byte(key))
}

func (r *Value) DeleteAll(txn *badger.Txn, keyvals ...interface{}) error {
	key := fmt.Sprintf(r.iterator, keyvals...)
	return delVals(txn, key)
}
