package badger

import (
	"bytes"

	"github.com/dgraph-io/badger"
)

type Iterator struct {
	it    *badger.Iterator
	seek  []byte
	start bool
}

func NewIterator(txn *badger.Txn, seek []byte) *Iterator {
	opts := badger.DefaultIteratorOptions
	opts.Prefix = seek

	it := txn.NewIterator(opts)

	return &Iterator{it, seek, false}
}

func (r *Iterator) Next() bool {
	if !r.start {
		r.it.Rewind()
		r.start = true
		return r.it.Valid()
	}

	r.it.Next()

	return r.it.Valid()
}

func (r *Iterator) Value() []byte {
	if !r.it.Valid() {
		return nil
	}

	item := r.it.Item()
	out, err := item.ValueCopy(nil)
	if err != nil {
		return nil
	}

	return out
}

func (r *Iterator) Close() {
	r.it.Close()
}

func (r *Iterator) Key() []byte {
	if !r.it.Valid() {
		return nil
	}

	return r.it.Item().KeyCopy(nil)
}

type SetIterator struct {
	it     *badger.Iterator
	seek   []byte
	curIdx []byte
	curKey []byte
	curVal [][]byte
}

func NewSetIterator(txn *badger.Txn, seek []byte) *SetIterator {
	opts := badger.DefaultIteratorOptions
	opts.Prefix = seek

	it := txn.NewIterator(opts)

	return &SetIterator{
		it:   it,
		seek: seek,
	}
}

func (r *SetIterator) Next() bool {
	if len(r.curIdx) == 0 {
		r.it.Seek(r.seek)
		if !r.it.Valid() {
			return false
		}

		item := r.it.Item()
		k := item.KeyCopy(nil)

		r.curKey = k[:len(k)-32]
		r.curIdx = k[:len(k)-32]
	}

	return r.batch()
}

func (r *SetIterator) batch() bool {
	if !r.it.Valid() {
		return false
	}

	var root []byte
	for r.curVal = [][]byte{}; r.it.Valid(); r.it.Next() {
		item := r.it.Item()
		k := item.KeyCopy(nil)

		root = k[:len(k)-32]

		if bytes.Compare(root, r.curIdx) != 0 {
			break
		}

		val, err := item.ValueCopy(nil)
		if err != nil {
			return false
		}

		r.curVal = append(r.curVal, val)

	}

	r.curKey = r.curIdx
	r.curIdx = root

	return true
}

func (r *SetIterator) Value() [][]byte {
	if r.curVal == nil {
		return nil
	}
	return r.curVal
}

func (r *SetIterator) Key() []byte {
	return r.curKey
}

func (r *SetIterator) Close() {
	r.it.Close()
}
