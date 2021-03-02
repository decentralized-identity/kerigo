package badger

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
)

func addVals(txn *badger.Txn, k string, vals [][]byte) error {
	cur, err := getVals(txn, k)
	if err != nil {
		return err
	}

	s := set(cur)

	for _, val := range vals {
		s[string(val)] = true
	}

	i := 0
	for v := range s {
		ik := fmt.Sprintf("%s%032x", k, i)
		err := txn.Set([]byte(ik), []byte(v))
		if err != nil {
			return err
		}
		i++
	}
	return nil
}

func delVals(txn *badger.Txn, k string) error {
	opts := badger.DefaultIteratorOptions
	opts.Prefix = []byte(k)
	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		key := it.Item().KeyCopy(nil)
		err := txn.Delete(key)
		if err != nil {
			return err
		}
	}

	return nil
}

func removeFromVals(txn *badger.Txn, k string, v []byte) error {
	opts := badger.DefaultIteratorOptions
	opts.Prefix = []byte(k)
	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		key := it.Item().KeyCopy(nil)
		val, _ := it.Item().ValueCopy(nil)
		if bytes.Compare(val, v) == 0 {
			err := txn.Delete(key)
			if err != nil {
				return err
			}
			break
		}
	}

	return nil
}

func countVals(txn *badger.Txn, k string) int {
	opts := badger.DefaultIteratorOptions
	opts.Prefix = []byte(k)
	it := txn.NewIterator(opts)
	defer it.Close()

	count := 0
	for it.Rewind(); it.Valid(); it.Next() {
		count++
	}

	return count
}

func getVals(txn *badger.Txn, k string) ([][]byte, error) {
	var vals [][]byte

	opts := badger.DefaultIteratorOptions
	opts.Prefix = []byte(k)
	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Seek([]byte(k)); it.ValidForPrefix([]byte(k)); it.Next() {
		item := it.Item()
		v, _ := item.ValueCopy(nil)
		vals = append(vals, v)
	}
	return vals, nil
}

func set(vals [][]byte) map[string]bool {
	out := map[string]bool{}
	for _, val := range vals {
		out[string(val)] = true
	}
	return out
}

func addOrderedVals(txn *badger.Txn, k string, vals [][]byte) error {
	cur, err := getOrderedVals(txn, k)
	if err != nil {
		return err
	}

	s := set(cur)

	for _, val := range vals {
		s[string(val)] = true
	}

	all := append(cur, vals...)

	i := 0
	for _, v := range all {
		if _, ok := s[string(v)]; !ok {
			continue
		}

		delete(s, string(v))
		ik := fmt.Sprintf("%s%032x", k, i)
		err := txn.Set([]byte(ik), v)
		if err != nil {
			return err
		}
		i++
	}
	return nil
}

func getOrderedVals(txn *badger.Txn, k string) ([][]byte, error) {
	var vals [][]byte

	opts := badger.DefaultIteratorOptions
	it := txn.NewIterator(opts)
	defer it.Close()

	for it.Seek([]byte(k)); it.ValidForPrefix([]byte(k)); it.Next() {
		item := it.Item()
		v, _ := item.ValueCopy(nil)
		vals = append(vals, v)
	}

	return vals, nil
}

func iteratorFromKeyCode(keyCode string) string {

	i := strings.LastIndexByte(keyCode, '/')
	if i == -1 {
		return keyCode
	}

	return keyCode[:i]
}

func distalVal(txn *badger.Txn, seek string, reverse bool) ([]byte, error) {

	opts := badger.DefaultIteratorOptions
	opts.Reverse = reverse

	it := txn.NewIterator(opts)
	defer it.Close()

	if reverse {
		seek += "~"
	}

	it.Rewind()
	it.Seek([]byte(seek))
	if !it.Valid() {
		return nil, errors.New("not found")
	}

	item := it.Item()
	out, err := item.ValueCopy(nil)
	if err != nil {
		return nil, err
	}

	return out, nil
}
