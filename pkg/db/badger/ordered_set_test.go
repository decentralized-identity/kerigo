package badger

import (
	"strconv"
	"testing"

	"github.com/dgraph-io/badger"
	"github.com/stretchr/testify/assert"
)

func TestOrderedSet_Add(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := badger.Open(badger.DefaultOptions(td))
	assert.NoError(t, err)

	txn := db.NewTransaction(true)

	s := NewOrderedSet("fses", "/%s/%s")

	for i := 0; i < 10; i++ {
		d := strconv.Itoa(i)
		err := s.Add(txn, []byte(d), "abc", "xyz")
		assert.NoError(t, err)
	}

	for i := 0; i < 10; i++ {
		d := strconv.Itoa(i)
		err := s.Add(txn, []byte(d), "abc", "123")
		assert.NoError(t, err)
	}
	err = txn.Commit()
	assert.NoError(t, err)

	txn = db.NewTransaction(false)

	vals, err := s.Get(txn, "abc", "xyz")
	assert.NoError(t, err)
	assert.Len(t, vals, 10)

	for i, val := range vals {
		d := strconv.Itoa(i)
		assert.Equal(t, d, string(val))
	}

	txn.Discard()
}

func TestModification(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := badger.Open(badger.DefaultOptions(td))
	assert.NoError(t, err)

	txn := db.NewTransaction(true)

	s := NewOrderedSet("fses", "/%s/%s")

	for i := 0; i < 10; i++ {
		d := strconv.Itoa(i)
		err := s.Add(txn, []byte(d), "abc", "xyz")
		assert.NoError(t, err)
	}

	for i := 0; i < 10; i++ {
		d := strconv.Itoa(i + 10)
		err := s.Add(txn, []byte(d), "abc", "123")
		assert.NoError(t, err)
	}

	vals, err := s.First(txn, "abc")
	assert.NoError(t, err)
	assert.Len(t, vals, 10)
	assert.Equal(t, "10", string(vals[0]))

	vals, err = s.Last(txn, "abc")
	assert.NoError(t, err)
	assert.Len(t, vals, 10)
	assert.Equal(t, "0", string(vals[0]))

	err = s.Delete(txn, "abc", "xyz")
	assert.NoError(t, err)

	vals, err = s.First(txn, "abc")
	assert.NoError(t, err)
	assert.Len(t, vals, 10)
	assert.Equal(t, "10", string(vals[0]))

	err = s.RemoveFromSet(txn, []byte("15"), "abc", "123")
	assert.NoError(t, err)
	vals, err = s.First(txn, "abc")
	assert.NoError(t, err)
	assert.Len(t, vals, 9)

	err = s.Put(txn, [][]byte{[]byte("16"), []byte("75")}, "abc", "123")
	assert.NoError(t, err)
	vals, err = s.First(txn, "abc")
	assert.NoError(t, err)
	assert.Len(t, vals, 10)
}
