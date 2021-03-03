package badger

import (
	"strconv"
	"testing"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/stretchr/testify/assert"
)

func TestValue_Last(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := badger.Open(badger.DefaultOptions(td))
	assert.NoError(t, err)

	txn := db.NewTransaction(true)

	vals := NewValue("fses", "/%s/%s.%08d")

	for i := 0; i < 10; i++ {
		d := strconv.Itoa(i)
		now := time.Now()
		dts := now.Format(time.RFC3339)

		err := vals.Set(txn, []byte(d), "pre", dts, now.Nanosecond())
		assert.NoError(t, err)
	}

	last, err := vals.Last(txn, "pre")
	assert.NoError(t, err)
	assert.Equal(t, "9", string(last))
	first, err := vals.First(txn, "pre")
	assert.NoError(t, err)
	assert.Equal(t, "0", string(first))
}
