package mem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPut(t *testing.T) {

	t.Run("empty get", func(t *testing.T) {
		db := NewMemDB()

		v, err := db.Get("test")
		assert.Empty(t, v)
		assert.NotNil(t, err)
		assert.Equal(t, "not found", err.Error())
	})

	t.Run("put and get", func(t *testing.T) {
		db := NewMemDB()

		err := db.Put("test", []byte("value"))

		v, err := db.Get("test")

		assert.NoError(t, err)
		assert.Equal(t, []byte("value"), v)
	})

}
