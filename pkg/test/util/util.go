package util

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func GetTempDir(t *testing.T) (string, func()) {
	td, err := ioutil.TempDir("", "badger-test-*")
	require.NoError(t, err)

	cleanup := func() {
		err := os.RemoveAll(td)
		require.NoError(t, err)
	}

	return td, cleanup
}
