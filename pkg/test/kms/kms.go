package kms

import (
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/db"
	"github.com/decentralized-identity/kerigo/pkg/keymanager"
)

func GetKMS(t *testing.T, secrets []string, store db.DB) *keymanager.KeyManager {

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	assert.NoError(t, err)

	a, err := aead.New(kh)
	assert.NoError(t, err)

	km, err := keymanager.NewKeyManager(keymanager.WithAEAD(a), keymanager.WithSecrets(secrets), keymanager.WithStore(store))
	assert.NoError(t, err)

	return km
}
