package keymanager

import (
	"encoding/base64"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/db/mem"
)

var (
	secrets = []string{
		"AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw",
		"AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ",
		"AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM",
		"AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs",
		"Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k",
		"Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8",
		"AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc",
		"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s",
	}
)

func keyMgr(t *testing.T, opts ...Option) *KeyManager {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	assert.NoError(t, err)

	a, err := aead.New(kh)
	assert.NoError(t, err)

	db := mem.NewMemDB()
	km, err := NewKeyManager(a, db, opts...)
	assert.NoError(t, err)
	return km
}

func TestKeyManager(t *testing.T) {
	t.Run("new", func(t *testing.T) {
		km := keyMgr(t)
		assert.NotNil(t, km)

		pub := km.PublicKey()
		assert.NotEmpty(t, pub)
	})

	t.Run("rotate", func(t *testing.T) {
		km := keyMgr(t)
		assert.NotNil(t, km)

		pub := km.PublicKey()
		assert.NotEmpty(t, pub)

		err := km.Rotate()
		assert.NoError(t, err)

		pub = km.PublicKey()
		assert.NotEmpty(t, pub)
	})

	t.Run("sign", func(t *testing.T) {
		km := keyMgr(t)
		assert.NotNil(t, km)

		signer := km.Signer()
		b, err := signer([]byte("test data"))
		assert.NoError(t, err)
		assert.NotEmpty(t, b)
	})

	t.Run("sign after rotate", func(t *testing.T) {
		km := keyMgr(t)
		assert.NotNil(t, km)

		err := km.Rotate()
		assert.NoError(t, err)

		signer := km.Signer()
		b, err := signer([]byte("test data"))
		assert.NoError(t, err)
		assert.NotEmpty(t, b)
	})

}

func TestKeyManagerWithSecrets(t *testing.T) {

	t.Run("new", func(t *testing.T) {
		km := keyMgr(t, WithSecrets(secrets))
		assert.NotNil(t, km)

		pub := km.PublicKey()
		enc := base64.URLEncoding.EncodeToString(pub)
		assert.Equal(t, "8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc=", enc)
	})

	t.Run("rotate", func(t *testing.T) {
		km := keyMgr(t, WithSecrets(secrets))
		assert.NotNil(t, km)

		pub := km.PublicKey()
		enc := base64.URLEncoding.EncodeToString(pub)
		assert.Equal(t, "8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc=", enc)

		err := km.Rotate()
		assert.NoError(t, err)

		pub = km.PublicKey()
		enc = base64.URLEncoding.EncodeToString(pub)
		assert.Equal(t, "bWeWTNGXPMQrVuJmScNQn81YF7T2fhh2kXwT8E_NbeI=", enc)

	})

	t.Run("rotate past handles", func(t *testing.T) {
		km := keyMgr(t, WithSecrets(secrets))
		assert.NotNil(t, km)

		pub := km.PublicKey()
		enc := base64.URLEncoding.EncodeToString(pub)
		assert.Equal(t, "8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc=", enc)

		for i := 0; i < 6; i++ {
			err := km.Rotate()
			assert.NoError(t, err)
		}

		pub = km.PublicKey()
		enc = base64.URLEncoding.EncodeToString(pub)
		assert.Equal(t, "AIyL2yT9nU6kChGXWce8d6q07l0vBLPNImw_f9bazeQ=", enc)

		err := km.Rotate()
		assert.NoError(t, err)

		pub = km.PublicKey()
		assert.NotEmpty(t, pub)
	})

	t.Run("sign", func(t *testing.T) {
		km := keyMgr(t, WithSecrets(secrets))
		assert.NotNil(t, km)

		signer := km.Signer()
		b, err := signer([]byte("test data"))
		assert.NoError(t, err)

		enc := base64.URLEncoding.EncodeToString(b)
		assert.Equal(t, "oMG5Z5l5PgrUeIlY93X9mi-v10gqiR7Ojq6nnHHfiEE6QymzaK5pjyfglgvJo3Ve_F_aD_lRL-Dx9jpVes5fCw==", enc)
	})

	t.Run("sign after rotate", func(t *testing.T) {
		km := keyMgr(t, WithSecrets(secrets))
		assert.NotNil(t, km)

		err := km.Rotate()
		assert.NoError(t, err)

		signer := km.Signer()
		b, err := signer([]byte("test data"))
		assert.NoError(t, err)

		enc := base64.URLEncoding.EncodeToString(b)
		assert.Equal(t, "s0Y1hRUeLfysPULLmROLMkUpvFIRlfsepViLxaIJ5Tq9VA0j2feZ4y81-qn4xAs5WF_NUU5xtMOEsxf1dWpPBA==", enc)
	})

}

func TestDB(t *testing.T) {
	t.Run("rotate", func(t *testing.T) {
		kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
		assert.NoError(t, err)

		a, err := aead.New(kh)
		assert.NoError(t, err)

		db := mem.NewMemDB()

		km1, err := NewKeyManager(a, db)
		assert.NoError(t, err)

		assert.NotNil(t, km1)

		pub := km1.PublicKey()
		assert.NotEmpty(t, pub)

		err = km1.Rotate()
		assert.NoError(t, err)

		pub = km1.PublicKey()
		assert.NotEmpty(t, pub)

		sig := km1.Signer()
		enc, err := sig([]byte("test data"))
		assert.NoError(t, err)

		km2, err := NewKeyManager(a, db)
		assert.NoError(t, err)

		sig2 := km2.Signer()
		enc2, err := sig2([]byte("test data"))
		assert.NoError(t, err)

		assert.Equal(t, enc, enc2)

	})
}
