package keri

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/db/mem"
	"github.com/decentralized-identity/kerigo/pkg/io/stream"
	"github.com/decentralized-identity/kerigo/pkg/keymanager"
)

func TestInception(t *testing.T) {
	secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	kms := getKMS(t, secrets)

	k, err := New(kms)
	assert.NoError(t, err)

	icp, err := k.Inception()
	assert.NoError(t, err)

	assert.Equal(t, "Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU", icp.Event.Prefix)
	assert.Equal(t, "D69EflciVP9zgsihNU14Dbm2bPXoNGxKHK_BBVFMQ-YU", icp.Event.Keys[0])
	assert.Equal(t, "E2N7cav-AXF8R86YPUWqo8oGu2YcdyFz_w6lTiNmmOY4", icp.Event.Next)
	assert.Equal(t, "Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU", k.Prefix())
}

func TestSign(t *testing.T) {
	secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	kms := getKMS(t, secrets)

	k, err := New(kms)
	assert.NoError(t, err)

	sig, err := k.Sign([]byte("this is test data"))
	assert.NoError(t, err)
	assert.Equal(t, "huHZ3nrg6FjhF4eKG4SoachALGHN5B0/dqM9Xchf6DMLA17sIjGBOTz9E4l34o/LqqeAbXPR+x7Tz1vWKM9IDw==", base64.StdEncoding.EncodeToString(sig))
}

func TestDirectConnection(t *testing.T) {
	addr := ":5803"

	eveSecrets := []string{"ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc", "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q"}
	eveKms := getKMS(t, eveSecrets)
	in, err := stream.NewStreamInbound(addr)
	assert.NoError(t, err)

	eve, err := New(eveKms)
	assert.NoError(t, err)
	go func() {
		err = eve.HandleDirect(in)
		assert.NoError(t, err)
	}()

	bobSecrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	bobKms := getKMS(t, bobSecrets)
	out, err := stream.NewStreamOutbound(addr, 3*time.Second)
	assert.NoError(t, err)

	bob, err := New(bobKms)
	assert.NoError(t, err)

	conns, err := out.Start()
	assert.NoError(t, err)

	icp, err := bob.Inception()
	assert.NoError(t, err)

	err = out.Write(icp)
	assert.NoError(t, err)

	conn := <-conns
	msg := <-conn.Msgs()

	assert.Equal(t, "EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w", msg.Event.Prefix)
	assert.Equal(t, "EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU", msg.Event.Next)

	eve.Close()
}

//TODO: move this into a test package to avoid duplication
func getKMS(t *testing.T, secrets []string) *keymanager.KeyManager {

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	assert.NoError(t, err)

	a, err := aead.New(kh)
	assert.NoError(t, err)

	km, err := keymanager.NewKeyManager(a, mem.NewMemDB(), keymanager.WithSecrets(secrets))
	assert.NoError(t, err)

	return km
}
