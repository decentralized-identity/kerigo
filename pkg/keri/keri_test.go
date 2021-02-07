package keri

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/test"
)

func TestInception(t *testing.T) {
	secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	kms := test.GetKMS(t, secrets)

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
	kms := test.GetKMS(t, secrets)

	k, err := New(kms)
	assert.NoError(t, err)

	sig, err := k.Sign([]byte("this is test data"))
	assert.NoError(t, err)
	assert.Equal(t, "huHZ3nrg6FjhF4eKG4SoachALGHN5B0/dqM9Xchf6DMLA17sIjGBOTz9E4l34o/LqqeAbXPR+x7Tz1vWKM9IDw==", base64.StdEncoding.EncodeToString(sig))
}

func TestDirectMode(t *testing.T) {

	eveSecrets := []string{"ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc", "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q"}
	eveKms := test.GetKMS(t, eveSecrets)

	eve, err := New(eveKms)
	assert.NoError(t, err)

	bobSecrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	bobKms := test.GetKMS(t, bobSecrets)

	bob, err := New(bobKms)
	assert.NoError(t, err)

	icp, err := bob.Inception()
	assert.NoError(t, err)

	//Send bob's icp to Eve and get back icp and receipt
	msgsToBob, err := eve.ProcessEvents(icp)
	assert.NoError(t, err)

	eveICP, err := eve.Inception()
	assert.NoError(t, err)

	msgsToBob = append([]*event.Message{eveICP}, msgsToBob...)

	//Send Eve's icp and vrc to Bob
	msgsToEve, err := bob.ProcessEvents(msgsToBob...)

	assert.Len(t, msgsToEve, 1)

	rot, err := bob.Rotate()

	//Duplicitious events not yet handled
	msgsToBob, err = eve.ProcessEvents(icp)
	assert.Error(t, err)
	assert.Equal(t, "duplicitious events not currently handled", err.Error())

	//Send bob's icp to Eve and get back icp and receipt
	msgsToBob, err = eve.ProcessEvents(rot)
	assert.NoError(t, err)
	assert.Len(t, msgsToBob, 1)

	assert.Equal(t, "Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU", rot.Event.Prefix)
	assert.Equal(t, "E2N7cav-AXF8R86YPUWqo8oGu2YcdyFz_w6lTiNmmOY4", rot.Event.Next)

}
