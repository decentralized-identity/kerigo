package keri

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/event"
	testkms "github.com/decentralized-identity/kerigo/pkg/test/kms"
)

func TestInception(t *testing.T) {
	secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	kms := testkms.GetKMS(t, secrets)

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
	kms := testkms.GetKMS(t, secrets)

	k, err := New(kms)
	assert.NoError(t, err)

	sig, err := k.Sign([]byte("this is test data"))
	assert.NoError(t, err)
	assert.Equal(t, "huHZ3nrg6FjhF4eKG4SoachALGHN5B0/dqM9Xchf6DMLA17sIjGBOTz9E4l34o/LqqeAbXPR+x7Tz1vWKM9IDw==", base64.StdEncoding.EncodeToString(sig))
}

func TestDirectMode(t *testing.T) {

	eveSecrets := []string{"ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc", "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q"}
	bobSecrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}

	t.Run("no wait", func(t *testing.T) {

		eveKms := testkms.GetKMS(t, eveSecrets)
		eve, err := New(eveKms)
		assert.NoError(t, err)

		bobKms := testkms.GetKMS(t, bobSecrets)
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
	})

	t.Run("wait", func(t *testing.T) {

		eveKms := testkms.GetKMS(t, eveSecrets)
		eve, err := New(eveKms)
		assert.NoError(t, err)

		bobKms := testkms.GetKMS(t, bobSecrets)
		bob, err := New(bobKms)
		assert.NoError(t, err)

		icp, err := bob.Inception()
		assert.NoError(t, err)

		rcpts, _ := bob.WaitForReceipt(icp.Event, 5*time.Second)

		//Send bob's icp to Eve and get back icp and receipt
		msgsToBob, err := eve.ProcessEvents(icp)
		assert.NoError(t, err)

		eveICP, err := eve.Inception()
		assert.NoError(t, err)

		msgsToBob = append([]*event.Message{eveICP}, msgsToBob...)

		//Send Eve's icp and vrc to Bob
		msgsToEve, err := bob.ProcessEvents(msgsToBob...)

		rcpt := <-rcpts
		dig, err := icp.Event.GetDigest()
		assert.NoError(t, err)
		assert.Equal(t, rcpt.EventDigest, dig)

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
	})

}

func TestInteractionEvent(t *testing.T) {
	expectedBytes := `{"v":"KERI10JSON000098_","i":"Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU","s":"1","t":"ixn","p":"EUO96wFpqn7NQgDqRybT1ADVgaony353BSIOkJwdBFSE","a":[]}-AABAAvle4YOvsulhpBC3PbZRe3hNF2JaVDUMlzLaiIk61Puaizy2jCYuoM3ycgM-v0VqKGDrSNbBFXxyVSYSesMhgDw`
	secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	kms := testkms.GetKMS(t, secrets)

	k, err := New(kms)
	assert.NoError(t, err)

	ixn, err := k.Interaction([]*event.Seal{})
	d, err := ixn.Serialize()
	assert.NoError(t, err)

	assert.Equal(t, expectedBytes, string(d))

}

func TestFindConnection(t *testing.T) {
	secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}

	eveSecrets := []string{"ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc", "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q"}
	bobSecrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}

	t.Run("no wait", func(t *testing.T) {

		eveKms := testkms.GetKMS(t, eveSecrets)
		eve, err := New(eveKms)
		assert.NoError(t, err)

		bobKms := testkms.GetKMS(t, bobSecrets)
		bob, err := New(bobKms)
		assert.NoError(t, err)

		icp, err := bob.Inception()
		assert.NoError(t, err)

		//Send bob's icp to Eve and get back icp and receipt
		_, err = eve.ProcessEvents(icp)
		assert.NoError(t, err)

		l, err := eve.FindConnection(icp.Event.Prefix)
		assert.NoError(t, err)
		assert.NotNil(t, l, 1)
		assert.Len(t, l.Events, 1)
	})

	t.Run("not found", func(t *testing.T) {
		kms := testkms.GetKMS(t, secrets)

		k, err := New(kms)
		assert.NoError(t, err)

		l, err := k.FindConnection("bad prefix")
		assert.Error(t, err)
		assert.Nil(t, l)
	})

}
