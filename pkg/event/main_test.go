package event

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	testkms "github.com/decentralized-identity/kerigo/pkg/test/kms"
)

func TestNewInceptionEvent(t *testing.T) {
	assert := assert.New(t)

	// ed25519
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if !assert.Nil(err) {
		return
	}

	basicDerivation, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub))
	assert.Nil(err)

	basicPre := prefix.New(basicDerivation)

	icp, err := NewInceptionEvent(WithKeys(basicPre))
	assert.Nil(err)
	if assert.Len(icp.Keys, 1) {
		basicPreAID := basicPre.String()
		assert.Contains(icp.Keys, basicPreAID)
	}

}

func TestNext(t *testing.T) {
	assert := assert.New(t)

	d1, _ := derivation.FromPrefix("BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE")
	d1p := prefix.New(d1)
	d2, _ := derivation.FromPrefix("BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk")
	d2p := prefix.New(d2)
	d3, _ := derivation.FromPrefix("B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw")
	d3p := prefix.New(d3)

	event, err := NewEvent(WithType(ICP), WithNext(2, derivation.Blake3256, d1p, d2p, d3p))
	assert.Nil(err)
	assert.Equal("ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs", event.Next)

	//test case from Bob demo in python
	der, err := derivation.FromPrefix("A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q")
	assert.NoError(err)
	edPriv := ed25519.NewKeyFromSeed(der.Raw)
	edPub := edPriv.Public()

	basicDerivation, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub.(ed25519.PublicKey)))
	basicPre := prefix.New(basicDerivation)

	event, err = NewEvent(WithType(ICP), WithNext(1, derivation.Blake3256, basicPre))
	assert.NoError(err)
	assert.Equal("EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU", event.Next)

}

func TestGetDigest(t *testing.T) {

	icp := incept(t, "ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc")

	dig, err := icp.GetDigest()
	assert.NoError(t, err)
	assert.Equal(t, "EeM1ZikRHU9XKxd3pQrjLOPyP8bQkQQriYBk-_UYpQfE", dig)

}

func TestRotationEvent(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		expectedRotBytes := `{"v":"KERI10JSON0000ba_","i":"Efxqin4pHh--KbxFN7xcOnOakf2CAK19zknumybXxabI","s":"0","t":"rot","kt":"1","n":"EOF414QEuea9A-Svo-tzipeVfk0-DvtAsaLULWCnHXw4","wt":"0","wr":[],"wa":[],"a":[]}`
		secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc", "Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k"}
		kms := testkms.GetKMS(t, secrets)

		icp := incept(t, "ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc")

		err := kms.Rotate()
		assert.NoError(t, err)

		nextPre := prefix.New(kms.Next())

		evt, err := NewRotationEvent(WithPrefix(icp.Prefix), WithNext(1, derivation.Blake3256, nextPre))
		assert.NoError(t, err)

		b, err := evt.Serialize()
		assert.NoError(t, err)

		assert.Equal(t, expectedRotBytes, string(b))
	})
	t.Run("invalid rotation prefix", func(t *testing.T) {
		evt, err := NewRotationEvent()
		assert.Error(t, err)
		assert.Nil(t, evt)
		assert.Equal(t, "prefix required for rot", err.Error())
	})
	t.Run("invalid rotation next commitment", func(t *testing.T) {
		evt, err := NewRotationEvent(WithPrefix("Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU"))
		assert.Error(t, err)
		assert.Nil(t, evt)
		assert.Equal(t, "next commitment required for rot", err.Error())
	})
}

func TestInteractionEvent(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		expectedRotBytes := `{"v":"KERI10JSON000065_","i":"Efxqin4pHh--KbxFN7xcOnOakf2CAK19zknumybXxabI","s":"1","t":"ixn","a":[]}`

		icp := incept(t, "ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc")

		evt, err := NewInteractionEvent(WithPrefix(icp.Prefix), WithSequence(1))
		assert.NoError(t, err)

		b, err := evt.Serialize()
		assert.NoError(t, err)

		assert.Equal(t, expectedRotBytes, string(b))
	})
}
