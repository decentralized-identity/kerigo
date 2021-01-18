package event

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
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
