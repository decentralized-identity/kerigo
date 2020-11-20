package event

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/stretchr/testify/assert"
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

	d1, _ := derivation.FromPrefix("EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY")
	d1p := prefix.New(d1)
	d2, _ := derivation.FromPrefix("EO4CXp8gs0yJg1fFhJLs5hH6neqJwhFEY7vrJEdPe87I")
	d2p := prefix.New(d2)
	d3, _ := derivation.FromPrefix("ELWWZEyBpjrfM1UU0n31KIyIXllrCoLEOI5UHD9x7WxI")
	d3p := prefix.New(d3)

	event, err := NewEvent(WithType(ICP), WithNext(2, derivation.Blake3256, d1p, d2p, d3p))
	assert.Nil(err)
	assert.Equal("ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs", event.Next)
}
