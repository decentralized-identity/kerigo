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
