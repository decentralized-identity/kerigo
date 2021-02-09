package test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/decentralized-identity/kerigo/pkg/version"
)

func InceptionFromSecrets(t *testing.T, secret, next string) *event.Event {
	der, err := derivation.FromPrefix(secret)
	assert.NoError(t, err)

	edPriv := ed25519.NewKeyFromSeed(der.Raw)
	edPub := edPriv.Public()

	nextder, err := derivation.FromPrefix(next)
	assert.NoError(t, err)

	nextPriv := ed25519.NewKeyFromSeed(nextder.Raw)
	nextPub := nextPriv.Public()
	nextPubDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(nextPub.(ed25519.PublicKey)))
	assert.NoError(t, err)

	return Inception(t, edPub.(ed25519.PublicKey), nextPubDer)
}

func Inception(t *testing.T, edPub ed25519.PublicKey, nextPubDer *derivation.Derivation) *event.Event {
	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub))
	assert.NoError(t, err)

	keyPre := prefix.New(keyDer)

	nextKeyPre := prefix.New(nextPubDer)

	icp, err := event.NewInceptionEvent(event.WithKeys(keyPre), event.WithDefaultVersion(event.JSON), event.WithNext(1, derivation.Blake3256, nextKeyPre))
	assert.NoError(t, err)

	// Serialize with defaults to get correct length for version string
	icp.Prefix = derivation.Blake3256.Default()
	icp.Version = event.DefaultVersionString(event.JSON)
	eventBytes, err := event.Serialize(icp, event.JSON)
	assert.NoError(t, err)

	eventBytesExpected := len(eventBytes)
	icp.Version = event.VersionString(event.JSON, version.Code(), len(eventBytes))
	icp.Prefix = ""

	ser, err := event.Serialize(icp, event.JSON)
	assert.NoError(t, err)

	saDerivation, err := derivation.New(derivation.WithCode(derivation.Blake3256))
	assert.NoError(t, err)

	_, err = saDerivation.Derive(ser)
	assert.NoError(t, err)

	selfAdd := prefix.New(saDerivation)
	assert.NoError(t, err)
	selfAddAID := selfAdd.String()
	assert.Nil(t, err)

	// Set as the prefix for the inception event
	icp.Prefix = selfAddAID

	eventBytes, err = event.Serialize(icp, event.JSON)
	assert.Equal(t, eventBytesExpected, len(eventBytes))

	return icp
}
