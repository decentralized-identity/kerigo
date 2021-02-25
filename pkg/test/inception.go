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

func InceptionFromSecrets(t *testing.T, keys, nexts []string, threshold, nextThreshold event.SigThreshold) *event.Event {
	var keyPres, nextPres []prefix.Prefix

	for _, k := range keys {
		kd, err := derivation.FromPrefix(k)
		if !assert.NoError(t, err) {
			return nil
		}
		edPriv := ed25519.NewKeyFromSeed(kd.Raw)
		keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPriv.Public().(ed25519.PublicKey)))
		if !assert.NoError(t, err) {
			return nil
		}
		keyPres = append(keyPres, prefix.New(keyDer))
	}

	for _, k := range nexts {
		kd, err := derivation.FromPrefix(k)
		if !assert.NoError(t, err) {
			return nil
		}
		edPriv := ed25519.NewKeyFromSeed(kd.Raw)
		keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPriv.Public().(ed25519.PublicKey)))
		if !assert.NoError(t, err) {
			return nil
		}
		nextPres = append(nextPres, prefix.New(keyDer))
	}

	icp, err := event.NewInceptionEvent(
		event.WithKeys(keyPres...),
		event.WithDefaultVersion(event.JSON),
		event.WithNext(nextThreshold.String(), derivation.Blake3256, nextPres...),
	)
	if !assert.NoError(t, err) {
		return nil
	}
	icp.SigThreshold = &threshold

	icp.Prefix = derivation.Blake3256.Default()
	eventBytes, err := icp.Serialize()
	if !assert.NoError(t, err) {
		return nil
	}
	icp.Version = event.VersionString(event.JSON, version.Code(), len(eventBytes))
	icp.Prefix = ""

	ser, err := icp.Serialize()
	if !assert.NoError(t, err) {
		return nil
	}

	saDerivation, _ := derivation.New(derivation.WithCode(derivation.Blake3256))
	_, err = saDerivation.Derive(ser)
	if !assert.NoError(t, err) {
		return nil
	}

	selfAdd := prefix.New(saDerivation)
	icp.Prefix = selfAdd.String()

	return icp
}

func Inception(t *testing.T, edPub ed25519.PublicKey, nextPubDer *derivation.Derivation) *event.Event {
	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub))
	assert.NoError(t, err)

	keyPre := prefix.New(keyDer)

	nextKeyPre := prefix.New(nextPubDer)

	icp, err := event.NewInceptionEvent(event.WithKeys(keyPre), event.WithDefaultVersion(event.JSON), event.WithNext("1", derivation.Blake3256, nextKeyPre))
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
	assert.NoError(t, err)
	assert.Equal(t, eventBytesExpected, len(eventBytes))

	return icp
}
