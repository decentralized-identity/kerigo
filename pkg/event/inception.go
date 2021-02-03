package event

import (
	"crypto/ed25519"
	"fmt"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/decentralized-identity/kerigo/pkg/version"
)

func Incept(signing ed25519.PublicKey, next *derivation.Derivation) (*Event, error) {
	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(signing))
	if err != nil {
		return nil, err
	}
	keyPre := prefix.New(keyDer)

	nextKeyPre := prefix.New(next)

	icp, err := NewInceptionEvent(WithKeys(keyPre), WithDefaultVersion(JSON), WithNext(1, derivation.Blake3256, nextKeyPre))
	if err != nil {
		return nil, err
	}

	// Serialize with defaults to get correct length for version string
	icp.Prefix = derivation.Blake3256.Default()
	icp.Version = DefaultVersionString(JSON)
	eventBytes, err := Serialize(icp, JSON)
	if err != nil {
		return nil, err
	}

	icp.Version = VersionString(JSON, version.Code(), len(eventBytes))

	ser, err := Serialize(icp, JSON)
	fmt.Println(string(ser))

	saDerivation, err := derivation.New(derivation.WithCode(derivation.Blake3256))
	if err != nil {
		return nil, err
	}

	_, err = saDerivation.Derive(ser)
	if err != nil {
		return nil, err
	}

	selfAdd := prefix.New(saDerivation)
	selfAddAID := selfAdd.String()

	// Set as the prefix for the inception event
	icp.Prefix = selfAddAID

	return icp, nil
}
