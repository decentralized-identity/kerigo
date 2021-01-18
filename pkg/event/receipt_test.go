package event

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/decentralized-identity/kerigo/pkg/version"
)

func TestTransferable(t *testing.T) {
	remoteSecret := "ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc"
	remoteNext := "A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q"
	localSecret := "AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw"
	localNext := "AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ"

	remoteICP := incept(t, remoteSecret, remoteNext)
	estEvent := incept(t, localSecret, localNext)

	icpBytes := `{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}`
	expectedVRCBytes := `{"v":"KERI10JSON000105_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"vrc","d":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","a":{"i":"EmGTyV9unQ59uIQIYv6Vsc7KweyTbplfumEV-IB33bEg","s":"0","d":"E-_qFJZK8ER6rJA7W4WR2xxSwKT1RLi8yCCyZ0XHTnLU"}}`

	d, _ := json.Marshal(remoteICP)
	assert.JSONEq(t, icpBytes, string(d))

	vrc, err := TransferableReceipt(remoteICP, estEvent, derivation.Blake3256)
	assert.NoError(t, err)

	vrc.Version = DefaultVersionString(JSON)

	eventBytes, err := vrc.Serialize()
	assert.NoError(t, err)
	vrc.Version = VersionString(JSON, version.Code(), len(eventBytes))

	vrcBytes, err := vrc.Serialize()
	assert.NoError(t, err)

	//TODO:  get the seal digest of the last establishment event to match
	assert.Equal(t, len(expectedVRCBytes), len(vrcBytes))
}

func incept(t *testing.T, secret, next string) *Event {
	der, err := derivation.FromPrefix(secret)
	assert.NoError(t, err)

	edPriv := ed25519.NewKeyFromSeed(der.Raw)
	edPub := edPriv.Public()
	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub.(ed25519.PublicKey)))
	assert.NoError(t, err)
	keyPre := prefix.New(keyDer)

	nextder, err := derivation.FromPrefix(next)
	assert.NoError(t, err)

	nextPriv := ed25519.NewKeyFromSeed(nextder.Raw)
	nextPub := nextPriv.Public()
	nextPubDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(nextPub.(ed25519.PublicKey)))
	assert.NoError(t, err)

	nextKeyPre := prefix.New(nextPubDer)

	icp, err := NewInceptionEvent(WithKeys(keyPre), WithDefaultVersion(JSON), WithNext(1, derivation.Blake3256, nextKeyPre))
	assert.NoError(t, err)

	// Serialize with defaults to get correct length for version string
	icp.Prefix = derivation.Blake3256.Default()
	icp.Version = DefaultVersionString(JSON)
	eventBytes, err := Serialize(icp, JSON)
	assert.NoError(t, err)

	eventBytesExpected := len(eventBytes)
	icp.Version = VersionString(JSON, version.Code(), len(eventBytes))
	icp.Prefix = ""

	ser, err := icp.extractDataSet()

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

	eventBytes, err = Serialize(icp, JSON)
	assert.Equal(t, eventBytesExpected, len(eventBytes))

	return icp
}
