package pkg

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/log"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/decentralized-identity/kerigo/pkg/version"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	assert := assert.New(t)

	// ed25519
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if !assert.Nil(err) {
		return
	}

	basicDerivation, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub))
	assert.Nil(err)

	basicPre := prefix.New(basicDerivation)

	icp, err := event.NewInceptionEvent(event.WithKeys(basicPre))
	assert.Nil(err)

	// create a self-addressing prefix for this

	// Serialize with defaults to get correct length for version string
	icp.Prefix = derivation.Blake2b256.Default()
	icp.Version = event.DefaultVersionString(event.JSON)
	eventBytes, err := event.Serialize(icp, event.JSON)
	assert.Nil(err)
	eventBytesExpected := len(eventBytes)

	//Generate correct version string
	icp.Version = event.VersionString(event.JSON, version.Code(), len(eventBytes))

	// Serialize without the prefix for hasing
	icp.Prefix = ""
	eventBytes, err = event.Serialize(icp, event.JSON)
	assert.Nil(err)

	// Create the selfAddresing prefix
	saDerivation, err := derivation.New(derivation.WithCode(derivation.Blake2b256))
	assert.Nil(err)

	_, err = saDerivation.Derive(eventBytes)
	assert.Nil(err)

	selfAdd := prefix.New(saDerivation)
	assert.Nil(err)
	selfAddAID := selfAdd.String()
	assert.Nil(err)

	// Set as the prefix for the inception event
	icp.Prefix = selfAddAID

	eventBytes, err = event.Serialize(icp, event.JSON)
	assert.Nil(err)

	// This should be the same length as was calculated for the version string
	assert.Equal(eventBytesExpected, len(eventBytes))
}

func TestLog(t *testing.T) {
	assert := assert.New(t)

	// events taken from keripy demo_sam
	msg := []byte(`{"vs":"KERI10JSON0000fb_","pre":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}`)
	e := &event.Event{}
	err := json.Unmarshal(msg, e)
	assert.Nil(err)

	sig := []byte(`-AABAAtf0OqrkGmK3vdMcS5E3mLxeFh14SbvCNjZnZrxAazgYTemZc1S-Pr0ge9IQuHesmh8cJncRkef1PgxFavDKqDQ`)
	d, extra, err := derivation.ParseAttachedSignatures(sig)
	assert.Nil(err)
	assert.Empty(extra)
	assert.Len(d, 1)

	keyD, err := e.KeyDerivation(0)
	assert.Nil(err)

	assert.True(ed25519.Verify(keyD.Raw, msg, d[0].Raw))

	l := &log.Log{}
	err = l.Apply(e)
	assert.Nil(err)

	nxt := []byte(`{"vs":"KERI10JSON0000a3_","pre":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","sn":"1","ilk":"ixn","dig":"EixO2SBNow3tYDfYX6NRt1O9ZSMx2IsBeWkh8YJRp5VI","data":[]}`)
	e = &event.Event{}
	err = json.Unmarshal(nxt, e)
	assert.Nil(err)

	err = l.Apply(e)
	assert.Nil(err)
}
