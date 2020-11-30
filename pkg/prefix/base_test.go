package prefix

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/stretchr/testify/assert"
)

// TODO: need to get test vectors to run against
func TestBase(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 32)
	int, err := rand.Read(data)
	assert.Equal(32, int)
	assert.Nil(err)

	der, err := derivation.New(derivation.WithCode(derivation.Ed25519NT), derivation.WithRaw(data))
	if !assert.Nil(err) {
		return
	}

	bp := New(der)

	// stored the key correctly
	assert.Equal(data, bp.Raw())

	// Generate the AID correctly
	aid := bp.String()
	assert.Len(aid, 44)
	assert.Equal(aid[:1], "B")

	// parse correctly
	bpn, err := FromString(aid)
	assert.Nil(err)
	assert.Equal(data, bpn.Raw())

	//
	// self-addressing derivation
	//
	der, err = derivation.New(derivation.WithCode(derivation.Blake2b256), derivation.WithRaw(data))
	assert.Nil(err)
	sap := New(der)

	// // Generate the AID correctly
	sapaid := sap.String()
	fmt.Println(sapaid)
	assert.Len(sapaid, 44)
	assert.Equal(sapaid[:1], "F")

	// parse correctly
	sapn, err := FromString(sapaid)
	assert.Nil(err)
	sapaidn := sapn.String()
	assert.Equal(sapaidn, sapaid)
}
