package event

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
)

func TestFormatFromVersion(t *testing.T) {
	assert := assert.New(t)

	f, err := FormatFromVersion(VersionString(JSON, "10", 123))
	assert.Nil(err)
	assert.Equal(JSON, f)

	f, err = FormatFromVersion("KERI10JSON")
	assert.Nil(err)
	assert.Equal(JSON, f)

	f, err = FormatFromVersion(VersionString(CBOR, "10", 123))
	assert.Nil(err)
	assert.Equal(CBOR, f)

	f, err = FormatFromVersion("KERI10CBOR")
	assert.Nil(err)
	assert.Equal(CBOR, f)

	f, err = FormatFromVersion(VersionString(MSGPK, "10", 123))
	assert.Nil(err)
	assert.Equal(MSGPK, f)

	f, err = FormatFromVersion("KERI10MSGPK")
	assert.Nil(err)
	assert.Equal(MSGPK, f)

	f, err = FormatFromVersion("KERI10PROTO")
	assert.NotNil(err)
	assert.Equal(FORMAT(-1), f)
}

func TestVersionString(t *testing.T) {
	assert := assert.New(t)

	vs := VersionString(JSON, "10", 123)
	assert.Equal("KERI10JSON00007b_", vs)

	vs = VersionString(CBOR, "10", 123)
	assert.Equal("KERI10CBOR00007b_", vs)

	vs = VersionString(MSGPK, "10", 123)
	assert.Equal("KERI10MSGPK00007b_", vs)
}

func TestSerialize(t *testing.T) {
	assert := assert.New(t)

	//JSON
	expected := []byte(`{"v":"KERI10JSON0000fb_","i":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","wt":"0","w":[],"c":[]}`)

	e := &Event{
		Version:          "KERI10JSON0000fb_",
		Prefix:           "ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo",
		EventType:        "icp",
		Sequence:         "0",
		SigThreshold:     &SigThreshold{conditions: [][]*big.Rat{{big.NewRat(1, 1)}}},
		WitnessThreshold: "0",
		Keys:             []string{"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"},
		Next:             "EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4",
		Config:           []prefix.Trait{},
		Witnesses:        []string{},
	}

	jsonSer, err := Serialize(e, JSON)
	assert.Nil(err)
	assert.Equal(expected, jsonSer)

	jsonSer, err = e.Serialize()
	assert.Nil(err)
	assert.Equal(expected, jsonSer)

}

func TestDigest(t *testing.T) {
	assert := assert.New(t)

	//JSON
	data := []byte(`{"v":"KERI10JSON0000fb_","i":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","wt":"0","w":[],"c":[]}`)
	expectedString := "ErgY910xsF3NSLGH4Yl6O9oEkdxj0FOujnHTD8W5V_AI"
	expectedBytes := []byte{174, 6, 61, 215, 76, 108, 23, 115, 82, 44, 97, 248, 98, 94, 142, 246, 129, 36, 119, 24, 244, 20, 235, 163, 156, 116, 195, 241, 110, 85, 252, 2}

	digestBytes, err := Digest(data, derivation.Blake3256)
	assert.Nil(err)
	assert.Equal(expectedBytes, digestBytes)

	digestString, err := DigestString(data, derivation.Blake3256)
	assert.Nil(err)
	assert.Equal(expectedString, digestString)
}

func TestSequenceInt(t *testing.T) {
	assert := assert.New(t)

	e := Event{Sequence: "0"}
	assert.Equal(0, e.SequenceInt())

	e.Sequence = fmt.Sprintf("%x", 93840482)
	assert.Equal(93840482, e.SequenceInt())
}

func TestNextDigest(t *testing.T) {
	assert := assert.New(t)
	d1, _ := derivation.FromPrefix("BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE")
	d1p := prefix.New(d1)
	d2, _ := derivation.FromPrefix("BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk")
	d2p := prefix.New(d2)
	d3, _ := derivation.FromPrefix("B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw")
	d3p := prefix.New(d3)

	evnt, _ := NewEvent(WithType(ROT), WithKeys(d1p, d2p, d3p), WithThreshold(2), WithSequence(2))

	next, err := NextDigest("2", derivation.Blake3256, d1p, d2p, d3p)
	assert.Nil(err)
	assert.Equal("ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs", next)

	next, err = evnt.NextDigest(derivation.Blake3256)
	assert.Nil(err)
	assert.Equal("ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs", next)

	next, err = NextDigest("1/2,1/2&1&1/4,1/4,1/4,1/4", derivation.Blake3256, d1p, d2p, d3p)
	assert.Nil(err)
	assert.Equal("EO5zVmvz-0yt1PlNvIG0iI-8X6qmkGwt-sQfcQ1GvmRc", next)

	evnt.SigThreshold, _ = NewMultiWeighted([]string{"1/2", "1/2"}, []string{"1"}, []string{"1/4", "1/4", "1/4", "1/4"})
	next, err = evnt.NextDigest(derivation.Blake3256)
	assert.Nil(err)
	assert.Equal("EO5zVmvz-0yt1PlNvIG0iI-8X6qmkGwt-sQfcQ1GvmRc", next)

	//test case from Bob demo in python
	der, err := derivation.FromPrefix("A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q")
	assert.NoError(err)
	edPriv := ed25519.NewKeyFromSeed(der.Raw)
	edPub := edPriv.Public()

	basicDerivation, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub.(ed25519.PublicKey)))
	assert.Nil(err)
	basicPre := prefix.New(basicDerivation)

	next, err = NextDigest("1", derivation.Blake3256, basicPre)
	assert.NoError(err)
	assert.Equal("EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU", next)

}
