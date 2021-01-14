package event

import (
	"fmt"
	"testing"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/stretchr/testify/assert"
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
		Version:                       "KERI10JSON0000fb_",
		Prefix:                        "ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo",
		EventType:                     "icp",
		Sequence:                      "0",
		SigningThreshold:              "1",
		AccountableDuplicityThreshold: "0",
		Keys:                          []string{"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"},
		Next:                          "EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4",
		Config:                        []prefix.Trait{},
		Witnesses:                     []string{},
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
