package event

import (
	"fmt"
	"testing"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
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
	expected := []byte(`{"vs":"KERI10JSON0000fb_","pre":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}`)

	e := &Event{
		Version:                       "KERI10JSON0000fb_",
		Prefix:                        "ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo",
		EventType:                     "icp",
		Sequence:                      "0",
		SigningThreshold:              "1",
		AccountableDuplicityThreshold: "0",
		Keys:                          []string{"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"},
		Next:                          "EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4",
		Config:                        []interface{}{},
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
	data := []byte(`{"vs":"KERI10JSON0000fb_","pre":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}`)
	expectedString := "EixO2SBNow3tYDfYX6NRt1O9ZSMx2IsBeWkh8YJRp5VI"
	expectedBytes := []byte{139, 19, 182, 72, 19, 104, 195, 123, 88, 13, 246, 23, 232, 212, 109, 212, 239, 89, 72, 204, 118, 34, 192, 94, 90, 72, 124, 96, 148, 105, 229, 82}

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
