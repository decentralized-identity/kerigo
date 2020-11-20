package derivation

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testCase struct {
	rawData            []byte
	code               Code
	codePrefix         string
	derivedEncodedData string
	isBasic            bool
	isSelfAddressing   bool
	isSelfSigning      bool
}

var selfAddressingData = []byte(`{"vs":"KERI10JSON0000fb_","pre":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}`)

var tests = []testCase{
	{
		rawData:            selfAddressingData,
		code:               Blake2b256,
		codePrefix:         "F",
		derivedEncodedData: "8U-qx8WrArOojkGYplBNKOpJvv6EpfERwAOX1MzWiQU",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
	{
		rawData:            selfAddressingData,
		code:               Blake2b512,
		codePrefix:         "0F",
		derivedEncodedData: "Suq8NLKt-3-_RyufsFEWz233bZHv1t5Wuvk9sgNonKg9uj84tIc8MYSyJrV4ekkXLmVr9fS_5feDLdcJHlvp_w",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
	{
		rawData:            selfAddressingData,
		code:               Blake2s256,
		codePrefix:         "G",
		derivedEncodedData: "RlKwWtXkr6-ZUqZqJP0j77_nadOWc0fOChqLgaFMH28",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
	{
		rawData:            selfAddressingData,
		code:               Blake3256,
		codePrefix:         "E",
		derivedEncodedData: "ixO2SBNow3tYDfYX6NRt1O9ZSMx2IsBeWkh8YJRp5VI",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
	{
		rawData:            selfAddressingData,
		code:               Blake3512,
		codePrefix:         "0D",
		derivedEncodedData: "ixO2SBNow3tYDfYX6NRt1O9ZSMx2IsBeWkh8YJRp5VL8Vexq3aW_c7fghG3ElPkIALFlJHkQ0qZbz8Okny6FRw",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
	{
		rawData:            selfAddressingData,
		code:               SHA3256,
		codePrefix:         "H",
		derivedEncodedData: "rSgv0xSxOZNJnmhhydXGZn5hqwf4gCtxXd3-gtYsc-U",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
	{
		rawData:            selfAddressingData,
		code:               SHA3512,
		codePrefix:         "0E",
		derivedEncodedData: "ZB9X5wwz4-nMVSR3dqdvD3gW9FJ3WH0zUMW4aouv6niwO_fff-rY4rLoDZJEjz9QVeaNYe4R5xkVy27EOmCEgQ",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
	{
		rawData:            selfAddressingData,
		code:               SHA2256,
		codePrefix:         "I",
		derivedEncodedData: "7g54GlHtcHXJ0kHTWcyvrg1ESABze2hw0-Ozj2biMxI",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
	{
		rawData:            selfAddressingData,
		code:               SHA2512,
		codePrefix:         "0G",
		derivedEncodedData: "cOLn-6qNximYELEuxph-4mhjhQJR-3OtsCDXUu3qMft8yAYVb0kaZhLx58msABi8tREqnYDubZ0uLEvDGdChjg",
		isBasic:            false,
		isSelfAddressing:   true,
		isSelfSigning:      false,
	},
}

func TestBasicDerivations(t *testing.T) {
	assert := assert.New(t)
	basicData := make([]byte, 32)
	read, err := rand.Read(basicData)
	assert.Nil(err)
	assert.Equal(32, read)

	d, err := New(WithCode(Ed25519NT))
	if !assert.Nil(err) {
		return
	}
	assert.True(d.Code.Basic())
	assert.Equal("B", d.Code.String())
	derived, err := d.Derive(basicData)
	assert.Nil(err)
	assert.Equal(basicData, derived)

	d, err = New(WithCode(Ed25519))
	if !assert.Nil(err) {
		return
	}
	assert.True(d.Code.Basic())
	assert.Equal("D", d.Code.String())
	derived, err = d.Derive(basicData)
	assert.Nil(err)
	assert.Equal(basicData, derived)
}

func TestDerivations(t *testing.T) {
	assert := assert.New(t)

	for _, test := range tests {
		d, err := New(WithCode(test.code))
		if !assert.Nil(err) {
			continue
		}
		assert.Equal(test.codePrefix, d.Code.String())

		derived, err := d.Derive(test.rawData)
		if !assert.Nil(err) {
			continue
		}

		encodedDerived := base64.RawURLEncoding.EncodeToString(derived)
		assert.Equal(test.derivedEncodedData, encodedDerived)
		assert.Equal(test.isBasic, d.Code.Basic())
		assert.Equal(test.isSelfAddressing, d.Code.SelfAddressing())
		assert.Equal(test.isSelfSigning, d.Code.SelfSigning())
	}
}

func TestSelfAddressing(t *testing.T) {
	assert := assert.New(t)

	d, err := New(WithCode(Ed25519Sig))
	assert.Nil(err)

	// make sure we error if we don't provide a signer
	_, err = d.Derive([]byte(`asdf`))
	assert.NotNil(err)

	d, err = New(WithCode(Ed25519Sig), WithSigner(func(data []byte) ([]byte, error) { return data, nil }))
	assert.Nil(err)

	derived, err := d.Derive([]byte(`asdf`))
	assert.Nil(err)
	assert.Equal([]byte(`asdf`), derived)
}

func TestFromString(t *testing.T) {
	assert := assert.New(t)

	blake3 := []byte(`Ftq3upkY_KoTFc0dJaZ_QRmU1Eb5-kEpcqHoGhzeSCk0`)
	d, err := FromPrefix(string(blake3))
	assert.Nil(err)
	assert.Equal(blake3, []byte(d.AsPrefix()))
}

// func TestConvertion(t *testing.T) {
// 	// assert := assert.New(t)

// 	// prefixes := []map[string]string{
// 	// 	{"basic": "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
// 	// 		"expected": "EmB26yMzroICh-opKNdkYyP000kwevU18WQI95JaJDjY",
// 	// 	},
// 	// 	{
// 	// 		"basic":    "BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk",
// 	// 		"expected": "EO4CXp8gs0yJg1fFhJLs5hH6neqJwhFEY7vrJEdPe87I",
// 	// 	},
// 	// 	{
// 	// 		"basic":    "B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw",
// 	// 		"expected": "ELWWZEyBpjrfM1UU0n31KIyIXllrCoLEOI5UHD9x7WxI",
// 	// 	},
// 	// }

// 	// for _, p := range prefixes {
// 	// 	b, err := FromPrefix(p["basic"])
// 	// 	if !assert.Nil(err) {
// 	// 		continue
// 	// 	}
// 	// 	assert.True(b.Code.Basic())
// 	// 	sa, _ := New(WithCode(Blake3256))
// 	// 	_, err = sa.Derive(b.Raw)
// 	// 	assert.Nil(err)
// 	// 	assert.Equal(p["expected"], sa.AsPrefix())
// 	// }
// }

func TestBase64IndexConverstion(t *testing.T) {
	assert := assert.New(t)

	_, err := IndexToBase64(4096)
	assert.NotNil(err)

	_, err = Base64ToIndex("ASDF")
	assert.NotNil(err)

	b64, err := IndexToBase64(1)
	assert.Nil(err)
	assert.Len(b64, 1)
	assert.Equal("B", b64)

	indexInt, err := Base64ToIndex(b64)
	assert.Nil(err)
	assert.Equal(uint16(1), indexInt)

	b64, err = IndexToBase64(63)
	assert.Nil(err)
	assert.Len(b64, 1)
	assert.Equal("_", b64)

	indexInt, err = Base64ToIndex(b64)
	assert.Nil(err)
	assert.Equal(uint16(63), indexInt)

	b64, err = IndexToBase64(256)
	assert.Nil(err)
	assert.Len(b64, 2)
	assert.Equal("EA", b64)

	indexInt, err = Base64ToIndex(b64)
	assert.Nil(err)
	assert.Equal(uint16(256), indexInt)

	b64, err = IndexToBase64(4095)
	assert.Nil(err)
	assert.Len(b64, 2)
	assert.Equal("__", b64)

	indexInt, err = Base64ToIndex(b64)
	assert.Nil(err)
	assert.Equal(uint16(4095), indexInt)
}

func TestParseSignatureCount(t *testing.T) {
	assert := assert.New(t)

	_, err := ParseSignatureCount("noway")
	assert.NotNil(err)

	_, err = ParseSignatureCount("nono")
	assert.NotNil(err)

	count, err := ParseSignatureCount("-AAA")
	assert.Nil(err)
	assert.Equal(uint16(0), count)

	count, err = ParseSignatureCount("-AAB")
	assert.Nil(err)
	assert.Equal(uint16(1), count)

	count, err = ParseSignatureCount("-AEA")
	assert.Nil(err)
	assert.Equal(uint16(256), count)

	count, err = ParseSignatureCount("-A__")
	assert.Nil(err)
	assert.Equal(uint16(4095), count)

}

func TestFromAttachedSignature(t *testing.T) {
	assert := assert.New(t)

	attachedED25519 := "ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	attachedEcDSA := "BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	_, err := FromAttachedSignature("asdf")
	assert.NotNil(err)

	d, err := FromAttachedSignature(attachedED25519)
	assert.Nil(err)
	assert.Equal(uint16(1), d.KeyIndex)
	assert.Equal(d.Code, Ed25519Attached)

	d, err = FromAttachedSignature(attachedEcDSA)
	assert.Nil(err)
	assert.Equal(uint16(2), d.KeyIndex)
	assert.Equal(d.Code, EcDSAAttached)
}

func TestParseAttachedSignatures(t *testing.T) {
	assert := assert.New(t)
	sigString := []byte("-AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	ders, extra, err := ParseAttachedSignatures(sigString)
	assert.Nil(err)
	assert.Empty(extra)
	if assert.Len(ders, 1) {
		assert.Equal(uint16(0), ders[0].KeyIndex)
	}

	sigString = []byte("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	ders, extra, err = ParseAttachedSignatures(sigString)
	assert.Nil(err)
	assert.Empty(extra)
	if assert.Len(ders, 2) {
		assert.Equal(uint16(0), ders[0].KeyIndex)
		assert.Equal(uint16(1), ders[1].KeyIndex)
	}

	// Correctly return extra bytes
	sigString = []byte("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsome extra data at the end")
	ders, extra, err = ParseAttachedSignatures(sigString)
	assert.Nil(err)
	if assert.NotEmpty(extra) {
		assert.Equal("some extra data at the end", string(extra))
	}
	assert.Len(ders, 2)

	// Invalid derivation code for 3rd sig
	sigString = []byte("-AADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsome extra data at the end")
	_, _, err = ParseAttachedSignatures(sigString)
	assert.NotNil(err)

	// Valid derivation for 3 sig, but invalid data length
	sigString = []byte("-AADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAA")
	_, _, err = ParseAttachedSignatures(sigString)
	assert.NotNil(err)
}
