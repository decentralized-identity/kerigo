package derivation

import "strings"

type Code int

// Code constants represent the available hashing and encryptions algorithms for
// the derivations.
const (
	Ed25519Seed Code = iota
	Ed25519NT
	X25519
	Ed25519
	Blake3256
	Blake2b256
	Blake2s256
	SHA3256
	SHA2256
	RandomSeed128
	Ed25519Sig
	EcDSASig
	Blake3512
	SHA3512
	Blake2b512
	SHA2512
)

var (
	codeValue = map[string]Code{
		"A":  Ed25519Seed,
		"B":  Ed25519NT,
		"C":  X25519,
		"D":  Ed25519,
		"E":  Blake3256,
		"F":  Blake2b256,
		"G":  Blake2s256,
		"H":  SHA3256,
		"I":  SHA2256,
		"0A": RandomSeed128,
		"0B": Ed25519Sig,
		"0C": EcDSASig,
		"0D": Blake3512,
		"0E": SHA3512,
		"0F": Blake2b512,
		"0G": SHA2512,
	}

	codeString = map[Code]string{
		Ed25519Seed:   "A",
		Ed25519NT:     "B",
		X25519:        "C",
		Ed25519:       "D",
		Blake3256:     "E",
		Blake2b256:    "F",
		Blake2s256:    "G",
		SHA3256:       "H",
		SHA2256:       "I",
		RandomSeed128: "0A",
		Ed25519Sig:    "0B",
		EcDSASig:      "0C",
		Blake3512:     "0D",
		SHA3512:       "0E",
		Blake2b512:    "0F",
		SHA2512:       "0G",
	}

	codeName = map[Code]string{
		Ed25519Seed:   "Ed25519Seed",
		Ed25519NT:     "Ed25519NT",
		X25519:        "X25519",
		Ed25519:       "Ed25519",
		Blake3256:     "Blake3256",
		Blake2b256:    "Blake2b256",
		Blake2s256:    "Blake2s256",
		SHA3256:       "SHA3256",
		SHA2256:       "SHA2256",
		RandomSeed128: "RandomSeed128",
		Ed25519Sig:    "Ed25519Sig",
		EcDSASig:      "EcDSASig",
		Blake3512:     "Blake3512",
		SHA3512:       "SHA3512",
		Blake2b512:    "Blake2b512",
		SHA2512:       "SHA2512",
	}

	codeDataLength = map[Code]int{
		Ed25519Seed:   32,
		Ed25519NT:     32,
		X25519:        32,
		Ed25519:       32,
		Blake3256:     32,
		Blake2b256:    32,
		Blake2s256:    32,
		SHA3256:       32,
		SHA2256:       32,
		RandomSeed128: 16,
		Ed25519Sig:    64,
		EcDSASig:      64,
		Blake3512:     64,
		SHA3512:       64,
		Blake2b512:    64,
		SHA2512:       64,
	}

	codePrefixBase64Length = map[Code]int{
		Ed25519Seed:   44,
		Ed25519NT:     44,
		X25519:        44,
		Ed25519:       44,
		Blake3256:     44,
		Blake2b256:    44,
		Blake2s256:    44,
		SHA3256:       44,
		SHA2256:       44,
		RandomSeed128: 24,
		Ed25519Sig:    88,
		EcDSASig:      88,
		Blake3512:     88,
		SHA3512:       88,
		Blake2b512:    88,
		SHA2512:       88,
	}

	codePrefixDataLength = map[Code]int{
		Ed25519Seed:   33,
		Ed25519NT:     33,
		X25519:        33,
		Ed25519:       33,
		Blake3256:     33,
		Blake2b256:    33,
		Blake2s256:    33,
		SHA3256:       33,
		SHA2256:       33,
		RandomSeed128: 18,
		Ed25519Sig:    66,
		EcDSASig:      66,
		Blake3512:     66,
		SHA3512:       66,
		Blake2b512:    66,
		SHA2512:       66,
	}
)

// String returns the 1, 2 or 4 character representation of the encoding.
// This code string should be pre-pended to a base64 representation of
// the derived data to make it self-describing
func (c Code) String() string {
	return codeString[c]
}

// Length of the code representing the derivation (1, 2 or 4)
func (c Code) Length() int {
	return len(c.String())
}

// DataLength of the derived data
func (c Code) DataLength() int {
	return codeDataLength[c]
}

// PrefixBase64Lenghth of the derived data after it has been
// bsae64 encoded and the appropriate code has be prepended
func (c Code) PrefixBase64Length() int {
	return codePrefixBase64Length[c]
}

// PrefixDataLength of the data with the code prepended
func (c Code) PrefixDataLength() int {
	return codePrefixDataLength[c]
}

// Human readable name of the underlying algorithim
// used in the derivation
func (c Code) Name() string {
	return codeName[c]
}

// Default derivation data: used for calculating total data length
// in some KERI functions
func (c Code) Default() string {
	return string(append([]byte(c.String()), []byte(strings.Repeat("A", c.PrefixBase64Length()-len(c.String())))...))
}

// SelfAdressing derivaitons
func (c Code) SelfAddressing() bool {
	switch c {
	case Blake3256, Blake3512, Blake2b256, Blake2b512, Blake2s256, SHA2256, SHA2512, SHA3256, SHA3512:
		return true
	}
	return false
}

// SelfSigning derivaitons
func (c Code) SelfSigning() bool {
	switch c {
	case Ed25519Sig:
		return true
	}
	return false
}

// Basic derivations
func (c Code) Basic() bool {
	switch c {
	case Ed25519NT, Ed25519:
		return true
	}
	return false
}
