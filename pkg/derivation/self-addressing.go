package derivation

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
	"lukechampine.com/blake3"
)

func selfAddressingDeriver(c Code) (d deriver) {
	switch c {
	case Blake3256:
		d = func(data []byte) ([]byte, error) {
			hash := blake3.Sum256(data)
			return hash[:], nil
		}
	case Blake3512:
		d = func(data []byte) ([]byte, error) {
			hash := blake3.Sum512(data)
			return hash[:], nil
		}
	case Blake2b256:
		d = func(data []byte) ([]byte, error) {
			hash := blake2b.Sum256(data)
			return hash[:], nil
		}
	case Blake2b512:
		d = func(data []byte) ([]byte, error) {
			hash := blake2b.Sum512(data)
			return hash[:], nil
		}
	case Blake2s256:
		d = func(data []byte) ([]byte, error) {
			hash := blake2s.Sum256(data)
			return hash[:], nil
		}
	case SHA3256:
		d = func(data []byte) ([]byte, error) {
			hash := sha3.Sum256(data)
			return hash[:], nil
		}
	case SHA3512:
		d = func(data []byte) ([]byte, error) {
			hash := sha3.Sum512(data)
			return hash[:], nil
		}
	case SHA2256:
		d = func(data []byte) ([]byte, error) {
			hash := sha256.Sum256(data)
			return hash[:], nil
		}
	case SHA2512:
		d = func(data []byte) ([]byte, error) {
			hash := sha512.Sum512(data)
			return hash[:], nil
		}
	}

	return
}
