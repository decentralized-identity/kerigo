package derivation

import "errors"

// Signer function for signing self-signing derivations
// KERI does not want to access any private key data directly.
// This function can take the provided input bytes, sign it using
// the appropriate key and return the signed data.
// The Signer function has the same signature as, and will be
// used in place of, the deriver
type Signer func(raw []byte) ([]byte, error)

// Self signing derivations must provide a signer function
func selfSigningDeriver(c Code) (d deriver) {
	return func(data []byte) ([]byte, error) {
		return nil, errors.New("For self-signing derivations must provide Signer function")
	}
}
