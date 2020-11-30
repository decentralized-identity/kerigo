package prefix

import (
	"encoding/base64"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

type base struct {
	derivation *derivation.Derivation // the derivation
}

func (b *base) String() string {
	return string(append([]byte(b.derivation.Code.String()), base64.RawURLEncoding.EncodeToString(b.derivation.Raw)...))
}

func (b *base) Derivation() *derivation.Derivation {
	return b.derivation
}

func (b *base) Raw() []byte {
	return b.derivation.Raw
}
