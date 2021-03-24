package derivation

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
)

type Ordinal struct {
	num uint16
}

func NewOrdinal(val uint16) *Ordinal {
	return &Ordinal{num: val}
}

func (r *Ordinal) Base64() []byte {
	sint := new(big.Int)
	sint.SetUint64(uint64(r.num))

	buf := make([]byte, 16)
	b := sint.Bytes()
	copy(buf[16-len(b):], b)

	dst := make([]byte, RandomSeed128.PrefixBase64Length())
	base64.URLEncoding.Encode(dst, buf)

	code := RandomSeed128.String()
	out := append([]byte(code), dst[:len(dst)-len(code)]...)

	return out
}

func (r *Ordinal) Num() int {
	return int(r.num)
}

func ParseOrdinal(r io.Reader) (*Ordinal, error) {

	b64len := RandomSeed128.PrefixBase64Length()
	buf := make([]byte, b64len)

	c, err := r.Read(buf)
	if err != nil {
		return nil, err
	}

	code := RandomSeed128.String()
	if c != b64len || string(buf[:len(code)]) != code {
		return nil, errors.New(fmt.Sprint("invalid ordinal", " ", string(buf), " ", c))
	}

	dlen := RandomSeed128.PrefixDataLength()
	dst := make([]byte, dlen-2)

	b64 := append(buf[len(code):], []byte("==")...)

	_, err = base64.URLEncoding.Decode(dst, b64)
	if err != nil {
		return nil, err
	}

	sint := new(big.Int)
	sint.SetBytes(dst)

	return NewOrdinal(uint16(sint.Uint64())), nil
}
