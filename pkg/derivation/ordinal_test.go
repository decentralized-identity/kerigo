package derivation

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewOrdinal(t *testing.T) {
	type args struct {
		val int
	}

	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "4",
			args: args{4},
			want: []byte("0AAAAAAAAAAAAAAAAAAAAABA"),
		},
		{
			name: "12",
			args: args{12},
			want: []byte("0AAAAAAAAAAAAAAAAAAAAADA"),
		},
		{
			name: "256",
			args: args{256},
			want: []byte("0AAAAAAAAAAAAAAAAAAAABAA"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewOrdinal(uint16(tt.args.val))
			b64 := o.Base64()

			assert.Equal(t, b64, tt.want)

			r := bytes.NewReader(b64)

			o, err := ParseOrdinal(r)
			assert.NoError(t, err)
			assert.Equal(t, tt.args.val, o.Num())
		})
	}
}
