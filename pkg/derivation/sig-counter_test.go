package derivation

import (
	"testing"
)

func TestSigCounter_String(t *testing.T) {
	type fields struct {
		code   string
		count  uint16
		length int
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name:    "test 1",
			fields:  fields{code: SigCountCodeBase64, count: 1, length: 2},
			want:    "-AAB",
			wantErr: false,
		},
		{
			name:    "test 2",
			fields:  fields{code: SigCountCodeBase64, count: 2, length: 2},
			want:    "-AAC",
			wantErr: false,
		},
		{
			name:    "test 3",
			fields:  fields{code: SigCountCodeBase64, count: 3, length: 2},
			want:    "-AAD",
			wantErr: false,
		},
		{
			name:    "test 256",
			fields:  fields{code: SigCountCodeBase64, count: 256, length: 2},
			want:    "-AEA",
			wantErr: false,
		},
		{
			name:    "test 5000",
			fields:  fields{code: SigCountCodeBase64, count: 5000, length: 2},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &SigCounter{
				code:   tt.fields.code,
				count:  tt.fields.count,
				length: tt.fields.length,
			}
			got, err := r.String()
			if (err != nil) != tt.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("String() got = %v, want %v", got, tt.want)
			}
		})
	}
}
