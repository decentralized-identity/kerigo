package derivation

import (
	"testing"
)

func TestSigCounter_String(t *testing.T) {
	type fields struct {
		code   CountCode
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
			fields:  fields{code: ControllerSigCountCode, count: 1, length: 2},
			want:    "-AAB",
			wantErr: false,
		},
		{
			name:    "test 2",
			fields:  fields{code: ControllerSigCountCode, count: 2, length: 2},
			want:    "-AAC",
			wantErr: false,
		},
		{
			name:    "test 3",
			fields:  fields{code: ControllerSigCountCode, count: 3, length: 2},
			want:    "-AAD",
			wantErr: false,
		},
		{
			name:    "test 256",
			fields:  fields{code: ControllerSigCountCode, count: 256, length: 2},
			want:    "-AEA",
			wantErr: false,
		},
		{
			name:    "test 5000",
			fields:  fields{code: ControllerSigCountCode, count: 5000, length: 2},
			want:    "",
			wantErr: true,
		},
		{
			name:    "transferable test 1",
			fields:  fields{code: TransferableRctCountCode, count: 1, length: 2},
			want:    "-DAB",
			wantErr: false,
		},
		{
			name:    "transferable test 2",
			fields:  fields{code: TransferableRctCountCode, count: 2, length: 2},
			want:    "-DAC",
			wantErr: false,
		},
		{
			name:    "transferable test 256",
			fields:  fields{code: TransferableRctCountCode, count: 256, length: 2},
			want:    "-DEA",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Counter{
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
