package internal

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadData(t *testing.T) {
	path := path.Join(t.TempDir(), "tmpfile")
	err := os.WriteFile(path, []byte("Some data"), 0770)
	assert.NoError(t, err)

	os.Stdin, err = os.Open(path)
	assert.NoError(t, err)

	type args struct {
		file string
	}
	tests := []struct {
		name     string
		args     args
		wantData []byte
		wantErr  bool
	}{
		{
			name:     "Read from file",
			args:     args{file: path},
			wantData: []byte("Some data"),
			wantErr:  false,
		},
		{
			name:    "Get an error",
			args:    args{file: "/tmp/doesntexists"},
			wantErr: true,
		},
		{
			name:     "Read from stdin",
			args:     args{file: "-"},
			wantData: []byte("Some data"),
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, err := ReadData(tt.args.file)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantData, gotData)
			}
		})
	}
}
