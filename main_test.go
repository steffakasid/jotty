package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainFunction(t *testing.T) {

	// Backup and restore original os.Args and os.Stdout
	origArgs := os.Args
	origStdout := os.Stdout
	defer func() {
		os.Args = origArgs
		os.Stdout = origStdout
	}()

	// Create a pipe to capture stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Create a buffer to read the output
	var buf bytes.Buffer
	done := make(chan bool)
	go func() {
		_, err := io.Copy(&buf, r)
		require.NoError(t, err)
		done <- true
	}()

	// Set up test arguments
	os.Args = []string{"jotty", "--version"}

	// Call the main function
	main()

	// Close the writer and wait for the goroutine to finish
	w.Close()
	<-done

	// Check the output
	expectedOutput := "jotty version: 1.0.0\n" // Replace with the expected version output
	assert.Contains(t, buf.String(), expectedOutput)
}

func TestCheckError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		loggerFunc func(format string, args ...interface{})
		wantErr    bool
	}{
		{
			name: "No error",
			err:  nil,
			loggerFunc: func(format string, args ...interface{}) {
				t.Errorf(format, args...)
			},
			wantErr: false,
		},
		{
			name: "With error",
			err:  errors.New("test error"),
			loggerFunc: func(format string, args ...interface{}) {
				t.Errorf(format, args...)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := CheckError(tt.err, tt.loggerFunc)
			assert.Equal(t, tt.wantErr, gotErr)
		})
	}
}
