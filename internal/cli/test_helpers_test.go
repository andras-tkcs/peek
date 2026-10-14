package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func setTestConfigHome(t *testing.T) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
}

func configureTestClient(t *testing.T, host string) {
	t.Helper()
	setTestConfigHome(t)
	t.Setenv("PEEK_HOST", host)
	t.Setenv("PEEK_TOKEN", "test-token")
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}

	readDone := make(chan struct {
		out string
		err error
	}, 1)
	go func() {
		data, err := io.ReadAll(r)
		readDone <- struct {
			out string
			err error
		}{out: string(data), err: err}
	}()

	os.Stdout = w
	runErr := fn()
	os.Stdout = old

	if err := w.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	result := <-readDone
	if err := r.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	if result.err != nil {
		t.Fatalf("read captured stdout: %v", result.err)
	}
	return result.out, runErr
}

func captureStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	readDone := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r)
		readDone <- data
	}()

	os.Stderr = w
	runErr := fn()
	os.Stderr = old

	if err := w.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	out := <-readDone
	_ = r.Close()
	return string(out), runErr
}
