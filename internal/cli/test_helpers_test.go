package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
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

// withStdin replaces os.Stdin with a temp file holding input and restores the
// original in t.Cleanup.
func withStdin(t *testing.T, input string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write stdin file: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open stdin file: %v", err)
	}
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = old
		_ = f.Close()
	})
}

// breakSaveConfig makes SaveConfig fail while LoadConfig still succeeds: the
// config file is a dangling symlink, so reads see "not exist" and writes fail.
func breakSaveConfig(t *testing.T) {
	t.Helper()

	p, err := configPath()
	if err != nil {
		t.Fatalf("configPath: %v", err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing", "config.json"), p); err != nil {
		t.Fatalf("symlink config: %v", err)
	}
}

// closedServerURL returns the URL of an httptest server that has been closed.
func closedServerURL(t *testing.T) string {
	t.Helper()

	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL
	ts.Close()
	return url
}

// jsonServer serves body with the given status on every path.
func jsonServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts
}
