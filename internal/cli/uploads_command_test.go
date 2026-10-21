package cli

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// covFake serves routes (URL path -> JSON body, "{}" when absent) and answers
// any path listed in failures with that status and a JSON error body.
func covFake(t *testing.T, routes map[string]string, failures map[string]int) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if status, ok := failures[r.URL.Path]; ok {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
			return
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			body = "{}"
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts
}

// covEnvFailures runs fn under a corrupt config file, with no host or token
// configured, and against a server that answers 500 to every path.
func covEnvFailures(t *testing.T, fn func() error) {
	t.Helper()

	t.Run("bad config", func(t *testing.T) {
		configureTestClient(t, "http://127.0.0.1:1")
		p, err := configPath()
		if err != nil {
			t.Fatalf("configPath: %v", err)
		}
		if err := os.MkdirAll(strings.TrimSuffix(p, "/config.json"), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		if _, err := captureStdout(t, fn); err == nil {
			t.Fatal("expected config error")
		}
	})
	t.Run("no host", func(t *testing.T) {
		setTestConfigHome(t)
		t.Setenv("PEEK_HOST", "")
		t.Setenv("PEEK_TOKEN", "")
		if _, err := captureStdout(t, fn); err == nil || !strings.Contains(err.Error(), "host not set") {
			t.Fatalf("expected host error, got %v", err)
		}
	})
	t.Run("http error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
		}))
		defer ts.Close()
		configureTestClient(t, ts.URL)
		if _, err := captureStdout(t, fn); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected boom error, got %v", err)
		}
	})
	t.Run("transport error", func(t *testing.T) {
		configureTestClient(t, closedServerURL(t))
		if _, err := captureStdout(t, fn); err == nil {
			t.Fatal("expected transport error")
		}
	})
}

func TestCovListVersionsDeleteRenameVisibilityEnvFailures(t *testing.T) {
	cases := map[string]func() error{
		"list":       func() error { return cmdList(nil) },
		"versions":   func() error { return cmdVersions([]string{"demo"}) },
		"delete":     func() error { return cmdDelete([]string{"demo"}) },
		"rename":     func() error { return cmdRename([]string{"demo", "New"}) },
		"visibility": func() error { return cmdVisibility([]string{"demo", "public"}) },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) { covEnvFailures(t, fn) })
	}
}

func TestCovListPrintsEmptyAndRows(t *testing.T) {
	ts := covFake(t, map[string]string{"/api/uploads": `[]`}, nil)
	configureTestClient(t, ts.URL)
	out, err := captureStdout(t, func() error { return cmdList(nil) })
	if err != nil || !strings.Contains(out, "no uploads yet") {
		t.Fatalf("empty list: %q %v", out, err)
	}

	ts = covFake(t, map[string]string{"/api/uploads": `[{"slug":"demo","name":"Demo page","size":2048,"visibility":"public","url":"http://x/p/demo"}]`}, nil)
	configureTestClient(t, ts.URL)
	out, err = captureStdout(t, func() error { return cmdList(nil) })
	if err != nil || !strings.Contains(out, "demo") || !strings.Contains(out, "http://x/p/demo") {
		t.Fatalf("list rows: %q %v", out, err)
	}
	if err := cmdList([]string{"extra"}); err == nil {
		t.Fatal("expected usage error")
	}
}

func TestCovVersionsDeleteRenameVisibilitySuccess(t *testing.T) {
	ts := covFake(t, map[string]string{
		"/api/uploads/demo/versions":   `[{"version":1,"size":10,"created_at":0,"url":"u1"}]`,
		"/api/uploads/demo/name":       `{"slug":"demo","url":"http://x/p/demo","name":"New name"}`,
		"/api/uploads/demo/visibility": `{"visibility":"public"}`,
	}, nil)
	configureTestClient(t, ts.URL)

	for _, tc := range []struct {
		name string
		fn   func() error
		want string
	}{
		{"versions", func() error { return cmdVersions([]string{"demo"}) }, "v1"},
		{"delete", func() error { return cmdDelete([]string{"demo"}) }, "deleted: demo"},
		{"rename", func() error { return cmdRename([]string{"demo", "New", "name"}) }, "name: New name"},
		{"visibility", func() error { return cmdVisibility([]string{"demo", "public"}) }, "visibility: public"},
	} {
		out, err := captureStdout(t, tc.fn)
		if err != nil || !strings.Contains(out, tc.want) {
			t.Fatalf("%s: %q %v", tc.name, out, err)
		}
	}
}

func TestCovUploadsCommandUsageErrors(t *testing.T) {
	configureTestClient(t, "http://127.0.0.1:1")
	withStdin(t, "\n")
	cases := map[string]func() error{
		"versions arity":      func() error { return cmdVersions(nil) },
		"versions slug":       func() error { return cmdVersions([]string{"bad/slug"}) },
		"delete arity":        func() error { return cmdDelete(nil) },
		"delete slug":         func() error { return cmdDelete([]string{"bad slug"}) },
		"rename arity":        func() error { return cmdRename([]string{"demo"}) },
		"rename blank":        func() error { return cmdRename([]string{"demo", "  "}) },
		"rename slug":         func() error { return cmdRename([]string{"bad/slug", "x"}) },
		"visibility flag":     func() error { return cmdVisibility([]string{"demo", "public", "--nope"}) },
		"visibility extra":    func() error { return cmdVisibility([]string{"demo", "public", "extra"}) },
		"visibility usage":    func() error { return cmdVisibility([]string{"demo"}) },
		"visibility invalid":  func() error { return cmdVisibility([]string{"demo", "weird"}) },
		"visibility password": func() error { return cmdVisibility([]string{"demo", "password"}) },
		"visibility slug":     func() error { return cmdVisibility([]string{"bad/slug", "public"}) },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

type covFailAfterWriter struct{ left int }

func (w *covFailAfterWriter) Write(p []byte) (int, error) {
	if len(p) > w.left {
		return 0, errors.New("write failed")
	}
	w.left -= len(p)
	return len(p), nil
}

type covErrReader struct{}

func (covErrReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestCovWriteMultipartUploadErrorPaths(t *testing.T) {
	for n := 0; n < 1024; n += 8 {
		mw := multipart.NewWriter(&covFailAfterWriter{left: n})
		_ = writeMultipartUpload(mw, strings.NewReader("<html></html>"), "p", "restricted", "slug")
	}
	mw := multipart.NewWriter(io.Discard)
	if err := writeMultipartUpload(mw, covErrReader{}, "p", "", ""); err == nil {
		t.Fatal("expected read error")
	}
	body, _ := streamMultipartUpload(covErrReader{}, "p", "", "")
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("expected stream error")
	}
}
