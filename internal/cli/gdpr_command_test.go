package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCmdExportPrintsSuccessfulExport(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/uploads/page/export" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"slug":"page"}`))
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)

	out, err := captureStdout(t, func() error {
		return cmdExport([]string{"page"})
	})
	if err != nil {
		t.Fatalf("cmdExport: %v", err)
	}
	if out != "{\"slug\":\"page\"}\n" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestCmdExportReturnsAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/uploads/page/export" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"export failed"}`))
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)

	out, err := captureStdout(t, func() error {
		return cmdExport([]string{"page"})
	})
	if err == nil || !strings.Contains(err.Error(), "export failed") {
		t.Fatalf("error = %v", err)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestCovExportAndDeleteAllErrors(t *testing.T) {
	configureTestClient(t, "http://127.0.0.1:1")
	for name, fn := range map[string]func() error{
		"export arity":     func() error { return cmdExport(nil) },
		"export slug":      func() error { return cmdExport([]string{"bad/slug"}) },
		"delete-all arity": func() error { return cmdDeleteAll([]string{"x"}) },
	} {
		if err := fn(); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	t.Run("export env", func(t *testing.T) {
		covEnvFailures(t, func() error { return cmdExport([]string{"demo"}) })
	})
	t.Run("delete-all env", func(t *testing.T) {
		covEnvFailures(t, func() error { return cmdDeleteAll(nil) })
	})
}

func TestCovDeleteAllPrintsCount(t *testing.T) {
	ts := covFake(t, map[string]string{"/api/uploads-by-owner": `{"deleted":3}`}, nil)
	configureTestClient(t, ts.URL)
	out, err := captureStdout(t, func() error { return cmdDeleteAll(nil) })
	if err != nil || !strings.Contains(out, "deleted 3 uploads") {
		t.Fatalf("got %q %v", out, err)
	}
}
