package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCmdDeleteSendsAuthenticatedDelete(t *testing.T) {
	seen := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/uploads/page" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s", r.Method)
		}
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)

	if _, err := captureStdout(t, func() error {
		return cmdDelete([]string{"page"})
	}); err != nil {
		t.Fatalf("cmdDelete: %v", err)
	}
	if got := <-seen; got != "Bearer test-token" {
		t.Fatalf("authorization = %q", got)
	}
}

func TestCmdVisibilitySendsSetVisibilityRequest(t *testing.T) {
	type requestBody struct {
		Visibility string `json:"visibility"`
		Password   string `json:"password"`
	}
	seen := make(chan requestBody, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/uploads/page/visibility" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content type = %q", got)
		}
		var body requestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		seen <- body
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"visibility": "password"})
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)

	if _, err := captureStdout(t, func() error {
		return cmdVisibility([]string{"page", "password", "--password", "secret"})
	}); err != nil {
		t.Fatalf("cmdVisibility: %v", err)
	}
	if got := <-seen; got.Visibility != "password" || got.Password != "secret" {
		t.Fatalf("request body = %+v", got)
	}
}

func TestCmdVisibilityRejectsConflictingOptions(t *testing.T) {
	err := cmdVisibility([]string{"page", "password", "--password", "secret", "--password-stdin"})
	if err == nil {
		t.Fatal("expected conflict error")
	}
}

func TestVersionsCommandRequestsVersions(t *testing.T) {
	seen := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"version": 1, "size": 10, "created_at": 1700000000, "url": "http://x/p/page/v/1"},
			{"version": 2, "size": 20, "created_at": 1700000100, "url": "http://x/p/page/v/2"},
		})
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)

	out, err := captureStdout(t, func() error { return cmdVersions([]string{"page"}) })
	if err != nil {
		t.Fatalf("cmdVersions: %v", err)
	}
	if got := <-seen; got != "GET /api/uploads/page/versions" {
		t.Fatalf("request = %q", got)
	}
	if !strings.Contains(out, "v2") || !strings.Contains(out, "20 bytes") || !strings.Contains(out, "http://x/p/page/v/2") {
		t.Fatalf("output = %q", out)
	}
}

func TestCommentsVersionFlag(t *testing.T) {
	seen := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)

	if _, err := captureStdout(t, func() error { return cmdComments([]string{"page", "--version", "2"}) }); err != nil {
		t.Fatalf("cmdComments: %v", err)
	}
	if got := <-seen; !strings.HasSuffix(got, "/comments?v=2") {
		t.Fatalf("request = %q", got)
	}
	if err := cmdComments([]string{"page", "--version", "0"}); err == nil || !strings.Contains(err.Error(), "positive integer") {
		t.Fatalf("expected positive integer error, got %v", err)
	}
}

func TestCmdRenameSendsRenameRequest(t *testing.T) {
	seen := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/uploads/page/name" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		seen <- body.Name
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"slug": "new-name", "url": "http://x/p/new-name", "name": "New Name"})
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)

	out, err := captureStdout(t, func() error {
		return cmdRename([]string{"page", "New", "Name"})
	})
	if err != nil {
		t.Fatalf("cmdRename: %v", err)
	}
	if got := <-seen; got != "New Name" {
		t.Fatalf("name = %q", got)
	}
	for _, want := range []string{"slug: new-name", "url: http://x/p/new-name"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %s", want, out)
		}
	}
	if err := cmdRename([]string{"page"}); err == nil || !strings.Contains(err.Error(), "usage: peek rename") {
		t.Fatalf("err = %v", err)
	}
}
