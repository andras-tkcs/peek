package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type grantReqBody struct {
	Kind  string `json:"kind"`
	Email string `json:"email"`
}

func grantServer(t *testing.T, method string) chan grantReqBody {
	t.Helper()
	seen := make(chan grantReqBody, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/uploads/page/grants" || r.Method != method {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q", got)
		}
		var b grantReqBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("decode: %v", err)
		}
		seen <- b
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"removed":true}`))
	}))
	t.Cleanup(ts.Close)
	configureTestClient(t, ts.URL)
	return seen
}

func TestGrantCommandPostsUserGrant(t *testing.T) {
	seen := grantServer(t, http.MethodPost)
	out, err := captureStdout(t, func() error { return cmdGrant([]string{"page", "bob@example.com"}) })
	if err != nil {
		t.Fatalf("cmdGrant: %v", err)
	}
	if got := <-seen; got.Kind != "user" || got.Email != "bob@example.com" {
		t.Fatalf("body = %+v", got)
	}
	if !strings.Contains(out, "granted user bob@example.com on page") {
		t.Fatalf("output = %q", out)
	}
}

func TestGrantCommandGroupFlag(t *testing.T) {
	seen := grantServer(t, http.MethodPost)
	out, err := captureStdout(t, func() error { return cmdGrant([]string{"page", "eng@example.com", "--group"}) })
	if err != nil {
		t.Fatalf("cmdGrant: %v", err)
	}
	if got := <-seen; got.Kind != "group" || got.Email != "eng@example.com" {
		t.Fatalf("body = %+v", got)
	}
	if !strings.Contains(out, "granted group eng@example.com on page") {
		t.Fatalf("output = %q", out)
	}
}

func TestRevokeCommandSendsDelete(t *testing.T) {
	seen := grantServer(t, http.MethodDelete)
	out, err := captureStdout(t, func() error { return cmdRevoke([]string{"page", "bob@example.com"}) })
	if err != nil {
		t.Fatalf("cmdRevoke: %v", err)
	}
	if got := <-seen; got.Kind != "user" || got.Email != "bob@example.com" {
		t.Fatalf("body = %+v", got)
	}
	if !strings.Contains(out, "revoked user bob@example.com on page") {
		t.Fatalf("output = %q", out)
	}
}
