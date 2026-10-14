package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// admSetupServer builds a fresh install (no accounts) and returns the server
// with its one-time setup code.
func admSetupServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := New(Config{DataDir: t.TempDir(), BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32), MaxUpload: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	code := s.readSetupCode()
	if code == "" {
		t.Fatal("no setup code on a fresh install")
	}
	return s, code
}

func admSetupPost(t *testing.T, s *Server, form url.Values, withCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	opts := []func(*http.Request){func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }}
	if withCSRF {
		form.Set("csrf", "csrf-token")
		opts = append(opts, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"}) })
	}
	return doRequest(t, s, http.MethodPost, "/setup", strings.NewReader(form.Encode()), opts...)
}

func TestSetupGetShowsFormOrHint(t *testing.T) {
	s, code := admSetupServer(t)

	rec := doRequest(t, s, http.MethodGet, "/setup", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Use the setup URL printed by the server.") {
		t.Fatalf("missing code: status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = doRequest(t, s, http.MethodGet, "/setup?code="+url.QueryEscape(code), nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "Use the setup URL printed by the server.") || !strings.Contains(rec.Body.String(), code) {
		t.Fatalf("valid code: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSetupGetCSRFTokenFailure(t *testing.T) {
	s, code := admSetupServer(t)
	stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand down") })
	rec := doRequest(t, s, http.MethodGet, "/setup?code="+url.QueryEscape(code), nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestSetupPostBranches(t *testing.T) {
	good := func(code string) url.Values {
		return url.Values{"code": {code}, "email": {"Boss@Example.test"}, "name": {"Boss"}, "password": {"correct horse"}}
	}
	tests := []struct {
		name     string
		mutate   func(code string) url.Values
		csrf     bool
		wantBody string
	}{
		{name: "invalid csrf", mutate: good, csrf: false, wantBody: "Invalid setup session."},
		{name: "invalid code", mutate: func(string) url.Values { return good("wrong") }, csrf: true, wantBody: "Invalid setup session."},
		{name: "empty email", mutate: func(c string) url.Values { v := good(c); v.Set("email", ""); return v }, csrf: true, wantBody: "Admin email is required."},
		{name: "email without at", mutate: func(c string) url.Values { v := good(c); v.Set("email", "boss"); return v }, csrf: true, wantBody: "Admin email is required."},
		{name: "empty password", mutate: func(c string) url.Values { v := good(c); v.Set("password", ""); return v }, csrf: true, wantBody: "Password is required."},
		{name: "long password", mutate: func(c string) url.Values { v := good(c); v.Set("password", strings.Repeat("x", 73)); return v }, csrf: true, wantBody: "72 characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, code := admSetupServer(t)
			rec := admSetupPost(t, s, tt.mutate(code), tt.csrf)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("status=%d, want body containing %q: %s", rec.Code, tt.wantBody, rec.Body.String())
			}
		})
	}

	t.Run("bad form", func(t *testing.T) {
		s, _ := admSetupServer(t)
		rec := doRequest(t, s, http.MethodPost, "/setup", strings.NewReader("a=%zz"),
			func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") })
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Invalid form.") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("csrf generation failure", func(t *testing.T) {
		s, code := admSetupServer(t)
		stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand down") })
		rec := admSetupPost(t, s, good(code), true)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("create account failure", func(t *testing.T) {
		s, code := admSetupServer(t)
		addFailTrigger(t, s.store, "accounts", "INSERT")
		rec := admSetupPost(t, s, good(code), true)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Could not create admin account.") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("success then redirect", func(t *testing.T) {
		s, code := admSetupServer(t)
		rec := admSetupPost(t, s, good(code), true)
		assertDashboardRedirect(t, rec, "/dashboard")
		if _, err := os.Stat(setupCodePath(s.dataDir)); !os.IsNotExist(err) {
			t.Fatalf("setup code file still present: %v", err)
		}
		if n, err := s.store.CountAccounts(context.Background()); err != nil || n != 1 {
			t.Fatalf("accounts = %d, err=%v", n, err)
		}
		// Setup is complete, so both methods now redirect to /login.
		assertDashboardRedirect(t, doRequest(t, s, http.MethodGet, "/setup", nil), "/login")
	})
}
