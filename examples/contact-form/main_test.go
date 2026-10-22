package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, send func(submission) error) (*server, http.Handler) {
	t.Helper()
	s := &server{token: "tok", dataDir: t.TempDir(), send: send}
	return s, s.routes()
}

func do(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var authed = map[string]string{"X-Peek-Backend-Token": "tok"}

func TestTokenRequired(t *testing.T) {
	_, h := newTestServer(t, func(submission) error { return nil })
	for _, hdr := range []map[string]string{nil, {"X-Peek-Backend-Token": "wrong"}} {
		if rec := do(h, "GET", "/api/healthz", "", hdr); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	}
	rec := do(h, "GET", "/api/healthz", "", authed)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

func TestEmptyServerTokenRejectsEverything(t *testing.T) {
	s := &server{dataDir: t.TempDir()}
	if rec := do(s.routes(), "GET", "/api/healthz", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestContactValidation(t *testing.T) {
	_, h := newTestServer(t, func(submission) error { return nil })
	long := strings.Repeat("x", maxMessageBytes+1)
	cases := map[string]string{
		"bad json":      `{`,
		"missing field": `{"name":"A","email":"a@b.c"}`,
		"bad email":     `{"name":"A","email":"nope","message":"hi"}`,
		"header inject": `{"name":"A\r\nBcc: x@y.z","email":"a@b.c","message":"hi"}`,
		"too long":      `{"name":"A","email":"a@b.c","message":"` + long + `"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := do(h, "POST", "/api/contact", body, authed)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			var out map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["error"] == "" {
				t.Fatalf("body = %q, want JSON error", rec.Body.String())
			}
		})
	}
}

func TestContactSendsAndStores(t *testing.T) {
	var got submission
	s, h := newTestServer(t, func(in submission) error { got = in; return nil })
	rec := do(h, "POST", "/api/contact", `{"name":" Ann ","email":"ann@example.com","message":"hello"}`, authed)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sent"`) {
		t.Fatalf("contact = %d %s", rec.Code, rec.Body.String())
	}
	if got.Name != "Ann" || got.Message != "hello" {
		t.Fatalf("sent = %+v", got)
	}
	data, err := os.ReadFile(s.submissionsPath())
	if err != nil || !strings.Contains(string(data), `"ann@example.com"`) {
		t.Fatalf("file = %q, %v", data, err)
	}
}

func TestContactSendFailure(t *testing.T) {
	s, h := newTestServer(t, func(submission) error { return errors.New("smtp down") })
	rec := do(h, "POST", "/api/contact", `{"name":"A","email":"a@b.c","message":"hi"}`, authed)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if _, err := os.Stat(s.submissionsPath()); err == nil {
		t.Fatal("failed send must not be stored")
	}
}

func TestContactStoreFailureStillSucceeds(t *testing.T) {
	s, h := newTestServer(t, func(submission) error { return nil })
	s.dataDir = s.dataDir + "/missing"
	rec := do(h, "POST", "/api/contact", `{"name":"A","email":"a@b.c","message":"hi"}`, authed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestSubmissions(t *testing.T) {
	_, h := newTestServer(t, func(submission) error { return nil })
	if rec := do(h, "GET", "/api/submissions", "", authed); rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous = %d, want 403", rec.Code)
	}
	user := map[string]string{"X-Peek-Backend-Token": "tok", "X-Peek-User-Email": "a@b.c"}
	rec := do(h, "GET", "/api/submissions", "", user)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty = %d %q", rec.Code, rec.Body.String())
	}
	do(h, "POST", "/api/contact", `{"name":"A","email":"a@b.c","message":"hi"}`, authed)
	do(h, "POST", "/api/contact", `{"name":"B","email":"b@b.c","message":"yo"}`, authed)
	rec = do(h, "GET", "/api/submissions", "", user)
	var list []submission
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 || list[1].Name != "B" {
		t.Fatalf("list = %q, %v", rec.Body.String(), err)
	}
}

func TestSubmissionsUnreadable(t *testing.T) {
	s, h := newTestServer(t, func(submission) error { return nil })
	// A directory at the file path makes ReadFile fail with something other than not-exist.
	if err := os.Mkdir(s.submissionsPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	user := map[string]string{"X-Peek-Backend-Token": "tok", "X-Peek-User-Email": "a@b.c"}
	if rec := do(h, "GET", "/api/submissions", "", user); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestSendMailRequiresConfig(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	if err := sendMail(submission{}); err == nil {
		t.Fatal("want error when SMTP is not configured")
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("CF_TEST", "")
	if envOr("CF_TEST", "d") != "d" {
		t.Fatal("default expected")
	}
	t.Setenv("CF_TEST", "v")
	if envOr("CF_TEST", "d") != "v" {
		t.Fatal("env expected")
	}
}
