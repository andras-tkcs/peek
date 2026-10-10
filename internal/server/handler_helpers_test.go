package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/puemos/peek/internal/db"
	"github.com/puemos/peek/internal/models"
)

// newHandlerTestServer builds a full Server through New (file storage under t.TempDir(),
// all limiters set) and seeds an admin bearer token. It mirrors api_test.go.
func newHandlerTestServer(t *testing.T) (s *Server, adminToken string) {
	t.Helper()
	dir := t.TempDir()
	adminToken = "dev-admin-token"
	store, err := db.Open(filepath.Join(dir, "peek.db"))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	if err := store.CreateToken(context.Background(), adminToken, "admin", true, 0); err != nil {
		t.Fatalf("seed admin token: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close test store: %v", err)
	}
	s, err = New(Config{
		DataDir:   dir,
		BaseURL:   "http://localhost:7700",
		Secret:    strings.Repeat("ab", 32),
		MaxUpload: 10 << 20,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, adminToken
}

// doRequest runs one request through s.Handler() and returns the recorder.
func doRequest(t *testing.T, s *Server, method, path string, body io.Reader, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	for _, opt := range opts {
		opt(req)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// asBearer sets the Authorization header to a bearer token.
func asBearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

// asSession adds a signed dashboard session cookie for the account.
func asSession(s *Server, accountID int64) func(*http.Request) {
	return func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(accountID, 10), sessionTTL)})
	}
}

// withJSON sets Content-Type: application/json.
func withJSON() func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }
}

// newAccountWithToken creates an account and a bearer token that belongs to it.
func newAccountWithToken(t *testing.T, s *Server, email, token string, isAdmin bool) *models.Account {
	t.Helper()
	ctx := context.Background()
	account, err := s.store.CreateAccount(ctx, email, email, isAdmin)
	if err != nil {
		t.Fatalf("create account %s: %v", email, err)
	}
	if err := s.store.CreateTokenForAccount(ctx, token, account.ID, email); err != nil {
		t.Fatalf("create token for %s: %v", email, err)
	}
	return account
}

func TestHandlerHarnessServesHealthz(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerHarnessAuthHelpers(t *testing.T) {
	s, adminToken := newHandlerTestServer(t)
	owner := newAccountWithToken(t, s, "owner@example.test", "owner-token", false)

	for name, token := range map[string]string{"admin": adminToken, "owner": "owner-token"} {
		rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(token))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s GET /api/uploads = %d, want 200: %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /api/uploads = %d, want 401", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	asSession(s, owner.ID)(req)
	withJSON()(req)
	c, err := req.Cookie(sessionCookie)
	if err != nil {
		t.Fatalf("session cookie not set: %v", err)
	}
	sub, ok := parseSignedSubject(s.secret, c.Value)
	if !ok || sub != strconv.FormatInt(owner.ID, 10) {
		t.Fatalf("session subject = %q ok=%v, want %d", sub, ok, owner.ID)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
}
