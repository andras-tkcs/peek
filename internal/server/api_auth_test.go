package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
)

func TestAuthTokenStoresVerifiedAPIToken(t *testing.T) {
	store := newAuthTestStore(t, "user-token", "user", false)
	s := &Server{store: store}
	var actorName string

	handler := s.authToken(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := apiToken(r)
		if !ok {
			t.Fatal("api token missing from request context")
		}
		actorName = actor.Name
		jsonOK(w, map[string]string{"status": "ok"})
	})
	req := httptest.NewRequest(http.MethodGet, "/api/uploads", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if actorName != "user" {
		t.Fatalf("actor name = %q", actorName)
	}
}

func TestAuthAdminStoresVerifiedAPIToken(t *testing.T) {
	store := newAuthTestStore(t, "admin-token", "admin", true)
	s := &Server{store: store}
	var actorName string

	handler := s.authAdmin(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := apiToken(r)
		if !ok {
			t.Fatal("api token missing from request context")
		}
		actorName = actor.Name
		jsonOK(w, map[string]string{"status": "ok"})
	})
	req := httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if actorName != "admin" {
		t.Fatalf("actor name = %q", actorName)
	}
}

func TestAPIHandlerWithoutAuthContextFailsClosed(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/uploads", nil)

	s.handleListUploads(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Error != "auth context missing" {
		t.Fatalf("error = %q", body.Error)
	}
}

func newAuthTestStore(t *testing.T, token, name string, isAdmin bool) *db.Store {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CreateToken(context.Background(), token, name, isAdmin, 0); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	return store
}

func tokenLastUsed(t *testing.T, s *Server, token string) sql.NullInt64 {
	t.Helper()
	var v sql.NullInt64
	if err := s.store.QueryRow(`SELECT last_used_at FROM tokens WHERE token=?`, db.HashToken(token)).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func setTokenLastUsed(t *testing.T, s *Server, token string, v any) {
	t.Helper()
	if _, err := s.store.Exec(`UPDATE tokens SET last_used_at=? WHERE token=?`, v, db.HashToken(token)); err != nil {
		t.Fatal(err)
	}
}

func requireNear(t *testing.T, v sql.NullInt64, want int64) {
	t.Helper()
	if !v.Valid || v.Int64 < want-5 || v.Int64 > want+5 {
		t.Fatalf("last_used_at = %v, want about %d", v, want)
	}
}

func TestAuthTokenRecordsTokenUse(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	token := "user-token-0123456789"
	newAccountWithToken(t, s, "u@example.test", token, false)
	get := func() {
		if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(token)); rec.Code != http.StatusOK {
			t.Fatalf("GET /api/uploads = %d", rec.Code)
		}
	}
	get()
	requireNear(t, tokenLastUsed(t, s, token), time.Now().Unix())

	old := time.Now().Unix() - 30
	setTokenLastUsed(t, s, token, old)
	get()
	if v := tokenLastUsed(t, s, token); v.Int64 != old {
		t.Fatalf("throttled write changed value to %v", v)
	}

	setTokenLastUsed(t, s, token, time.Now().Unix()-120)
	get()
	requireNear(t, tokenLastUsed(t, s, token), time.Now().Unix())
}

func TestAuthAdminRecordsTokenUse(t *testing.T) {
	s, adminToken := newHandlerTestServer(t)
	if rec := doRequest(t, s, http.MethodGet, "/api/tokens", nil, asBearer(adminToken)); rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tokens = %d", rec.Code)
	}
	requireNear(t, tokenLastUsed(t, s, adminToken), time.Now().Unix())
}

func TestListCommentsRecordsTokenUse(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	token := "user-token-0123456789"
	newAccountWithToken(t, s, "u@example.test", token, false)
	rec := uploadPage(t, s, token, versionTestHTML1, map[string]string{"visibility": "public"})
	if rec.Code != http.StatusOK {
		t.Fatalf("upload = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	setTokenLastUsed(t, s, token, nil)
	rec = doRequest(t, s, http.MethodGet, "/api/uploads/"+out.Slug+"/comments", nil, asBearer(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("comments = %d: %s", rec.Code, rec.Body.String())
	}
	requireNear(t, tokenLastUsed(t, s, token), time.Now().Unix())
}
