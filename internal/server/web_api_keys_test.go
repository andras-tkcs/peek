package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/db"
	"github.com/privacyfence/peek/internal/models"
)

var apiKeyPattern = regexp.MustCompile("peek_[A-Za-z0-9_-]{32}")

func newKeyAccount(t *testing.T, s *Server, email string, isAdmin bool) int64 {
	t.Helper()
	a, err := s.store.CreateAccount(context.Background(), email, email, isAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func createDashboardKey(t *testing.T, s *Server, accountID int64, name string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := dashboardPost(t, s, accountID, "/dashboard/api-keys", url.Values{"name": {name}}, true)
	return apiKeyPattern.FindString(rec.Body.String()), rec
}

func regenerateDashboardKey(t *testing.T, s *Server, accountID, id int64) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := dashboardPost(t, s, accountID, "/dashboard/api-keys/"+strconv.FormatInt(id, 10)+"/regenerate", url.Values{}, true)
	return apiKeyPattern.FindString(rec.Body.String()), rec
}

func keyStatus(t *testing.T, s *Server, key string) int {
	t.Helper()
	return doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(key)).Code
}

func accountKeys(t *testing.T, s *Server, accountID int64) []struct {
	ID         int64
	Name, Hint string
	LastUsedAt int64
} {
	t.Helper()
	keys, err := s.store.ListAccountTokens(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]struct {
		ID         int64
		Name, Hint string
		LastUsedAt int64
	}, len(keys))
	for i, k := range keys {
		out[i].ID, out[i].Name, out[i].Hint, out[i].LastUsedAt = k.ID, k.Name, k.Hint, k.LastUsedAt
	}
	return out
}

func TestDashboardAPIKeyCreateShowsKeyOnce(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	key, rec := createDashboardKey(t, s, id, "QA runner")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	if !strings.Contains(rec.Body.String(), key) || !strings.Contains(rec.Body.String(), "Copy it now. Peek stores only a hash and cannot show it again.") {
		t.Fatalf("body lacks key or notice: %s", rec.Body.String())
	}
	if len(key) != 37 {
		t.Fatalf("key length = %d", len(key))
	}
	dash := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, id))
	body := dash.Body.String()
	if !strings.Contains(body, "QA runner") || !strings.Contains(body, "…"+key[33:]) || strings.Contains(body, key) {
		t.Fatalf("dashboard list wrong: %d", dash.Code)
	}
}

func TestDashboardAPIKeyAuthenticatesAPI(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	key, _ := createDashboardKey(t, s, id, "QA runner")
	if code := keyStatus(t, s, key); code != http.StatusOK {
		t.Fatalf("GET /api/uploads = %d", code)
	}
	keys := accountKeys(t, s, id)
	if len(keys) != 1 || keys[0].LastUsedAt <= 0 || keys[0].Hint != key[33:] {
		t.Fatalf("keys = %+v", keys)
	}
}

func TestDashboardAPIKeyRegenerate(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	old, _ := createDashboardKey(t, s, id, "QA runner")
	before := accountKeys(t, s, id)
	fresh, rec := regenerateDashboardKey(t, s, id, before[0].ID)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "API key regenerated") {
		t.Fatalf("regenerate = %d: %s", rec.Code, rec.Body.String())
	}
	if fresh == "" || fresh == old {
		t.Fatalf("new key %q, old %q", fresh, old)
	}
	if code := keyStatus(t, s, old); code != http.StatusUnauthorized {
		t.Fatalf("old key = %d", code)
	}
	if code := keyStatus(t, s, fresh); code != http.StatusOK {
		t.Fatalf("new key = %d", code)
	}
	after := accountKeys(t, s, id)
	if len(after) != 1 || after[0].ID != before[0].ID || after[0].Name != "QA runner" {
		t.Fatalf("after = %+v", after)
	}
}

func TestDashboardAPIKeyRevoke(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	key, _ := createDashboardKey(t, s, id, "QA runner")
	keys := accountKeys(t, s, id)
	rec := dashboardPost(t, s, id, "/dashboard/api-keys/"+strconv.FormatInt(keys[0].ID, 10)+"/revoke", url.Values{}, true)
	assertDashboardRedirect(t, rec, "/dashboard?ok=api_key_revoked")
	if code := keyStatus(t, s, key); code != http.StatusUnauthorized {
		t.Fatalf("revoked key = %d", code)
	}
	if got := accountKeys(t, s, id); len(got) != 0 {
		t.Fatalf("keys = %+v", got)
	}

	key2, _ := createDashboardKey(t, s, id, "second")
	up := uploadPage(t, s, key2, versionTestHTML1, map[string]string{"visibility": "public"})
	if up.Code != http.StatusOK {
		t.Fatalf("upload = %d: %s", up.Code, up.Body.String())
	}
	keys = accountKeys(t, s, id)
	rec = dashboardPost(t, s, id, "/dashboard/api-keys/"+strconv.FormatInt(keys[0].ID, 10)+"/revoke", url.Values{}, true)
	assertDashboardRedirect(t, rec, "/dashboard?ok=api_key_revoked")
	if code := keyStatus(t, s, key2); code != http.StatusUnauthorized {
		t.Fatalf("revoked key2 = %d", code)
	}
}

func TestDashboardAPIKeyOtherAccountNotFound(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	a := newKeyAccount(t, s, "a@example.test", false)
	b := newKeyAccount(t, s, "b@example.test", false)
	c := newKeyAccount(t, s, "c@example.test", true)
	key, _ := createDashboardKey(t, s, a, "mine")
	aid := strconv.FormatInt(accountKeys(t, s, a)[0].ID, 10)
	for _, acct := range []int64{b, c} {
		for _, action := range []string{"regenerate", "revoke"} {
			rec := dashboardPost(t, s, acct, "/dashboard/api-keys/"+aid+"/"+action, url.Values{}, true)
			if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "API key not found") {
				t.Fatalf("account %d %s = %d", acct, action, rec.Code)
			}
		}
	}
	rec := dashboardPost(t, s, b, "/dashboard/api-keys/abc/revoke", url.Values{}, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-numeric id = %d", rec.Code)
	}
	if code := keyStatus(t, s, key); code != http.StatusOK {
		t.Fatalf("A's key = %d", code)
	}
}

func TestDashboardAPIKeyRequiresCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	key, _ := createDashboardKey(t, s, id, "QA runner")
	kid := strconv.FormatInt(accountKeys(t, s, id)[0].ID, 10)
	for _, path := range []string{"/dashboard/api-keys", "/dashboard/api-keys/" + kid + "/regenerate", "/dashboard/api-keys/" + kid + "/revoke"} {
		rec := dashboardPost(t, s, id, path, url.Values{"name": {"x"}}, false)
		assertDashboardRedirect(t, rec, "/dashboard?err=invalid_session")
	}
	if got := accountKeys(t, s, id); len(got) != 1 {
		t.Fatalf("keys = %+v", got)
	}
	if code := keyStatus(t, s, key); code != http.StatusOK {
		t.Fatalf("key = %d", code)
	}
}

func TestDashboardAPIKeyDisabledAccountRefused(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	createDashboardKey(t, s, id, "QA runner")
	hashes := func() []string {
		rows, err := s.store.Query(`SELECT token FROM tokens WHERE account_id=?`, id)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				t.Fatal(err)
			}
			out = append(out, h)
		}
		return out
	}
	before := hashes()
	if err := s.store.SetAccountDisabled(context.Background(), id, true); err != nil {
		t.Fatal(err)
	}
	kid := strconv.FormatInt(accountKeys(t, s, id)[0].ID, 10)
	for _, path := range []string{"/dashboard/api-keys", "/dashboard/api-keys/" + kid + "/regenerate"} {
		rec := dashboardPost(t, s, id, path, url.Values{"name": {"x"}}, true)
		assertDashboardRedirect(t, rec, "/login")
	}
	after := hashes()
	if len(after) != 1 || len(before) != 1 || after[0] != before[0] {
		t.Fatalf("before %v after %v", before, after)
	}
}

func TestDashboardAPIKeyRequiresLogin(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/dashboard/api-keys", strings.NewReader("name=x"),
		func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") })
	assertDashboardRedirect(t, rec, "/login")
}

func TestDashboardAPIKeyNameValidation(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	for _, name := range []string{"", "   ", strings.Repeat("a", 101), "bad\nname"} {
		rec := dashboardPost(t, s, id, "/dashboard/api-keys", url.Values{"name": {name}}, true)
		assertDashboardRedirect(t, rec, "/dashboard?err=api_key_name")
	}
	if got := accountKeys(t, s, id); len(got) != 0 {
		t.Fatalf("keys = %+v", got)
	}
	if _, rec := createDashboardKey(t, s, id, strings.Repeat("é", 100)); rec.Code != http.StatusOK {
		t.Fatalf("100 runes = %d", rec.Code)
	}
}

func TestDashboardAPIKeyRateLimit(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	other := newKeyAccount(t, s, "o@example.test", false)
	for i := 0; i < 10; i++ {
		if _, rec := createDashboardKey(t, s, id, "k"); rec.Code != http.StatusOK {
			t.Fatalf("create %d = %d", i, rec.Code)
		}
	}
	if _, rec := createDashboardKey(t, s, id, "k"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("11th create = %d", rec.Code)
	}
	if _, rec := createDashboardKey(t, s, other, "k"); rec.Code != http.StatusOK {
		t.Fatalf("other account = %d", rec.Code)
	}
}

func TestDashboardAPIKeyListsCLILoginTokens(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newKeyAccount(t, s, "u@example.test", false)
	ctx := context.Background()
	for _, tok := range []string{"cli-token-0123456789", "cli-token-9876543210"} {
		if err := s.store.CreateTokenForAccount(ctx, tok, id, "CLI login"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.store.Exec(`UPDATE tokens SET hint=NULL WHERE token=?`, db.HashToken("cli-token-9876543210")); err != nil {
		t.Fatal(err)
	}
	body := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, id)).Body.String()
	for _, want := range []string{"CLI login", "…6789", "—"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard lacks %q", want)
		}
	}
}

func TestDashboardAPIKeyNeverLoggedOrAudited(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	id := newKeyAccount(t, s, "u@example.test", false)
	key1, _ := createDashboardKey(t, s, id, "QA runner")
	kid := accountKeys(t, s, id)[0].ID
	key2, _ := regenerateDashboardKey(t, s, id, kid)
	rec := dashboardPost(t, s, id, "/dashboard/api-keys/"+strconv.FormatInt(kid, 10)+"/revoke", url.Values{}, true)
	assertDashboardRedirect(t, rec, "/dashboard?ok=api_key_revoked")
	if key1 == "" || key2 == "" {
		t.Fatal("keys not captured")
	}
	for _, key := range []string{key1, key2} {
		if strings.Contains(logs.String(), key) {
			t.Fatalf("log contains key %s", key)
		}
		if strings.Contains(rec.Header().Get("Location"), key) {
			t.Fatal("redirect contains key")
		}
	}
	rows, err := s.store.Query(`SELECT actor, action, detail FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	actions := map[string]string{}
	for rows.Next() {
		var actor, action, detail string
		if err := rows.Scan(&actor, &action, &detail); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{key1, key2} {
			if strings.Contains(actor+action+detail, key) {
				t.Fatalf("audit row contains key: %s %s", action, detail)
			}
		}
		actions[action] = detail
	}
	want := "id=" + strconv.FormatInt(kid, 10) + ` name="QA runner"`
	for _, action := range []string{"token.create", "token.regenerate", "token.revoke"} {
		if actions[action] != want {
			t.Fatalf("audit %s detail = %q, want %q", action, actions[action], want)
		}
	}
	dash := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, id)).Body.String()
	for _, key := range []string{key1, key2} {
		if strings.Contains(dash, key) {
			t.Fatal("dashboard contains key")
		}
	}
}

// dashCovFailRandAfter makes secureRandomRead fail from call number n on and
// restores it when the returned func is called.
func dashCovFailRandAfter(n int) (restore func()) {
	real := secureRandomRead
	calls := 0
	secureRandomRead = func(b []byte) (int, error) {
		calls++
		if calls > n {
			return 0, errors.New("rand failed")
		}
		return real(b)
	}
	return func() { secureRandomRead = real }
}

func TestDashCovAPIKeyRowFormatting(t *testing.T) {
	now := time.Now()
	row := dashboardAPIKeyRow(models.APIKey{
		ID: 1, Name: "k", Hint: "abcd", CreatedAt: now,
		LastUsedAt: now.Unix(), ExpiresAt: now.Add(-time.Hour).Unix(),
	}, now)
	if row.LastUsed == "Never" || !strings.HasSuffix(row.Expires, "(expired)") {
		t.Fatalf("row = %+v", row)
	}
	row = dashboardAPIKeyRow(models.APIKey{ID: 2, Name: "k", CreatedAt: now, ExpiresAt: now.Add(time.Hour).Unix()}, now)
	if row.Expires == "Never" || strings.HasSuffix(row.Expires, "(expired)") {
		t.Fatalf("future expiry row = %+v", row)
	}
}

func TestDashCovAPIKeyListFailure(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)
	dropTable(t, store, "tokens")
	if rows := s.dashboardAPIKeyRows(context.Background(), adminID); rows != nil {
		t.Fatalf("rows = %v, want nil", rows)
	}
}

func TestDashCovAPIKeyCreateRegenerateRevokeFailures(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)

	restore := dashCovFailRandAfter(1)
	rec := dashboardPost(t, s, adminID, "/dashboard/api-keys", url.Values{"name": {"k"}}, true)
	restore()
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashAPIKeyCreateFailed)

	key, rec := createDashboardKey(t, s, adminID, "k")
	if key == "" {
		t.Fatalf("create failed: %d", rec.Code)
	}
	keys := accountKeys(t, s, adminID)
	id := keys[0].ID
	path := "/dashboard/api-keys/" + strconv.FormatInt(id, 10)

	restore = dashCovFailRandAfter(1)
	rec = dashboardPost(t, s, adminID, path+"/regenerate", url.Values{}, true)
	restore()
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashAPIKeyRegenerateFailed)

	for _, p := range []string{"/dashboard/api-keys/abc/regenerate", "/dashboard/api-keys/abc/revoke"} {
		if rec := dashboardPost(t, s, adminID, p, url.Values{}, true); rec.Code != http.StatusNotFound {
			t.Fatalf("POST %s = %d, want 404", p, rec.Code)
		}
	}

	s.apiKeyLimiter = newLimiter(1, time.Minute)
	if rec := dashboardPost(t, s, adminID, path+"/regenerate", url.Values{}, true); rec.Code != http.StatusOK {
		t.Fatalf("first regenerate = %d, want 200", rec.Code)
	}
	rec = dashboardPost(t, s, adminID, path+"/regenerate", url.Values{}, true)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("limited regenerate = %d, want 429", rec.Code)
	}

	if rec := doRequest(t, s, http.MethodPost, path+"/revoke", nil); rec.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous revoke Location = %q", rec.Header().Get("Location"))
	}
	addFailTrigger(t, store, "tokens", "DELETE")
	rec = dashboardPost(t, s, adminID, path+"/revoke", url.Values{}, true)
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashAPIKeyRevokeFailed)
}
