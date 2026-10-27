package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type provTestEnv struct {
	s   *Server
	key string
}

func newProvTestEnv(t *testing.T) provTestEnv {
	t.Helper()
	s, _ := newHandlerTestServer(t)
	_, key := newProvisionerKey(t, s, "PF")
	return provTestEnv{s: s, key: key}
}

func (e provTestEnv) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, e.s, method, path, strings.NewReader(body), asBearer(e.key), withJSON())
}

func (e provTestEnv) upsert(t *testing.T, ext, email, name string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "name": name})
	rec := e.do(t, http.MethodPut, "/api/provisioning/accounts/"+ext, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert %s: %d %s", ext, rec.Code, rec.Body)
	}
	return decodeMap(t, rec)
}

func (e provTestEnv) mint(t *testing.T, ext, body string) map[string]any {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/api/provisioning/accounts/"+ext+"/token", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint %s: %d %s", ext, rec.Code, rec.Body)
	}
	return decodeMap(t, rec)
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body, err)
	}
	return out
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, code int, msg string) {
	t.Helper()
	if rec.Code != code || policyErrorBody(t, rec.Body.Bytes()) != msg {
		t.Fatalf("got %d %s, want %d %q", rec.Code, rec.Body, code, msg)
	}
}

func TestProvisioningSelf(t *testing.T) {
	e := newProvTestEnv(t)
	e.upsert(t, "e1", "a@x.test", "")
	rec := e.do(t, http.MethodGet, "/api/provisioning/self", "")
	out := decodeMap(t, rec)
	if rec.Code != http.StatusOK || out["name"] != "PF" || out["accounts"] != float64(1) {
		t.Fatalf("got %d %v", rec.Code, out)
	}
}

func TestProvisioningUpsertCreates(t *testing.T) {
	e := newProvTestEnv(t)
	out := e.upsert(t, "e1", " Alice@X.test ", "Alice A")
	if out["created"] != true || out["adopted"] != false || out["email"] != "alice@x.test" || out["name"] != "Alice A" ||
		out["external_id"] != "e1" || out["disabled"] != false || out["has_token"] != false || out["token_expires_at"] != float64(0) {
		t.Fatalf("out = %v", out)
	}
}

func TestProvisioningUpsertIsIdempotent(t *testing.T) {
	e := newProvTestEnv(t)
	first := e.upsert(t, "e1", "a@x.test", "")
	second := e.upsert(t, "e1", "a@x.test", "")
	if second["created"] != false || second["adopted"] != false || second["account_id"] != first["account_id"] {
		t.Fatalf("first %v second %v", first, second)
	}
}

func TestProvisioningUpsertAdopts(t *testing.T) {
	e := newProvTestEnv(t)
	acct := newAccountWithToken(t, e.s, "a@x.test", "peek_existing-1234", false)
	out := e.upsert(t, "e1", "a@x.test", "")
	if out["adopted"] != true || out["created"] != false || out["account_id"] != float64(acct.ID) {
		t.Fatalf("out = %v", out)
	}
	// The person's own token is untouched and not provisioned.
	if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads", nil, asBearer("peek_existing-1234")); rec.Code != http.StatusOK {
		t.Fatalf("own token: %d", rec.Code)
	}
}

func TestProvisioningUpsertRefusesAdmin(t *testing.T) {
	e := newProvTestEnv(t)
	newAccountWithToken(t, e.s, "root@x.test", "peek_admin-1234", true)
	rec := e.do(t, http.MethodPut, "/api/provisioning/accounts/e1", `{"email":"root@x.test"}`)
	wantError(t, rec, http.StatusConflict, "account is a Peek admin; connect it by hand")
}

func TestProvisioningUpsertConflict(t *testing.T) {
	e := newProvTestEnv(t)
	e.upsert(t, "e1", "a@x.test", "")
	rec := e.do(t, http.MethodPut, "/api/provisioning/accounts/e2", `{"email":"a@x.test"}`)
	wantError(t, rec, http.StatusConflict, "account is linked to another external id or email")
	rec = e.do(t, http.MethodPut, "/api/provisioning/accounts/e1", `{"email":"b@x.test"}`)
	wantError(t, rec, http.StatusConflict, "account is linked to another external id or email")
}

func TestProvisioningUpsertInvalidEmail(t *testing.T) {
	e := newProvTestEnv(t)
	for _, email := range []string{"", "nope", "@x.test", "a@", "a@b@c", strings.Repeat("a", 250) + "@x.test"} {
		body, _ := json.Marshal(map[string]string{"email": email})
		wantError(t, e.do(t, http.MethodPut, "/api/provisioning/accounts/e1", string(body)), http.StatusBadRequest, "invalid email")
	}
	wantError(t, e.do(t, http.MethodPut, "/api/provisioning/accounts/e1", `{bad`), http.StatusBadRequest, "invalid json")
}

func TestProvisioningUpsertNameTooLong(t *testing.T) {
	e := newProvTestEnv(t)
	body, _ := json.Marshal(map[string]string{"email": "a@x.test", "name": strings.Repeat("n", 101)})
	wantError(t, e.do(t, http.MethodPut, "/api/provisioning/accounts/e1", string(body)), http.StatusBadRequest, "name too long")
}

func TestProvisioningUpsertInvalidExternalID(t *testing.T) {
	e := newProvTestEnv(t)
	for _, ext := range []string{"a%20b", strings.Repeat("a", 201)} {
		rec := e.do(t, http.MethodPut, "/api/provisioning/accounts/"+ext, `{"email":"a@x.test"}`)
		wantError(t, rec, http.StatusBadRequest, "invalid external id")
		rec = e.do(t, http.MethodDelete, "/api/provisioning/accounts/"+ext, "")
		wantError(t, rec, http.StatusBadRequest, "invalid external id")
	}
}

func TestProvisioningUpsertDomainNotAllowed(t *testing.T) {
	e := newProvTestEnv(t)
	setAllowedDomainForTest(t, e.s, "example.test")
	rec := e.do(t, http.MethodPut, "/api/provisioning/accounts/e1", `{"email":"a@other.test"}`)
	wantError(t, rec, http.StatusForbidden, "account email domain is not allowed")
}

func TestProvisioningTokenWorksWithOAuthRequired(t *testing.T) {
	e := newProvTestEnv(t)
	e.upsert(t, "e1", "a@x.test", "")
	enableGitHubOAuthForTest(t, e.s)
	tok := e.mint(t, "e1", `{}`)["token"].(string)
	if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads", nil, asBearer(tok)); rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestProvisioningTokenCanUploadThenBeReplaced(t *testing.T) {
	e := newProvTestEnv(t)
	e.upsert(t, "e1", "a@x.test", "")
	old := e.mint(t, "e1", `{}`)["token"].(string)
	slug := pageCovUpload(t, e.s, old, "")
	fresh := e.mint(t, "e1", `{}`)["token"].(string)
	if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads", nil, asBearer(old)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old token: %d", rec.Code)
	}
	rec := doRequest(t, e.s, http.MethodGet, "/api/uploads", nil, asBearer(fresh))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), slug) {
		t.Fatalf("new token: %d %s", rec.Code, rec.Body)
	}
}

func TestProvisioningTokenDisabledAccount(t *testing.T) {
	e := newProvTestEnv(t)
	out := e.upsert(t, "e1", "a@x.test", "")
	if _, err := e.s.store.Exec(`UPDATE accounts SET disabled=1 WHERE id=?`, int64(out["account_id"].(float64))); err != nil {
		t.Fatal(err)
	}
	wantError(t, e.do(t, http.MethodPost, "/api/provisioning/accounts/e1/token", `{}`), http.StatusForbidden, "account disabled")
}

func TestProvisioningTokenAdminAndDomainRefused(t *testing.T) {
	e := newProvTestEnv(t)
	out := e.upsert(t, "e1", "a@x.test", "")
	setAllowedDomainForTest(t, e.s, "other.test")
	wantError(t, e.do(t, http.MethodPost, "/api/provisioning/accounts/e1/token", `{}`), http.StatusForbidden, "account email domain is not allowed")
	setAllowedDomainForTest(t, e.s, "")
	if err := e.s.store.SetAccountAdmin(context.Background(), int64(out["account_id"].(float64)), true); err != nil {
		t.Fatal(err)
	}
	wantError(t, e.do(t, http.MethodPost, "/api/provisioning/accounts/e1/token", `{}`), http.StatusConflict, "account is a Peek admin; connect it by hand")
}

func TestProvisioningTokenExpiresDaysBounds(t *testing.T) {
	e := newProvTestEnv(t)
	e.upsert(t, "e1", "a@x.test", "")
	out := e.mint(t, "e1", `{"expires_days":0}`)
	want := time.Now().Add(90 * 24 * time.Hour).Unix()
	if got := int64(out["expires_at"].(float64)); got < want-5 || got > want+5 {
		t.Fatalf("expires_at = %d, want about %d", got, want)
	}
	if out["token_id"] == nil || !strings.HasPrefix(out["token"].(string), "peek_") {
		t.Fatalf("out = %v", out)
	}
	for _, d := range []string{"-1", "366"} {
		wantError(t, e.do(t, http.MethodPost, "/api/provisioning/accounts/e1/token", `{"expires_days":`+d+`}`), http.StatusBadRequest, "expires_days must be 1 to 365")
	}
	e.mint(t, "e1", `{"expires_days":365}`)
	// An empty body means the default.
	rec := doRequest(t, e.s, http.MethodPost, "/api/provisioning/accounts/e1/token", nil, asBearer(e.key))
	if rec.Code != http.StatusCreated {
		t.Fatalf("empty body: %d %s", rec.Code, rec.Body)
	}
	wantError(t, e.do(t, http.MethodPost, "/api/provisioning/accounts/e1/token", `{bad`), http.StatusBadRequest, "invalid json")
}

func TestProvisioningTokenUnknownExternalID(t *testing.T) {
	e := newProvTestEnv(t)
	wantError(t, e.do(t, http.MethodPost, "/api/provisioning/accounts/none/token", `{}`), http.StatusNotFound, "not found")
}

func TestProvisioningUpsertHasToken(t *testing.T) {
	e := newProvTestEnv(t)
	e.upsert(t, "e1", "a@x.test", "")
	minted := e.mint(t, "e1", `{"expires_days":30}`)
	out := e.upsert(t, "e1", "a@x.test", "")
	if out["has_token"] != true || out["token_expires_at"] != minted["expires_at"] {
		t.Fatalf("out = %v minted = %v", out, minted)
	}
	// An expired token no longer counts.
	if _, err := e.s.store.Exec(`UPDATE tokens SET expires_at=1`); err != nil {
		t.Fatal(err)
	}
	out = e.upsert(t, "e1", "a@x.test", "")
	if out["has_token"] != false || out["token_expires_at"] != float64(0) {
		t.Fatalf("expired: %v", out)
	}
}

func TestProvisioningReleaseRevokesTokenKeepsAccount(t *testing.T) {
	e := newProvTestEnv(t)
	acct := e.upsert(t, "e1", "a@x.test", "")
	tok := e.mint(t, "e1", `{}`)["token"].(string)
	rec := e.do(t, http.MethodDelete, "/api/provisioning/accounts/e1", "")
	if rec.Code != http.StatusOK || decodeMap(t, rec)["released"] != true {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads", nil, asBearer(tok)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token after release: %d", rec.Code)
	}
	if _, err := e.s.store.GetAccountByID(context.Background(), int64(acct["account_id"].(float64))); err != nil {
		t.Fatal(err)
	}
}

func TestProvisioningReleaseAfterUpload(t *testing.T) {
	e := newProvTestEnv(t)
	acct := e.upsert(t, "e1", "a@x.test", "")
	tok := e.mint(t, "e1", `{}`)["token"].(string)
	slug := pageCovUpload(t, e.s, tok, "")
	if rec := e.do(t, http.MethodDelete, "/api/provisioning/accounts/e1", ""); rec.Code != http.StatusOK {
		t.Fatalf("release: %d %s", rec.Code, rec.Body)
	}
	up, err := e.s.store.GetUpload(context.Background(), slug)
	if err != nil || up.OwnerAccountID != int64(acct["account_id"].(float64)) {
		t.Fatalf("upload = %+v, %v", up, err)
	}
}

func TestProvisioningReleaseNotFound(t *testing.T) {
	e := newProvTestEnv(t)
	wantError(t, e.do(t, http.MethodDelete, "/api/provisioning/accounts/none", ""), http.StatusNotFound, "not found")
}

func TestProvisioningOtherProvisionerCannotSeeLinks(t *testing.T) {
	e := newProvTestEnv(t)
	e.upsert(t, "e1", "a@x.test", "")
	_, keyB := newProvisionerKey(t, e.s, "B")
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/provisioning/accounts/e1/token"},
		{http.MethodDelete, "/api/provisioning/accounts/e1"},
	} {
		rec := doRequest(t, e.s, tc.method, tc.path, strings.NewReader(`{}`), asBearer(keyB), withJSON())
		wantError(t, rec, http.StatusNotFound, "not found")
	}
}

func TestProvisioningAuditHasNoSecrets(t *testing.T) {
	e := newProvTestEnv(t)
	e.upsert(t, "e1", "alice@x.test", "Alice")
	e.mint(t, "e1", `{}`)
	e.do(t, http.MethodDelete, "/api/provisioning/accounts/e1", "")
	entries, err := e.s.store.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, en := range entries {
		if !strings.HasPrefix(en.Action, "provisioning.") {
			continue
		}
		seen[en.Action] = true
		if en.Actor != "provisioner:PF" {
			t.Fatalf("actor = %q", en.Actor)
		}
		for _, bad := range []string{"peek_", "peekprov_", "@", "Alice"} {
			if strings.Contains(en.Detail, bad) {
				t.Fatalf("audit %s leaks %q: %s", en.Action, bad, en.Detail)
			}
		}
	}
	for _, a := range []string{"provisioning.account_upsert", "provisioning.token_issue", "provisioning.account_release"} {
		if !seen[a] {
			t.Fatalf("missing audit %s (have %v)", a, seen)
		}
	}
}
