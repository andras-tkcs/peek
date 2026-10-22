package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
)

// grantsFixture returns a server, a restricted page, and the owner's bearer token.
func grantsFixture(t *testing.T, slug string) (*Server, *models.Upload, string) {
	t.Helper()
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, slug)
	if err := s.store.CreateTokenForAccount(context.Background(), "owner-"+slug, u.OwnerAccountID, "owner"); err != nil {
		t.Fatalf("owner token: %v", err)
	}
	return s, u, "owner-" + slug
}

func grantReq(t *testing.T, s *Server, method, slug, token, body string) (int, string) {
	t.Helper()
	rec := doRequest(t, s, method, "/api/uploads/"+slug+"/grants", strings.NewReader(body), asBearer(token), withJSON())
	return rec.Code, rec.Body.String()
}

func TestGrantsAPIAddListRemove(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-basic")
	code, body := grantReq(t, s, http.MethodPost, u.Slug, tok, `{"kind":"user","email":"  Bob@Example.com "}`)
	if code != http.StatusOK {
		t.Fatalf("add: %d %s", code, body)
	}
	var added grantOut
	if err := json.Unmarshal([]byte(body), &added); err != nil || added.Email != "bob@example.com" || added.Kind != "user" || added.ID == 0 {
		t.Fatalf("add response = %s (%v)", body, err)
	}
	// Idempotent.
	if code, body := grantReq(t, s, http.MethodPost, u.Slug, tok, `{"kind":"user","email":"bob@example.com"}`); code != http.StatusOK {
		t.Fatalf("re-add: %d %s", code, body)
	}
	rec := doRequest(t, s, http.MethodGet, "/api/uploads/"+u.Slug+"/grants", nil, asBearer(tok))
	var list []grantOut
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].Email != "bob@example.com" {
		t.Fatalf("list = %s (%v)", rec.Body.String(), err)
	}
	code, body = grantReq(t, s, http.MethodDelete, u.Slug, tok, `{"kind":"user","email":"bob@example.com"}`)
	if code != http.StatusOK || !strings.Contains(body, `"removed":true`) {
		t.Fatalf("remove: %d %s", code, body)
	}
	rec = doRequest(t, s, http.MethodGet, "/api/uploads/"+u.Slug+"/grants", nil, asBearer(tok))
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("list after remove = %s", rec.Body.String())
	}
}

func TestGrantsAPIRequiresOwnerOrAdmin(t *testing.T) {
	s, u, _ := grantsFixture(t, "g-auth")
	newAccountWithToken(t, s, "other@example.test", "other-tok", false)
	body := `{"kind":"user","email":"bob@example.com"}`
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		if code, b := grantReq(t, s, m, u.Slug, "other-tok", body); code != http.StatusForbidden || !strings.Contains(b, "not owner") {
			t.Fatalf("%s as non-owner: %d %s", m, code, b)
		}
	}
	if code, _ := grantReq(t, s, http.MethodPost, u.Slug, "dev-admin-token", body); code != http.StatusOK {
		t.Fatalf("admin add: %d", code)
	}
	if code, b := grantReq(t, s, http.MethodGet, "missing", "dev-admin-token", ""); code != http.StatusNotFound {
		t.Fatalf("missing page: %d %s", code, b)
	}
}

func TestGrantsAPIRejectsInvalidEmail(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-email")
	long := strings.Repeat("a", 255-len("@example.com")) + "@example.com"
	if len(long) != 255 {
		t.Fatalf("fixture length %d", len(long))
	}
	for _, email := range []string{"bob", "Bob <bob@example.com>", long} {
		b, _ := json.Marshal(map[string]string{"kind": "user", "email": email})
		code, resp := grantReq(t, s, http.MethodPost, u.Slug, tok, string(b))
		if code != http.StatusBadRequest || !strings.Contains(resp, "invalid email address") {
			t.Fatalf("email %q: %d %s", email, code, resp)
		}
	}
	if code, resp := grantReq(t, s, http.MethodPost, u.Slug, tok, `{"kind":"team","email":"bob@example.com"}`); code != http.StatusBadRequest || !strings.Contains(resp, "kind must be user or group") {
		t.Fatalf("bad kind: %d %s", code, resp)
	}
}

func TestGrantsAPIRejectsGroupWithoutChecker(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-nochk")
	code, resp := grantReq(t, s, http.MethodPost, u.Slug, tok, `{"kind":"group","email":"eng@example.com"}`)
	want := "group grants need Google group lookup; set PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL on the server"
	if code != http.StatusBadRequest || !strings.Contains(resp, want) {
		t.Fatalf("%d %s", code, resp)
	}
}

func TestGrantsAPIAcceptsGroupWithChecker(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-chk")
	s.groups = fakeGroups{}
	if code, resp := grantReq(t, s, http.MethodPost, u.Slug, tok, `{"kind":"group","email":"Eng@example.com"}`); code != http.StatusOK || !strings.Contains(resp, `"group"`) {
		t.Fatalf("%d %s", code, resp)
	}
}

func TestGrantsAPIRemoveMissing404(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-404")
	code, resp := grantReq(t, s, http.MethodDelete, u.Slug, tok, `{"kind":"user","email":"nobody@example.com"}`)
	if code != http.StatusNotFound || !strings.Contains(resp, "grant not found") {
		t.Fatalf("%d %s", code, resp)
	}
}

func TestGrantsAPIWritesAuditLog(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-audit")
	body := `{"kind":"user","email":"bob@example.com"}`
	grantReq(t, s, http.MethodPost, u.Slug, tok, body)
	grantReq(t, s, http.MethodDelete, u.Slug, tok, body)
	entries, err := s.store.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, e := range entries {
		found[e.Action] = e.Detail
	}
	want := "slug=g-audit kind=user email=bob@example.com"
	for _, a := range []string{"upload.grant.add", "upload.grant.remove"} {
		if found[a] != want {
			t.Fatalf("%s detail = %q, want %q", a, found[a], want)
		}
	}
}

func TestExportIncludesGrants(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-export")
	grant(t, s, u, models.UploadGrantUser, "bob@example.com")
	rec := doRequest(t, s, http.MethodGet, "/api/uploads/"+u.Slug+"/export", nil, asBearer(tok))
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Grants []struct {
			Kind, Email string
			CreatedAt   int64 `json:"created_at"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Grants) != 1 || out.Grants[0].Email != "bob@example.com" || out.Grants[0].Kind != "user" {
		t.Fatalf("grants = %s (%v)", rec.Body.String(), err)
	}
}

func TestAPICovGrantsAccessAndBadBodies(t *testing.T) {
	s, u, ownerTok := grantsFixture(t, "cov-grants")
	_ = u
	apiCovStatus(t, s, http.MethodGet, "/api/uploads/missing/grants", ownerTok, "", http.StatusNotFound)
	// A malformed body must not create or remove anything.
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		rec := doRequest(t, s, method, "/api/uploads/cov-grants/grants", strings.NewReader(`{`), asBearer(ownerTok), withJSON())
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s with bad JSON = %d: %s", method, rec.Code, rec.Body.String())
		}
	}
	grants, err := s.store.ListUploadGrants(context.Background(), u.ID)
	if err != nil || len(grants) != 0 {
		t.Fatalf("grants = %v err = %v", grants, err)
	}
}

// The oversized body stays under the global 64 KiB cap so it reaches the 8 KiB grant limit.
func TestGrantsAPIRejectsMalformedJSON(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-badjson")
	bodies := []string{`{`, `{"kind":"user","email":"` + strings.Repeat("a", 20000) + `"}`}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, b := range bodies {
			rec := doRequest(t, s, method, "/api/uploads/g-badjson/grants", strings.NewReader(b), asBearer(tok), withJSON())
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "bad json") {
				t.Fatalf("%s %.20q = %d: %s", method, b, rec.Code, rec.Body.String())
			}
		}
	}
	grants, err := s.store.ListUploadGrants(context.Background(), u.ID)
	if err != nil || len(grants) != 0 {
		t.Fatalf("grants = %v err = %v", grants, err)
	}
}

func TestAPICovGrantsDBFailures(t *testing.T) {
	s, _, ownerTok := grantsFixture(t, "cov-grants-db")
	apiCovStatus(t, s, http.MethodPost, "/api/uploads/cov-grants-db/grants", ownerTok, `{"kind":"user","email":"a@example.test"}`, http.StatusOK)
	dropTable(t, s.store, "upload_grants")
	body := `{"kind":"user","email":"a@example.test"}`
	apiCovStatus(t, s, http.MethodGet, "/api/uploads/cov-grants-db/grants", ownerTok, "", http.StatusInternalServerError)
	apiCovStatus(t, s, http.MethodPost, "/api/uploads/cov-grants-db/grants", ownerTok, body, http.StatusInternalServerError)
	apiCovStatus(t, s, http.MethodDelete, "/api/uploads/cov-grants-db/grants", ownerTok, body, http.StatusInternalServerError)
}

func TestAPIAddGrantNotified(t *testing.T) {
	s, u, tok := grantsFixture(t, "g-notify")
	fake := &fakeMailer{}
	s.mailer = fake
	configureSMTP(t, s)
	code, body := grantReq(t, s, http.MethodPost, u.Slug, tok, `{"kind":"user","email":"bob@example.com"}`)
	if code != http.StatusOK || !strings.Contains(body, `"notified":true`) || fake.sends() != 1 {
		t.Fatalf("add: %d %s sends=%d", code, body, fake.sends())
	}
	code, body = grantReq(t, s, http.MethodPost, u.Slug, tok, `{"kind":"user","email":"bob@example.com"}`)
	if code != http.StatusOK || !strings.Contains(body, `"notified":false`) || fake.sends() != 1 {
		t.Fatalf("re-add: %d %s sends=%d", code, body, fake.sends())
	}
}
