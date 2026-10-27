package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCreateProvisionerReturnsKeyOnce(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/api/provisioners", strings.NewReader(`{"name":" PrivacyFence "}`), asBearer(admin), withJSON())
	if rec.Code != http.StatusCreated {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Key  string `json:"key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "PrivacyFence" || !strings.HasPrefix(created.Key, "peekprov_") || created.ID == 0 {
		t.Fatalf("created = %+v", created)
	}
	list := doRequest(t, s, http.MethodGet, "/api/provisioners", nil, asBearer(admin))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), created.Key) {
		t.Fatalf("list %d leaks key: %s", list.Code, list.Body)
	}
	var rows []map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("rows = %v, %v", rows, err)
	}
	if rows[0]["hint"] != created.Key[len(created.Key)-4:] || rows[0]["accounts"] != float64(0) {
		t.Fatalf("row = %v", rows[0])
	}
}

func TestCreateProvisionerRequiresName(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	for _, body := range []string{`{"name":"  "}`, `{}`, `nope`, `{"name":"` + strings.Repeat("a", 101) + `"}`} {
		rec := doRequest(t, s, http.MethodPost, "/api/provisioners", strings.NewReader(body), asBearer(admin), withJSON())
		if rec.Code != http.StatusBadRequest || policyErrorBody(t, rec.Body.Bytes()) != "name required" {
			t.Fatalf("%q: got %d %s", body, rec.Code, rec.Body)
		}
	}
}

func TestCreateProvisionerRequiresAdmin(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newAccountWithToken(t, s, "u@x.test", "peek_user-token-1234", false)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/provisioners"}, {http.MethodGet, "/api/provisioners"}, {http.MethodDelete, "/api/provisioners/1"},
	} {
		rec := doRequest(t, s, tc.method, tc.path, strings.NewReader(`{"name":"x"}`), asBearer("peek_user-token-1234"), withJSON())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s: got %d", tc.method, tc.path, rec.Code)
		}
	}
}

func TestDeleteProvisionerRevokesItsTokens(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	f := newProvisionedFixture(t, s, "PF", "u@x.test", "e1")
	if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(f.Token)); rec.Code != http.StatusOK {
		t.Fatalf("token before revoke: %d", rec.Code)
	}
	rec := doRequest(t, s, http.MethodDelete, "/api/provisioners/"+jsonID(f.Provisioner.ID), nil, asBearer(admin))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"revoked"`) {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(f.Token)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token after revoke: %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, "/api/provisioning/self", nil, asBearer(f.Key)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("key after revoke: %d", rec.Code)
	}
	if _, err := s.store.GetAccountByID(context.Background(), f.AccountID); err != nil {
		t.Fatalf("account should stay: %v", err)
	}
}

func jsonID(id int64) string {
	b, _ := json.Marshal(id)
	return string(b)
}

func TestDeleteProvisionerNotFound(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodDelete, "/api/provisioners/99", nil, asBearer(admin))
	if rec.Code != http.StatusNotFound || policyErrorBody(t, rec.Body.Bytes()) != "not found" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestDeleteProvisionerInvalidID(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodDelete, "/api/provisioners/abc", nil, asBearer(admin))
	if rec.Code != http.StatusBadRequest || policyErrorBody(t, rec.Body.Bytes()) != "invalid id" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestProvisionerAuditHasNoKey(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/api/provisioners", strings.NewReader(`{"name":"PF"}`), asBearer(admin), withJSON())
	var created struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	doRequest(t, s, http.MethodDelete, "/api/provisioners/"+jsonID(created.ID), nil, asBearer(admin))
	entries, err := s.store.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if strings.Contains(e.Detail, "peekprov_") || strings.Contains(e.Actor, "peekprov_") {
			t.Fatalf("audit leaks key: %+v", e)
		}
		seen[e.Action] = true
	}
	if !seen["provisioner.create"] || !seen["provisioner.revoke"] {
		t.Fatalf("audit actions = %v", seen)
	}
}
