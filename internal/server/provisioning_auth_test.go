package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
)

// provisionedFixture is a provisioner with one linked account and a minted token.
type provisionedFixture struct {
	Provisioner *models.Provisioner
	Key         string
	AccountID   int64
	Token       string
	TokenID     int64
}

// newProvisionedFixture creates a provisioner named name and links email under
// external id ext with a minted token, all through the store.
func newProvisionedFixture(t *testing.T, s *Server, name, email, ext string) provisionedFixture {
	t.Helper()
	ctx := context.Background()
	key, err := newProvisioningKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.store.CreateProvisioner(ctx, name, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, acct, err := s.store.UpsertProvisionedAccount(ctx, p.ID, ext, email, "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := newAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err := s.store.ReplaceProvisionedToken(ctx, p.ID, ext, token, name, 0)
	if err != nil {
		t.Fatal(err)
	}
	return provisionedFixture{Provisioner: p, Key: key, AccountID: acct.ID, Token: token, TokenID: tokenID}
}

func newProvisionerKey(t *testing.T, s *Server, name string) (*models.Provisioner, string) {
	t.Helper()
	key, err := newProvisioningKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.store.CreateProvisioner(context.Background(), name, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	return p, key
}

func TestAuthProvisionerMissingToken(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodGet, "/api/provisioning/self", nil)
	if rec.Code != http.StatusUnauthorized || policyErrorBody(t, rec.Body.Bytes()) != "missing token" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestAuthProvisionerRejectsOrdinaryToken(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	newAccountWithToken(t, s, "u@x.test", "peek_user-token-1234", false)
	for _, tok := range []string{"peek_user-token-1234", admin} {
		rec := doRequest(t, s, http.MethodGet, "/api/provisioning/self", nil, asBearer(tok))
		if rec.Code != http.StatusUnauthorized || policyErrorBody(t, rec.Body.Bytes()) != "invalid token" {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	}
}

func TestAuthProvisionerUnknownKey(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodGet, "/api/provisioning/self", nil, asBearer("peekprov_nope"))
	if rec.Code != http.StatusUnauthorized || policyErrorBody(t, rec.Body.Bytes()) != "invalid token" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestAuthProvisionerAcceptsKey(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	p, key := newProvisionerKey(t, s, "PF")
	var seen *models.Provisioner
	h := s.authProvisioner(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = requireProvisioner(w, r)
		w.WriteHeader(http.StatusNoContent)
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x", h)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || seen == nil || seen.ID != p.ID {
		t.Fatalf("got %d, seen %+v", rec.Code, seen)
	}
	list, _ := s.store.ListProvisioners(context.Background())
	if list[0].LastUsedAt == 0 {
		t.Fatal("last used not recorded")
	}
}

func TestRequireProvisionerWithoutContext(t *testing.T) {
	rec := httptest.NewRecorder()
	if _, ok := requireProvisioner(rec, httptest.NewRequest(http.MethodGet, "/", nil)); ok || rec.Code != http.StatusInternalServerError {
		t.Fatalf("got ok=%v code=%d", ok, rec.Code)
	}
}

func TestProvisioningKeyRejectedByAuthToken(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	_, key := newProvisionerKey(t, s, "PF")
	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(key))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	rec = doRequest(t, s, http.MethodGet, "/api/provisioners", nil, asBearer(key))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin route got %d", rec.Code)
	}
}

func TestProvisioningKeyRejectedByMetrics(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	_, key := newProvisionerKey(t, s, "PF")
	rec := doRequest(t, s, http.MethodGet, "/metrics", nil, asBearer(key))
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "peek_") {
		t.Fatalf("got %d", rec.Code)
	}
}
