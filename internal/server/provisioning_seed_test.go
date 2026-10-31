package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

const (
	seedKeyA = "peekprov_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111"
	seedKeyB = "peekprov_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2222"
)

func TestSeedRegistersFirstStart(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	if err := s.seedProvisioner(ctx, "PrivacyFence", seedKeyA); err != nil {
		t.Fatal(err)
	}
	p, err := s.store.GetProvisionerByKey(ctx, seedKeyA)
	if err != nil || p.Name != "PrivacyFence" || p.CreatedByAccountID != 0 {
		t.Fatalf("provisioner = %+v, %v", p, err)
	}
	logs, _ := s.store.ListAuditLog(ctx, 10)
	found := false
	for _, e := range logs {
		if e.Action == "provisioner registered" && e.Actor == "PEEK_PROVISIONING_KEY_FILE" {
			found = true
		}
		if strings.Contains(e.Detail, seedKeyA) {
			t.Fatal("audit leaks the key")
		}
	}
	if !found {
		t.Fatalf("no registered audit entry: %+v", logs)
	}
}

func TestSeedSameKeyNoop(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := s.seedProvisioner(ctx, "PF", seedKeyA); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := s.store.ListProvisioners(ctx)
	logs, _ := s.store.ListAuditLog(ctx, 10)
	if len(list) != 1 || len(logs) != 1 {
		t.Fatalf("providers %d, audit entries %d; want 1 and 1", len(list), len(logs))
	}
}

func TestSeedRotatesInPlaceKeepingLinks(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	ctx := context.Background()
	f := newProvisionedFixture(t, s, "PF", "u@example.test", "e1")
	if err := s.seedProvisioner(ctx, "PF", seedKeyB); err != nil {
		t.Fatal(err)
	}
	list, _ := s.store.ListProvisioners(ctx)
	if len(list) != 1 || list[0].ID != f.Provisioner.ID || list[0].Accounts != 1 {
		t.Fatalf("list = %+v", list)
	}
	if rec := doRequest(t, s, http.MethodGet, "/api/provisioning/self", nil, asBearer(f.Key)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old key = %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(f.Token)); rec.Code != http.StatusOK {
		t.Fatalf("provisioned token = %d", rec.Code)
	}
	logs, _ := s.store.ListAuditLog(ctx, 10)
	if len(logs) == 0 || logs[0].Action != "provisioner rotated" {
		t.Fatalf("audit = %+v", logs)
	}
}

func TestSeedTwoSameNameFails(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	for _, k := range []string{"peekprov_one-1111", "peekprov_two-2222"} {
		if _, err := s.store.CreateProvisioner(ctx, "PF", k, 0); err != nil {
			t.Fatal(err)
		}
	}
	err := s.seedProvisioner(ctx, "PF", seedKeyA)
	want := "PEEK_PROVISIONING_KEY_NAME matches more than one provisioner; revoke the extra ones on the Admin page"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v", err)
	}
}

func TestSeedWorksWithoutAccounts(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	if n, _ := s.store.CountAccounts(ctx); n != 0 {
		t.Fatalf("accounts = %d", n)
	}
	if err := s.seedProvisioner(ctx, "PF", seedKeyA); err != nil {
		t.Fatal(err)
	}
}

func TestSeededKeyAnswersProvisioningSelf(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	if err := s.seedProvisioner(context.Background(), "PrivacyFence", seedKeyA); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodGet, "/api/provisioning/self", nil, asBearer(seedKeyA))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"PrivacyFence"`) {
		t.Fatalf("self = %d %s", rec.Code, rec.Body)
	}
}
