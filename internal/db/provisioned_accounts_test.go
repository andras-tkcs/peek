package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/uploadquota"
)

func newProv(t *testing.T, s *Store, name, key string) int64 {
	t.Helper()
	p, err := s.CreateProvisioner(context.Background(), name, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func TestUpsertProvisionedAccountCreatesAccount(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	link, acct, err := s.UpsertProvisionedAccount(context.Background(), pid, "e1", "alice@x.test", "Alice A")
	if err != nil {
		t.Fatal(err)
	}
	if !link.CreatedAccount || link.AccountID != acct.ID || link.TokenID != 0 {
		t.Fatalf("link = %+v", link)
	}
	if acct.Email != "alice@x.test" || acct.Name != "Alice A" || acct.IsAdmin || acct.Disabled {
		t.Fatalf("account = %+v", acct)
	}
}

func TestUpsertProvisionedAccountUsesEmailLocalPartWithoutName(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	_, acct, err := s.UpsertProvisionedAccount(context.Background(), pid, "e1", "alice@x.test", "")
	if err != nil || acct.Name != "alice" {
		t.Fatalf("acct = %+v, %v", acct, err)
	}
}

func TestUpsertProvisionedAccountAdoptsExistingNonAdmin(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	existing, _ := s.CreateAccount(ctx, "Alice@X.test", "Alice", false)
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	link, acct, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "alice@x.test", "Other Name")
	if err != nil {
		t.Fatal(err)
	}
	if link.CreatedAccount || acct.ID != existing.ID || acct.Name != "Alice" {
		t.Fatalf("link = %+v acct = %+v", link, acct)
	}
}

func TestUpsertProvisionedAccountAdoptsDisabled(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	existing, _ := s.CreateAccount(ctx, "d@x.test", "d", false)
	if _, err := s.Exec(`UPDATE accounts SET disabled=1 WHERE id=?`, existing.ID); err != nil {
		t.Fatal(err)
	}
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	link, acct, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "d@x.test", "")
	if err != nil || link.CreatedAccount || !acct.Disabled {
		t.Fatalf("link = %+v acct = %+v err = %v", link, acct, err)
	}
}

func TestUpsertProvisionedAccountRefusesAdmin(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	s.CreateAccount(ctx, "root@x.test", "root", true)
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	_, _, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "root@x.test", "")
	if !errors.Is(err, ErrProvisionAdmin) {
		t.Fatalf("err = %v", err)
	}
	if n, _ := s.CountProvisionedAccounts(ctx, pid); n != 0 {
		t.Fatalf("links = %d", n)
	}
}

func TestUpsertProvisionedAccountRefusesLinkedAccountPromotedToAdmin(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	_, acct, _ := s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
	if err := s.SetAccountAdmin(ctx, acct.ID, true); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
	if !errors.Is(err, ErrProvisionAdmin) {
		t.Fatalf("err = %v", err)
	}
}

func TestUpsertProvisionedAccountConflictOtherExternalID(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
	_, _, err := s.UpsertProvisionedAccount(ctx, pid, "e2", "a@x.test", "")
	if !errors.Is(err, ErrProvisionConflict) {
		t.Fatalf("err = %v", err)
	}
}

func TestUpsertProvisionedAccountConflictEmailChanged(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
	_, _, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "b@x.test", "")
	if !errors.Is(err, ErrProvisionConflict) {
		t.Fatalf("err = %v", err)
	}
}

func TestUpsertProvisionedAccountUpdatesName(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "Old")
	link, acct, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "New")
	if err != nil || acct.Name != "New" || !link.CreatedAccount {
		t.Fatalf("link = %+v acct = %+v err = %v", link, acct, err)
	}
	// An empty name keeps the stored one.
	_, acct, _ = s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
	if acct.Name != "New" {
		t.Fatalf("name = %q", acct.Name)
	}
	got, _ := s.GetAccountByEmail(ctx, "a@x.test")
	if got.Name != "New" {
		t.Fatalf("stored name = %q", got.Name)
	}
}

func TestReplaceProvisionedTokenDeletesPrevious(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid, _, old := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
	id, err := s.ReplaceProvisionedToken(ctx, pid, "e1", "newtoken-1234", "PF", 0)
	if err != nil || id == old {
		t.Fatalf("id = %d old = %d err = %v", id, old, err)
	}
	if _, err := s.GetTokenByID(ctx, old); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old token still there: %v", err)
	}
	if ok, _ := s.IsProvisionedToken(ctx, id); !ok {
		t.Fatal("new token not provisioned")
	}
}

func TestReplaceProvisionedTokenDetachesUploads(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid, acct, old := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
	if err := s.CreateUploadChecked(ctx, "page", acct, old, "p.html", 1, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceProvisionedToken(ctx, pid, "e1", "newtoken-1234", "PF", 0); err != nil {
		t.Fatal(err)
	}
	var owner sql.NullInt64
	if err := s.QueryRow(`SELECT owner_token_id FROM uploads WHERE slug='page'`).Scan(&owner); err != nil || owner.Valid {
		t.Fatalf("owner_token_id = %v, %v", owner, err)
	}
}

func TestReplaceProvisionedTokenWithoutLink(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	if _, err := s.ReplaceProvisionedToken(context.Background(), pid, "none", "tok-12345", "n", 0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetProvisionedAccountTokenExpiresAt(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
	link, _ := s.GetProvisionedAccount(ctx, pid, "e1")
	if link.TokenID != 0 || link.TokenExpiresAt != 0 {
		t.Fatalf("link = %+v", link)
	}
	exp := time.Now().Add(time.Hour).Unix()
	id, _ := s.ReplaceProvisionedToken(ctx, pid, "e1", "tok-12345678", "n", exp)
	link, err := s.GetProvisionedAccount(ctx, pid, "e1")
	if err != nil || link.TokenID != id || link.TokenExpiresAt != exp {
		t.Fatalf("link = %+v, %v", link, err)
	}
	if _, err := s.GetProvisionedAccount(ctx, pid, "other"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v", err)
	}
}

func TestTokenDeletedByOwnerClearsLink(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid, acct, tok := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
	if _, err := s.DeleteAccountToken(ctx, acct, tok); err != nil {
		t.Fatal(err)
	}
	link, err := s.GetProvisionedAccount(ctx, pid, "e1")
	if err != nil || link.TokenID != 0 {
		t.Fatalf("link = %+v, %v", link, err)
	}
}

func TestReleaseProvisionedAccountKeepsAccount(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid, acct, tok := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
	if err := s.ReleaseProvisionedAccount(ctx, pid, "e1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAccountByID(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetTokenByID(ctx, tok); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("token still there: %v", err)
	}
	if _, err := s.GetProvisionedAccount(ctx, pid, "e1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("link still there: %v", err)
	}
}

func TestReleaseProvisionedAccountDetachesUploads(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid, acct, tok := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
	if err := s.CreateUploadChecked(ctx, "page", acct, tok, "p.html", 1, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseProvisionedAccount(ctx, pid, "e1"); err != nil {
		t.Fatal(err)
	}
	var owner sql.NullInt64
	if err := s.QueryRow(`SELECT owner_token_id FROM uploads WHERE slug='page'`).Scan(&owner); err != nil || owner.Valid {
		t.Fatalf("owner_token_id = %v, %v", owner, err)
	}
}

func TestReleaseProvisionedAccountWithoutLink(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	if err := s.ReleaseProvisionedAccount(context.Background(), pid, "x"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v", err)
	}
}

func TestIsProvisionedToken(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	_, acct, tok := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
	other, _ := s.CreateAccountToken(ctx, acct, "other-token-1234", "mine")
	if ok, err := s.IsProvisionedToken(ctx, tok); err != nil || !ok {
		t.Fatalf("link token: %v, %v", ok, err)
	}
	if ok, err := s.IsProvisionedToken(ctx, other); err != nil || ok {
		t.Fatalf("other token: %v, %v", ok, err)
	}
}

func TestProvisionedByAccountJoinsNames(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	a := newProv(t, s, "A", "peekprov_aaaa1111")
	b := newProv(t, s, "B", "peekprov_bbbb2222")
	_, acct, _ := s.UpsertProvisionedAccount(ctx, b, "x", "a@x.test", "")
	s.UpsertProvisionedAccount(ctx, a, "y", "a@x.test", "")
	m, err := s.ProvisionedByAccount(ctx)
	if err != nil || m[acct.ID] != "A, B" || len(m) != 1 {
		t.Fatalf("m = %v, %v", m, err)
	}
}

func TestCountProvisionedAccounts(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := newProv(t, s, "PF", "peekprov_aaaa1111")
	s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
	s.UpsertProvisionedAccount(ctx, pid, "e2", "b@x.test", "")
	if n, err := s.CountProvisionedAccounts(ctx, pid); err != nil || n != 2 {
		t.Fatalf("n = %d, %v", n, err)
	}
}

func TestProvisionedAccountMethodsReportFaults(t *testing.T) {
	ctx := context.Background()
	t.Run("upsert insert account", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid := newProv(t, s, "PF", "peekprov_aaaa1111")
		failOn(t, s, "accounts", "INSERT")
		_, _, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
		wantErr(t, "upsert", err, errInjected)
	})
	t.Run("upsert insert link", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid := newProv(t, s, "PF", "peekprov_aaaa1111")
		failOn(t, s, "provisioned_accounts", "INSERT")
		_, _, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
		wantErr(t, "upsert", err, errInjected)
	})
	t.Run("upsert update", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid := newProv(t, s, "PF", "peekprov_aaaa1111")
		s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
		failOn(t, s, "accounts", "UPDATE")
		_, _, err := s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "New")
		wantErr(t, "upsert", err, errInjected)
	})
	t.Run("replace insert token", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid := newProv(t, s, "PF", "peekprov_aaaa1111")
		s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
		failOn(t, s, "tokens", "INSERT")
		_, err := s.ReplaceProvisionedToken(ctx, pid, "e1", "tok-12345678", "n", 0)
		wantErr(t, "replace", err, errInjected)
	})
	t.Run("replace delete token", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid, _, _ := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
		failOn(t, s, "tokens", "DELETE")
		_, err := s.ReplaceProvisionedToken(ctx, pid, "e1", "tok-87654321", "n", 0)
		wantErr(t, "replace", err, errInjected)
	})
	t.Run("replace update link", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid := newProv(t, s, "PF", "peekprov_aaaa1111")
		s.UpsertProvisionedAccount(ctx, pid, "e1", "a@x.test", "")
		failOn(t, s, "provisioned_accounts", "UPDATE")
		_, err := s.ReplaceProvisionedToken(ctx, pid, "e1", "tok-12345678", "n", 0)
		wantErr(t, "replace", err, errInjected)
	})
	t.Run("release delete link", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid, _, _ := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
		failOn(t, s, "provisioned_accounts", "DELETE")
		wantErr(t, "release", s.ReleaseProvisionedAccount(ctx, pid, "e1"), errInjected)
	})
	t.Run("release delete token", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid, _, _ := seedLink(t, s, "PF", "peekprov_aaaa1111", "e1", "a@x.test")
		failOn(t, s, "tokens", "DELETE")
		wantErr(t, "release", s.ReleaseProvisionedAccount(ctx, pid, "e1"), errInjected)
	})
	t.Run("closed", func(t *testing.T) {
		s := openTestStore(t)
		s.Close()
		_, _, err := s.UpsertProvisionedAccount(ctx, 1, "e", "a@x.test", "")
		wantErr(t, "upsert", err, errClosed)
		_, err = s.ReplaceProvisionedToken(ctx, 1, "e", "t", "n", 0)
		wantErr(t, "replace", err, errClosed)
		wantErr(t, "release", s.ReleaseProvisionedAccount(ctx, 1, "e"), errClosed)
		_, err = s.IsProvisionedToken(ctx, 1)
		wantErr(t, "is", err, errClosed)
		_, err = s.ProvisionedByAccount(ctx)
		wantErr(t, "by", err, errClosed)
		_, err = s.CountProvisionedAccounts(ctx, 1)
		wantErr(t, "count", err, errClosed)
		_, err = s.GetProvisionedAccount(ctx, 1, "e")
		wantErr(t, "get", err, errClosed)
	})
}
