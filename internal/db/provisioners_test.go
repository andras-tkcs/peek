package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/uploadquota"
)

// seedLink creates a provisioner, a linked account and a token for it.
func seedLink(t *testing.T, s *Store, pname, key, ext, email string) (provID, accountID, tokenID int64) {
	t.Helper()
	ctx := context.Background()
	p, err := s.CreateProvisioner(ctx, pname, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, acct, err := s.UpsertProvisionedAccount(ctx, p.ID, ext, email, "")
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err = s.ReplaceProvisionedToken(ctx, p.ID, ext, "tok-"+ext+"-"+key, "n", 0)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID, acct.ID, tokenID
}

func TestCreateProvisionerStoresHashAndHint(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	key := "peekprov_abcdefgh1234"
	p, err := s.CreateProvisioner(context.Background(), "  PF ", key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "PF" || p.Hint != "1234" || p.CreatedAt == 0 {
		t.Fatalf("provisioner = %+v", p)
	}
	var hash string
	if err := s.QueryRow(`SELECT key_hash FROM provisioners WHERE id=?`, p.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == key || hash != HashToken(key) {
		t.Fatalf("key_hash = %q", hash)
	}
}

func TestGetProvisionerByKey(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	acct, err := s.CreateAccount(ctx, "admin@x.test", "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := s.CreateProvisioner(ctx, "PF", "peekprov_key-one-1111", acct.ID)
	got, err := s.GetProvisionerByKey(ctx, "peekprov_key-one-1111")
	if err != nil || got.ID != p.ID || got.CreatedByAccountID != acct.ID {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestGetProvisionerByKeyUnknown(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if _, err := s.GetProvisionerByKey(context.Background(), "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v, want ErrNoRows", err)
	}
}

func TestListProvisionersCountsAccounts(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	a, _ := s.CreateProvisioner(ctx, "A", "peekprov_aaaa1111", 0)
	b, _ := s.CreateProvisioner(ctx, "B", "peekprov_bbbb2222", 0)
	for i, e := range []string{"u1@x.test", "u2@x.test"} {
		acct, _ := s.CreateAccount(ctx, e, e, false)
		if _, err := s.Exec(`INSERT INTO provisioned_accounts(provisioner_id,external_id,account_id,created_at,updated_at) VALUES(?,?,?,1,1)`, a.ID, string(rune('a'+i)), acct.ID); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListProvisioners(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if list[0].ID != a.ID || list[0].Accounts != 2 || list[1].ID != b.ID || list[1].Accounts != 0 {
		t.Fatalf("list = %+v", list)
	}
}

func TestTouchProvisionerLastUsed(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	p, _ := s.CreateProvisioner(ctx, "A", "peekprov_aaaa1111", 0)
	now := time.Unix(1234567, 0)
	if err := s.TouchProvisionerLastUsed(ctx, p.ID, now); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetProvisionerByKey(ctx, "peekprov_aaaa1111")
	if got.LastUsedAt != 1234567 {
		t.Fatalf("last used = %d", got.LastUsedAt)
	}
}

func TestDeleteProvisionerRevokesTokensAndLinks(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid, accountID, _ := seedLink(t, s, "A", "peekprov_aaaa1111", "e1", "u1@x.test")
	if err := s.DeleteProvisioner(ctx, pid); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, q := range []string{`SELECT COUNT(*) FROM tokens`, `SELECT COUNT(*) FROM provisioned_accounts`, `SELECT COUNT(*) FROM provisioners`} {
		if err := s.QueryRow(q).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s = %d, %v", q, n, err)
		}
	}
	if _, err := s.GetAccountByID(ctx, accountID); err != nil {
		t.Fatalf("account should stay: %v", err)
	}
}

func TestDeleteProvisionerDetachesUploads(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid, accountID, tokenID := seedLink(t, s, "A", "peekprov_aaaa1111", "e1", "u1@x.test")
	if err := s.CreateUploadChecked(ctx, "page", accountID, tokenID, "p.html", 1, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProvisioner(ctx, pid); err != nil {
		t.Fatal(err)
	}
	var owner sql.NullInt64
	if err := s.QueryRow(`SELECT owner_token_id FROM uploads WHERE slug='page'`).Scan(&owner); err != nil || owner.Valid {
		t.Fatalf("owner_token_id = %v, %v; want NULL", owner, err)
	}
}

func TestDeleteProvisionerUnknown(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.DeleteProvisioner(context.Background(), 99); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v", err)
	}
}

func TestProvisionerWriteMethodsReportFaults(t *testing.T) {
	ctx := context.Background()
	t.Run("create", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		failOn(t, s, "provisioners", "INSERT")
		_, err := s.CreateProvisioner(ctx, "A", "peekprov_aaaa1111", 0)
		wantErr(t, "CreateProvisioner", err, errInjected)
	})
	t.Run("touch", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		p, _ := s.CreateProvisioner(ctx, "A", "peekprov_aaaa1111", 0)
		failOn(t, s, "provisioners", "UPDATE")
		wantErr(t, "Touch", s.TouchProvisionerLastUsed(ctx, p.ID, time.Now()), errInjected)
	})
	t.Run("delete provisioner row", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		p, _ := s.CreateProvisioner(ctx, "A", "peekprov_aaaa1111", 0)
		failOn(t, s, "provisioners", "DELETE")
		wantErr(t, "DeleteProvisioner", s.DeleteProvisioner(ctx, p.ID), errInjected)
	})
	t.Run("delete token", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		pid, _, _ := seedLink(t, s, "A", "peekprov_aaaa1111", "e1", "u1@x.test")
		failOn(t, s, "tokens", "DELETE")
		wantErr(t, "DeleteProvisioner", s.DeleteProvisioner(ctx, pid), errInjected)
	})
	t.Run("list scan", func(t *testing.T) {
		s := openTestStore(t)
		defer s.Close()
		s.CreateProvisioner(ctx, "A", "peekprov_aaaa1111", 0)
		corruptInt(t, s, "provisioners", "created_at")
		_, err := s.ListProvisioners(ctx)
		wantErr(t, "ListProvisioners", err, errScan)
	})
	t.Run("closed", func(t *testing.T) {
		s := openTestStore(t)
		s.Close()
		_, err := s.ListProvisioners(ctx)
		wantErr(t, "List", err, errClosed)
		wantErr(t, "Delete", s.DeleteProvisioner(ctx, 1), errClosed)
	})
}

func TestRotateProvisionerKeyKeepsLinksAndTokens(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	provID, acctID, tokenID := seedLink(t, s, "PF", "peekprov_old-key-0001", "e1", "a@x.test")
	newKey := "peekprov_new-key-9999"
	if err := s.RotateProvisionerKey(ctx, provID, newKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetProvisionerByKey(ctx, "peekprov_old-key-0001"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old key still resolves: %v", err)
	}
	p, err := s.GetProvisionerByKey(ctx, newKey)
	if err != nil || p.ID != provID || p.Hint != "9999" {
		t.Fatalf("new key = %+v, %v", p, err)
	}
	list, err := s.ListProvisioners(ctx)
	if err != nil || len(list) != 1 || list[0].Accounts != 1 {
		t.Fatalf("links lost: %+v, %v", list, err)
	}
	var gotAcct, gotToken int64
	if err := s.QueryRow(`SELECT account_id, token_id FROM provisioned_accounts WHERE provisioner_id=?`, provID).Scan(&gotAcct, &gotToken); err != nil {
		t.Fatal(err)
	}
	if gotAcct != acctID || gotToken != tokenID {
		t.Fatalf("link = account %d token %d, want %d / %d", gotAcct, gotToken, acctID, tokenID)
	}
	var n int
	if err := s.QueryRow(`SELECT COUNT(*) FROM tokens WHERE id=?`, tokenID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("token gone: %d, %v", n, err)
	}
	if err := s.RotateProvisionerKey(ctx, 9999, "peekprov_x"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown id err = %v", err)
	}
}
