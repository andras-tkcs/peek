package db

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

const testKey = "peek_abcdefghijklmnopqrstuvwxyz12a1b2"

func openTokenTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func insertTokenUpload(t *testing.T, s *Store, accountID, tokenID int64) {
	t.Helper()
	if _, err := s.Exec(`INSERT INTO uploads(slug,owner_account_id,owner_token_id,filename,size,created_at) VALUES('s1',?,?,'f.html',1,0)`, accountID, tokenID); err != nil {
		t.Fatal(err)
	}
}

func uploadOwnerToken(t *testing.T, s *Store) sql.NullInt64 {
	t.Helper()
	var v sql.NullInt64
	if err := s.QueryRow(`SELECT owner_token_id FROM uploads WHERE slug='s1'`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTokenHint(t *testing.T) {
	if got := TokenHint(testKey); got != "a1b2" {
		t.Fatalf("hint = %q", got)
	}
	for _, short := range []string{"short", ""} {
		if got := TokenHint(short); got != "" {
			t.Fatalf("hint(%q) = %q", short, got)
		}
	}
}

func TestCreateAccountTokenStoresHashAndHint(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	a, err := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateAccount(ctx, "b@example.test", "b", false)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateAccountToken(ctx, a.ID, testKey, "QA runner")
	if err != nil || id <= 0 {
		t.Fatalf("create = %d, %v", id, err)
	}
	var hash, hint string
	if err := s.QueryRow(`SELECT token, hint FROM tokens WHERE id=?`, id).Scan(&hash, &hint); err != nil {
		t.Fatal(err)
	}
	if hash != HashToken(testKey) || hint != "a1b2" {
		t.Fatalf("stored %q %q", hash, hint)
	}
	tok, err := s.GetToken(ctx, testKey)
	if err != nil || tok.LastUsedAt != 0 {
		t.Fatalf("GetToken = %+v, %v", tok, err)
	}
	keys, err := s.ListAccountTokens(ctx, a.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("list = %+v, %v", keys, err)
	}
	k := keys[0]
	if k.ID != id || k.Name != "QA runner" || k.Hint != "a1b2" || k.LastUsedAt != 0 {
		t.Fatalf("key = %+v", k)
	}
	other, err := s.ListAccountTokens(ctx, b.ID)
	if err != nil || len(other) != 0 {
		t.Fatalf("other list = %+v, %v", other, err)
	}
}

func TestCreateTokenForAccountWritesHint(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	a, _ := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err := s.CreateTokenForAccount(ctx, "cli-token-0123456789", a.ID, "CLI login"); err != nil {
		t.Fatal(err)
	}
	var name, hint string
	if err := s.QueryRow(`SELECT name, hint FROM tokens WHERE account_id=?`, a.ID).Scan(&name, &hint); err != nil {
		t.Fatal(err)
	}
	if name != "CLI login" || hint != "6789" {
		t.Fatalf("name=%q hint=%q", name, hint)
	}
}

func TestRegenerateAccountTokenReplacesSecret(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	a, _ := s.CreateAccount(ctx, "a@example.test", "a", false)
	b, _ := s.CreateAccount(ctx, "b@example.test", "b", false)
	id, err := s.CreateAccountToken(ctx, a.ID, testKey, "QA runner")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := s.ListAccountTokens(ctx, a.ID)
	newKey := "peek_ZYXWVUTSRQPONMLKJIHGFEDCBA98z9y8"
	k, err := s.RegenerateAccountToken(ctx, a.ID, id, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetToken(ctx, testKey); err == nil {
		t.Fatal("old key still works")
	}
	tok, err := s.GetToken(ctx, newKey)
	if err != nil || tok.ID != id {
		t.Fatalf("new key: %+v, %v", tok, err)
	}
	if k.Name != "QA runner" || !k.CreatedAt.Equal(before[0].CreatedAt) || k.Hint != "z9y8" || k.LastUsedAt != 0 {
		t.Fatalf("key = %+v", k)
	}
	if _, err := s.RegenerateAccountToken(ctx, b.ID, id, "peek_otherotherotherotherotherother00"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign regenerate err = %v", err)
	}
	if _, err := s.GetToken(ctx, newKey); err != nil {
		t.Fatalf("new key broken: %v", err)
	}
}

func TestDeleteAccountTokenDetachesUploads(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	a, _ := s.CreateAccount(ctx, "a@example.test", "a", false)
	b, _ := s.CreateAccount(ctx, "b@example.test", "b", false)
	id, err := s.CreateAccountToken(ctx, a.ID, testKey, "QA runner")
	if err != nil {
		t.Fatal(err)
	}
	insertTokenUpload(t, s, a.ID, id)
	if _, err := s.DeleteAccountToken(ctx, b.ID, id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign delete err = %v", err)
	}
	if _, err := s.GetToken(ctx, testKey); err != nil {
		t.Fatalf("token gone: %v", err)
	}
	k, err := s.DeleteAccountToken(ctx, a.ID, id)
	if err != nil || k.Name != "QA runner" {
		t.Fatalf("delete = %+v, %v", k, err)
	}
	if _, err := s.GetToken(ctx, testKey); err == nil {
		t.Fatal("token still exists")
	}
	if v := uploadOwnerToken(t, s); v.Valid {
		t.Fatalf("owner_token_id = %v", v)
	}
}

func TestDeleteTokenCheckedDetachesUploads(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if err := s.CreateToken(ctx, "plain-token-0123456789", "bot", false, 0); err != nil {
		t.Fatal(err)
	}
	tok, err := s.GetToken(ctx, "plain-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	insertTokenUpload(t, s, tok.AccountID, tok.ID)
	if _, err := s.DeleteTokenChecked(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if v := uploadOwnerToken(t, s); v.Valid {
		t.Fatalf("owner_token_id = %v", v)
	}
}

func TestTouchTokenLastUsedThrottles(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	a, _ := s.CreateAccount(ctx, "a@example.test", "a", false)
	id, _ := s.CreateAccountToken(ctx, a.ID, testKey, "k")
	now := time.Unix(1_800_000_000, 0)
	lastUsed := func() int64 {
		tok, err := s.GetToken(ctx, testKey)
		if err != nil {
			t.Fatal(err)
		}
		return tok.LastUsedAt
	}
	steps := []struct {
		at   time.Time
		want int64
	}{
		{now, now.Unix()},
		{now.Add(30 * time.Second), now.Unix()},
		{now.Add(61 * time.Second), now.Unix() + 61},
	}
	for i, st := range steps {
		if err := s.TouchTokenLastUsed(ctx, id, st.at); err != nil {
			t.Fatal(err)
		}
		if got := lastUsed(); got != st.want {
			t.Fatalf("step %d: last_used_at = %d, want %d", i, got, st.want)
		}
	}
}

func TestMigrationAddsTokenHintLastUsed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "peek.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.CreateAccount(ctx, "a@example.test", "a", false)
	id, err := s.CreateAccountToken(ctx, a.ID, testKey, "k")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`ALTER TABLE tokens DROP COLUMN hint`,
		`ALTER TABLE tokens DROP COLUMN last_used_at`,
		`DELETE FROM schema_migrations WHERE id=10`,
	} {
		if _, err := s.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, col := range []string{"hint", "last_used_at"} {
		if exists, _, err := s.columnInfo("tokens", col); err != nil || !exists {
			t.Fatalf("column %s: exists=%v err=%v", col, exists, err)
		}
	}
	var hint sql.NullString
	var used sql.NullInt64
	if err := s.QueryRow(`SELECT hint, last_used_at FROM tokens WHERE id=?`, id).Scan(&hint, &used); err != nil {
		t.Fatal(err)
	}
	if hint.Valid || used.Valid {
		t.Fatalf("hint=%v used=%v", hint, used)
	}
	if _, err := s.GetToken(ctx, testKey); err != nil {
		t.Fatal(err)
	}
}

func TestCreateAccountTokenExpiringStoresExpiry(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	a, err := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	if _, err := s.CreateAccountTokenExpiring(ctx, a.ID, "future-token-0123456789", "future", exp); err != nil {
		t.Fatal(err)
	}
	tk, err := s.GetToken(ctx, "future-token-0123456789")
	if err != nil || tk.ExpiresAt != exp {
		t.Fatalf("GetToken = %+v, %v", tk, err)
	}
	keys, err := s.ListAccountTokens(ctx, a.ID)
	if err != nil || len(keys) != 1 || keys[0].ExpiresAt != exp {
		t.Fatalf("ListAccountTokens = %+v, %v", keys, err)
	}
	if _, err := s.CreateAccountTokenExpiring(ctx, a.ID, "past-token-0123456789", "past", time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetToken(ctx, "past-token-0123456789"); err == nil {
		t.Fatal("expired token was returned")
	}
}

func TestIsHashed(t *testing.T) {
	good := HashToken("x")
	if !isHashed(good) {
		t.Fatalf("hash %q not recognised", good)
	}
	for _, bad := range []string{"", "short", good + "0", good[:63] + "G", good[:63] + "Z"} {
		if isHashed(bad) {
			t.Fatalf("%q recognised as a hash", bad)
		}
	}
}

func TestTokenCountsAndLookups(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if err := s.CreateToken(ctx, "admin-token-0001", " admin ", true, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, "user-token-0002", "user", false, 0); err != nil {
		t.Fatal(err)
	}
	acct, _ := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err := s.CreateTokenForAccount(ctx, "acct-token-0003", acct.ID, "  "); err != nil {
		t.Fatal(err)
	}
	if id, err := s.CreateAccountToken(ctx, acct.ID, "acct-token-0004", ""); err != nil || id == 0 {
		t.Fatalf("empty name token = %d, %v", id, err)
	}
	if n, err := s.CountTokens(ctx); err != nil || n != 4 {
		t.Fatalf("CountTokens = %d, %v", n, err)
	}
	if n, err := s.CountAdminTokens(ctx); err != nil || n != 1 {
		t.Fatalf("CountAdminTokens = %d, %v", n, err)
	}
	list, err := s.ListTokens(ctx)
	if err != nil || len(list) != 4 || list[0].Name != "admin" || !list[0].IsAdmin {
		t.Fatalf("ListTokens = %+v, %v", list, err)
	}
	byID, err := s.GetTokenByID(ctx, list[1].ID)
	if err != nil || byID.Name != "user" {
		t.Fatalf("GetTokenByID = %+v, %v", byID, err)
	}
	if _, err := s.GetTokenByID(ctx, 9999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown id err = %v", err)
	}
	keys, err := s.ListAccountTokens(ctx, acct.ID)
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListAccountTokens = %+v, %v", keys, err)
	}
	var sawDefault bool
	for _, k := range keys {
		sawDefault = sawDefault || k.Name == "API token"
	}
	if !sawDefault {
		t.Fatalf("default token name missing: %+v", keys)
	}
	if err := s.DeleteToken(ctx, list[1].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteToken(ctx, list[1].ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second delete err = %v", err)
	}
}

func TestDeleteTokenCheckedProtectsLastAdminToken(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if err := s.CreateToken(ctx, "admin-token-0001", "admin", true, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, "user-token-0002", "user", false, 0); err != nil {
		t.Fatal(err)
	}
	admin, _ := s.GetToken(ctx, "admin-token-0001")
	user, _ := s.GetToken(ctx, "user-token-0002")
	if _, err := s.DeleteTokenChecked(ctx, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin token err = %v", err)
	}
	if _, err := s.DeleteTokenChecked(ctx, 9999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown token err = %v", err)
	}
	got, err := s.DeleteTokenChecked(ctx, user.ID)
	if err != nil || got.Name != "user" {
		t.Fatalf("delete user token = %+v, %v", got, err)
	}
}

func TestTokenWritesFailMidTransaction(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, table, op string
		call            func(s *Store, accountID, tokenID int64) error
	}{
		{"CreateToken account insert", "accounts", "INSERT", func(s *Store, _, _ int64) error { return s.CreateToken(ctx, "new-token-0009", "n", false, 0) }},
		{"CreateToken token insert", "tokens", "INSERT", func(s *Store, _, _ int64) error { return s.CreateToken(ctx, "new-token-0009", "n", false, 0) }},
		{"RegenerateAccountToken update", "tokens", "UPDATE", func(s *Store, a, k int64) error {
			_, err := s.RegenerateAccountToken(ctx, a, k, "regen-token-0009")
			return err
		}},
		{"DeleteAccountToken detach", "uploads", "UPDATE", func(s *Store, a, k int64) error { _, err := s.DeleteAccountToken(ctx, a, k); return err }},
		{"DeleteAccountToken delete", "tokens", "DELETE", func(s *Store, a, k int64) error { _, err := s.DeleteAccountToken(ctx, a, k); return err }},
		{"DeleteTokenChecked detach", "uploads", "UPDATE", func(s *Store, _, k int64) error { _, err := s.DeleteTokenChecked(ctx, k); return err }},
		{"DeleteTokenChecked delete", "tokens", "DELETE", func(s *Store, _, k int64) error { _, err := s.DeleteTokenChecked(ctx, k); return err }},
		{"TouchTokenLastUsed", "tokens", "UPDATE", func(s *Store, _, k int64) error { return s.TouchTokenLastUsed(ctx, k, time.Now()) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := openTokenTestStore(t)
			acct, err := s.CreateAccount(ctx, "a@example.test", "a", false)
			if err != nil {
				t.Fatalf("seed: %v", err)
			}
			id, err := s.CreateAccountToken(ctx, acct.ID, "seed-token-0001", "seed")
			if err != nil {
				t.Fatal(err)
			}
			insertTokenUpload(t, s, acct.ID, id) // row-level triggers need a row to fire on
			failOn(t, s, c.table, c.op)
			wantErr(t, c.name, c.call(s, acct.ID, id), errInjected)
		})
	}
}

func TestTokenScanErrors(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	acct, err := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	id, err := s.CreateAccountToken(ctx, acct.ID, "seed-token-0001", "seed")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	corruptInt(t, s, "tokens", "created_at")
	_, err = s.ListTokens(ctx)
	wantErr(t, "ListTokens", err, errScan)
	_, err = s.GetTokenByID(ctx, id)
	wantErr(t, "GetTokenByID", err, errScan)
	_, err = s.ListAccountTokens(ctx, acct.ID)
	wantErr(t, "ListAccountTokens", err, errScan)
	_, err = s.DeleteTokenChecked(ctx, id)
	wantErr(t, "DeleteTokenChecked", err, errScan)
}
