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
