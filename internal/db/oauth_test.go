package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestOAuthIdentityUpsertAndGet(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	a, err := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateAccount(ctx, "b@example.test", "b", false)
	if err != nil {
		t.Fatal(err)
	}
	if has, err := s.AccountHasOAuthIdentity(ctx, a.ID); err != nil || has {
		t.Fatalf("has before = %v, %v", has, err)
	}
	if _, err := s.GetOAuthIdentity(ctx, "github", "42"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing identity err = %v", err)
	}
	if err := s.UpsertOAuthIdentity(ctx, a.ID, "github", "42", " A@Example.test ", " Alice "); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetOAuthIdentity(ctx, "github", "42")
	if err != nil || got.AccountID != a.ID || got.Email != "a@example.test" || got.Name != "Alice" {
		t.Fatalf("identity = %+v, %v", got, err)
	}
	if err := s.UpsertOAuthIdentity(ctx, b.ID, "github", "42", "b@example.test", "Bob"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetOAuthIdentity(ctx, "github", "42")
	if err != nil || got.AccountID != b.ID || got.Email != "b@example.test" || got.Name != "Bob" {
		t.Fatalf("updated identity = %+v, %v", got, err)
	}
	if has, err := s.AccountHasOAuthIdentity(ctx, b.ID); err != nil || !has {
		t.Fatalf("has after = %v, %v", has, err)
	}
	if has, err := s.AccountHasOAuthIdentity(ctx, a.ID); err != nil || has {
		t.Fatalf("has after reassign = %v, %v", has, err)
	}
}

func TestOAuthIdentityScanError(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	a, err := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpsertOAuthIdentity(ctx, a.ID, "github", "1", "a@example.test", "a"); err != nil {
		t.Fatal(err)
	}
	corruptInt(t, s, "oauth_identities", "created_at")
	_, err = s.GetOAuthIdentity(ctx, "github", "1")
	wantErr(t, "GetOAuthIdentity", err, errScan)
}
