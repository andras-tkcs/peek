package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestInviteLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	admin, err := s.CreateAccount(ctx, "admin@example.test", "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	used, err := s.CreateInvite(ctx, "raw-used", "cipher-used", " New@Example.test ", admin.ID, exp)
	if err != nil {
		t.Fatal(err)
	}
	if used.Email != "new@example.test" || used.Token != "cipher-used" || !used.UsedAt.IsZero() || !used.RevokedAt.IsZero() {
		t.Fatalf("invite = %+v", used)
	}
	revoked, err := s.CreateInvite(ctx, "raw-revoked", "cipher-revoked", "r@example.test", admin.ID, exp)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeInvite(ctx, used.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInvite(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { return s.ConsumeInvite(ctx, used.ID) },
		func() error { return s.ConsumeInvite(ctx, revoked.ID) },
		func() error { return s.RevokeInvite(ctx, used.ID) },
		func() error { return s.RevokeInvite(ctx, revoked.ID) },
	} {
		if err := call(); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("second transition err = %v", err)
		}
	}

	byID, err := s.GetInviteByID(ctx, used.ID)
	if err != nil || byID.UsedAt.IsZero() || !byID.RevokedAt.IsZero() {
		t.Fatalf("used invite = %+v, %v", byID, err)
	}
	byToken, err := s.GetInviteByToken(ctx, "raw-revoked")
	if err != nil || byToken.RevokedAt.IsZero() || !byToken.UsedAt.IsZero() {
		t.Fatalf("revoked invite = %+v, %v", byToken, err)
	}
	if _, err := s.GetInviteByToken(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing invite err = %v", err)
	}

	list, err := s.ListInvites(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListInvites = %+v, %v", list, err)
	}
	var sawUsed, sawRevoked bool
	for _, inv := range list {
		sawUsed = sawUsed || (inv.ID == used.ID && !inv.UsedAt.IsZero())
		sawRevoked = sawRevoked || (inv.ID == revoked.ID && !inv.RevokedAt.IsZero())
	}
	if !sawUsed || !sawRevoked {
		t.Fatalf("ListInvites missing used/revoked timestamps: %+v", list)
	}
}

func TestCreateInviteRejectsDuplicateToken(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	admin, _ := s.CreateAccount(ctx, "admin@example.test", "admin", true)
	if _, err := s.CreateInvite(ctx, "dup", "c", "a@example.test", admin.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateInvite(ctx, "dup", "c", "b@example.test", admin.ID, time.Now()); err == nil {
		t.Fatal("expected duplicate token to fail")
	}
}

func TestInviteScanErrors(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	admin, err := s.CreateAccount(ctx, "admin@example.test", "admin", true)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	inv, err := s.CreateInvite(ctx, "raw", "c", "a@example.test", admin.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	corruptInt(t, s, "invites", "created_at")
	_, err = s.ListInvites(ctx)
	wantErr(t, "ListInvites", err, errScan)
	_, err = s.GetInviteByID(ctx, inv.ID)
	wantErr(t, "GetInviteByID", err, errScan)
}
