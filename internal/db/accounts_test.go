package db

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestBumpSessionEpoch(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	a, err := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err != nil {
		t.Fatal(err)
	}
	if a.SessionEpoch != 0 {
		t.Fatalf("new epoch = %d", a.SessionEpoch)
	}
	for want := int64(1); want <= 2; want++ {
		got, err := s.BumpSessionEpoch(ctx, a.ID)
		if err != nil || got != want {
			t.Fatalf("bump = %d, %v; want %d", got, err, want)
		}
	}
	got, err := s.GetAccountByID(ctx, a.ID)
	if err != nil || got.SessionEpoch != 2 {
		t.Fatalf("GetAccountByID = %+v, %v", got, err)
	}
	list, err := s.ListAccounts(ctx)
	if err != nil || len(list) != 1 || list[0].SessionEpoch != 2 {
		t.Fatalf("ListAccounts = %+v, %v", list, err)
	}
	if _, err := s.BumpSessionEpoch(ctx, a.ID+100); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown id err = %v", err)
	}
}

func TestSetAccountDisabledBumpsSessionEpoch(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if _, err := s.CreateAccount(ctx, "admin@example.test", "admin", true); err != nil {
		t.Fatal(err)
	}
	a, err := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err != nil {
		t.Fatal(err)
	}
	epoch := func() int64 {
		t.Helper()
		got, err := s.GetAccountByID(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.SessionEpoch
	}
	if err := s.SetAccountDisabledChecked(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := epoch(); got != 1 {
		t.Fatalf("after disable epoch = %d", got)
	}
	if err := s.SetAccountDisabledChecked(ctx, a.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := epoch(); got != 1 {
		t.Fatalf("after enable epoch = %d", got)
	}
	if err := s.SetAccountDisabled(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := epoch(); got != 2 {
		t.Fatalf("after SetAccountDisabled epoch = %d", got)
	}
}

func TestMigrationAddsCLILoginContextAndSessionEpoch(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "peek.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.CreateAccount(ctx, "a@example.test", "a", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateCLILoginDevice(ctx, "device-code", "ABCDEFGH", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`ALTER TABLE accounts DROP COLUMN session_epoch`,
		`ALTER TABLE cli_login_devices DROP COLUMN request_ip`,
		`ALTER TABLE cli_login_devices DROP COLUMN request_user_agent`,
		`DELETE FROM schema_migrations WHERE id IN (11,12)`,
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
	for _, c := range [][2]string{{"accounts", "session_epoch"}, {"cli_login_devices", "request_ip"}, {"cli_login_devices", "request_user_agent"}} {
		if exists, _, err := s.columnInfo(c[0], c[1]); err != nil || !exists {
			t.Fatalf("column %s.%s: exists=%v err=%v", c[0], c[1], exists, err)
		}
	}
	got, err := s.GetAccountByID(ctx, a.ID)
	if err != nil || got.SessionEpoch != 0 {
		t.Fatalf("account = %+v, %v", got, err)
	}
	d, err := s.GetCLILoginByDevice(ctx, "device-code")
	if err != nil || d.RequestIP != "" {
		t.Fatalf("device = %+v, %v", d, err)
	}
	for _, id := range []int{11, 12} {
		if ok, err := s.isMigrationApplied(id); err != nil || !ok {
			t.Fatalf("migration %d applied=%v err=%v", id, ok, err)
		}
	}
}
