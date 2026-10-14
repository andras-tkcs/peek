package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestCreateCLILoginDeviceWithContextStoresRequestContext(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if err := s.CreateCLILoginDeviceWithContext(ctx, "device-code", "ABCDEFGH", time.Now().Add(time.Minute), "203.0.113.7", "peek-cli/1.2.3"); err != nil {
		t.Fatal(err)
	}
	d, err := s.GetCLILoginByUserCode(ctx, "ABCDEFGH")
	if err != nil {
		t.Fatal(err)
	}
	if d.RequestIP != "203.0.113.7" || d.UserAgent != "peek-cli/1.2.3" || d.Status != "pending" {
		t.Fatalf("device = %+v", d)
	}
}

func TestCreateCLILoginDeviceLeavesRequestContextEmpty(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if err := s.CreateCLILoginDevice(ctx, "device-code", "ABCDEFGH", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	d, err := s.GetCLILoginByDevice(ctx, "device-code")
	if err != nil {
		t.Fatal(err)
	}
	if d.RequestIP != "" || d.UserAgent != "" {
		t.Fatalf("device = %+v", d)
	}
}

func TestCLILoginTransitions(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	a, _ := s.CreateAccount(ctx, "a@example.test", "a", false)
	exp := time.Now().Add(time.Minute)
	for _, c := range []struct{ device, code string }{{"d1", "AAAAAAAA"}, {"d2", "BBBBBBBB"}, {"d3", "CCCCCCCC"}} {
		if err := s.CreateCLILoginDevice(ctx, c.device, c.code, exp); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateCLILoginDevice(ctx, "d1", "DDDDDDDD", exp); err == nil {
		t.Fatal("expected duplicate device to fail")
	}
	if _, err := s.GetCLILoginByUserCode(ctx, "ZZZZZZZZ"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown code err = %v", err)
	}
	d1, err := s.GetCLILoginByUserCode(ctx, " aaaaaaaa ")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveCLILogin(ctx, d1.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveCLILogin(ctx, d1.ID, a.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second approve err = %v", err)
	}
	if err := s.ConsumeCLILogin(ctx, d1.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeCLILogin(ctx, d1.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second consume err = %v", err)
	}
	got, err := s.GetCLILoginByDevice(ctx, "d1")
	if err != nil || got.Status != "approved" || got.AccountID != a.ID || got.ConsumedAt.IsZero() {
		t.Fatalf("consumed device = %+v, %v", got, err)
	}
	d2, _ := s.GetCLILoginByDevice(ctx, "d2")
	if err := s.DenyCLILogin(ctx, d2.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DenyCLILogin(ctx, d2.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second deny err = %v", err)
	}
	d3, _ := s.GetCLILoginByDevice(ctx, "d3")
	if err := s.ExpireCLILogin(ctx, d3.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ExpireCLILogin(ctx, d3.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second expire err = %v", err)
	}
	if got, _ := s.GetCLILoginByDevice(ctx, "d3"); got.Status != "expired" {
		t.Fatalf("status = %q", got.Status)
	}
}

func TestCLILoginScanError(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if err := s.CreateCLILoginDevice(ctx, "d", "AAAAAAAA", time.Now()); err != nil {
		t.Fatal(err)
	}
	corruptInt(t, s, "cli_login_devices", "created_at")
	_, err := s.GetCLILoginByDevice(ctx, "d")
	wantErr(t, "GetCLILoginByDevice", err)
}
