package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	if _, err := s.GetSetting(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing setting err = %v", err)
	}
	if err := s.SetSetting(ctx, "b", "1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, "a", "x"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, "b", "2"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.GetSetting(ctx, "b"); err != nil || v != "2" {
		t.Fatalf("GetSetting = %q, %v", v, err)
	}
	all, err := s.GetAllSettings(ctx)
	if err != nil || len(all) != 2 || all["a"] != "x" || all["b"] != "2" {
		t.Fatalf("GetAllSettings = %+v, %v", all, err)
	}
}
