package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestRenameUploadKeepsOldSlugAsAlias(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, id := seedVersionUpload(t, s, "o1@example.test", "first", 1)
	if err := s.RenameUpload(ctx, id, "second", "Second"); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUpload(ctx, "second")
	if err != nil || u.Name != "Second" || u.ID != id {
		t.Fatalf("GetUpload(second) = %+v, %v", u, err)
	}
	if _, err := s.GetUpload(ctx, "first"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUpload(first) err = %v", err)
	}
	if cur, err := s.ResolveSlugAlias(ctx, "first"); err != nil || cur != "second" {
		t.Fatalf("ResolveSlugAlias = %q, %v", cur, err)
	}
	if ok, err := s.UploadSlugExists(ctx, "first"); err != nil || !ok {
		t.Fatalf("UploadSlugExists(first) = %v, %v", ok, err)
	}
	v, err := s.GetUploadVersion(ctx, id, 1)
	if err != nil || v.ObjectKey != "first" {
		t.Fatalf("version = %+v, %v", v, err)
	}
}

func TestRenameUploadRejectsTakenSlug(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, a := seedVersionUpload(t, s, "o1@example.test", "a", 1)
	_, b := seedVersionUpload(t, s, "o2@example.test", "b", 1)
	if err := s.RenameUpload(ctx, a, "b", "A"); !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("err = %v, want ErrSlugTaken", err)
	}
	if err := s.RenameUpload(ctx, b, "c", "C"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameUpload(ctx, a, "b", "A"); !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("err = %v, want ErrSlugTaken for alias", err)
	}
}

func TestRenameUploadReclaimsOwnAlias(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, id := seedVersionUpload(t, s, "o1@example.test", "a", 1)
	if err := s.RenameUpload(ctx, id, "b", "B"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameUpload(ctx, id, "a", "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUpload(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSlugAlias(ctx, "a"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("alias a err = %v", err)
	}
	if cur, err := s.ResolveSlugAlias(ctx, "b"); err != nil || cur != "a" {
		t.Fatalf("alias b = %q, %v", cur, err)
	}
}

func TestRenameUploadNameOnly(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, id := seedVersionUpload(t, s, "o1@example.test", "a", 1)
	if err := s.RenameUpload(ctx, id, "a", "New name"); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUpload(ctx, "a")
	if err != nil || u.Name != "New name" {
		t.Fatalf("upload = %+v, %v", u, err)
	}
	if _, err := s.ResolveSlugAlias(ctx, "a"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("alias err = %v", err)
	}
}

func TestRenameUploadMissingUpload(t *testing.T) {
	s := openTestStore(t)
	if err := s.RenameUpload(context.Background(), 9999, "x", "x"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v, want sql.ErrNoRows", err)
	}
}

func TestSlugAliasesCascadeOnUploadDelete(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, id := seedVersionUpload(t, s, "o1@example.test", "a", 1)
	if err := s.RenameUpload(ctx, id, "b", "B"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUpload(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSlugAlias(ctx, "a"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("alias err = %v", err)
	}
	if ok, err := s.UploadSlugExists(ctx, "a"); err != nil || ok {
		t.Fatalf("UploadSlugExists(a) = %v, %v", ok, err)
	}
}
