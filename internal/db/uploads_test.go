package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/models"
	"github.com/andras-tkcs/peek/internal/uploadquota"
)

func TestUploadQueriesAndMutations(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	owner, err := s.CreateAccount(ctx, "o@example.test", "o", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, "owner-token-1234", "t", false, 0); err != nil {
		t.Fatal(err)
	}
	tok, err := s.GetToken(ctx, "owner-token-1234")
	if err != nil {
		t.Fatal(err)
	}
	// An empty visibility defaults to password; a token id is recorded.
	if err := s.CreateUploadChecked(ctx, "one", owner.ID, tok.ID, "one.html", 100, "", "hash", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUploadChecked(ctx, "two", owner.ID, 0, "two.html", 50, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	one, err := s.GetUpload(ctx, "one")
	if err != nil || one.Visibility != models.UploadVisibilityPassword || one.OwnerTokenID != tok.ID || one.LatestVersion != 1 {
		t.Fatalf("upload one = %+v, %v", one, err)
	}
	byID, err := s.GetUploadByID(ctx, one.ID)
	if err != nil || byID.Slug != "one" {
		t.Fatalf("GetUploadByID = %+v, %v", byID, err)
	}
	if _, err := s.GetUploadByID(ctx, one.ID+100); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown id err = %v", err)
	}
	if all, err := s.ListAllUploads(ctx); err != nil || len(all) != 2 {
		t.Fatalf("ListAllUploads = %+v, %v", all, err)
	}
	if mine, err := s.ListUploadsByOwner(ctx, owner.ID); err != nil || len(mine) != 2 {
		t.Fatalf("ListUploadsByOwner = %+v, %v", mine, err)
	}
	if n, err := s.CountUploads(ctx); err != nil || n != 2 {
		t.Fatalf("CountUploads = %d, %v", n, err)
	}
	if n, err := s.CountUploadsByOwner(ctx, owner.ID); err != nil || n != 2 {
		t.Fatalf("CountUploadsByOwner = %d, %v", n, err)
	}
	if n, err := s.SumUploadSizes(ctx); err != nil || n != 150 {
		t.Fatalf("SumUploadSizes = %d, %v", n, err)
	}
	if n, err := s.SumUploadSizesByOwner(ctx, owner.ID); err != nil || n != 150 {
		t.Fatalf("SumUploadSizesByOwner = %d, %v", n, err)
	}
	if old, err := s.ListUploadsOlderThan(ctx, time.Now().Add(time.Hour)); err != nil || len(old) != 2 {
		t.Fatalf("ListUploadsOlderThan = %+v, %v", old, err)
	}
	if exists, err := s.UploadSlugExists(ctx, "one"); err != nil || !exists {
		t.Fatalf("UploadSlugExists = %v, %v", exists, err)
	}
	if exists, err := s.UploadSlugExists(ctx, "nope"); err != nil || exists {
		t.Fatalf("UploadSlugExists missing = %v, %v", exists, err)
	}

	if err := s.SetUploadVisibility(ctx, one.ID, "public", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUploadByID(ctx, one.ID); got.Visibility != "public" || got.PasswordHash != "" {
		t.Fatalf("after visibility = %+v", got)
	}
	if err := s.SetUploadVisibility(ctx, one.ID+100, "public", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("visibility unknown err = %v", err)
	}
	if err := s.DeleteUpload(ctx, one.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUpload(ctx, one.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second delete err = %v", err)
	}
}

func TestCreateUploadCheckedQuotas(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	owner, _ := s.CreateAccount(ctx, "o@example.test", "o", false)
	create := func(slug string, size int64, lim uploadquota.Limits) error {
		return s.CreateUploadChecked(ctx, slug, owner.ID, 0, slug+".html", size, "public", "", lim)
	}
	if err := create("a", 60, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := create("b", 50, uploadquota.Limits{MaxTotalSize: 100}); !errors.Is(err, uploadquota.ErrTotalExceeded) {
		t.Fatalf("total quota err = %v", err)
	}
	if err := create("b", 1, uploadquota.Limits{MaxUploadsPerOwner: 1}); !errors.Is(err, uploadquota.ErrOwnerCountExceeded) {
		t.Fatalf("count quota err = %v", err)
	}
	if err := create("b", 50, uploadquota.Limits{MaxStoragePerOwner: 100}); !errors.Is(err, uploadquota.ErrOwnerStorageExceeded) {
		t.Fatalf("storage quota err = %v", err)
	}
	if err := create("b", 40, uploadquota.Limits{MaxTotalSize: 100, MaxUploadsPerOwner: 2, MaxStoragePerOwner: 100}); err != nil {
		t.Fatalf("within quotas: %v", err)
	}
	if err := create("a", 1, uploadquota.Limits{}); err == nil {
		t.Fatal("expected duplicate slug to fail")
	}
}

func TestCreateUploadCheckedFailsMidTransaction(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"uploads", "upload_versions"} {
		t.Run(table, func(t *testing.T) {
			s := openTestStore(t)
			t.Cleanup(func() { s.Close() })
			owner, _ := s.CreateAccount(ctx, "o@example.test", "o", false)
			failOn(t, s, table, "INSERT")
			wantErr(t, "CreateUploadChecked", s.CreateUploadChecked(ctx, "x", owner.ID, 0, "x.html", 1, "public", "", uploadquota.Limits{}))
			if n, _ := s.CountUploads(ctx); n != 0 {
				t.Fatalf("upload row survived the failed transaction: %d", n)
			}
		})
	}
}

func TestUploadScanErrors(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	owner, _ := s.CreateAccount(ctx, "o@example.test", "o", false)
	if err := s.CreateUploadChecked(ctx, "x", owner.ID, 0, "x.html", 1, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	corruptInt(t, s, "uploads", "created_at")
	_, err := s.ListAllUploads(ctx)
	wantErr(t, "ListAllUploads", err)
	_, err = s.GetUpload(ctx, "x")
	wantErr(t, "GetUpload", err)
}
