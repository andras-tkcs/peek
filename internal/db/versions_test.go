package db

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/uploadquota"
)

func seedVersionUpload(t *testing.T, s *Store, email, slug string, size int64) (accountID, uploadID int64) {
	t.Helper()
	ctx := context.Background()
	acct, err := s.CreateAccount(ctx, email, email, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUploadChecked(ctx, slug, acct.ID, 0, slug+".html", size, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUpload(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	return acct.ID, u.ID
}

func TestCreateUploadCheckedCreatesVersionOne(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "page-one", 10)
	versions, err := s.ListUploadVersions(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(versions))
	}
	v := versions[0]
	if v.Version != 1 || v.ObjectKey != "page-one" || v.Size != 10 || v.CreatedByAccountID != owner {
		t.Fatalf("unexpected version: %+v", v)
	}
	u, _ := s.GetUpload(ctx, "page-one")
	if u.LatestVersion != 1 {
		t.Fatalf("latest version = %d", u.LatestVersion)
	}
}

func TestCreateVersionCheckedAllocatesSequentialVersions(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "page-seq", 10)
	v2, err := s.CreateVersionChecked(ctx, id, "versions/page-seq/aaaaaaaaaaaaaaaa", 20, owner, uploadquota.Limits{})
	if err != nil || v2 != 2 {
		t.Fatalf("v2 = %d, %v", v2, err)
	}
	v3, err := s.CreateVersionChecked(ctx, id, "versions/page-seq/bbbbbbbbbbbbbbbb", 30, owner, uploadquota.Limits{})
	if err != nil || v3 != 3 {
		t.Fatalf("v3 = %d, %v", v3, err)
	}
	u, err := s.GetUpload(ctx, "page-seq")
	if err != nil {
		t.Fatal(err)
	}
	if u.Size != 30 || u.LatestVersion != 3 {
		t.Fatalf("upload size=%d latest=%d", u.Size, u.LatestVersion)
	}
	got, err := s.GetUploadVersion(ctx, id, 3)
	if err != nil || got.ObjectKey != "versions/page-seq/bbbbbbbbbbbbbbbb" {
		t.Fatalf("get v3: %+v, %v", got, err)
	}
	if _, err := s.GetUploadVersion(ctx, id, 9); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing version err = %v", err)
	}
}

func TestCreateVersionCheckedEnforcesOwnerStorageQuota(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	_, id := seedVersionUpload(t, s, "o@example.test", "page-quota", 60)
	actor, err := s.CreateAccount(ctx, "actor@example.test", "Actor", true)
	if err != nil {
		t.Fatal(err)
	}
	limits := uploadquota.Limits{MaxStoragePerOwner: 100}
	if _, err := s.CreateVersionChecked(ctx, id, "versions/page-quota/aaaaaaaaaaaaaaaa", 50, actor.ID, limits); !errors.Is(err, uploadquota.ErrOwnerStorageExceeded) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.CreateVersionChecked(ctx, id, "versions/page-quota/aaaaaaaaaaaaaaaa", 40, actor.ID, limits); err != nil {
		t.Fatalf("within quota: %v", err)
	}
}

func TestCreateVersionCheckedEnforcesTotalQuota(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	owner, id := seedVersionUpload(t, s, "o@example.test", "page-total", 60)
	limits := uploadquota.Limits{MaxTotalSize: 100}
	if _, err := s.CreateVersionChecked(context.Background(), id, "versions/page-total/aaaaaaaaaaaaaaaa", 50, owner, limits); !errors.Is(err, uploadquota.ErrTotalExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateVersionCheckedUnknownUpload(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	_, err := s.CreateVersionChecked(context.Background(), 9999, "versions/x/aaaaaaaaaaaaaaaa", 1, 0, uploadquota.Limits{})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v", err)
	}
}

func TestListPrunableVersionsSkipsLatest(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "page-prune", 10)
	if _, err := s.CreateVersionChecked(ctx, id, "versions/page-prune/aaaaaaaaaaaaaaaa", 10, owner, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := s.Exec(`UPDATE upload_versions SET created_at=?`, old); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListPrunableVersions(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Version != 1 {
		t.Fatalf("prunable = %+v", got)
	}
}

func TestDeleteUploadVersionRemovesItsComments(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "page-del", 10)
	if _, err := s.CreateVersionChecked(ctx, id, "versions/page-del/aaaaaaaaaaaaaaaa", 10, owner, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{1, 2} {
		if _, err := s.Exec(`INSERT INTO comments(upload_id,version,element_selector,author_name,author_cookie,body,created_at) VALUES(?,?,?,?,?,?,?)`,
			id, v, "body", "a", "c", "hi", time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteUploadVersion(ctx, id, 1); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.QueryRow(`SELECT COUNT(*) FROM comments WHERE upload_id=? AND version=1`, id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("v1 comments = %d, %v", n, err)
	}
	if err := s.QueryRow(`SELECT COUNT(*) FROM comments WHERE upload_id=? AND version=2`, id).Scan(&n); err != nil || n != 1 {
		t.Fatalf("v2 comments = %d, %v", n, err)
	}
	if _, err := s.GetUploadVersion(ctx, id, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("v1 still present: %v", err)
	}
	if err := s.DeleteUploadVersion(ctx, id, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second delete err = %v", err)
	}
}

func TestListUploadsOlderThanUsesLatestVersion(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "page-age", 10)
	if _, err := s.CreateVersionChecked(ctx, id, "versions/page-age/aaaaaaaaaaaaaaaa", 10, owner, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := s.Exec(`UPDATE uploads SET created_at=?`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exec(`UPDATE upload_versions SET created_at=? WHERE version=1`, old); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	got, err := s.ListUploadsOlderThan(ctx, cutoff)
	if err != nil || len(got) != 0 {
		t.Fatalf("fresh latest version should keep page: %v, %v", got, err)
	}
	if _, err := s.Exec(`UPDATE upload_versions SET created_at=?`, old); err != nil {
		t.Fatal(err)
	}
	got, err = s.ListUploadsOlderThan(ctx, cutoff)
	if err != nil || len(got) != 1 {
		t.Fatalf("expected page to expire: %v, %v", got, err)
	}
	// A page without version rows still expires on uploads.created_at.
	if _, err := s.Exec(`DELETE FROM upload_versions`); err != nil {
		t.Fatal(err)
	}
	got, err = s.ListUploadsOlderThan(ctx, cutoff)
	if err != nil || len(got) != 1 {
		t.Fatalf("expected versionless page to expire: %v, %v", got, err)
	}
}

func TestMigrationBackfillsUploadVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peek.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = seedVersionUpload(t, s, "o@example.test", "page-mig", 12)
	if _, err := s.Exec(`DELETE FROM upload_versions`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exec(`DELETE FROM schema_migrations WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.Query(`SELECT object_key, version FROM upload_versions`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var key string
		var version int
		if err := rows.Scan(&key, &version); err != nil {
			t.Fatal(err)
		}
		if key != "page-mig" || version != 1 {
			t.Fatalf("row = %q v%d", key, version)
		}
		n++
	}
	if n != 1 {
		t.Fatalf("expected 1 version row, got %d", n)
	}
}

func TestVersionWritesFailMidTransaction(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, table, op string
		call            func(s *Store, accountID, uploadID int64) error
	}{
		{"CreateVersionChecked insert", "upload_versions", "INSERT", func(s *Store, a, u int64) error {
			_, err := s.CreateVersionChecked(ctx, u, "k2", 5, a, uploadquota.Limits{})
			return err
		}},
		{"CreateVersionChecked size update", "uploads", "UPDATE", func(s *Store, a, u int64) error {
			_, err := s.CreateVersionChecked(ctx, u, "k2", 5, a, uploadquota.Limits{})
			return err
		}},
		{"DeleteUploadVersion comments", "comments", "DELETE", func(s *Store, _, u int64) error { return s.DeleteUploadVersion(ctx, u, 1) }},
		{"DeleteUploadVersion version", "upload_versions", "DELETE", func(s *Store, _, u int64) error { return s.DeleteUploadVersion(ctx, u, 1) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := openTestStore(t)
			t.Cleanup(func() { s.Close() })
			a, u := seedVersionUpload(t, s, "o@example.test", "v", 10)
			if _, err := s.AddComment(ctx, u, 1, "p", "", "element", "G", "c", "b", 0); err != nil {
				t.Fatal(err)
			}
			failOn(t, s, c.table, c.op)
			wantErr(t, c.name, c.call(s, a, u), errInjected)
		})
	}
}

func TestVersionScanErrorsAndVersionlessUpload(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	_, u := seedVersionUpload(t, s, "o@example.test", "v", 10)
	if _, err := s.GetUploadVersion(ctx, u, 9); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown version err = %v", err)
	}
	if got, err := s.GetUploadVersion(ctx, u, 1); err != nil || got.Version != 1 {
		t.Fatalf("GetUploadVersion = %+v, %v", got, err)
	}
	corruptInt(t, s, "upload_versions", "created_at")
	_, err := s.GetUploadVersion(ctx, u, 1)
	wantErr(t, "GetUploadVersion", err, errScan)
	_, err = s.ListUploadVersions(ctx, u)
	wantErr(t, "ListUploadVersions", err, errScan)
	if _, err := s.CreateVersionChecked(ctx, u, "k2", 1, 0, uploadquota.Limits{}); err != nil {
		t.Fatalf("anonymous actor version: %v", err)
	}
}
