package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
	"github.com/andras-tkcs/peek/internal/uploadquota"
)

type retentionCleanupStorage struct {
	mu      sync.Mutex
	deleted []string
	err     error
}

func (s *retentionCleanupStorage) Save(_ context.Context, _ string, _ []byte) error {
	return nil
}

func (s *retentionCleanupStorage) Open(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (s *retentionCleanupStorage) Delete(_ context.Context, slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, slug)
	return s.err
}

func (s *retentionCleanupStorage) deletedSlugs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deleted...)
}

func TestRetentionCleanupKeepsUploadWhenStorageDeleteFails(t *testing.T) {
	s, store, storage, accountID := newRetentionCleanupTestServer(t)
	storage.err = errors.New("delete blocked")
	seedExpiredRetentionUpload(t, store, accountID, "expired-page")

	s.cleanupExpired(context.Background())

	deleted := storage.deletedSlugs()
	if len(deleted) != 1 || deleted[0] != "expired-page" {
		t.Fatalf("storage deletes = %+v", deleted)
	}
	if _, err := store.GetUpload(context.Background(), "expired-page"); err != nil {
		t.Fatalf("upload should remain after storage failure: %v", err)
	}
}

func TestRetentionCleanupRemovesUploadAfterStorageDelete(t *testing.T) {
	s, store, storage, accountID := newRetentionCleanupTestServer(t)
	seedExpiredRetentionUpload(t, store, accountID, "expired-page")

	s.cleanupExpired(context.Background())

	deleted := storage.deletedSlugs()
	if len(deleted) != 1 || deleted[0] != "expired-page" {
		t.Fatalf("storage deletes = %+v", deleted)
	}
	if _, err := store.GetUpload(context.Background(), "expired-page"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected upload to be deleted, err=%v", err)
	}
}

func TestRetentionCleanupWorkerHonorsRuntimeSettingChanges(t *testing.T) {
	s, store, storage, accountID := newRetentionCleanupTestServer(t)
	if err := store.SetSetting(context.Background(), "retention_days", "0"); err != nil {
		t.Fatal(err)
	}
	seedExpiredRetentionUpload(t, store, accountID, "runtime-page")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ticks := make(chan time.Time)
	afterCleanup := make(chan struct{}, 2)
	go func() {
		defer close(done)
		s.runRetentionCleanupLoop(ctx, ticks, func() {
			afterCleanup <- struct{}{}
		})
	}()

	ticks <- time.Now()
	<-afterCleanup
	if deleted := storage.deletedSlugs(); len(deleted) != 0 {
		t.Fatalf("storage deletes while retention disabled = %+v", deleted)
	}
	if _, err := store.GetUpload(context.Background(), "runtime-page"); err != nil {
		t.Fatalf("upload should remain while retention disabled: %v", err)
	}

	if err := store.SetSetting(context.Background(), "retention_days", "1"); err != nil {
		t.Fatal(err)
	}
	ticks <- time.Now()
	<-afterCleanup
	if _, err := store.GetUpload(context.Background(), "runtime-page"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("upload was not removed after retention was enabled; err=%v deletes=%+v", err, storage.deletedSlugs())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("retention cleanup worker did not stop")
	}
}

func TestAuditRequestLogsPersistenceFailure(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, secret: strings.Repeat("0", 64)}

	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	s.auditRequest(req, "Ada", "upload.create", "slug=page")

	if !strings.Contains(logs.String(), "audit log write failed") {
		t.Fatalf("audit persistence failure was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "action=upload.create") {
		t.Fatalf("audit action was not logged: %s", logs.String())
	}
}

func newRetentionCleanupTestServer(t *testing.T) (*Server, *db.Store, *retentionCleanupStorage, int64) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetSetting(context.Background(), "retention_days", "1"); err != nil {
		t.Fatal(err)
	}
	account, err := store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	storage := &retentionCleanupStorage{}
	return &Server{store: store, storage: storage, secret: strings.Repeat("0", 64)}, store, storage, account.ID
}

func seedExpiredRetentionUpload(t *testing.T, store *db.Store, ownerID int64, slug string) {
	t.Helper()
	if err := store.CreateUploadChecked(context.Background(), slug, ownerID, 0, slug+".html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := store.Exec(`UPDATE uploads SET created_at=? WHERE slug=?`, createdAt, slug); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`UPDATE upload_versions SET created_at=? WHERE upload_id=(SELECT id FROM uploads WHERE slug=?)`, createdAt, slug); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionPrunesOldVersionsButKeepsLatest(t *testing.T) {
	ctx := context.Background()
	s, store, storage, ownerID := newRetentionCleanupTestServer(t)
	if err := store.CreateUploadChecked(ctx, "versioned", ownerID, 0, "versioned", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	u, err := store.GetUpload(ctx, "versioned")
	if err != nil {
		t.Fatal(err)
	}
	k2 := "versions/versioned/0000000000000002"
	k3 := "versions/versioned/0000000000000003"
	if _, err := store.CreateVersionChecked(ctx, u.ID, k2, 10, ownerID, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateVersionChecked(ctx, u.ID, k3, 11, ownerID, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := store.Exec(`UPDATE upload_versions SET created_at=? WHERE upload_id=? AND version IN (1,2)`, old, u.ID); err != nil {
		t.Fatal(err)
	}

	s.cleanupExpired(ctx)

	versions, err := store.ListUploadVersions(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].Version != 3 {
		t.Fatalf("versions after cleanup = %+v, want only v3", versions)
	}
	deleted := strings.Join(storage.deletedSlugs(), ",")
	if !strings.Contains(deleted, "versioned") || !strings.Contains(deleted, k2) || strings.Contains(deleted, k3) {
		t.Fatalf("deleted keys = %q, want slug and %s but not %s", deleted, k2, k3)
	}
	if _, err := store.GetUpload(ctx, "versioned"); err != nil {
		t.Fatalf("page should survive: %v", err)
	}
}

func TestAuditDetailQuotesUnsafeValues(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{[]string{"slug", "page", "name", "Q3 plan", "size", "42"}, `slug=page name="Q3 plan" size=42`},
		{[]string{"name", "x size=999 slug=evil"}, `name="x size=999 slug=evil"`},
		{[]string{"name", "a\nb"}, `name="a\nb"`},
		{[]string{"name", `say "hi"`}, `name="say \"hi\""`},
		{[]string{"name", `back\slash`}, `name="back\\slash"`},
		{[]string{"name", ""}, `name=""`},
		{[]string{"name", "café"}, `name=café`},
		{[]string{"name", "a b"}, `name="a b"`},
		{[]string{"slug"}, `slug=""`},
	}
	for _, tt := range tests {
		if got := auditDetail(tt.in...); got != tt.want {
			t.Errorf("auditDetail(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAPIUploadAuditQuotesName(t *testing.T) {
	s, tok := newHandlerTestServer(t)
	body := "<!DOCTYPE html><html><body></body></html>"
	rec := doRequest(t, s, http.MethodPost, "/api/upload?visibility=public&filename="+url.QueryEscape("x size=1 slug=evil.html"), strings.NewReader(body), asBearer(tok), func(r *http.Request) { r.Header.Set("Content-Type", "text/html") })
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("upload status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Slug == "" {
		t.Fatalf("decode slug: %v: %s", err, rec.Body.String())
	}
	entries, err := s.store.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	want := "slug=" + resp.Slug + ` name="x size=1 slug=evil.html" size=` + strconv.Itoa(len(body))
	for _, e := range entries {
		if e.Action == "upload.create" {
			if e.Detail != want {
				t.Fatalf("detail = %q, want %q", e.Detail, want)
			}
			return
		}
	}
	t.Fatal("no upload.create audit entry")
}

func TestPageCovCloseWithoutStore(t *testing.T) {
	if err := (&Server{}).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPageCovRetentionCleanupDefaultsIntervalAndStopsOnCancel(t *testing.T) {
	s := &Server{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		s.runRetentionCleanup(ctx, 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runRetentionCleanup did not stop on a cancelled context")
	}
}

func TestPageCovCleanupExpiredListFailure(t *testing.T) {
	s, store, storage, _ := newFaultServer(t)
	if err := store.SetSetting(context.Background(), "retention_days", "1"); err != nil {
		t.Fatal(err)
	}
	dropTable(t, store, "upload_versions")
	s.cleanupExpired(context.Background())
	if len(storage.objects) != 0 {
		t.Fatalf("unexpected storage writes: %v", storage.objects)
	}
}

func pageCovPrunableUpload(t *testing.T, store *db.Store, ownerID int64) (uploadID int64) {
	t.Helper()
	ctx := context.Background()
	if err := store.CreateUploadChecked(ctx, "versioned", ownerID, 0, "versioned", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	u, err := store.GetUpload(ctx, "versioned")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateVersionChecked(ctx, u.ID, "versions/versioned/2", 10, ownerID, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := store.Exec(`UPDATE upload_versions SET created_at=? WHERE upload_id=? AND version=1`, old, u.ID); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestPageCovPruneOldVersionsFailures(t *testing.T) {
	cutoff := time.Now().Add(-24 * time.Hour)

	t.Run("list fails", func(t *testing.T) {
		s, store, _, _ := newFaultServer(t)
		dropTable(t, store, "upload_versions")
		s.pruneOldVersions(context.Background(), cutoff)
	})
	t.Run("storage delete fails", func(t *testing.T) {
		s, store, storage, ownerID := newFaultServer(t)
		uploadID := pageCovPrunableUpload(t, store, ownerID)
		storage.deleteErr = errors.New("blocked")
		s.pruneOldVersions(context.Background(), cutoff)
		if _, err := store.GetUploadVersion(context.Background(), uploadID, 1); err != nil {
			t.Fatalf("version 1 should survive a storage failure: %v", err)
		}
	})
	t.Run("record delete fails", func(t *testing.T) {
		s, store, _, ownerID := newFaultServer(t)
		uploadID := pageCovPrunableUpload(t, store, ownerID)
		addFailTrigger(t, store, "upload_versions", "DELETE")
		s.pruneOldVersions(context.Background(), cutoff)
		if _, err := store.GetUploadVersion(context.Background(), uploadID, 1); err != nil {
			t.Fatalf("version 1 should survive a record failure: %v", err)
		}
	})
}
