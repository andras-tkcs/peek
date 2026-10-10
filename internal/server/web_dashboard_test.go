package server

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/puemos/peek/internal/db"
	"github.com/puemos/peek/internal/uploadquota"
	webui "github.com/puemos/peek/internal/web"
)

type dashboardDeleteStorage struct {
	deleted []string
	err     error
}

func (s *dashboardDeleteStorage) Save(_ context.Context, _ string, _ []byte) error {
	return nil
}

func (s *dashboardDeleteStorage) Open(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (s *dashboardDeleteStorage) Delete(_ context.Context, slug string) error {
	s.deleted = append(s.deleted, slug)
	return s.err
}

func TestDashboardReportsUploadListFailure(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`DROP TABLE uploads`); err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, renderer: renderer, secret: strings.Repeat("0", 64)}

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(account.ID, 10), sessionTTL)})
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "uploads could not be loaded") {
		t.Fatalf("dashboard did not report list failure: %s", rec.Body.String())
	}
}

func TestDashboardRendersGenericSuccessFlash(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, renderer: renderer, secret: strings.Repeat("0", 64)}

	req := httptest.NewRequest(http.MethodGet, "/dashboard?ok=settings+saved", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(account.ID, 10), sessionTTL)})
	rec := httptest.NewRecorder()

	s.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "settings saved") {
		t.Fatalf("dashboard did not render generic flash: %s", body)
	}
	if strings.Contains(body, "Uploaded! Share link:") {
		t.Fatalf("generic flash rendered as upload success: %s", body)
	}
}

func TestDashboardStatsRendersVisitSparkline(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	upload, err := store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatal(err)
	}
	today := bucketStart(time.Now(), 86400).Unix()
	for i, ts := range []int64{today - 86400, today} {
		if _, err := store.Exec(`INSERT INTO visits(upload_id,visitor_cookie,visitor_name,ip,user_agent,visited_at) VALUES(?,?,?,?,?,?)`,
			upload.ID, "visitor-"+strconv.Itoa(i), "", "ip", "ua", ts+3600); err != nil {
			t.Fatal(err)
		}
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, renderer: renderer, secret: strings.Repeat("0", 64)}

	req := httptest.NewRequest(http.MethodGet, "/dashboard/stats/page", nil)
	req.SetPathValue("slug", "page")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(account.ID, 10), sessionTTL)})
	rec := httptest.NewRecorder()

	s.handleDashboardStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"2 visits last 7 days",
		`aria-label="Visit trend for the last 7 days"`,
		`<circle cx=`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stats page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "Trend unavailable.") {
		t.Fatalf("stats page rendered unavailable trend: %s", body)
	}
}

func TestDashboardStatsReportsVisitQueryFailure(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(`DROP TABLE visits`); err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, renderer: renderer, secret: strings.Repeat("0", 64)}

	req := httptest.NewRequest(http.MethodGet, "/dashboard/stats/page", nil)
	req.SetPathValue("slug", "page")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(account.ID, 10), sessionTTL)})
	rec := httptest.NewRecorder()

	s.handleDashboardStats(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "stats could not be loaded") {
		t.Fatalf("stats page did not report load failure: %s", rec.Body.String())
	}
}

func TestDashboardStatsMissingUploadRendersWebError(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, renderer: renderer, secret: strings.Repeat("0", 64)}

	req := httptest.NewRequest(http.MethodGet, "/dashboard/stats/missing", nil)
	req.SetPathValue("slug", "missing")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(account.ID, 10), sessionTTL)})
	rec := httptest.NewRecorder()

	s.handleDashboardStats(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "Stats not found") {
		t.Fatalf("stats page did not render web error: %s", rec.Body.String())
	}
}

func TestDashboardUploadPassesVisibility(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, storage: &dashboardDeleteStorage{}, secret: strings.Repeat("0", 64), baseURL: "http://localhost:7700"}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range map[string]string{
		"csrf":       "csrf-token",
		"mode":       "paste",
		"name":       "private-page",
		"visibility": "private",
		"html":       "<!doctype html><html></html>",
	} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(account.ID, 10), sessionTTL)})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	rec := httptest.NewRecorder()

	s.handleDashboardUpload(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	list, err := store.ListUploadsByOwner(context.Background(), account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Visibility != "private" {
		t.Fatalf("uploads = %+v", list)
	}
}

func TestDashboardDeleteReportsDatabaseDeleteFailureAfterStorageDelete(t *testing.T) {
	s, store, storage, accountID := newDashboardDeleteTestServer(t)
	seedDashboardDeleteUpload(t, store, accountID)
	if _, err := store.Exec(`CREATE TRIGGER block_upload_delete BEFORE DELETE ON uploads BEGIN SELECT RAISE(ABORT, 'blocked delete'); END;`); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.handleDashboardDelete(rec, dashboardDeleteRequest(t, s, accountID, "page"))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := u.Query().Get("err"); got != "delete failed" {
		t.Fatalf("err query = %q, location = %q", got, loc)
	}
	if len(storage.deleted) != 1 || storage.deleted[0] != "page" {
		t.Fatalf("storage deletes = %+v", storage.deleted)
	}
	if _, err := store.GetUpload(context.Background(), "page"); err != nil {
		t.Fatalf("upload should remain after DB failure: %v", err)
	}
}

func TestDashboardDeleteStopsWhenStorageDeleteFails(t *testing.T) {
	s, store, storage, accountID := newDashboardDeleteTestServer(t)
	storage.err = errors.New("storage blocked")
	seedDashboardDeleteUpload(t, store, accountID)

	rec := httptest.NewRecorder()
	s.handleDashboardDelete(rec, dashboardDeleteRequest(t, s, accountID, "page"))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := u.Query().Get("err"); got != "delete failed" {
		t.Fatalf("err query = %q, location = %q", got, loc)
	}
	if len(storage.deleted) != 1 || storage.deleted[0] != "page" {
		t.Fatalf("storage deletes = %+v", storage.deleted)
	}
	if _, err := store.GetUpload(context.Background(), "page"); err != nil {
		t.Fatalf("upload should remain after storage failure: %v", err)
	}
}

func TestDashboardDeleteRemovesUploadAndStorageObject(t *testing.T) {
	s, store, storage, accountID := newDashboardDeleteTestServer(t)
	seedDashboardDeleteUpload(t, store, accountID)

	rec := httptest.NewRecorder()
	s.handleDashboardDelete(rec, dashboardDeleteRequest(t, s, accountID, "page"))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("location = %q", rec.Header().Get("Location"))
	}
	if len(storage.deleted) != 1 || storage.deleted[0] != "page" {
		t.Fatalf("storage deletes = %+v", storage.deleted)
	}
	if _, err := store.GetUpload(context.Background(), "page"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected upload to be deleted, err=%v", err)
	}
}

func newDashboardDeleteTestServer(t *testing.T) (*Server, *db.Store, *dashboardDeleteStorage, int64) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	storage := &dashboardDeleteStorage{}
	return &Server{store: store, storage: storage, secret: strings.Repeat("0", 64)}, store, storage, account.ID
}

func seedDashboardDeleteUpload(t *testing.T, store *db.Store, ownerID int64) {
	t.Helper()
	if err := store.CreateUploadChecked(context.Background(), "page", ownerID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
}

func dashboardDeleteRequest(t *testing.T, s *Server, accountID int64, slug string) *http.Request {
	t.Helper()
	form := url.Values{"csrf": {"csrf-token"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/delete/"+slug, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("slug", slug)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(accountID, 10), sessionTTL)})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	return req
}

func TestDashboardOffersRestrictedVisibility(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, account.ID))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `value="restricted"`) {
		t.Fatalf("status = %d, body lacks restricted radio", rec.Code)
	}
}

func dashboardPost(t *testing.T, s *Server, accountID int64, path string, form url.Values, withCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	opts := []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
		asSession(s, accountID),
	}
	if withCSRF {
		form.Set("csrf", "csrf-token")
		opts = append(opts, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
		})
	}
	return doRequest(t, s, http.MethodPost, path, strings.NewReader(form.Encode()), opts...)
}

func assertDashboardRedirect(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestDashboardVisibilitySetsPasswordAndAudits(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/visibility/page", url.Values{"visibility": {"password"}, "password": {"pw"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?ok=Password+updated+for+%2Fp%2Fpage")
	got, err := s.store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if got.Visibility != "password" {
		t.Fatalf("visibility = %q, want password", got.Visibility)
	}
	if bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte("pw")) != nil {
		t.Fatal("stored hash does not verify the password")
	}
	entries, err := s.store.ListAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "upload.visibility.set" && e.Detail == "slug=page visibility=password password=updated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit entry not found: %+v", entries)
	}
}

func TestDashboardVisibilityMakesPublic(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/visibility/page", url.Values{"visibility": {"public"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?ok=%2Fp%2Fpage+is+now+public")
	got, err := s.store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if got.Visibility != "public" || got.PasswordHash != "" {
		t.Fatalf("visibility = %q hash = %q, want public and empty", got.Visibility, got.PasswordHash)
	}
}

func TestDashboardVisibilityRejectsPasswordWithoutValue(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/visibility/page", url.Values{"visibility": {"password"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?err=password+visibility+requires+a+password")
	assertVisibilityUnchanged(t, s, "page")
}

func TestDashboardVisibilityRejectsNonOwner(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	restrictedPage(t, s, "page")
	other, err := s.store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	rec := dashboardPost(t, s, other.ID, "/dashboard/visibility/page", url.Values{"visibility": {"public"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?err=not+owner")
	assertVisibilityUnchanged(t, s, "page")
}

func TestDashboardVisibilityRejectsMissingCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/visibility/page", url.Values{"visibility": {"public"}}, false)
	assertDashboardRedirect(t, rec, "/dashboard?err=invalid+session")
	assertVisibilityUnchanged(t, s, "page")
}

func assertVisibilityUnchanged(t *testing.T, s *Server, slug string) {
	t.Helper()
	got, err := s.store.GetUpload(context.Background(), slug)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if got.Visibility != "restricted" {
		t.Fatalf("visibility = %q, want restricted", got.Visibility)
	}
}
