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

	"github.com/andras-tkcs/peek/internal/db"
	"github.com/andras-tkcs/peek/internal/models"
	"github.com/andras-tkcs/peek/internal/uploadquota"
	webui "github.com/andras-tkcs/peek/internal/web"
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

	req := httptest.NewRequest(http.MethodGet, "/dashboard?ok=settings_saved", nil)
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
	if err := store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", uploadquota.Limits{}); err != nil {
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
	if err := store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", uploadquota.Limits{}); err != nil {
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
		"visibility": "signed-in",
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
	if len(list) != 1 || list[0].Visibility != "signed-in" {
		t.Fatalf("uploads = %+v", list)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard?uploaded="+list[0].Slug {
		t.Fatalf("Location = %q", loc)
	}
}

func TestDashboardIgnoresFreeTextFlash(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	viewer, err := s.store.CreateAccount(context.Background(), "viewer@example.test", "Viewer", false)
	if err != nil {
		t.Fatal(err)
	}

	rec := doRequest(t, s, http.MethodGet,
		"/dashboard?err=Your+session+expired.+Call+IT&ok=Pay+now&uploaded=https%3A%2F%2Fevil.example%2Fx",
		nil, asSession(s, viewer.ID))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, banned := range []string{"Call IT", "Pay now", "evil.example", "Uploaded! Share link:"} {
		if strings.Contains(body, banned) {
			t.Fatalf("dashboard rendered %q from the query string", banned)
		}
	}
}

func TestDashboardUploadedFlashShowsOwnUploadLink(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "page", models.UploadVisibilityPublic)

	rec := doRequest(t, s, http.MethodGet, "/dashboard?uploaded=page", nil, asSession(s, u.OwnerAccountID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Uploaded! Share link:") || !strings.Contains(body, s.baseURL+"/p/page") {
		t.Fatalf("owner dashboard missing share link: %s", body)
	}

	other, err := s.store.CreateAccount(context.Background(), "other@example.test", "Other", false)
	if err != nil {
		t.Fatal(err)
	}
	rec = doRequest(t, s, http.MethodGet, "/dashboard?uploaded=page", nil, asSession(s, other.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Uploaded! Share link:") {
		t.Fatal("another account's dashboard rendered the upload link")
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
	if got := u.Query().Get("err"); got != "delete_failed" {
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
	if got := u.Query().Get("err"); got != "delete_failed" {
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
	if err := store.CreateUploadChecked(context.Background(), "page", ownerID, 0, "page.html", 42, "public", uploadquota.Limits{}); err != nil {
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

func TestDashboardVisibilityAudits(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/visibility/page", url.Values{"visibility": {"signed-in"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?ok=visibility_set&slug=page")
	got, err := s.store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if got.Visibility != "signed-in" {
		t.Fatalf("visibility = %q, want signed-in", got.Visibility)
	}
	entries, err := s.store.ListAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "upload.visibility.set" && e.Detail == "slug=page visibility=signed-in" {
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
	assertDashboardRedirect(t, rec, "/dashboard?ok=visibility_set&slug=page")
	got, err := s.store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if got.Visibility != "public" {
		t.Fatalf("visibility = %q, want public", got.Visibility)
	}
}

func TestDashboardVisibilityRejectsPassword(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/visibility/page", url.Values{"visibility": {"password"}, "password": {"pw"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?err=upload_invalid_visibility")
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
	assertDashboardRedirect(t, rec, "/dashboard?err=not_owner")
	assertVisibilityUnchanged(t, s, "page")
}

func TestDashboardVisibilityRejectsMissingCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/visibility/page", url.Values{"visibility": {"public"}}, false)
	assertDashboardRedirect(t, rec, "/dashboard?err=invalid_session")
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

func TestDashboardVisibilityRestrictedReopensDialog(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "page", "public")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/visibility/page", url.Values{"visibility": {"restricted"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?manage=page&ok=visibility_set&slug=page")
}

func TestDashboardListsGrantsInAccessDialog(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	grant(t, s, u, models.UploadGrantUser, "alice@example.com")
	get := func() string {
		rec := doRequest(t, s, http.MethodGet, "/dashboard?manage=page", nil, asSession(s, u.OwnerAccountID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		return rec.Body.String()
	}
	body := get()
	for _, want := range []string{
		`alice@example.com`,
		`action="/dashboard/grants/page/remove"`,
		`action="/dashboard/grants/page"`,
		`$nextTick(() => $refs.visibilityDialog.showModal())`,
		`<input type="hidden" name="kind" value="user">`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}
	s.groups = fakeGroups{members: map[string]bool{}}
	if body := get(); !strings.Contains(body, `<option value="group">Google group</option>`) {
		t.Fatal("dashboard missing group option")
	}
}

// dashCovUpload seeds an upload owned by ownerID on s.
func dashCovUpload(t *testing.T, s *Server, slug string, ownerID int64) {
	t.Helper()
	if err := s.store.CreateUploadChecked(context.Background(), slug, ownerID, 0, slug+".html", 42, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
}

// dashCovUser creates a non-admin account.
func dashCovUser(t *testing.T, s *Server, email string) int64 {
	t.Helper()
	a, err := s.store.CreateAccount(context.Background(), email, email, false)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// dashCovMultipart posts a multipart form to /dashboard/upload with a valid
// CSRF cookie. file may be nil.
func dashCovMultipart(t *testing.T, s *Server, accountID int64, fields map[string]string, filename string, file []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if file != nil {
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(file); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return doRequest(t, s, http.MethodPost, "/dashboard/upload", &body,
		func(r *http.Request) { r.Header.Set("Content-Type", mw.FormDataContentType()) },
		asSession(s, accountID),
		func(r *http.Request) { r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"}) })
}

func TestDashCovDashboardRedirects(t *testing.T) {
	s, store, _, _ := newFaultServer(t)

	rec := doRequest(t, s, http.MethodGet, "/dashboard", nil)
	assertDashboardRedirect(t, rec, "/login")

	rec = doRequest(t, s, http.MethodGet, "/dashboard/stats/page", nil)
	assertDashboardRedirect(t, rec, "/login")

	if _, err := store.Exec("DELETE FROM accounts"); err != nil {
		t.Fatal(err)
	}
	rec = doRequest(t, s, http.MethodGet, "/dashboard", nil)
	assertDashboardRedirect(t, rec, "/setup")
}

func TestDashCovDashboardRendersFlashErrorAndGrantFailure(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)
	dashCovUpload(t, s, "page", adminID)

	rec := doRequest(t, s, http.MethodGet, "/dashboard?err="+flashNotFound, nil, asSession(s, adminID))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), flashMessages[flashNotFound]) {
		t.Fatalf("status = %d, flash error not rendered", rec.Code)
	}

	dropTable(t, store, "upload_grants")
	rec = doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, adminID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d after grants table drop", rec.Code)
	}
}

func TestDashCovDashboardCSRFGenerationFailure(t *testing.T) {
	s, _, _, adminID := newFaultServer(t)
	stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand failed") })
	rec := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, adminID))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestDashCovUploadFailurePaths(t *testing.T) {
	s, _, storage, adminID := newFaultServer(t)
	good := map[string]string{"csrf": "csrf-token", "mode": "paste", "html": "<html></html>", "visibility": "public"}

	if rec := doRequest(t, s, http.MethodPost, "/dashboard/upload", nil); rec.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous upload Location = %q", rec.Header().Get("Location"))
	}

	rec := doRequest(t, s, http.MethodPost, "/dashboard/upload", strings.NewReader("x"), asSession(s, adminID),
		func(r *http.Request) { r.Header.Set("Content-Type", "multipart/form-data") })
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashFormInvalid)

	bad := map[string]string{"csrf": "wrong", "mode": "paste", "html": "<html></html>"}
	rec = dashCovMultipart(t, s, adminID, bad, "", nil)
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashInvalidSession)

	realRead := secureRandomRead
	secureRandomRead = func([]byte) (int, error) { return 0, errors.New("rand failed") }
	rec = dashCovMultipart(t, s, adminID, good, "", nil)
	secureRandomRead = realRead
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("csrf rand failure status = %d", rec.Code)
	}

	rec = dashCovMultipart(t, s, adminID, map[string]string{"csrf": "csrf-token", "mode": "paste", "html": "  "}, "", nil)
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashNoHTML)

	rec = dashCovMultipart(t, s, adminID, map[string]string{"csrf": "csrf-token"}, "", nil)
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashNoFile)

	big := bytes.Repeat([]byte("a"), (2<<20)+10)
	rec = dashCovMultipart(t, s, adminID, map[string]string{"csrf": "csrf-token"}, "big.html", big)
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashFileTooLarge)

	rec = dashCovMultipart(t, s, adminID, map[string]string{"csrf": "csrf-token", "visibility": "public"}, "from-file.html", []byte("<html>file</html>"))
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/dashboard?uploaded=") {
		t.Fatalf("file upload = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = dashCovMultipart(t, s, adminID, good, "", nil)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/dashboard?uploaded=") {
		t.Fatalf("paste upload = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	list, err := s.store.ListAllUploads(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, u := range list {
		names[u.Name] = true
	}
	if !names["pasted"] || !names["from-file.html"] {
		t.Fatalf("default names not applied: %v", names)
	}

	storage.saveErr = errors.New("disk full")
	rec = dashCovMultipart(t, s, adminID, good, "", nil)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/dashboard?err=") {
		t.Fatalf("storage failure = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDashCovDeleteAndVisibilityGuards(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)
	userID := dashCovUser(t, s, "user@example.test")
	otherID := dashCovUser(t, s, "other@example.test")
	dashCovUpload(t, s, "page", userID)

	for _, op := range []string{"delete", "visibility"} {
		path := "/dashboard/" + op + "/page"
		if rec := doRequest(t, s, http.MethodPost, path, nil); rec.Header().Get("Location") != "/login" {
			t.Fatalf("%s anonymous Location = %q", op, rec.Header().Get("Location"))
		}
		rec := dashboardPost(t, s, userID, path, url.Values{}, false)
		assertDashboardRedirect(t, rec, "/dashboard?err="+flashInvalidSession)
		rec = dashboardPost(t, s, userID, "/dashboard/"+op+"/missing", url.Values{}, true)
		assertDashboardRedirect(t, rec, "/dashboard?err="+flashNotFound)
		rec = dashboardPost(t, s, otherID, path, url.Values{}, true)
		assertDashboardRedirect(t, rec, "/dashboard?err="+flashNotOwner)
	}

	addFailTrigger(t, store, "uploads", "UPDATE")
	rec := dashboardPost(t, s, userID, "/dashboard/visibility/page", url.Values{"visibility": {"signed-in"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?err="+flashVisibilityFailed)
	_ = adminID
}

func TestDashCovStatsGuardsAndFailures(t *testing.T) {
	s, store, _, _ := newFaultServer(t)
	userID := dashCovUser(t, s, "user@example.test")
	otherID := dashCovUser(t, s, "other@example.test")
	dashCovUpload(t, s, "page", userID)

	rec := doRequest(t, s, http.MethodGet, "/dashboard/stats/page", nil, asSession(s, otherID))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-owner stats = %d, want 404", rec.Code)
	}

	// Without visits the sparkline is all zero.
	rec = doRequest(t, s, http.MethodGet, "/dashboard/stats/page", nil, asSession(s, userID))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "0 visits last 7 days") {
		t.Fatalf("empty stats = %d: %s", rec.Code, rec.Body.String())
	}

	// Dropping a column RecentVisits selects (but CountVisits does not) fails
	// only the recent-visits query.
	if _, err := store.Exec("ALTER TABLE visits DROP COLUMN user_agent"); err != nil {
		t.Fatal(err)
	}
	rec = doRequest(t, s, http.MethodGet, "/dashboard/stats/page", nil, asSession(s, userID))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "stats could not be loaded") {
		t.Fatalf("recent failure = %d", rec.Code)
	}
}

func TestDashCovStatsSparklineEdges(t *testing.T) {
	if got := statsSparkline(nil); !strings.HasPrefix(got.LinePath, "M 2.0 54.0") {
		t.Fatalf("empty sparkline path = %q", got.LinePath)
	}
	got := statsSparkline([]bucket{{Count: 1}})
	if got.Summary != "1 visit last 7 days" {
		t.Fatalf("summary = %q", got.Summary)
	}
}

func dashboardBody(t *testing.T, s *Server, accountID int64) string {
	t.Helper()
	rec := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, accountID))
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestDashboardRowShowsTitleOnly(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "title-only")
	body := dashboardBody(t, s, u.OwnerAccountID)
	if !strings.Contains(body, `href="/p/title-only" target="_blank" title="page.html" class="min-w-0 truncate font-medium text-primary no-underline hover:underline">page.html</a>`) {
		t.Fatalf("row does not show the name as the link: %s", body)
	}
	for _, bad := range []string{"peek-copy-button", ">/p/title-only<"} {
		if strings.Contains(body, bad) {
			t.Fatalf("dashboard still contains %q", bad)
		}
	}
}

func TestDashboardListsPagesSharedWithMe(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "shared-me")
	bob := newViewer(t, s, "bob@example.com", "Bob", false)
	grant(t, s, u, models.UploadGrantUser, "bob@example.com")
	grant(t, s, u, models.UploadGrantUser, "carol@example.com")
	body := dashboardBody(t, s, bob.ID)
	if !strings.Contains(body, "Shared with you by Owner. View only") {
		t.Fatalf("shared row missing: %s", body)
	}
	for _, bad := range []string{"/dashboard/delete/shared-me", "/dashboard/visibility/shared-me", "carol@example.com"} {
		if strings.Contains(body, bad) {
			t.Fatalf("viewer dashboard contains %q", bad)
		}
	}
}

func TestDashboardSharedViaGroup(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	s.groups = fakeGroups{members: map[string]bool{"team@example.com|bob@example.com": true}}
	u := restrictedPage(t, s, "shared-group")
	grant(t, s, u, models.UploadGrantGroup, "team@example.com")
	bob := newViewer(t, s, "bob@example.com", "Bob", false)
	eve := newViewer(t, s, "eve@example.com", "Eve", false)
	if body := dashboardBody(t, s, bob.ID); !strings.Contains(body, "Shared with you by") {
		t.Fatalf("group member does not see the page: %s", body)
	}
	if body := dashboardBody(t, s, eve.ID); strings.Contains(body, "Shared with you by") {
		t.Fatalf("non-member sees the page: %s", body)
	}
}

func TestDashboardSkipsNonRestrictedShares(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	signedIn := newTwoVersionPage(t, s, "shared-signed-in", models.UploadVisibilityRestricted)
	public := newTwoVersionPage(t, s, "shared-public", models.UploadVisibilityRestricted)
	bob := newViewer(t, s, "bob@example.com", "Bob", false)
	grant(t, s, signedIn, models.UploadGrantUser, "bob@example.com")
	grant(t, s, public, models.UploadGrantUser, "bob@example.com")
	if err := s.store.SetUploadVisibility(context.Background(), signedIn.ID, models.UploadVisibilitySignedIn); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetUploadVisibility(context.Background(), public.ID, models.UploadVisibilityPublic); err != nil {
		t.Fatal(err)
	}
	body := dashboardBody(t, s, bob.ID)
	for _, bad := range []string{"shared-signed-in", "shared-public", "Shared with you by"} {
		if strings.Contains(body, bad) {
			t.Fatalf("dashboard contains %q: %s", bad, body)
		}
	}
}

func TestDashboardAdminRoleIcon(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	restrictedPage(t, s, "admin-other")
	admin := newViewer(t, s, "admin@example.test", "Admin", true)
	mine := restrictedPage(t, s, "admin-mine")
	if _, err := s.store.ExecContext(context.Background(), `UPDATE uploads SET owner_account_id=? WHERE id=?`, admin.ID, mine.ID); err != nil {
		t.Fatal(err)
	}
	body := dashboardBody(t, s, admin.ID)
	for _, want := range []string{"You can edit it as an admin", "You own this page and can edit it"} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin dashboard missing %q: %s", want, body)
		}
	}
}

func TestDashboardNoPasswordOption(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "no-password")
	if body := dashboardBody(t, s, u.OwnerAccountID); strings.Contains(body, `value="password"`) {
		t.Fatalf("dashboard offers a password option")
	}
}
