package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/privacyfence/peek/internal/db"
	"github.com/privacyfence/peek/internal/models"
	"github.com/privacyfence/peek/internal/uploadquota"
	webui "github.com/privacyfence/peek/internal/web"
)

type rawPageStorage struct {
	body      string
	openCount int
}

func (s *rawPageStorage) Save(_ context.Context, _ string, _ []byte) error {
	return nil
}

func (s *rawPageStorage) Open(_ context.Context, _ string) (io.ReadCloser, error) {
	s.openCount++
	return io.NopCloser(strings.NewReader(s.body)), nil
}

func (s *rawPageStorage) Delete(_ context.Context, _ string) error {
	return nil
}

func TestHandlePageMissingUploadRendersWebError(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, renderer: renderer}
	req := httptest.NewRequest(http.MethodGet, "/p/missing", nil)
	req.SetPathValue("slug", "missing")
	rec := httptest.NewRecorder()

	s.handlePage(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "Page not found") {
		t.Fatalf("body did not render web error: %s", rec.Body.String())
	}
}

func TestPrivatePageRequiresActiveWebSession(t *testing.T) {
	s := newTestServer(t)
	owner, err := s.store.CreateAccount(context.Background(), "owner@example.test", "Owner", false)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := s.store.CreateAccount(context.Background(), "viewer@example.test", "Viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUploadChecked(context.Background(), "private", owner.ID, 0, "private.html", 42, "signed-in", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/p/private", nil)
	req.SetPathValue("slug", "private")
	rec := httptest.NewRecorder()
	s.handlePage(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("anonymous status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("redirect = %q", got)
	}
	if c := pageTestCookie(rec.Result().Cookies(), nextCookie); c == nil || c.Value != "/p/private" {
		t.Fatalf("next cookie not set for private page: %+v", rec.Result().Cookies())
	}

	req = httptest.NewRequest(http.MethodGet, "/p/private", nil)
	req.SetPathValue("slug", "private")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(viewer.ID, 10), sessionTTL)})
	rec = httptest.NewRecorder()
	s.handlePage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("active viewer status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRawStreamsHTMLWithBridgeInjection(t *testing.T) {
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
	secret := strings.Repeat("0", 64)
	vid := "visitor"
	storage := &rawPageStorage{body: "<HTML><BODY><h1>Hello</h1></BODY></HTML>"}
	s := &Server{store: store, storage: storage, secret: secret}
	req := httptest.NewRequest(http.MethodGet, "/raw/page/v/1?t="+makeViewToken(secret, viewSubject("page", 1), vid), nil)
	req.SetPathValue("slug", "page")
	req.SetPathValue("n", "1")
	req.AddCookie(&http.Cookie{Name: visitorCookie, Value: vid})
	rec := httptest.NewRecorder()

	s.handleRawVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if storage.openCount != 2 {
		t.Fatalf("storage open count = %d, want two-pass scan and stream", storage.openCount)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != rawContentCSP {
		t.Fatalf("CSP = %q, want rawContentCSP", got)
	}
	assertBridgeBefore(t, rec.Body.String(), "</BODY>")
}

func TestInjectBridgeInsertsBeforeCaseInsensitiveBodyClose(t *testing.T) {
	got := string(injectBridge([]byte("<HTML><BODY><h1>Hello</h1></BODY></HTML>")))
	assertBridgeBefore(t, got, "</BODY>")
}

func TestInjectBridgeFallsBackToCaseInsensitiveHTMLClose(t *testing.T) {
	got := string(injectBridge([]byte("<HTML><main>Hello</main></HTML>")))
	assertBridgeBefore(t, got, "</HTML>")
}

func TestInjectBridgeAppendsToFragment(t *testing.T) {
	got := string(injectBridge([]byte("<main>Hello</main>")))
	if !strings.HasPrefix(got, "<main>Hello</main>") {
		t.Fatalf("fragment prefix changed: %s", got)
	}
	if !strings.Contains(got, `src="/bridge.js?v=`) {
		t.Fatalf("bridge script missing: %s", got)
	}
}

func TestBridgeInsertOffsetFindsMarkerAcrossReadBoundary(t *testing.T) {
	html := "<HTML><BODY><h1>Hello</h1></BODY></HTML>"
	offset, err := bridgeInsertOffset(&chunkedReader{chunks: []string{
		"<HTML><BODY><h1>Hello</h1></BO",
		"DY></HTML>",
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := int64(strings.Index(strings.ToLower(html), "</body>"))
	if offset != want {
		t.Fatalf("offset = %d, want %d", offset, want)
	}
}

func TestBridgeInsertOffsetUsesLastBodyMarker(t *testing.T) {
	html := "<body></body><template></body></template></html>"
	offset, err := bridgeInsertOffset(strings.NewReader(html))
	if err != nil {
		t.Fatal(err)
	}
	want := int64(strings.LastIndex(strings.ToLower(html), "</body>"))
	if offset != want {
		t.Fatalf("offset = %d, want %d", offset, want)
	}
}

func TestWriteRawHTMLLogsWriteFailure(t *testing.T) {
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })
	w := &failingJSONWriter{}

	writeRawHTML(w, "page", strings.NewReader("<html></html>"), 0)

	if got := w.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	if !strings.Contains(logs.String(), "write raw html response") {
		t.Fatalf("write failure was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "slug=page") {
		t.Fatalf("slug was not logged: %s", logs.String())
	}
}

type chunkedReader struct {
	chunks []string
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	return copy(p, chunk), nil
}

func assertBridgeBefore(t *testing.T, html, marker string) {
	t.Helper()
	bridge := strings.Index(html, `src="/bridge.js?v=`)
	if bridge < 0 {
		t.Fatalf("bridge script missing: %s", html)
	}
	closeTag := strings.Index(html, marker)
	if closeTag < 0 {
		t.Fatalf("marker %q missing: %s", marker, html)
	}
	if bridge > closeTag {
		t.Fatalf("bridge script appears after %s: %s", marker, html)
	}
}

func pageTestCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestDownloadFilename(t *testing.T) {
	cases := map[string]string{
		"report.html":     "report.html",
		"report":          "report.html",
		"../../etc/x.htm": "x.htm",
		"  ":              "slug1.html",
		`a\b\c.html`:      "c.html",
	}
	for in, want := range cases {
		if got := downloadFilename(in, "slug1"); got != want {
			t.Errorf("downloadFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// pageCovSeed creates a one-version upload owned by the admin token's account
// and stores html under its version-1 object key.
func pageCovSeed(t *testing.T, s *Server, token, slug, visibility, html string) *models.Upload {
	t.Helper()
	ctx := context.Background()
	tok, err := s.store.GetToken(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUploadChecked(ctx, slug, tok.AccountID, tok.ID, slug+".html", int64(len(html)), visibility, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	u, err := s.store.GetUpload(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.store.GetUploadVersion(ctx, u.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.storage.Save(ctx, v.ObjectKey, []byte(html)); err != nil {
		t.Fatal(err)
	}
	return u
}

// pageCovRawRequest requests /raw for slug version n with a valid view token
// and the matching visitor cookie.
func pageCovRawRequest(t *testing.T, s *Server, slug string, n int, extraQuery string) *httptest.ResponseRecorder {
	t.Helper()
	vid := "visitor-1"
	tok := makeViewToken(s.secret, viewSubject(slug, n), vid)
	path := "/raw/" + slug + "/v/" + strconv.Itoa(n) + "?t=" + tok + extraQuery
	return doRequest(t, s, http.MethodGet, path, nil, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: visitorCookie, Value: vid})
	})
}

type pageCovFlakyStorage struct {
	faultStorage
	opens, failFrom int
	rc              func() io.ReadCloser
}

func (f *pageCovFlakyStorage) Open(_ context.Context, _ string) (io.ReadCloser, error) {
	f.opens++
	if f.failFrom > 0 && f.opens >= f.failFrom {
		return nil, errors.New("open failed")
	}
	return f.rc(), nil
}

type pageCovBadReader struct {
	data     string
	closeErr error
	readErr  error
	done     bool
}

func (b *pageCovBadReader) Read(p []byte) (int, error) {
	if b.done {
		if b.readErr != nil {
			return 0, b.readErr
		}
		return 0, io.EOF
	}
	b.done = true
	return copy(p, b.data), nil
}

func (b *pageCovBadReader) Close() error { return b.closeErr }

// pageCovLimitedWriter accepts okWrites writes and then fails.
type pageCovLimitedWriter struct {
	httptest.ResponseRecorder
	okWrites int
}

func (w *pageCovLimitedWriter) Write(p []byte) (int, error) {
	if w.okWrites <= 0 {
		return 0, errors.New("write failed")
	}
	w.okWrites--
	return w.ResponseRecorder.Write(p)
}

// WriteString is overridden too: io.Copy from a strings.Reader uses it and would
// otherwise bypass Write.
func (w *pageCovLimitedWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

func TestPageCovPageVersionMissingUpload(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodGet, "/p/nope/v/1", nil)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Page not found") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestPageCovStaleSessionCookieIsCleared(t *testing.T) {
	s, token := newHandlerTestServer(t)
	pageCovSeed(t, s, token, "priv", "signed-in", "<html></html>")
	pageCovSeed(t, s, token, "restr", "restricted", "<html></html>")
	for _, slug := range []string{"priv", "restr"} {
		rec := doRequest(t, s, http.MethodGet, "/p/"+slug+"?x=1", nil, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "garbage"})
		})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Fatalf("%s: status = %d location = %q", slug, rec.Code, rec.Header().Get("Location"))
		}
		if c := pageTestCookie(rec.Result().Cookies(), sessionCookie); c == nil || c.MaxAge >= 0 {
			t.Fatalf("%s: session cookie not cleared: %+v", slug, c)
		}
		if c := pageTestCookie(rec.Result().Cookies(), nextCookie); c == nil || c.Value != "/p/"+slug+"?x=1" {
			t.Fatalf("%s: next cookie = %+v", slug, c)
		}
	}
}

func TestPageCovRawVersionBranches(t *testing.T) {
	s, token := newHandlerTestServer(t)
	pageCovSeed(t, s, token, "page", "public", "<html><body>hi</body></html>")

	if rec := doRequest(t, s, http.MethodGet, "/raw/page/v/abc", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("bad version status = %d", rec.Code)
	}
	if rec := pageCovRawRequest(t, s, "gone", 1, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing upload status = %d", rec.Code)
	}
	if rec := pageCovRawRequest(t, s, "page", 9, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing version status = %d", rec.Code)
	}
	rec := pageCovRawRequest(t, s, "page", 1, "&download=1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") || strings.Contains(rec.Body.String(), "bridge.js") {
		t.Fatalf("download = %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
}

func TestPageCovRawStorageFailures(t *testing.T) {
	s, token := newHandlerTestServer(t)
	pageCovSeed(t, s, token, "page", "public", "<html><body>hi</body></html>")
	html := "<html><body>hi</body></html>"
	tests := []struct {
		name  string
		store *pageCovFlakyStorage
		query string
		want  int
	}{
		{"first open fails", &pageCovFlakyStorage{failFrom: 1, rc: func() io.ReadCloser { return nil }}, "", http.StatusNotFound},
		{"download open fails", &pageCovFlakyStorage{failFrom: 1, rc: func() io.ReadCloser { return nil }}, "&download=1", http.StatusNotFound},
		{"scan read fails", &pageCovFlakyStorage{rc: func() io.ReadCloser {
			return &pageCovBadReader{data: html, readErr: errors.New("read failed")}
		}}, "", http.StatusNotFound},
		{"scan close fails", &pageCovFlakyStorage{rc: func() io.ReadCloser {
			return &pageCovBadReader{data: html, closeErr: errors.New("close failed")}
		}}, "", http.StatusOK},
		{"second open fails", &pageCovFlakyStorage{failFrom: 2, rc: func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(html))
		}}, "", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s.storage = tt.store
			rec := pageCovRawRequest(t, s, "page", 1, tt.query)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestPageCovWriteRawHTMLWriteFailures(t *testing.T) {
	body := func() io.Reader { return strings.NewReader("<html><body>hi</body></html>") }
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })
	checkLogged := func(name string) {
		t.Helper()
		if !strings.Contains(logs.String(), "write raw html response") || !strings.Contains(logs.String(), "slug=s") {
			t.Errorf("%s: write failure was not logged: %s", name, logs.String())
		}
	}

	logs.Reset()
	prefixFail := &failingWriter{ResponseRecorder: *httptest.NewRecorder()}
	writeRawHTML(prefixFail, "s", body(), 12) // prefix copy fails
	checkLogged("prefix copy")
	if csp := prefixFail.Header().Get("Content-Security-Policy"); csp != rawContentCSP {
		t.Errorf("prefix copy CSP = %q, want rawContentCSP", csp)
	}

	logs.Reset()
	bridgeFail := &failingWriter{ResponseRecorder: *httptest.NewRecorder()}
	writeRawHTML(bridgeFail, "s", body(), 0) // bridge tag write fails
	checkLogged("bridge tag")
	if csp := bridgeFail.Header().Get("Content-Security-Policy"); csp != rawContentCSP {
		t.Errorf("bridge tag CSP = %q, want rawContentCSP", csp)
	}

	logs.Reset()
	bodyFail := &pageCovLimitedWriter{ResponseRecorder: *httptest.NewRecorder(), okWrites: 1}
	writeRawHTML(bodyFail, "s", body(), 0) // body copy fails
	checkLogged("body copy")
	if got := bodyFail.Body.String(); got != string(bridgeScriptTag()) {
		t.Errorf("body copy wrote %q, want only the bridge tag", got)
	}
}

func TestPageCovServeDownloadCopyFailure(t *testing.T) {
	st := &faultStorage{}
	if err := st.Save(context.Background(), "k", []byte("<html></html>")); err != nil {
		t.Fatal(err)
	}
	s := &Server{storage: st}
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })
	w := &failingWriter{ResponseRecorder: *httptest.NewRecorder()}
	s.serveDownload(w, httptest.NewRequest(http.MethodGet, "/", nil), "s", "n", "k")
	if !strings.Contains(logs.String(), "write download response") || !strings.Contains(logs.String(), "slug=s") {
		t.Errorf("copy failure was not logged: %s", logs.String())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", cd)
	}
}

func TestPageCovIndexRoutes(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	if rec := doRequest(t, s, http.MethodGet, "/", nil); rec.Code != http.StatusOK {
		t.Fatalf("index status = %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, "/no-such-path", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d", rec.Code)
	}
}

func TestPageCovBridgeInsertOffsetReaders(t *testing.T) {
	off, err := bridgeInsertOffset(iotest.OneByteReader(strings.NewReader("ab</BODY>x")))
	if err != nil || off != 2 {
		t.Fatalf("offset = %d err = %v, want 2", off, err)
	}
	if _, err := bridgeInsertOffset(io.MultiReader(strings.NewReader("x"), iotest.ErrReader(errors.New("boom")))); err == nil {
		t.Fatal("reader error not returned")
	}
	if got := lastMarkerOffset(nil, []byte("</body>"), 0, 0, 5); got != 5 {
		t.Fatalf("lastMarkerOffset on empty input = %d, want 5", got)
	}
}

func TestPagePasswordRoutesRemoved(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "pwgone", models.UploadVisibilityPublic)
	form := func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }
	for _, path := range []string{"/p/pwgone", "/p/pwgone/v/1"} {
		rec := doRequest(t, s, http.MethodPost, path, strings.NewReader("password=x"), form)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, rec.Code)
		}
	}
}

// TestStrayPasswordVisibilityFailsClosed uses the literal string rather than the
// model constant so it keeps passing once the constant is removed.
func TestStrayPasswordVisibilityFailsClosed(t *testing.T) {
	e := newMatrixEnv(t)
	ctx := context.Background()
	body := []byte("<html><body>stray secret body</body></html>")
	if err := e.s.storage.Save(ctx, "stray-pw", body); err != nil {
		t.Fatal(err)
	}
	if err := e.s.store.CreateUploadChecked(ctx, "stray-pw", e.owner.ID, 0, "stray.html", int64(len(body)), "password", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	actors := map[string]func(*http.Request){
		"anonymous": func(*http.Request) {},
		"owner":     asSession(e.s, e.owner.ID),
		"admin":     asSession(e.s, e.admin.ID),
	}
	for name, opts := range actors {
		t.Run(name, func(t *testing.T) {
			page := doRequest(t, e.s, http.MethodGet, "/p/stray-pw", nil, opts)
			if page.Code != http.StatusForbidden {
				t.Errorf("GET /p = %d, want 403", page.Code)
			}
			if strings.Contains(page.Body.String(), "/raw/stray-pw") || strings.Contains(page.Body.String(), "stray secret body") {
				t.Error("page response exposes content")
			}
			// No bearer token: the session cookie alone must not open the API.
			if c := doRequest(t, e.s, http.MethodGet, "/api/uploads/stray-pw/comments", nil); c.Code != http.StatusUnauthorized {
				t.Errorf("GET comments without token = %d, want 401", c.Code)
			}
			raw := doRequest(t, e.s, http.MethodGet, "/raw/stray-pw/v/1", nil, opts)
			if raw.Code != http.StatusForbidden && raw.Code != http.StatusNotFound {
				t.Errorf("GET raw = %d, want 403 or 404", raw.Code)
			}
			if strings.Contains(raw.Body.String(), "stray secret body") {
				t.Error("raw response exposes content")
			}
		})
	}
}
