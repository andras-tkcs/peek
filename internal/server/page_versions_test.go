package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/andras-tkcs/peek/internal/models"
	"github.com/andras-tkcs/peek/internal/uploadquota"
)

const (
	v1Marker = "MARKER-VERSION-ONE"
	v2Marker = "MARKER-VERSION-TWO"
)

// newTwoVersionPage creates a page with two versions. Version 1 is stored under
// the slug and version 2 under a versions/ key.
func newTwoVersionPage(t *testing.T, s *Server, slug, visibility, passwordHash string) *models.Upload {
	t.Helper()
	ctx := context.Background()
	owner, err := s.store.CreateAccount(ctx, "owner-"+slug+"@example.test", "Owner", false)
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	v1 := []byte("<html><body>" + v1Marker + "</body></html>")
	if err := s.storage.Save(ctx, slug, v1); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	if err := s.store.CreateUploadChecked(ctx, slug, owner.ID, 0, "page.html", int64(len(v1)), visibility, passwordHash, uploadquota.Limits{}); err != nil {
		t.Fatalf("create upload: %v", err)
	}
	u, err := s.store.GetUpload(ctx, slug)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	key := "versions/" + slug + "/0123456789abcdef"
	v2 := []byte("<html><body>" + v2Marker + "</body></html>")
	if err := s.storage.Save(ctx, key, v2); err != nil {
		t.Fatalf("save v2: %v", err)
	}
	if _, err := s.store.CreateVersionChecked(ctx, u.ID, key, int64(len(v2)), owner.ID, uploadquota.Limits{}); err != nil {
		t.Fatalf("create v2: %v", err)
	}
	u, err = s.store.GetUpload(ctx, slug)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	return u
}

// withVID1 sets the visitor cookie the raw view tokens in these tests are bound to.
var withVID1 = func(r *http.Request) { r.AddCookie(&http.Cookie{Name: visitorCookie, Value: "vid1"}) }

var rawSrcRe = regexp.MustCompile(`src="(/raw/[^"]+)"`)

// withCookieList adds every cookie to the request.
func withCookieList(cs []*http.Cookie) func(*http.Request) {
	return func(r *http.Request) {
		for _, c := range cs {
			r.AddCookie(c)
		}
	}
}

// withFetchDest sets the Sec-Fetch-Dest header.
func withFetchDest(v string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", v) }
}

// rawSrcFromPage GETs pagePath (with opts) and returns the iframe src and the
// response cookies.
func rawSrcFromPage(t *testing.T, s *Server, pagePath string, opts ...func(*http.Request)) (src string, cookies []*http.Cookie) {
	t.Helper()
	rec := doRequest(t, s, http.MethodGet, pagePath, nil, opts...)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", pagePath, rec.Code, rec.Body.String())
	}
	m := rawSrcRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("GET %s: no raw iframe src in %s", pagePath, rec.Body.String())
	}
	return strings.ReplaceAll(m[1], "&amp;", "&"), rec.Result().Cookies()
}

// fetchRawFromPage GETs a page path, follows its iframe src with the response
// cookies and returns the raw body.
func fetchRawFromPage(t *testing.T, s *Server, pagePath string) (page, raw string) {
	t.Helper()
	rec := doRequest(t, s, http.MethodGet, pagePath, nil)
	src, cookies := rawSrcFromPage(t, s, pagePath)
	raw2 := doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies))
	if raw2.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", src, raw2.Code, raw2.Body.String())
	}
	return rec.Body.String(), raw2.Body.String()
}

func TestPageVersionServesRequestedVersion(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "pgver1", models.UploadVisibilityPublic, "")
	for path, want := range map[string]string{"/p/pgver1/v/1": v1Marker, "/p/pgver1/v/2": v2Marker} {
		_, raw := fetchRawFromPage(t, s, path)
		if !strings.Contains(raw, want) {
			t.Fatalf("%s raw body missing %q: %s", path, want, raw)
		}
	}
}

func TestPageLatestServesNewestVersion(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "pglatest", models.UploadVisibilityPublic, "")
	_, raw := fetchRawFromPage(t, s, "/p/pglatest")
	if !strings.Contains(raw, v2Marker) || strings.Contains(raw, v1Marker) {
		t.Fatalf("latest page should serve v2 only: %s", raw)
	}
}

func TestPageVersionNotFound(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "pgnf", models.UploadVisibilityPublic, "")
	for _, n := range []string{"0", "abc", "99"} {
		rec := doRequest(t, s, http.MethodGet, "/p/pgnf/v/"+n, nil)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Version not found") {
			t.Fatalf("v/%s = %d, want 404 Version not found: %s", n, rec.Code, rec.Body.String())
		}
	}
}

func TestRawVersionRejectsTokenForOtherVersion(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawother", models.UploadVisibilityPublic, "")
	tok := makeViewToken(s.secret, viewSubject("rawother", 1), "vid1")
	rec := doRequest(t, s, http.MethodGet, "/raw/rawother/v/2?t="+url.QueryEscape(tok), nil, withVID1)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token for v1 on v2 = %d, want 403", rec.Code)
	}
	rec = doRequest(t, s, http.MethodGet, "/raw/rawother/v/1?t="+url.QueryEscape(tok), nil, withVID1)
	if rec.Code != http.StatusOK {
		t.Fatalf("token for v1 on v1 = %d, want 200", rec.Code)
	}
}

func TestRawVersionChecksTokenBeforeLookup(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawlookup", models.UploadVisibilityPublic, "")
	rec := doRequest(t, s, http.MethodGet, "/raw/rawlookup/v/99?t=bad", nil, withVID1)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad token on missing version = %d, want 403", rec.Code)
	}
}

func TestLegacyRawRouteRemoved(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawlegacy", models.UploadVisibilityPublic, "")
	tok := makeViewToken(s.secret, "rawlegacy", "vid1")
	rec := doRequest(t, s, http.MethodGet, "/raw/rawlegacy?t="+url.QueryEscape(tok), nil, withVID1)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), v2Marker) {
		t.Fatalf("legacy raw = %d, want 404 without page content: %s", rec.Code, rec.Body.String())
	}
}

func TestRawSetsSandboxCSP(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawcsp", models.UploadVisibilityPublic, "")
	src, cookies := rawSrcFromPage(t, s, "/p/rawcsp")
	rec := doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies))
	if rec.Code != http.StatusOK {
		t.Fatalf("raw = %d: %s", rec.Code, rec.Body.String())
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.HasPrefix(csp, "sandbox allow-scripts allow-popups;") || csp != rawContentCSP {
		t.Fatalf("raw CSP = %q", csp)
	}
}

func TestRawRejectsNonIframeFetchDest(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawdest", models.UploadVisibilityPublic, "")
	src, cookies := rawSrcFromPage(t, s, "/p/rawdest")
	cases := []struct {
		dest string
		want int
	}{
		{"document", http.StatusForbidden},
		{"empty", http.StatusForbidden},
		{"frame", http.StatusForbidden},
		{"iframe", http.StatusOK},
		{"", http.StatusOK},
	}
	for _, tc := range cases {
		opts := []func(*http.Request){withCookieList(cookies)}
		if tc.dest != "" {
			opts = append(opts, withFetchDest(tc.dest))
		}
		if rec := doRequest(t, s, http.MethodGet, src, nil, opts...); rec.Code != tc.want {
			t.Errorf("Sec-Fetch-Dest %q = %d, want %d", tc.dest, rec.Code, tc.want)
		}
	}
}

func TestRawDownloadFetchDest(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawdl", models.UploadVisibilityPublic, "")
	src, cookies := rawSrcFromPage(t, s, "/p/rawdl")
	dl := src + "&download=1"
	for _, dest := range []string{"document", "empty", "iframe", ""} {
		opts := []func(*http.Request){withCookieList(cookies)}
		if dest != "" {
			opts = append(opts, withFetchDest(dest))
		}
		rec := doRequest(t, s, http.MethodGet, dl, nil, opts...)
		if rec.Code != http.StatusOK {
			t.Errorf("download dest %q = %d, want 200", dest, rec.Code)
			continue
		}
		if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
			t.Errorf("download dest %q disposition = %q", dest, cd)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); csp != rawContentCSP {
			t.Errorf("download dest %q CSP = %q, want rawContentCSP", dest, csp)
		}
	}
	for _, dest := range []string{"document", "empty"} {
		if rec := doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies), withFetchDest(dest)); rec.Code != http.StatusForbidden {
			t.Errorf("non-download dest %q = %d, want 403", dest, rec.Code)
		}
		if rec := doRequest(t, s, http.MethodGet, dl, nil, withFetchDest(dest)); rec.Code != http.StatusForbidden {
			t.Errorf("download dest %q without cookie = %d, want 403", dest, rec.Code)
		}
		bad := strings.Replace(dl, "t=", "t=x", 1)
		if rec := doRequest(t, s, http.MethodGet, bad, nil, withCookieList(cookies), withFetchDest(dest)); rec.Code != http.StatusForbidden {
			t.Errorf("download dest %q bad token = %d, want 403", dest, rec.Code)
		}
	}
	if rec := doRequest(t, s, http.MethodGet, dl, nil, withFetchDest("frame"), withCookieList(cookies)); rec.Code != http.StatusForbidden {
		t.Errorf("download dest frame = %d, want 403", rec.Code)
	}
}

func TestRawTokenRequiresVisitorCookie(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawvid", models.UploadVisibilityPublic, "")
	src, cookies := rawSrcFromPage(t, s, "/p/rawvid")
	var vid string
	for _, c := range cookies {
		if c.Name == visitorCookie {
			vid = c.Value
		}
	}
	if vid == "" {
		t.Fatalf("page did not set %s: %+v", visitorCookie, cookies)
	}
	if rec := doRequest(t, s, http.MethodGet, src, nil); rec.Code != http.StatusForbidden {
		t.Errorf("no cookies = %d, want 403", rec.Code)
	}
	other := []*http.Cookie{{Name: visitorCookie, Value: "someone-else"}}
	if rec := doRequest(t, s, http.MethodGet, src, nil, withCookieList(other)); rec.Code != http.StatusForbidden {
		t.Errorf("other visitor cookie = %d, want 403", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, src+"&v="+url.QueryEscape(vid), nil); rec.Code != http.StatusForbidden {
		t.Errorf("?v= without cookie = %d, want 403", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies)); rec.Code != http.StatusOK {
		t.Errorf("page cookies = %d, want 200", rec.Code)
	}
}

func TestRawSandboxMatchesIframeAttribute(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawattr", models.UploadVisibilityPublic, "")
	rec := doRequest(t, s, http.MethodGet, "/p/rawattr", nil)
	m := regexp.MustCompile(`sandbox="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	if m == nil || m[1] != rawSandbox {
		t.Fatalf("iframe sandbox = %v, want %q", m, rawSandbox)
	}
}

func TestRawRefusedAfterVisibilityChange(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "rawvis", models.UploadVisibilityPublic, "")
	src, cookies := rawSrcFromPage(t, s, "/p/rawvis")
	if rec := doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies)); rec.Code != http.StatusOK {
		t.Fatalf("before change = %d, want 200", rec.Code)
	}
	if err := s.store.SetUploadVisibility(context.Background(), u.ID, models.UploadVisibilityPrivate, ""); err != nil {
		t.Fatal(err)
	}
	if rec := doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies)); rec.Code != http.StatusForbidden {
		t.Fatalf("after going private = %d, want 403", rec.Code)
	}
}

func TestRawRefusedAfterGrantRemoved(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	ctx := context.Background()
	u := newTwoVersionPage(t, s, "rawgrant", models.UploadVisibilityRestricted, "")
	v, err := s.store.CreateAccount(ctx, "viewer@example.test", "Viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.AddUploadGrant(ctx, u.ID, models.UploadGrantUser, "viewer@example.test", u.OwnerAccountID); err != nil {
		t.Fatal(err)
	}
	src, cookies := rawSrcFromPage(t, s, "/p/rawgrant", asSession(s, v.ID))
	get := func() int {
		return doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies), asSession(s, v.ID)).Code
	}
	if got := get(); got != http.StatusOK {
		t.Fatalf("with grant = %d, want 200", got)
	}
	if err := s.store.RemoveUploadGrant(ctx, u.ID, models.UploadGrantUser, "viewer@example.test"); err != nil {
		t.Fatal(err)
	}
	if got := get(); got != http.StatusForbidden {
		t.Fatalf("after grant removed = %d, want 403", got)
	}
}

func TestRawRefusedAfterPasswordChange(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	hash := func(pw string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	u := newTwoVersionPage(t, s, "rawpw", models.UploadVisibilityPassword, hash("one"))
	post := doRequest(t, s, http.MethodPost, "/p/rawpw", strings.NewReader(url.Values{"password": {"one"}}.Encode()), func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	var auth *http.Cookie
	for _, c := range post.Result().Cookies() {
		if c.Name == authCookieName("rawpw") {
			auth = c
		}
	}
	if auth == nil {
		t.Fatalf("password POST did not set the auth cookie: %d", post.Code)
	}
	src, cookies := rawSrcFromPage(t, s, "/p/rawpw", withCookieList([]*http.Cookie{auth}))
	cookies = append(cookies, auth)
	if rec := doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies)); rec.Code != http.StatusOK {
		t.Fatalf("before change = %d, want 200", rec.Code)
	}
	if err := s.store.SetUploadVisibility(context.Background(), u.ID, models.UploadVisibilityPassword, hash("two")); err != nil {
		t.Fatal(err)
	}
	if rec := doRequest(t, s, http.MethodGet, src, nil, withCookieList(cookies)); rec.Code != http.StatusForbidden {
		t.Fatalf("after password change = %d, want 403", rec.Code)
	}
}

func TestPasswordGateOnVersionRedirectsToVersion(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	newTwoVersionPage(t, s, "pgpass", models.UploadVisibilityPassword, string(hash))

	gate := doRequest(t, s, http.MethodGet, "/p/pgpass/v/1", nil)
	if !strings.Contains(gate.Body.String(), `action="/p/pgpass/v/1"`) {
		t.Fatalf("gate should post to the version path: %s", gate.Body.String())
	}
	post := func(pw string) *httptest.ResponseRecorder {
		return doRequest(t, s, http.MethodPost, "/p/pgpass/v/1", strings.NewReader(url.Values{"password": {pw}}.Encode()), func(r *http.Request) {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		})
	}
	if rec := post("wrong"); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `action="/p/pgpass/v/1"`) {
		t.Fatalf("wrong password = %d: %s", rec.Code, rec.Body.String())
	}
	rec := post("hunter2")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/p/pgpass/v/1" {
		t.Fatalf("right password = %d Location=%q, want 303 /p/pgpass/v/1", rec.Code, rec.Header().Get("Location"))
	}
}

func TestVersionBannerOnlyOnOlderVersions(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "pgbanner", models.UploadVisibilityPublic, "")
	if body := doRequest(t, s, http.MethodGet, "/p/pgbanner/v/1", nil).Body.String(); !strings.Contains(body, "hn-version-banner") {
		t.Fatalf("v1 should show the banner: %s", body)
	}
	for _, path := range []string{"/p/pgbanner/v/2", "/p/pgbanner"} {
		if body := doRequest(t, s, http.MethodGet, path, nil).Body.String(); strings.Contains(body, "hn-version-banner") {
			t.Fatalf("%s should not show the banner", path)
		}
	}
}

func TestPageVersionRecordsVisitVersion(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "pgvisit", models.UploadVisibilityPublic, "")
	if rec := doRequest(t, s, http.MethodGet, "/p/pgvisit/v/1", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET v/1 = %d", rec.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.FlushVisits(ctx); err != nil {
		t.Fatalf("flush visits: %v", err)
	}
	visits, err := s.store.RecentVisits(ctx, u.ID, 10)
	if err != nil || len(visits) != 1 {
		t.Fatalf("recent visits = %v err=%v, want 1", visits, err)
	}
	if visits[0].Version != 1 {
		t.Fatalf("visit version = %d, want 1", visits[0].Version)
	}
}

func TestPageQueryReachesFrameAsFragmentOnly(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "pgquery", models.UploadVisibilityPublic, "")
	rec := doRequest(t, s, http.MethodGet, "/p/pgquery?region=eu&q=a%20b", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `#region=eu&amp;q=a%20b"`) {
		t.Fatalf("iframe src missing query fragment: %s", body)
	}
	if strings.Contains(body, "region=eu&amp;download") || strings.Contains(body, "download=1#") {
		t.Fatalf("query leaked into the download link: %s", body)
	}
}
