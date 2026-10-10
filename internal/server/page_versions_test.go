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

var rawSrcRe = regexp.MustCompile(`src="(/raw/[^"]+)"`)

// fetchRawFromPage GETs a page path, follows its iframe src with the response
// cookies and returns the raw body.
func fetchRawFromPage(t *testing.T, s *Server, pagePath string) (page, raw string) {
	t.Helper()
	rec := doRequest(t, s, http.MethodGet, pagePath, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", pagePath, rec.Code, rec.Body.String())
	}
	m := rawSrcRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("GET %s: no raw iframe src in %s", pagePath, rec.Body.String())
	}
	src := strings.ReplaceAll(m[1], "&amp;", "&")
	cookies := rec.Result().Cookies()
	raw2 := doRequest(t, s, http.MethodGet, src, nil, func(r *http.Request) {
		for _, c := range cookies {
			r.AddCookie(c)
		}
	})
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
	rec := doRequest(t, s, http.MethodGet, "/raw/rawother/v/2?t="+url.QueryEscape(tok)+"&v=vid1", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token for v1 on v2 = %d, want 403", rec.Code)
	}
	rec = doRequest(t, s, http.MethodGet, "/raw/rawother/v/1?t="+url.QueryEscape(tok)+"&v=vid1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("token for v1 on v1 = %d, want 200", rec.Code)
	}
}

func TestRawVersionChecksTokenBeforeLookup(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawlookup", models.UploadVisibilityPublic, "")
	rec := doRequest(t, s, http.MethodGet, "/raw/rawlookup/v/99?t=bad&v=vid1", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad token on missing version = %d, want 403", rec.Code)
	}
}

func TestLegacyRawRouteServesLatest(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "rawlegacy", models.UploadVisibilityPublic, "")
	tok := makeViewToken(s.secret, "rawlegacy", "vid1")
	rec := doRequest(t, s, http.MethodGet, "/raw/rawlegacy?t="+url.QueryEscape(tok)+"&v=vid1", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), v2Marker) {
		t.Fatalf("legacy raw = %d, want 200 with v2 marker: %s", rec.Code, rec.Body.String())
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
