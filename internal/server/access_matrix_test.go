package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/andras-tkcs/peek/internal/models"
	"github.com/andras-tkcs/peek/internal/uploadquota"
)

// matrixEnv is one server with an owner, a grantee, an unrelated signed-in user and
// an admin, each with a session cookie and a bearer token.
type matrixEnv struct {
	s        *Server
	owner    *models.Account
	grantee  *models.Account
	other    *models.Account
	admin    *models.Account
	password string
}

const matrixPagePassword = "matrix-secret"

func newMatrixEnv(t *testing.T) *matrixEnv {
	t.Helper()
	s, _ := newHandlerTestServer(t)
	return &matrixEnv{
		s:        s,
		owner:    newAccountWithToken(t, s, "owner@example.test", "owner-token", false),
		grantee:  newAccountWithToken(t, s, "grantee@example.test", "grantee-token", false),
		other:    newAccountWithToken(t, s, "other@example.test", "other-token", false),
		admin:    newAccountWithToken(t, s, "admin@example.test", "admin-token", true),
		password: matrixPagePassword,
	}
}

func (e *matrixEnv) page(t *testing.T, slug, visibility string) *models.Upload {
	t.Helper()
	ctx := context.Background()
	hash := ""
	if visibility == models.UploadVisibilityPassword {
		b, err := bcrypt.GenerateFromPassword([]byte(e.password), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		hash = string(b)
	}
	body := []byte("<html><body>matrix secret body</body></html>")
	if err := e.s.storage.Save(ctx, slug, body); err != nil {
		t.Fatal(err)
	}
	if err := e.s.store.CreateUploadChecked(ctx, slug, e.owner.ID, 0, "matrix.html", int64(len(body)), visibility, hash, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	u, err := e.s.store.GetUpload(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	grant(t, e.s, u, models.UploadGrantUser, "grantee@example.test")
	return u
}

// unlockCookie returns the page-password cookie a viewer gets by entering the right password.
func (e *matrixEnv) unlockCookie(t *testing.T, slug string) *http.Cookie {
	t.Helper()
	rec := doRequest(t, e.s, http.MethodPost, "/p/"+slug, strings.NewReader("password="+e.password),
		func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") })
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("unlock status = %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == authCookieName(slug) {
			return c
		}
	}
	t.Fatal("unlock set no page auth cookie")
	return nil
}

// TestPageAccessMatrix checks every page-side read and write route for every
// visibility against every kind of viewer. A viewer who gets a non-200 on the
// page must also be refused by the comment and views APIs and must not receive
// the page content anywhere.
func TestPageAccessMatrix(t *testing.T) {
	e := newMatrixEnv(t)

	type actor struct {
		name string
		opts func(*http.Request)
	}
	anon := actor{"anonymous", func(*http.Request) {}}
	owner := actor{"owner", asSession(e.s, e.owner.ID)}
	grantee := actor{"grantee", asSession(e.s, e.grantee.ID)}
	other := actor{"other", asSession(e.s, e.other.ID)}
	admin := actor{"admin", asSession(e.s, e.admin.ID)}

	// want is [page status, API status] per actor; API status is shared by
	// GET views, GET comments and POST comments.
	type want struct{ page, api int }
	const (
		ok     = http.StatusOK
		redir  = http.StatusSeeOther
		deny   = http.StatusForbidden
		noauth = http.StatusUnauthorized
	)
	cases := []struct {
		visibility string
		want       map[string]want
	}{
		{models.UploadVisibilityPublic, map[string]want{
			"anonymous": {ok, ok}, "owner": {ok, ok}, "grantee": {ok, ok}, "other": {ok, ok}, "admin": {ok, ok},
		}},
		// The gate page is a 200 that must not carry content. Accounts do not bypass it.
		{models.UploadVisibilityPassword, map[string]want{
			"anonymous": {ok, noauth}, "owner": {ok, noauth}, "grantee": {ok, noauth}, "other": {ok, noauth}, "admin": {ok, noauth},
		}},
		{models.UploadVisibilitySignedIn, map[string]want{
			"anonymous": {redir, noauth}, "owner": {ok, ok}, "grantee": {ok, ok}, "other": {ok, ok}, "admin": {ok, ok},
		}},
		{models.UploadVisibilityRestricted, map[string]want{
			"anonymous": {redir, noauth}, "owner": {ok, ok}, "grantee": {ok, ok}, "other": {deny, deny}, "admin": {ok, ok},
		}},
	}

	for _, tc := range cases {
		u := e.page(t, "m-"+strings.ReplaceAll(tc.visibility, "-", ""), tc.visibility)
		for _, a := range []actor{anon, owner, grantee, other, admin} {
			w := tc.want[a.name]
			t.Run(tc.visibility+"/"+a.name, func(t *testing.T) {
				page := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, a.opts)
				if page.Code != w.page {
					t.Fatalf("GET /p = %d, want %d", page.Code, w.page)
				}
				hasIframe := strings.Contains(page.Body.String(), "/raw/"+u.Slug)
				if wantFrame := tc.visibility != models.UploadVisibilityPassword && w.page == ok; hasIframe != wantFrame {
					t.Fatalf("page has raw iframe = %v, want %v", hasIframe, wantFrame)
				}
				if strings.Contains(page.Body.String(), "matrix secret body") {
					t.Fatal("page response contains uploaded content")
				}
				if w.page == redir && page.Header().Get("Location") != "/login" {
					t.Fatalf("redirect = %q, want /login", page.Header().Get("Location"))
				}

				views := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+u.Slug+"/views", nil, a.opts)
				if views.Code != w.api {
					t.Fatalf("GET views = %d, want %d", views.Code, w.api)
				}
				comments := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+u.Slug+"/comments", nil, a.opts)
				if comments.Code != w.api {
					t.Fatalf("GET comments = %d, want %d", comments.Code, w.api)
				}
				post := doRequest(t, e.s, http.MethodPost, "/api/uploads/"+u.Slug+"/comments",
					strings.NewReader(`{"name":"Mallory","body":"hello"}`), a.opts, withJSON())
				if post.Code != w.api {
					t.Fatalf("POST comments = %d, want %d", post.Code, w.api)
				}
				if w.api != ok && strings.Contains(post.Body.String(), "hello") {
					t.Fatal("refused comment response echoed the comment list")
				}
			})
		}
	}
}

// TestPasswordPageAccessMatrix covers the unlocked and wrong-password states.
func TestPasswordPageAccessMatrix(t *testing.T) {
	e := newMatrixEnv(t)
	u := e.page(t, "m-pw", models.UploadVisibilityPassword)
	other := e.page(t, "m-pw-other", models.UploadVisibilityPassword)

	cookie := e.unlockCookie(t, u.Slug)
	withCookie := func(r *http.Request) { r.AddCookie(cookie) }
	if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+u.Slug+"/views", nil, withCookie); rec.Code != http.StatusOK {
		t.Fatalf("unlocked views = %d, want 200", rec.Code)
	}
	// The unlock cookie is per page: it opens nothing else.
	if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+other.Slug+"/views", nil, withCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie for another page = %d, want 401", rec.Code)
	}
	// A cookie renamed to another slug must not verify either.
	renamed := &http.Cookie{Name: authCookieName(other.Slug), Value: cookie.Value}
	if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+other.Slug+"/views", nil, func(r *http.Request) { r.AddCookie(renamed) }); rec.Code != http.StatusUnauthorized {
		t.Fatalf("relabelled cookie = %d, want 401", rec.Code)
	}
	for _, bad := range []string{"", "x", "a.b.c", cookie.Value + "0", u.Slug + ".9999999999.deadbeef"} {
		c := &http.Cookie{Name: authCookieName(u.Slug), Value: bad}
		if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+u.Slug+"/views", nil, func(r *http.Request) { r.AddCookie(c) }); rec.Code != http.StatusUnauthorized {
			t.Fatalf("forged cookie %q = %d, want 401", bad, rec.Code)
		}
	}
	wrong := doRequest(t, e.s, http.MethodPost, "/p/"+u.Slug, strings.NewReader("password=nope"),
		func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") })
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d, want 401", wrong.Code)
	}
	for _, c := range wrong.Result().Cookies() {
		if c.Name == authCookieName(u.Slug) {
			t.Fatal("wrong password set an auth cookie")
		}
	}
}

// TestRawAccessMatrix checks that /raw serves content only to viewers who may see
// the page, even when they hold a validly signed view token and visitor cookie.
func TestRawAccessMatrix(t *testing.T) {
	e := newMatrixEnv(t)
	for _, visibility := range []string{models.UploadVisibilitySignedIn, models.UploadVisibilityRestricted, models.UploadVisibilityPassword} {
		t.Run(visibility, func(t *testing.T) {
			u := e.page(t, "raw-"+strings.ReplaceAll(visibility, "-", ""), visibility)
			authorized := asSession(e.s, e.owner.ID)
			if visibility == models.UploadVisibilityPassword {
				c := e.unlockCookie(t, u.Slug)
				authorized = func(r *http.Request) { r.AddCookie(c) }
			}
			src, pageCookies := rawSrcFromPage(t, e.s, "/p/"+u.Slug, authorized)
			// Only the visitor cookie: the page response may also carry the
			// password-unlock cookie, which is a credential in its own right.
			var cookies []*http.Cookie
			for _, c := range pageCookies {
				if c.Name == visitorCookie {
					cookies = append(cookies, c)
				}
			}
			if len(cookies) == 0 {
				t.Fatal("page set no visitor cookie")
			}
			if rec := doRequest(t, e.s, http.MethodGet, src, nil, withCookieList(cookies), authorized); rec.Code != http.StatusOK ||
				!strings.Contains(rec.Body.String(), "matrix secret body") {
				t.Fatalf("authorized raw = %d: %s", rec.Code, rec.Body.String())
			}
			// The same URL and visitor cookie replayed without the viewer's credentials.
			if rec := doRequest(t, e.s, http.MethodGet, src, nil, withCookieList(cookies)); rec.Code != http.StatusForbidden {
				t.Fatalf("leaked raw URL with visitor cookie = %d, want 403", rec.Code)
			}
			if visibility == models.UploadVisibilityRestricted {
				if rec := doRequest(t, e.s, http.MethodGet, src, nil, withCookieList(cookies), asSession(e.s, e.other.ID)); rec.Code != http.StatusForbidden {
					t.Fatalf("leaked raw URL as ungranted user = %d, want 403", rec.Code)
				}
			}
			// Without the visitor cookie, or with a tampered token, the URL alone is refused.
			if rec := doRequest(t, e.s, http.MethodGet, src, nil, authorized); rec.Code != http.StatusForbidden {
				t.Fatalf("raw without visitor cookie = %d, want 403", rec.Code)
			}
			if rec := doRequest(t, e.s, http.MethodGet, src+"0", nil, withCookieList(cookies), authorized); rec.Code != http.StatusForbidden {
				t.Fatalf("raw with tampered token = %d, want 403", rec.Code)
			}
			other := strings.Replace(src, "/raw/"+u.Slug+"/", "/raw/m-other/", 1)
			if rec := doRequest(t, e.s, http.MethodGet, other, nil, withCookieList(cookies), authorized); rec.Code != http.StatusForbidden {
				t.Fatalf("token reused for another slug = %d, want 403", rec.Code)
			}
		})
	}
}

// TestSignedInAccessLostWhenAccountDisabled makes sure a disabled account loses
// access to signed-in and restricted pages at once, for sessions already issued.
func TestSignedInAccessLostWhenAccountDisabled(t *testing.T) {
	e := newMatrixEnv(t)
	signedIn := e.page(t, "m-dis-signedin", models.UploadVisibilitySignedIn)
	restricted := e.page(t, "m-dis-restricted", models.UploadVisibilityRestricted)
	session := asSession(e.s, e.grantee.ID)

	for _, u := range []*models.Upload{signedIn, restricted} {
		if rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, session); rec.Code != http.StatusOK {
			t.Fatalf("%s before disable = %d, want 200", u.Slug, rec.Code)
		}
	}
	if err := e.s.store.SetAccountDisabled(context.Background(), e.grantee.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*models.Upload{signedIn, restricted} {
		if rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, session); rec.Code != http.StatusSeeOther {
			t.Fatalf("%s after disable = %d, want 303", u.Slug, rec.Code)
		}
		if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+u.Slug+"/views", nil, session); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s views after disable = %d, want 401", u.Slug, rec.Code)
		}
	}
}

// TestSessionCookieForgeryIsRefused checks that tampered or unsigned session
// cookies never count as a signed-in viewer.
func TestSessionCookieForgeryIsRefused(t *testing.T) {
	e := newMatrixEnv(t)
	u := e.page(t, "m-forge", models.UploadVisibilitySignedIn)
	good := makeWebSession(e.s.secret, "1", sessionTTL)
	for name, val := range map[string]string{
		"plain account id": "1",
		"unsigned subject": "1.9999999999.",
		"bad signature":    strings.TrimSuffix(good, good[len(good)-1:]) + "0",
		"other secret":     makeWebSession("some-other-secret", "1", sessionTTL),
		"expired":          makeWebSession(e.s.secret, "1", -sessionTTL),
	} {
		c := &http.Cookie{Name: sessionCookie, Value: val}
		rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, func(r *http.Request) { r.AddCookie(c) })
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s: status = %d, want 303", name, rec.Code)
		}
	}
}

// TestOwnerOnlyAPIMatrix checks that every owner-scoped API route refuses
// anonymous callers and signed-in non-owners for every visibility, and that
// nothing was changed by the refused calls.
func TestOwnerOnlyAPIMatrix(t *testing.T) {
	e := newMatrixEnv(t)
	type route struct {
		method, path, body string
	}
	routes := func(slug string) []route {
		base := "/api/uploads/" + slug
		return []route{
			{http.MethodGet, base + "/stats", ""},
			{http.MethodGet, base + "/export", ""},
			{http.MethodGet, base + "/versions", ""},
			{http.MethodGet, base + "/grants", ""},
			{http.MethodPost, base + "/grants", `{"kind":"user","email":"other@example.test"}`},
			{http.MethodDelete, base + "/grants", `{"kind":"user","email":"grantee@example.test"}`},
			{http.MethodPost, base + "/visibility", `{"visibility":"public"}`},
			{http.MethodPost, base + "/name", `{"name":"hijacked"}`},
			{http.MethodPost, base + "/account-comments", `{"body":"hi"}`},
			{http.MethodDelete, base, ""},
		}
	}

	for _, visibility := range []string{
		models.UploadVisibilityPublic, models.UploadVisibilityPassword,
		models.UploadVisibilitySignedIn, models.UploadVisibilityRestricted,
	} {
		u := e.page(t, "own-"+strings.ReplaceAll(visibility, "-", ""), visibility)
		for _, rt := range routes(u.Slug) {
			for _, c := range []struct {
				name string
				opts []func(*http.Request)
				want int
			}{
				{"anonymous", nil, http.StatusUnauthorized},
				{"signed-in non-owner", []func(*http.Request){asBearer("other-token")}, http.StatusForbidden},
				{"granted viewer", []func(*http.Request){asBearer("grantee-token")}, http.StatusForbidden},
				{"bogus token", []func(*http.Request){asBearer("nope")}, http.StatusUnauthorized},
			} {
				opts := append([]func(*http.Request){withJSON()}, c.opts...)
				rec := doRequest(t, e.s, rt.method, rt.path, strings.NewReader(rt.body), opts...)
				if rec.Code != c.want {
					t.Errorf("%s %s %s as %s = %d, want %d: %s", visibility, rt.method, rt.path, c.name, rec.Code, c.want, rec.Body.String())
				}
			}
		}
		got, err := e.s.store.GetUpload(context.Background(), u.Slug)
		if err != nil {
			t.Fatalf("%s: upload gone after refused calls: %v", visibility, err)
		}
		if got.Visibility != visibility || got.Name != u.Name {
			t.Errorf("%s: upload changed by refused calls: visibility=%q name=%q", visibility, got.Visibility, got.Name)
		}
		grants, err := e.s.store.ListUploadGrants(context.Background(), u.ID)
		if err != nil || len(grants) != 1 {
			t.Errorf("%s: grants changed by refused calls: %v err=%v", visibility, grants, err)
		}
	}
}

// TestBearerCommentsReadIsOwnerOnly: the CLI path of the comments API must not
// let a non-owner token read comments of a page it cannot open.
func TestBearerCommentsReadIsOwnerOnly(t *testing.T) {
	e := newMatrixEnv(t)
	u := e.page(t, "m-cm", models.UploadVisibilityRestricted)
	for token, want := range map[string]int{
		"other-token":   http.StatusForbidden,
		"grantee-token": http.StatusForbidden,
		"nope":          http.StatusUnauthorized,
		"owner-token":   http.StatusOK,
		"admin-token":   http.StatusOK,
	} {
		rec := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+u.Slug+"/comments", nil, asBearer(token))
		if rec.Code != want {
			t.Errorf("bearer %s: status = %d, want %d", token, rec.Code, want)
		}
	}
}

// TestDashboardStatsIsOwnerOnly: stats rows hold visitor names, IP hashes and
// user agents, so only the owner and admins may see them.
func TestDashboardStatsIsOwnerOnly(t *testing.T) {
	e := newMatrixEnv(t)
	u := e.page(t, "m-stats", models.UploadVisibilityPublic)
	for name, c := range map[string]struct {
		opts func(*http.Request)
		want int
	}{
		"anonymous": {func(*http.Request) {}, http.StatusSeeOther},
		"other":     {asSession(e.s, e.other.ID), http.StatusNotFound},
		"grantee":   {asSession(e.s, e.grantee.ID), http.StatusNotFound},
		"owner":     {asSession(e.s, e.owner.ID), http.StatusOK},
		"admin":     {asSession(e.s, e.admin.ID), http.StatusOK},
	} {
		if rec := doRequest(t, e.s, http.MethodGet, "/dashboard/stats/"+u.Slug, nil, c.opts); rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, c.want)
		}
	}
}

// TestRestrictedGrantLifecycle: a grant opens the page, removing it closes the
// page again (also for the comment API), and the owner sees no change.
func TestRestrictedGrantLifecycle(t *testing.T) {
	e := newMatrixEnv(t)
	u := e.page(t, "m-life", models.UploadVisibilityRestricted)
	as := asSession(e.s, e.grantee.ID)

	if rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, as); rec.Code != http.StatusOK {
		t.Fatalf("granted = %d, want 200", rec.Code)
	}
	if err := e.s.store.RemoveUploadGrant(context.Background(), u.ID, models.UploadGrantUser, "grantee@example.test"); err != nil {
		t.Fatal(err)
	}
	if rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, as); rec.Code != http.StatusForbidden {
		t.Fatalf("after revoke = %d, want 403", rec.Code)
	}
	if rec := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+u.Slug+"/comments", nil, as); rec.Code != http.StatusForbidden {
		t.Fatalf("comments after revoke = %d, want 403", rec.Code)
	}
	if rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, asSession(e.s, e.owner.ID)); rec.Code != http.StatusOK {
		t.Fatalf("owner after revoke = %d, want 200", rec.Code)
	}
}

// TestGrantsOnlyApplyWhileRestricted: grants stay stored when a page goes
// signed-in or public and must not widen access when it goes back to restricted
// beyond what the grants say.
func TestGrantsDoNotLeakAcrossVisibilityChanges(t *testing.T) {
	e := newMatrixEnv(t)
	u := e.page(t, "m-switch", models.UploadVisibilityPublic)
	rec := doRequest(t, e.s, http.MethodPost, "/api/uploads/"+u.Slug+"/visibility", strings.NewReader(`{"visibility":"restricted"}`), asBearer("owner-token"), withJSON())
	if rec.Code != http.StatusOK {
		t.Fatalf("set restricted = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, asSession(e.s, e.other.ID)); rec.Code != http.StatusForbidden {
		t.Fatalf("ungranted user after public→restricted = %d, want 403", rec.Code)
	}
	if rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("anonymous after public→restricted = %d, want 303", rec.Code)
	}
}

// TestLegacyPrivateInputMeansSignedIn: the old visibility name keeps working in
// the API and is stored under the new name, never as "private".
func TestLegacyPrivateInputMeansSignedIn(t *testing.T) {
	e := newMatrixEnv(t)
	u := e.page(t, "m-legacy", models.UploadVisibilityPublic)
	rec := doRequest(t, e.s, http.MethodPost, "/api/uploads/"+u.Slug+"/visibility", strings.NewReader(`{"visibility":"private"}`), asBearer("owner-token"), withJSON())
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"visibility":"signed-in"`) {
		t.Fatalf("legacy private = %d: %s", rec.Code, rec.Body.String())
	}
	got, err := e.s.store.GetUpload(context.Background(), u.Slug)
	if err != nil || got.Visibility != models.UploadVisibilitySignedIn {
		t.Fatalf("stored visibility = %q (err %v), want signed-in", got.Visibility, err)
	}
	if rec := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("anonymous = %d, want 303", rec.Code)
	}
}

// TestUnknownStoredVisibilityFailsClosed: a row holding a value the code does not
// know (for example "private" from a database that skipped the migration) must
// deny everyone, not fall through to public.
func TestUnknownStoredVisibilityFailsClosed(t *testing.T) {
	e := newMatrixEnv(t)
	u := e.page(t, "m-unknown", models.UploadVisibilityPublic)
	if _, err := e.s.store.Exec(`UPDATE uploads SET visibility='private' WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string]func(*http.Request){
		"anonymous": func(*http.Request) {},
		"owner":     asSession(e.s, e.owner.ID),
		"admin":     asSession(e.s, e.admin.ID),
	} {
		rec := doRequest(t, e.s, http.MethodGet, "/api/uploads/"+u.Slug+"/views", nil, opts)
		if rec.Code == http.StatusOK {
			t.Errorf("%s: views = 200 for unknown visibility, want it refused", name)
		}
		page := doRequest(t, e.s, http.MethodGet, "/p/"+u.Slug, nil, opts)
		if strings.Contains(page.Body.String(), "/raw/"+u.Slug) {
			t.Errorf("%s: page rendered the content frame for unknown visibility", name)
		}
	}
}
