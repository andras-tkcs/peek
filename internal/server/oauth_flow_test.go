package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// oauthCovGitHubFlow points the GitHub endpoints at a fake and enables the
// provider. tokenStatus and userStatus control the fake's answers.
func oauthCovGitHubFlow(t *testing.T, s *Server, tokenStatus, userStatus int) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if tokenStatus != http.StatusOK {
			http.Error(w, "denied", tokenStatus)
			return
		}
		jsonOK(w, map[string]any{"access_token": "at", "token_type": "Bearer"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if userStatus != http.StatusOK {
			http.Error(w, "down", userStatus)
			return
		}
		_, _ = w.Write([]byte(`{"id":7,"login":"octo","name":"Octo"}`))
	})
	mux.HandleFunc("/emails", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"email":"Octo@example.test","primary":true,"verified":true}]`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	restoreGitHubURLs(t, ts.URL)
	old := githubOAuthEndpoint
	githubOAuthEndpoint = oauth2.Endpoint{AuthURL: ts.URL + "/auth", TokenURL: ts.URL + "/token"}
	t.Cleanup(func() { githubOAuthEndpoint = old })
	oauthCovEnable(t, s, "github", "")
}

// oauthCovCallback runs handleOAuthCallback for provider with a valid flow
// cookie for state "st" and the given extra query and cookies.
func oauthCovCallback(s *Server, provider, query string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/oauth/"+provider+"/callback?"+query, nil)
	req.SetPathValue("provider", provider)
	req.AddCookie(&http.Cookie{Name: oauthCookieName(provider), Value: s.makeOAuthFlowCookie(provider, "st", oauth2.GenerateVerifier(), "nonce")})
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.handleOAuthCallback(rec, req)
	return rec
}

func oauthCovFlowCookieCleared(rec *httptest.ResponseRecorder, provider string) bool {
	c := findOAuthTestCookie(rec.Result().Cookies(), oauthCookieName(provider))
	return c != nil && c.MaxAge < 0
}

func TestOAuthCovStartFailures(t *testing.T) {
	s := newTestServer(t)
	oauthCovEnable(t, s, "github", "")
	start := func(provider string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/oauth/"+provider+"/start", nil)
		req.SetPathValue("provider", provider)
		rec := httptest.NewRecorder()
		s.handleOAuthStart(rec, req)
		return rec
	}
	if rec := start("google"); rec.Code != http.StatusNotFound {
		t.Fatalf("unconfigured provider status = %d", rec.Code)
	}
	for _, okCalls := range []int{0, 1} { // state, then nonce
		restore := dashCovFailRandAfter(okCalls)
		rec := start("github")
		restore()
		if rec.Code != http.StatusInternalServerError { // the error page itself cannot get a CSRF token either
			t.Fatalf("after %d ok rand calls: status=%d", okCalls, rec.Code)
		}
	}
	rec := start("github")
	if rec.Code != http.StatusFound || findOAuthTestCookie(rec.Result().Cookies(), oauthCookieName("github")) == nil {
		t.Fatalf("status = %d", rec.Code)
	}
	if loc, _ := url.Parse(rec.Header().Get("Location")); loc.Query().Get("redirect_uri") != "http://peek.test/oauth/github/callback" {
		t.Fatalf("location = %s", rec.Header().Get("Location"))
	}
}

func TestOAuthCovCallbackRejections(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	oauthCovGitHubFlow(t, s, http.StatusOK, http.StatusOK)

	unknown := httptest.NewRequest(http.MethodGet, "/oauth/google/callback", nil)
	unknown.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()
	s.handleOAuthCallback(rec, unknown)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown provider status = %d", rec.Code)
	}

	noCookie := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state=st&code=c", nil)
	noCookie.SetPathValue("provider", "github")
	rec = httptest.NewRecorder()
	s.handleOAuthCallback(rec, noCookie)
	if rec.Code != http.StatusBadRequest || !oauthCovFlowCookieCleared(rec, "github") {
		t.Fatalf("missing cookie status = %d", rec.Code)
	}

	for _, tc := range []struct {
		name, query string
		status      int
	}{
		{"state mismatch", "state=other&code=c", http.StatusBadRequest},
		{"provider error", "state=st&error=access_denied", http.StatusUnauthorized},
		{"missing code", "state=st&code=%20", http.StatusBadRequest},
	} {
		rec := oauthCovCallback(s, "github", tc.query)
		if rec.Code != tc.status || !oauthCovFlowCookieCleared(rec, "github") {
			t.Fatalf("%s: status = %d", tc.name, rec.Code)
		}
	}

	// No session is created and no account exists after any rejection.
	if n, _ := s.store.CountAccounts(ctx); n != 0 {
		t.Fatalf("accounts = %d", n)
	}
}

func TestOAuthCovCallbackUpstreamFailures(t *testing.T) {
	for _, tc := range []struct {
		name                string
		tokenStatus, userSt int
		msg                 string
	}{
		{"token exchange", http.StatusBadRequest, http.StatusOK, "token exchange failed"},
		{"profile lookup", http.StatusOK, http.StatusInternalServerError, "profile lookup failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			oauthCovGitHubFlow(t, s, tc.tokenStatus, tc.userSt)
			rec := oauthCovCallback(s, "github", "state=st&code=c")
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), tc.msg) || !oauthCovFlowCookieCleared(rec, "github") {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if findOAuthTestCookie(rec.Result().Cookies(), sessionCookie) != nil {
				t.Fatal("session cookie set on failure")
			}
		})
	}
}

func TestOAuthCovCallbackAccountFailures(t *testing.T) {
	t.Run("no invite", func(t *testing.T) {
		s := newTestServer(t)
		oauthCovGitHubFlow(t, s, http.StatusOK, http.StatusOK)
		rec := oauthCovCallback(s, "github", "state=st&code=c")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "invite is required") || !oauthCovFlowCookieCleared(rec, "github") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("identity link fails", func(t *testing.T) {
		s := newTestServer(t)
		oauthCovGitHubFlow(t, s, http.StatusOK, http.StatusOK)
		if _, err := s.store.CreateAccount(context.Background(), "octo@example.test", "Octo", false); err != nil {
			t.Fatal(err)
		}
		addFailTrigger(t, s.store, "oauth_identities", "INSERT")
		rec := oauthCovCallback(s, "github", "state=st&code=c")
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "account link failed") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if findOAuthTestCookie(rec.Result().Cookies(), sessionCookie) != nil {
			t.Fatal("session cookie set on failure")
		}
	})
}

func TestOAuthCovCallbackSuccessHonoursNextCookie(t *testing.T) {
	s := newTestServer(t)
	oauthCovGitHubFlow(t, s, http.StatusOK, http.StatusOK)
	a, err := s.store.CreateAccount(context.Background(), "octo@example.test", "Octo", false)
	if err != nil {
		t.Fatal(err)
	}
	rec := oauthCovCallback(s, "github", "state=st&code=c", &http.Cookie{Name: nextCookie, Value: "/dashboard/keys"})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard/keys" {
		t.Fatalf("status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if findOAuthTestCookie(rec.Result().Cookies(), sessionCookie) == nil {
		t.Fatal("no session cookie")
	}
	if oi, err := s.store.GetOAuthIdentity(context.Background(), "github", "7"); err != nil || oi.AccountID != a.ID {
		t.Fatalf("identity=%+v err=%v", oi, err)
	}
}

func TestOAuthCovAccountErrorMessages(t *testing.T) {
	if got := oauthAccountErrorMessage(nil); got != "OAuth account could not be linked." {
		t.Fatalf("nil message = %q", got)
	}
	if got := oauthAccountErrorMessage(errors.New("account disabled")); got != "This account is disabled." {
		t.Fatalf("message = %q", got)
	}
}
