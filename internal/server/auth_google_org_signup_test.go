package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"golang.org/x/oauth2"
)

// googleOrgOn enables the mode with a valid domain and Google settings.
func googleOrgOn(t *testing.T, s *Server, domain string) {
	t.Helper()
	ctx := context.Background()
	for k, v := range map[string]string{
		authGoogleOrgSignupSetting:    "true",
		authAllowedEmailDomainSetting: domain,
		"oauth_google_enabled":        "true",
		"oauth_google_client_id":      "client-id",
	} {
		if err := s.store.SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.encryptedSetSetting(ctx, "oauth_google_client_secret", "google-secret"); err != nil {
		t.Fatal(err)
	}
}

func googleOrgProfile(email, hd string) *oauthProfile {
	return &oauthProfile{Provider: "google", ProviderUserID: "g-" + email, Email: email, EmailVerified: true, Name: "Org User", HostedDomain: hd}
}

func TestGoogleOrgFetchGoogleProfileReadsHostedDomain(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: priv.Public(), KeyID: "test-key", Algorithm: oidc.RS256}}}
	ts := httptest.NewServer(issuer)
	defer ts.Close()
	issuer.SetIssuer(ts.URL)
	restoreGoogleIssuerURL(t, ts.URL)
	exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	p := &oauthProviderConfig{authProvider: authProvider{Key: "google"}, ClientID: "client-id"}
	s := newTestServer(t)
	for _, tc := range []struct{ extra, want string }{
		{`, "hd": " Example.COM "`, "example.com"},
		{``, ""},
	} {
		claims := `{"iss": "` + ts.URL + `", "aud": "client-id", "sub": "g-1", "exp": ` + exp + `, "email": "u@example.com", "email_verified": true, "nonce": "n"` + tc.extra + `}`
		tok := (&oauth2.Token{AccessToken: "a", TokenType: "Bearer"}).WithExtra(map[string]any{"id_token": oidctest.SignIDToken(priv, "test-key", oidc.RS256, claims)})
		profile, err := s.fetchGoogleProfile(context.Background(), p, tok, "n")
		if err != nil {
			t.Fatal(err)
		}
		if profile.HostedDomain != tc.want {
			t.Fatalf("HostedDomain = %q, want %q", profile.HostedDomain, tc.want)
		}
	}
}

func TestGoogleOrgResolveProvisionsAccount(t *testing.T) {
	s := newTestServer(t)
	googleOrgOn(t, s, "example.com")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	acc, err := s.resolveOAuthAccount(req, googleOrgProfile("new@example.com", "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.store.GetAccountByEmail(context.Background(), "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != acc.ID || got.IsAdmin || got.Disabled || got.Name != "Org User" {
		t.Fatalf("account = %+v", got)
	}
}

func TestGoogleOrgResolveRejections(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, s *Server)
		profile *oauthProfile
		want    error
	}{
		{name: "outside domain", profile: googleOrgProfile("a@other.com", "example.com"), want: errAccountNotEligible},
		{name: "no hosted domain", profile: googleOrgProfile("a@example.com", ""), want: errGoogleWorkspaceRequired},
		{name: "github provider", profile: &oauthProfile{Provider: "github", ProviderUserID: "1", Email: "a@example.com", EmailVerified: true, HostedDomain: "example.com"}, want: errAccountNotEligible},
		{name: "empty domain", prepare: func(t *testing.T, s *Server) {
			if err := s.store.SetSetting(ctx, authAllowedEmailDomainSetting, ""); err != nil {
				t.Fatal(err)
			}
		}, profile: googleOrgProfile("a@example.com", "example.com"), want: errAccountNotEligible},
		{name: "unverified", profile: &oauthProfile{Provider: "google", ProviderUserID: "1", Email: "a@example.com", HostedDomain: "example.com"}},
		{name: "existing account personal google", prepare: func(t *testing.T, s *Server) {
			if _, err := s.store.CreateAccount(ctx, "a@example.com", "A", false); err != nil {
				t.Fatal(err)
			}
		}, profile: googleOrgProfile("a@example.com", ""), want: errGoogleWorkspaceRequired},
		{name: "existing admin personal google", prepare: func(t *testing.T, s *Server) {
			if _, err := s.store.CreateAccount(ctx, "a@example.com", "A", true); err != nil {
				t.Fatal(err)
			}
		}, profile: googleOrgProfile("a@example.com", ""), want: errGoogleWorkspaceRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			googleOrgOn(t, s, "example.com")
			if tc.prepare != nil {
				tc.prepare(t, s)
			}
			acc, err := s.resolveOAuthAccount(httptest.NewRequest(http.MethodGet, "/", nil), tc.profile)
			if err == nil || acc != nil {
				t.Fatalf("account=%v err=%v, want rejection", acc, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGoogleOrgResolveLinksExistingAccountAndKeepsDisabled(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	googleOrgOn(t, s, "example.com")
	existing, err := s.store.CreateAccount(ctx, "old@example.com", "Old", false)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	acc, err := s.resolveOAuthAccount(req, googleOrgProfile("old@example.com", "example.com"))
	if err != nil || acc.ID != existing.ID {
		t.Fatalf("acc=%v err=%v", acc, err)
	}
	off, err := s.store.CreateAccount(ctx, "off@example.com", "Off", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetAccountDisabled(ctx, off.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveOAuthAccount(req, googleOrgProfile("off@example.com", "example.com")); err == nil || err.Error() != "account disabled" {
		t.Fatalf("err = %v, want account disabled", err)
	}
}

func TestGoogleOrgModeOffStillRequiresInvite(t *testing.T) {
	s := newTestServer(t)
	_, err := s.resolveOAuthAccount(httptest.NewRequest(http.MethodGet, "/", nil), googleOrgProfile("new@example.com", "example.com"))
	if err == nil || err.Error() != "invite required" {
		t.Fatalf("err = %v, want invite required", err)
	}
}

func TestGoogleOrgCallbackProvisionsAndSignsIn(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: priv.Public(), KeyID: "test-key", Algorithm: oidc.RS256}}}
	mux := http.NewServeMux()
	mux.Handle("/", issuer)
	var tsURL string
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		claims := `{"iss": "` + tsURL + `", "aud": "client-id", "sub": "g-1", "exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
			"email": "new@example.com", "email_verified": true, "hd": "example.com", "nonce": "nonce-123"}`
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "a", "token_type": "Bearer", "expires_in": 3600,
			"id_token": oidctest.SignIDToken(priv, "test-key", oidc.RS256, claims),
		})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	tsURL = ts.URL
	issuer.SetIssuer(ts.URL)
	restoreGoogleIssuerURL(t, ts.URL)

	s := newTestServer(t)
	googleOrgOn(t, s, "example.com")
	target, _ := url.Parse(ts.URL)
	client := &http.Client{Transport: rewriteHostTransport{targetScheme: target.Scheme, targetHost: target.Host}}

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state=state-1&code=abc", nil)
	req = req.WithContext(context.WithValue(req.Context(), oauth2.HTTPClient, client))
	req.SetPathValue("provider", "google")
	req.AddCookie(&http.Cookie{Name: oauthCookieName("google"), Value: s.makeOAuthFlowCookie("google", "state-1", "verifier", "nonce-123")})
	rec := httptest.NewRecorder()
	s.handleOAuthCallback(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if findOAuthTestCookie(rec.Result().Cookies(), sessionCookie) == nil {
		t.Fatal("session cookie not set")
	}
	if _, err := s.store.GetAccountByEmail(context.Background(), "new@example.com"); err != nil {
		t.Fatalf("account not created: %v", err)
	}
}

func TestGoogleOrgStartAddsHostedDomainHint(t *testing.T) {
	start := func(s *Server) url.Values {
		req := httptest.NewRequest(http.MethodGet, "/oauth/google/start", nil)
		req.SetPathValue("provider", "google")
		rec := httptest.NewRecorder()
		s.handleOAuthStart(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return loc.Query()
	}
	s := newTestServer(t)
	googleOrgOn(t, s, "example.com")
	if got := start(s).Get("hd"); got != "example.com" {
		t.Fatalf("hd = %q, want example.com", got)
	}
	if err := s.store.SetSetting(context.Background(), authGoogleOrgSignupSetting, ""); err != nil {
		t.Fatal(err)
	}
	if q := start(s); q.Has("hd") {
		t.Fatalf("hd present with mode off: %v", q)
	}
}

func TestGoogleOrgInviteCreateRefused(t *testing.T) {
	s, store, adminID, _ := admFaultAdmin(t)
	googleOrgOn(t, s, "example.test")
	rec := dashboardPost(t, s, adminID, "/dashboard/invites", url.Values{"email": {"new@example.test"}}, true)
	assertDashboardRedirect(t, rec, "/dashboard?err=invite_not_used")
	invites, err := store.ListInvites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 0 {
		t.Fatalf("invites = %+v, want none", invites)
	}
}

func TestGoogleOrgInviteLinkRedirects(t *testing.T) {
	s, store, adminID, _ := admFaultAdmin(t)
	if _, err := store.CreateInvite(context.Background(), "raw-token", "cipher", "new@example.test", adminID, time.Now().Add(inviteTTL)); err != nil {
		t.Fatal(err)
	}
	googleOrgOn(t, s, "example.test")
	rec := doRequest(t, s, http.MethodGet, "/invite/raw-token", nil)
	assertDashboardRedirect(t, rec, "/login")
	if findOAuthTestCookie(rec.Result().Cookies(), inviteCookie) != nil {
		t.Fatal("invite cookie set while mode is on")
	}
}
