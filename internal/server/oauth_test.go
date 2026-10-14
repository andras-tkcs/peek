package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
	webui "github.com/andras-tkcs/peek/internal/web"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const testSecret = "0000000000000000000000000000000000000000000000000000000000000000"

func newTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &Server{
		store:           store,
		secret:          testSecret,
		baseURL:         "http://peek.test",
		renderer:        renderer,
		loginLimiter:    newLimiter(100, time.Minute),
		commentLimiter:  newLimiter(100, time.Minute),
		cliLoginLimiter: newLimiter(100, time.Minute),
	}
}

func TestResolveOAuthAccountConsumesMatchingInvite(t *testing.T) {
	s := newTestServer(t)
	raw := "invite-token"
	ciphertext, err := encryptSecret(s.secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.store.CreateAccount(context.Background(), "", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.store.CreateInvite(context.Background(), raw, ciphertext, "User@Example.COM", admin.ID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: inviteCookie, Value: raw})

	account, err := s.resolveOAuthAccount(req, &oauthProfile{
		Provider:       "google",
		ProviderUserID: "sub-1",
		Email:          "user@example.com",
		EmailVerified:  true,
		Name:           "User",
	})
	if err != nil {
		t.Fatal(err)
	}
	if account.Email != "user@example.com" || account.IsAdmin {
		t.Fatalf("unexpected account: %+v", account)
	}
	used, err := s.store.GetInviteByID(context.Background(), inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if used.UsedAt.IsZero() {
		t.Fatal("invite was not consumed")
	}
}

func TestResolveOAuthAccountLinksExistingVerifiedEmailWithoutInvite(t *testing.T) {
	s := newTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "user@example.com", "Existing", false)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err := s.resolveOAuthAccount(req, &oauthProfile{
		Provider:       "github",
		ProviderUserID: "123",
		Email:          "USER@example.com",
		EmailVerified:  true,
		Name:           "Other",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != account.ID {
		t.Fatalf("expected account %d, got %d", account.ID, got.ID)
	}
}

func TestResolveOAuthAccountRejectsUnverifiedEmail(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := s.resolveOAuthAccount(req, &oauthProfile{
		Provider:       "google",
		ProviderUserID: "sub-1",
		Email:          "user@example.com",
		EmailVerified:  false,
		Name:           "User",
	})
	if err == nil || !strings.Contains(err.Error(), "verified") {
		t.Fatalf("expected verified email error, got %v", err)
	}
}

func TestOAuthStartErrorRendersLoginPage(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start", nil)
	req.SetPathValue("provider", "google")
	rec := httptest.NewRecorder()

	s.handleOAuthStart(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != webui.DashboardCSP {
		t.Fatalf("csp = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("cache-control = %q", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "OAuth provider is not configured.") {
		t.Fatalf("rendered page did not include oauth error: %s", body)
	}
	if !strings.Contains(body, "Sign in") {
		t.Fatalf("expected login template, got: %s", body)
	}
}

func TestEnabledOAuthProvidersIncludesConfiguredOIDCWithoutDiscovery(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.SetSetting(context.Background(), "oauth_oidc_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(context.Background(), "oauth_oidc_issuer_url", "https://8.8.8.8/issuer"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(context.Background(), "oauth_oidc_client_id", "client-id"); err != nil {
		t.Fatal(err)
	}
	if err := s.encryptedSetSetting(context.Background(), "oauth_oidc_client_secret", "client-secret"); err != nil {
		t.Fatal(err)
	}

	providers := s.enabledOAuthProviders(context.Background())
	if len(providers) != 1 || providers[0].Key != "oidc" || providers[0].Name != "SSO" {
		t.Fatalf("providers = %+v", providers)
	}
}

func TestOAuthAccountErrorMessageHidesInternalFailures(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{err: errors.New("OAuth account must have a verified email"), want: "OAuth account must have a verified email."},
		{err: errors.New("account disabled"), want: "This account is disabled."},
		{err: errors.New("invite required"), want: "An invite is required for this account."},
		{err: errors.New("invite not found"), want: "This invite is invalid or expired."},
		{err: errAccountNotEligible, want: "OAuth account could not be linked."},
		{err: errors.New("account lookup failed: driver timeout"), want: "OAuth account could not be linked."},
	}
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			if got := oauthAccountErrorMessage(tc.err); got != tc.want {
				t.Fatalf("message = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFetchGitHubProfileUsesVerifiedPrimaryEmail(t *testing.T) {
	var sawAuth atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer token" {
			sawAuth.Store(true)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("accept header = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(`{"id":42,"login":"octo","name":""}`))
		case "/emails":
			_, _ = w.Write([]byte(`[
				{"email":"secondary@example.com","primary":false,"verified":true},
				{"email":"PRIMARY@Example.COM","primary":true,"verified":true}
			]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	restoreGitHubURLs(t, provider.URL)

	s := newTestServer(t)
	profile, err := s.fetchGitHubProfile(context.Background(), testGitHubProviderConfig(), &oauth2.Token{
		AccessToken: "token",
		TokenType:   "Bearer",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawAuth.Load() {
		t.Fatal("provider did not receive bearer token")
	}
	if profile.Provider != "github" || profile.ProviderUserID != "42" || profile.Email != "primary@example.com" || !profile.EmailVerified || profile.Name != "octo" {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestFetchGitHubProfileRejectsOversizedProviderJSON(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat(" ", oauthJSONBodyLimit+1)))
	}))
	defer provider.Close()
	restoreGitHubURLs(t, provider.URL)

	s := newTestServer(t)
	_, err := s.fetchGitHubProfile(context.Background(), testGitHubProviderConfig(), &oauth2.Token{
		AccessToken: "token",
		TokenType:   "Bearer",
	})
	if err == nil || !strings.Contains(err.Error(), "response too large") {
		t.Fatalf("error = %v, want oversized response error", err)
	}
}

func TestFetchOIDCProfileUsesVerifiedIDTokenClaims(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{
			PublicKey: priv.Public(),
			KeyID:     "test-key",
			Algorithm: oidc.RS256,
		}},
	}
	ts := httptest.NewServer(issuer)
	defer ts.Close()
	issuer.SetIssuer(ts.URL)

	provider, err := oidc.NewProvider(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rawClaims := `{
		"iss": "` + ts.URL + `",
		"aud": "client-id",
		"sub": "user-123",
		"exp": ` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `,
		"email": "USER@Example.COM",
		"email_verified": true,
		"name": "OIDC User",
		"preferred_username": "oidc-user",
		"nonce": "nonce-123"
	}`
	rawIDToken := oidctest.SignIDToken(priv, "test-key", oidc.RS256, rawClaims)
	tok := (&oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}).WithExtra(map[string]any{"id_token": rawIDToken})

	s := newTestServer(t)
	profile, err := s.fetchOIDCProfile(context.Background(), &oauthProviderConfig{
		authProvider: authProvider{Key: "oidc", Name: "SSO"},
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    ts.URL,
		OIDCProvider: provider,
	}, tok, "nonce-123")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Provider != "oidc" || profile.ProviderUserID != ts.URL+"#user-123" || profile.Email != "user@example.com" || !profile.EmailVerified || profile.Name != "OIDC User" {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestOIDCCallbackWithFakeSSOServerCreatesSessionAndConsumesInvite(t *testing.T) {
	s := newTestServer(t)
	admin, err := s.store.CreateAccount(context.Background(), "admin@example.com", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	rawInvite := "invite-token"
	ciphertext, err := encryptSecret(s.secret, rawInvite)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.store.CreateInvite(context.Background(), rawInvite, ciphertext, "User@Example.COM", admin.ID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	issuerURL := "https://8.8.8.8/oidc"
	clientID := "peek-client"
	clientSecret := "peek-secret"
	fake := newFakeOIDCServer(t, fakeOIDCOptions{Issuer: issuerURL, ClientID: clientID, Sub: "user-123", Email: "USER@Example.COM", EmailVerified: true, Nonce: "nonce-123"})
	defer fake.close()

	if err := s.store.SetSetting(context.Background(), "oauth_oidc_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(context.Background(), "oauth_oidc_issuer_url", issuerURL); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(context.Background(), "oauth_oidc_client_id", clientID); err != nil {
		t.Fatal(err)
	}
	if err := s.encryptedSetSetting(context.Background(), "oauth_oidc_client_secret", clientSecret); err != nil {
		t.Fatal(err)
	}

	state := "state-123"
	verifier := oauth2.GenerateVerifier()
	req := httptest.NewRequest(http.MethodGet, "/oauth/oidc/callback?state="+state+"&code=auth-code", nil)
	req = req.WithContext(oidc.ClientContext(req.Context(), fake.client()))
	req.SetPathValue("provider", "oidc")
	req.AddCookie(&http.Cookie{Name: oauthCookieName("oidc"), Value: s.makeOAuthFlowCookie("oidc", state, verifier, "nonce-123")})
	req.AddCookie(&http.Cookie{Name: inviteCookie, Value: rawInvite})
	rec := httptest.NewRecorder()

	s.handleOAuthCallback(rec, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("callback status=%d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if !fake.sawToken.Load() {
		t.Fatal("fake SSO token endpoint was not called")
	}
	if c := findOAuthTestCookie(rec.Result().Cookies(), sessionCookie); c == nil || c.Value == "" {
		t.Fatalf("callback did not create session cookie: %+v", rec.Result().Cookies())
	}
	account, err := s.store.GetAccountByEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("expected OIDC callback to create invited account: %v", err)
	}
	if account.IsAdmin {
		t.Fatalf("invited OIDC account should not be admin: %+v", account)
	}
	identity, err := s.store.GetOAuthIdentity(context.Background(), "oidc", issuerURL+"#user-123")
	if err != nil {
		t.Fatalf("expected linked OIDC identity: %v", err)
	}
	if identity.AccountID != account.ID {
		t.Fatalf("identity account_id=%d, want %d", identity.AccountID, account.ID)
	}
	used, err := s.store.GetInviteByID(context.Background(), inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if used.UsedAt.IsZero() {
		t.Fatal("OIDC callback did not consume invite")
	}
}

func TestResolveOAuthAccountRejectsUnverifiedOIDCEmail(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := s.resolveOAuthAccount(req, &oauthProfile{
		Provider:       "oidc",
		ProviderUserID: "https://issuer.example.test#user-123",
		Email:          "user@example.com",
		EmailVerified:  false,
		Name:           "User",
	})
	if err == nil || !strings.Contains(err.Error(), "verified") {
		t.Fatalf("expected verified email error, got %v", err)
	}
}

type fakeOIDCServer struct {
	server   *httptest.Server
	issuer   string
	token    string
	sawToken atomic.Bool
}

type fakeOIDCOptions struct {
	Issuer, ClientID, Sub, Email string
	EmailVerified                bool           // email_verified in the ID token
	Nonce                        string         // nonce claim; "" leaves it out
	UserInfo                     map[string]any // JSON served at /oidc/userinfo; nil answers 404
}

func newFakeOIDCServer(t *testing.T, opts fakeOIDCOptions) *fakeOIDCServer {
	t.Helper()
	issuer, clientID := opts.Issuer, opts.ClientID
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss":            issuer,
		"aud":            clientID,
		"sub":            opts.Sub,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"email":          opts.Email,
		"email_verified": opts.EmailVerified,
		"name":           "OIDC User",
	}
	if opts.Nonce != "" {
		claims["nonce"] = opts.Nonce
	}
	rawClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeOIDCServer{
		issuer: issuer,
		token:  oidctest.SignIDToken(priv, "fake-key", oidc.RS256, string(rawClaims)),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/auth",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{oidc.RS256},
		})
	})
	mux.HandleFunc("/oidc/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       priv.Public(),
			KeyID:     "fake-key",
			Algorithm: oidc.RS256,
			Use:       "sig",
		}}})
	})
	mux.HandleFunc("/oidc/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if opts.UserInfo == nil {
			http.NotFound(w, r)
			return
		}
		jsonOK(w, opts.UserInfo)
	})
	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		fake.sawToken.Store(true)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code") != "auth-code" || r.FormValue("client_id") != clientID {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		jsonOK(w, map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     fake.token,
		})
	})
	fake.server = httptest.NewServer(mux)
	return fake
}

func fakeOIDCProviderConfig(t *testing.T, fake *fakeOIDCServer) (context.Context, *oauthProviderConfig) {
	t.Helper()
	ctx := oidc.ClientContext(context.Background(), fake.client())
	provider, err := oidc.NewProvider(ctx, fake.issuer)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, &oauthProviderConfig{
		authProvider: authProvider{Key: "oidc", Name: "SSO"},
		ClientID:     "peek-client",
		ClientSecret: "s",
		IssuerURL:    fake.issuer,
		Endpoint:     provider.Endpoint(),
		OIDCProvider: provider,
	}
}

func (f *fakeOIDCServer) idToken() *oauth2.Token {
	return (&oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}).WithExtra(map[string]any{"id_token": f.token})
}

func (f *fakeOIDCServer) close() {
	f.server.Close()
}

func (f *fakeOIDCServer) client() *http.Client {
	target, _ := url.Parse(f.server.URL)
	return &http.Client{Transport: rewriteHostTransport{
		targetScheme: target.Scheme,
		targetHost:   target.Host,
		base:         http.DefaultTransport,
	}}
}

type rewriteHostTransport struct {
	targetScheme string
	targetHost   string
	base         http.RoundTripper
}

func (t rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = t.targetScheme
	clone.URL.Host = t.targetHost
	clone.Host = req.URL.Host
	if t.base == nil {
		t.base = http.DefaultTransport
	}
	return t.base.RoundTrip(clone)
}

func findOAuthTestCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func restoreGitHubURLs(t *testing.T, base string) {
	t.Helper()
	oldUserURL, oldEmailsURL := githubUserURL, githubEmailsURL
	githubUserURL = base + "/user"
	githubEmailsURL = base + "/emails"
	t.Cleanup(func() {
		githubUserURL = oldUserURL
		githubEmailsURL = oldEmailsURL
	})
}

func restoreGoogleIssuerURL(t *testing.T, issuer string) {
	t.Helper()
	old := googleIssuerURL
	googleIssuerURL = issuer
	t.Cleanup(func() { googleIssuerURL = old })
}

func testGitHubProviderConfig() *oauthProviderConfig {
	return &oauthProviderConfig{
		authProvider: authProvider{Key: "github", Name: "GitHub"},
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://unused.example/auth",
			TokenURL: "http://unused.example/token",
		},
	}
}

func TestCLILoginPollIssuesTokenOnce(t *testing.T) {
	s := newTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "user@example.com", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateCLILoginDevice(context.Background(), "device-code", "ABCDEFGH", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	device, err := s.store.GetCLILoginByDevice(context.Background(), "device-code")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.ApproveCLILogin(context.Background(), device.ID, account.ID); err != nil {
		t.Fatal(err)
	}

	body := strings.NewReader(`{"device_code":"device-code"}`)
	rec := httptest.NewRecorder()
	s.handleCLILoginPoll(rec, httptest.NewRequest(http.MethodPost, "/api/cli/login/poll", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Status string `json:"status"`
		Token  string `json:"token"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "approved" || out.Token == "" {
		t.Fatalf("unexpected poll response: %+v", out)
	}
	if _, err := s.store.GetToken(context.Background(), out.Token); err != nil {
		t.Fatalf("issued token should authenticate: %v", err)
	}

	rec = httptest.NewRecorder()
	s.handleCLILoginPoll(rec, httptest.NewRequest(http.MethodPost, "/api/cli/login/poll", strings.NewReader(`{"device_code":"device-code"}`)))
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "consumed" {
		t.Fatalf("second poll should be consumed, got %+v", out)
	}
}

func TestCLILoginStartDoesNotRequireOAuth(t *testing.T) {
	s := newTestServer(t)
	if _, err := s.store.CreateAccountWithPassword(context.Background(), "admin@example.com", "Admin", "hash", true); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.handleCLILoginStart(rec, httptest.NewRequest(http.MethodPost, "/api/cli/login/start", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.DeviceCode == "" || out.UserCode == "" || out.VerificationURL == "" {
		t.Fatalf("unexpected start response: %+v", out)
	}
}

func fakeOIDCDefaults() fakeOIDCOptions {
	return fakeOIDCOptions{Issuer: "https://8.8.8.8/oidc", ClientID: "peek-client", Sub: "user-123", Email: "id@example.com", Nonce: "nonce-123"}
}

func TestFetchOIDCProfileRejectsNonceMismatch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		tokenNonce string
		callNonce  string
	}{
		{"wrong nonce", "nonce-123", "other"},
		{"missing claim", "", "nonce-123"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := fakeOIDCDefaults()
			opts.EmailVerified = true
			opts.Nonce = tc.tokenNonce
			fake := newFakeOIDCServer(t, opts)
			defer fake.close()
			ctx, p := fakeOIDCProviderConfig(t, fake)
			_, err := newTestServer(t).fetchOIDCProfile(ctx, p, fake.idToken(), tc.callNonce)
			if !errors.Is(err, errOIDCNonceMismatch) {
				t.Fatalf("err = %v, want errOIDCNonceMismatch", err)
			}
		})
	}
}

func TestOIDCCallbackRejectsNonceMismatch(t *testing.T) {
	s := newTestServer(t)
	opts := fakeOIDCDefaults()
	opts.Email, opts.EmailVerified = "user@example.com", true
	fake := newFakeOIDCServer(t, opts)
	defer fake.close()
	ctx := context.Background()
	for k, v := range map[string]string{"oauth_oidc_enabled": "true", "oauth_oidc_issuer_url": opts.Issuer, "oauth_oidc_client_id": opts.ClientID} {
		if err := s.store.SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.encryptedSetSetting(ctx, "oauth_oidc_client_secret", "peek-secret"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/oidc/callback?state=state-123&code=auth-code", nil)
	req = req.WithContext(oidc.ClientContext(req.Context(), fake.client()))
	req.SetPathValue("provider", "oidc")
	req.AddCookie(&http.Cookie{Name: oauthCookieName("oidc"), Value: s.makeOAuthFlowCookie("oidc", "state-123", oauth2.GenerateVerifier(), "other")})
	rec := httptest.NewRecorder()
	s.handleOAuthCallback(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	if c := findOAuthTestCookie(rec.Result().Cookies(), sessionCookie); c != nil && c.Value != "" {
		t.Fatalf("session cookie issued: %+v", c)
	}
	if _, err := s.store.GetAccountByEmail(ctx, "user@example.com"); err == nil {
		t.Fatal("account was created")
	}
}

func TestFetchOIDCProfileRejectsUserInfoSubjectMismatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		userInfo map[string]any
	}{
		{"different sub", map[string]any{"sub": "someone-else", "email": "user@example.com", "email_verified": true}},
		{"missing sub", map[string]any{"email": "user@example.com", "email_verified": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := fakeOIDCDefaults()
			opts.UserInfo = tc.userInfo
			fake := newFakeOIDCServer(t, opts)
			defer fake.close()
			ctx, p := fakeOIDCProviderConfig(t, fake)
			_, err := newTestServer(t).fetchOIDCProfile(ctx, p, fake.idToken(), "nonce-123")
			if !errors.Is(err, errOIDCUserInfoSubject) {
				t.Fatalf("err = %v, want errOIDCUserInfoSubject", err)
			}
		})
	}
}

func TestFetchOIDCProfileTakesEmailAndVerifiedFromUserInfoTogether(t *testing.T) {
	opts := fakeOIDCDefaults()
	opts.UserInfo = map[string]any{"sub": "user-123", "email": "info@example.com", "email_verified": true}
	fake := newFakeOIDCServer(t, opts)
	defer fake.close()
	ctx, p := fakeOIDCProviderConfig(t, fake)
	profile, err := newTestServer(t).fetchOIDCProfile(ctx, p, fake.idToken(), "nonce-123")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Email != "info@example.com" || !profile.EmailVerified {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestFetchOIDCProfileDoesNotMixIDEmailWithUserInfoVerified(t *testing.T) {
	opts := fakeOIDCDefaults()
	opts.UserInfo = map[string]any{"sub": "user-123", "email_verified": true}
	fake := newFakeOIDCServer(t, opts)
	defer fake.close()
	ctx, p := fakeOIDCProviderConfig(t, fake)
	profile, err := newTestServer(t).fetchOIDCProfile(ctx, p, fake.idToken(), "nonce-123")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Email != "id@example.com" || profile.EmailVerified {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestFetchOIDCProfileRequiresIDTokenSubject(t *testing.T) {
	opts := fakeOIDCDefaults()
	opts.Sub = ""
	opts.UserInfo = map[string]any{"sub": "user-123", "email": "id@example.com", "email_verified": true}
	fake := newFakeOIDCServer(t, opts)
	defer fake.close()
	ctx, p := fakeOIDCProviderConfig(t, fake)
	_, err := newTestServer(t).fetchOIDCProfile(ctx, p, fake.idToken(), "nonce-123")
	if err == nil || !strings.Contains(err.Error(), "missing oidc subject") {
		t.Fatalf("err = %v, want missing oidc subject", err)
	}
}

func TestFetchGoogleProfileRequiresMatchingNonce(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: priv.Public(), KeyID: "test-key", Algorithm: oidc.RS256}}}
	ts := httptest.NewServer(issuer)
	defer ts.Close()
	issuer.SetIssuer(ts.URL)
	restoreGoogleIssuerURL(t, ts.URL)

	rawClaims := `{"iss": "` + ts.URL + `", "aud": "client-id", "sub": "g-1", "exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"email": "user@example.com", "email_verified": true, "nonce": "nonce-123"}`
	tok := (&oauth2.Token{AccessToken: "a", TokenType: "Bearer"}).WithExtra(map[string]any{"id_token": oidctest.SignIDToken(priv, "test-key", oidc.RS256, rawClaims)})
	p := &oauthProviderConfig{authProvider: authProvider{Key: "google"}, ClientID: "client-id"}
	s := newTestServer(t)
	profile, err := s.fetchGoogleProfile(context.Background(), p, tok, "nonce-123")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Email != "user@example.com" {
		t.Fatalf("profile = %+v", profile)
	}
	if _, err := s.fetchGoogleProfile(context.Background(), p, tok, "other"); !errors.Is(err, errOIDCNonceMismatch) {
		t.Fatalf("err = %v, want errOIDCNonceMismatch", err)
	}
}

func TestOAuthStartSendsNonceAndStoresItInFlowCookie(t *testing.T) {
	s := newTestServer(t)
	opts := fakeOIDCDefaults()
	fake := newFakeOIDCServer(t, opts)
	defer fake.close()
	ctx := context.Background()
	for k, v := range map[string]string{"oauth_oidc_enabled": "true", "oauth_oidc_issuer_url": opts.Issuer, "oauth_oidc_client_id": opts.ClientID} {
		if err := s.store.SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.encryptedSetSetting(ctx, "oauth_oidc_client_secret", "peek-secret"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/oidc/start", nil)
	req = req.WithContext(oidc.ClientContext(req.Context(), fake.client()))
	req.SetPathValue("provider", "oidc")
	rec := httptest.NewRecorder()
	s.handleOAuthStart(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("nonce") == "" || q.Get("state") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("authorization URL missing params: %s", loc)
	}
	c := findOAuthTestCookie(rec.Result().Cookies(), oauthCookieName("oidc"))
	if c == nil {
		t.Fatal("flow cookie not set")
	}
	req2 := httptest.NewRequest(http.MethodGet, "/oauth/oidc/callback", nil)
	req2.AddCookie(c)
	state, _, nonce, ok := s.parseOAuthFlowCookie(req2, "oidc")
	if !ok || nonce != q.Get("nonce") || state != q.Get("state") {
		t.Fatalf("cookie parse ok=%v state=%q nonce=%q, query=%v", ok, state, nonce, q)
	}
}

func TestOAuthStartOmitsNonceForGitHub(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	if err := s.store.SetSetting(ctx, "oauth_github_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(ctx, "oauth_github_client_id", "gh-client"); err != nil {
		t.Fatal(err)
	}
	if err := s.encryptedSetSetting(ctx, "oauth_github_client_secret", "gh-secret"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/github/start", nil)
	req.SetPathValue("provider", "github")
	rec := httptest.NewRecorder()
	s.handleOAuthStart(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Has("nonce") {
		t.Fatalf("github URL carries nonce: %s", loc)
	}
}

func TestParseOAuthFlowCookie(t *testing.T) {
	s := newTestServer(t)
	parse := func(value, provider string) (string, string, string, bool) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: oauthCookieName("oidc"), Value: value})
		return s.parseOAuthFlowCookie(req, provider)
	}
	good := s.makeOAuthFlowCookie("oidc", "st", "ver", "non")
	flip := func(v string) string {
		b := []byte(v)
		i := len(b) - 1
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	legacy := makeWebSession(s.secret, base64.RawURLEncoding.EncodeToString([]byte("oidc|s|v")), time.Minute)
	emptyNonce := s.makeOAuthFlowCookie("oidc", "st", "ver", "")
	for _, tc := range []struct {
		name, value, provider string
		ok                    bool
	}{
		{"round trip", good, "oidc", true},
		{"provider mismatch", good, "google", false},
		{"tampered", flip(good), "oidc", false},
		{"legacy three part", legacy, "oidc", false},
		{"empty nonce", emptyNonce, "oidc", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, ver, non, ok := parse(tc.value, tc.provider)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (st != "st" || ver != "ver" || non != "non") {
				t.Fatalf("got %q %q %q", st, ver, non)
			}
		})
	}
}
