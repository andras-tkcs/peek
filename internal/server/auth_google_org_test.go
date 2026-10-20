package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/db"
	"github.com/andras-tkcs/peek/internal/models"
	webui "github.com/andras-tkcs/peek/internal/web"
)

const googleOrgTestOIDCIssuer = "https://8.8.8.8/oidc"

func setGoogleOrgSettings(t *testing.T, s *Server, values map[string]string) {
	t.Helper()
	ctx := context.Background()
	for k, v := range values {
		var err error
		if strings.HasSuffix(k, "_client_secret") {
			err = s.encryptedSetSetting(ctx, k, v)
		} else {
			err = s.store.SetSetting(ctx, k, v)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func validGoogleOrgSettings() map[string]string {
	return map[string]string{
		authGoogleOrgSignupSetting:    "true",
		authAllowedEmailDomainSetting: "example.com",
		"oauth_google_enabled":        "true",
		"oauth_google_client_id":      "google-client",
		"oauth_google_client_secret":  "google-secret",
	}
}

func TestGoogleOrgValidateUpdate(t *testing.T) {
	tests := []struct {
		name    string
		stored  map[string]string
		updates map[string]string
		want    string
	}{
		{
			name:    "mode off ignores everything else",
			updates: map[string]string{authAllowedEmailDomainSetting: "", "oauth_google_enabled": ""},
		},
		{
			name:    "unrelated update",
			stored:  map[string]string{authGoogleOrgSignupSetting: "true"},
			updates: map[string]string{"max_upload": "10"},
		},
		{
			name:    "no domain",
			updates: map[string]string{authGoogleOrgSignupSetting: "true", "oauth_google_enabled": "true", "oauth_google_client_id": "id", "oauth_google_client_secret": "secret"},
			want:    "auth_google_org_signup requires auth_allowed_email_domain",
		},
		{
			name:    "gmail",
			updates: map[string]string{authGoogleOrgSignupSetting: "true", authAllowedEmailDomainSetting: "gmail.com"},
			want:    "auth_google_org_signup cannot be used with a consumer Google domain",
		},
		{
			name:    "googlemail",
			updates: map[string]string{authGoogleOrgSignupSetting: "true", authAllowedEmailDomainSetting: "googlemail.com"},
			want:    "auth_google_org_signup cannot be used with a consumer Google domain",
		},
		{
			name:    "google disabled",
			stored:  map[string]string{"oauth_google_client_id": "id", "oauth_google_client_secret": "secret"},
			updates: map[string]string{authGoogleOrgSignupSetting: "true", authAllowedEmailDomainSetting: "example.com"},
			want:    "auth_google_org_signup requires Google login with client credentials",
		},
		{
			name:    "empty client secret",
			stored:  map[string]string{"oauth_google_enabled": "true", "oauth_google_client_id": "id"},
			updates: map[string]string{authGoogleOrgSignupSetting: "true", authAllowedEmailDomainSetting: "example.com"},
			want:    "auth_google_org_signup requires Google login with client credentials",
		},
		{
			name:    "fully valid",
			updates: validGoogleOrgSettings(),
		},
		{
			name:    "clearing the domain while on",
			stored:  validGoogleOrgSettings(),
			updates: map[string]string{authAllowedEmailDomainSetting: ""},
			want:    "auth_google_org_signup requires auth_allowed_email_domain",
		},
		{
			name:    "disabling google while on",
			stored:  validGoogleOrgSettings(),
			updates: map[string]string{"oauth_google_enabled": ""},
			want:    "auth_google_org_signup requires Google login with client credentials",
		},
		{
			name: "only the mode, stored settings valid",
			stored: func() map[string]string {
				m := validGoogleOrgSettings()
				delete(m, authGoogleOrgSignupSetting)
				return m
			}(),
			updates: map[string]string{authGoogleOrgSignupSetting: "true"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t)
			setGoogleOrgSettings(t, s, tt.stored)
			err := s.validateGoogleOrgSignupUpdate(context.Background(), tt.updates)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.want {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestGoogleOrgOnlyGoogleProviderWhileEnabled(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	setGoogleOrgSettings(t, s, map[string]string{
		"oauth_google_enabled":       "true",
		"oauth_google_client_id":     "g",
		"oauth_google_client_secret": "gs",
		"oauth_github_enabled":       "true",
		"oauth_github_client_id":     "h",
		"oauth_github_client_secret": "hs",
		"oauth_oidc_enabled":         "true",
		"oauth_oidc_issuer_url":      googleOrgTestOIDCIssuer,
		"oauth_oidc_client_id":       "o",
		"oauth_oidc_client_secret":   "os",
	})
	if got := s.enabledOAuthProviders(ctx); len(got) != 3 {
		t.Fatalf("mode off providers = %v, want 3", got)
	}
	setGoogleOrgSettings(t, s, map[string]string{authGoogleOrgSignupSetting: "true"})
	got := s.enabledOAuthProviders(ctx)
	if len(got) != 1 || got[0].Key != "google" {
		t.Fatalf("mode on providers = %v, want only google", got)
	}
	if _, err := s.oauthProviderConfig(ctx, "github"); err == nil {
		t.Fatal("github config should be refused while the mode is on")
	}
	if _, err := s.oauthProviderConfig(ctx, "google"); err != nil {
		t.Fatalf("google config: %v", err)
	}
}

func TestGoogleOrgLoginStillRequiredWhenGoogleUnloadable(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	setGoogleOrgSettings(t, s, map[string]string{
		"oauth_google_enabled":       "true",
		"oauth_google_client_id":     "g",
		"oauth_google_client_secret": "",
		authGoogleOrgSignupSetting:   "true",
		"auth_token_login_enabled":   "true",
	})
	if !s.oauthLoginRequired(ctx) {
		t.Fatal("oauthLoginRequired = false with the mode on")
	}
	if got := s.enabledOAuthProviders(ctx); len(got) != 0 {
		t.Fatalf("providers = %v, want none", got)
	}
	data := s.loginData("csrf", "", httptest.NewRequest(http.MethodGet, "/login", nil))
	if data.TokenLogin {
		t.Fatal("TokenLogin = true while the mode makes OAuth login required")
	}
	if !data.OAuthEnabled {
		t.Fatal("OAuthEnabled = false while the mode makes OAuth login required")
	}
	setGoogleOrgSettings(t, s, map[string]string{authGoogleOrgSignupSetting: ""})
	if s.oauthLoginRequired(ctx) {
		t.Fatal("oauthLoginRequired = true with the mode off")
	}
}

func TestGoogleOrgLoginIgnoresStaleInviteCookie(t *testing.T) {
	s := newTestServer(t)
	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/login", nil)
		r.AddCookie(&http.Cookie{Name: inviteCookie, Value: "stale"})
		return r
	}
	if !s.loginData("csrf", "", newReq()).Invite {
		t.Fatal("Invite = false with the mode off")
	}
	setGoogleOrgSettings(t, s, map[string]string{authGoogleOrgSignupSetting: "true"})
	if s.loginData("csrf", "", newReq()).Invite {
		t.Fatal("Invite = true with the mode on")
	}
}

func TestGoogleOrgSettingsAPIRejectsInvalid(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := &Server{store: store, secret: strings.Repeat("0", 64)}

	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"auth_google_org_signup":"true"}`))
	req = withAPIToken(req, &models.Token{Name: "admin", IsAdmin: true})
	rec := httptest.NewRecorder()
	s.handleUpdateSettings(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "auth_google_org_signup requires auth_allowed_email_domain") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if got, err := store.GetSetting(context.Background(), authGoogleOrgSignupSetting); err == nil {
		t.Fatalf("setting was written: %q", got)
	}
}

func googleOrgDashboardPost(t *testing.T, s *Server, accountID int64, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("csrf", "csrf-token")
	req := httptest.NewRequest(http.MethodPost, "/dashboard/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(accountID, 10), sessionTTL)})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	rec := httptest.NewRecorder()
	s.handleDashboardSettings(rec, req)
	return rec
}

func TestGoogleOrgDashboardSettingsRejectsInvalid(t *testing.T) {
	s := newTestServer(t)
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s.renderer = renderer
	admin, err := s.store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	rec := googleOrgDashboardPost(t, s, admin.ID, url.Values{authGoogleOrgSignupSetting: {"true"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "auth_google_org_signup requires auth_allowed_email_domain") {
		t.Fatalf("body missing inline error: %s", rec.Body.String())
	}
	if got, err := s.store.GetSetting(context.Background(), authGoogleOrgSignupSetting); err == nil {
		t.Fatalf("setting was written: %q", got)
	}
}

func TestGoogleOrgDashboardSettingsAcceptsCombinedEnable(t *testing.T) {
	s := newTestServer(t)
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s.renderer = renderer
	admin, err := s.store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	setGoogleOrgSettings(t, s, map[string]string{"oauth_google_client_secret": "google-secret"})

	rec := googleOrgDashboardPost(t, s, admin.ID, url.Values{
		authGoogleOrgSignupSetting:    {"true"},
		"oauth_google_enabled":        {"true"},
		"oauth_google_client_id":      {"google-client"},
		"oauth_google_client_secret":  {""},
		authAllowedEmailDomainSetting: {"example.test"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := mustGetSetting(t, s.store, authGoogleOrgSignupSetting); got != "true" {
		t.Fatalf("auth_google_org_signup = %q, want true", got)
	}
}
