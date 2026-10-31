package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func oidcProfile(email string) *oauthProfile {
	return &oauthProfile{Provider: "oidc", ProviderUserID: "o-" + email, Email: email, EmailVerified: true, Name: "SSO User"}
}

// oidcSignupSettings returns the stored settings that make SSO sign-up valid.
func oidcSignupSettings(domain string) map[string]string {
	return map[string]string{
		authOIDCSignupSetting:         "true",
		authAllowedEmailDomainSetting: domain,
		"oauth_oidc_enabled":          "true",
		"oauth_oidc_issuer_url":       "https://sso.example.test",
		"oauth_oidc_client_id":        "client-id",
	}
}

func oidcSignupOn(t *testing.T, s *Server, domain string) {
	t.Helper()
	ctx := context.Background()
	for k, v := range oidcSignupSettings(domain) {
		if err := s.store.SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.encryptedSetSetting(ctx, "oauth_oidc_client_secret", "oidc-secret"); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCSignupNeedsDomain(t *testing.T) {
	s := newTestServer(t)
	updates := oidcSignupSettings("")
	err := s.validateOIDCSignupUpdate(context.Background(), updates)
	if err == nil || err.Error() != "auth_oidc_signup requires auth_allowed_email_domain" {
		t.Fatalf("err = %v", err)
	}
}

func TestOIDCSignupNeedsSSO(t *testing.T) {
	s := newTestServer(t)
	updates := oidcSignupSettings("example.com")
	// No client secret is stored or sent.
	err := s.validateOIDCSignupUpdate(context.Background(), updates)
	if err == nil || err.Error() != "auth_oidc_signup requires SSO login with an issuer and client credentials" {
		t.Fatalf("err = %v", err)
	}
	updates["oauth_oidc_client_secret"] = "secret"
	if err := s.validateOIDCSignupUpdate(context.Background(), updates); err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}
	updates["oauth_oidc_enabled"] = "false"
	if err := s.validateOIDCSignupUpdate(context.Background(), updates); err == nil {
		t.Fatal("disabled SSO accepted")
	}
}

func TestOIDCSignupConflictsWithGoogleOrg(t *testing.T) {
	s := newTestServer(t)
	updates := oidcSignupSettings("example.com")
	updates["oauth_oidc_client_secret"] = "secret"
	updates[authGoogleOrgSignupSetting] = "true"
	err := s.validateOIDCSignupUpdate(context.Background(), updates)
	if err == nil || err.Error() != "auth_oidc_signup cannot be used with auth_google_org_signup" {
		t.Fatalf("err = %v", err)
	}
}

func TestOIDCSignupCreatesNonAdmin(t *testing.T) {
	s := newTestServer(t)
	oidcSignupOn(t, s, "example.com")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	acc, created, err := s.resolveOAuthAccountCreated(req, oidcProfile("new@example.com"))
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	got, err := s.store.GetAccountByEmail(context.Background(), "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != acc.ID || got.IsAdmin || got.Disabled || got.Name != "SSO User" {
		t.Fatalf("account = %+v", got)
	}
	again, created, err := s.resolveOAuthAccountCreated(req, oidcProfile("new@example.com"))
	if err != nil || created || again.ID != acc.ID {
		t.Fatalf("second sign-in: account=%v created=%v err=%v", again, created, err)
	}
}

func TestOIDCSignupRefusesOutsideDomain(t *testing.T) {
	s := newTestServer(t)
	oidcSignupOn(t, s, "example.com")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	acc, err := s.resolveOAuthAccount(req, oidcProfile("a@other.com"))
	if err == nil || acc != nil {
		t.Fatalf("account=%v err=%v, want rejection", acc, err)
	}
	if _, err := s.store.GetAccountByEmail(context.Background(), "a@other.com"); err == nil {
		t.Fatal("account created outside the domain")
	}
	// Other providers still need an invite.
	gh := &oauthProfile{Provider: "github", ProviderUserID: "1", Email: "b@example.com", EmailVerified: true}
	if _, err := s.resolveOAuthAccount(req, gh); err == nil || err.Error() != "invite required" {
		t.Fatalf("github err = %v, want invite required", err)
	}
}
