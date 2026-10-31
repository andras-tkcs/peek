package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func lockedFixture() map[string]LockedSetting {
	return map[string]LockedSetting{
		"oauth_oidc_enabled":       {Value: "true", Env: "PEEK_OIDC_ISSUER_URL"},
		"oauth_oidc_issuer_url":    {Value: "https://sso.example.test/", Env: "PEEK_OIDC_ISSUER_URL"},
		"oauth_oidc_client_id":     {Value: "client-id", Env: "PEEK_OIDC_CLIENT_ID"},
		"oauth_oidc_client_secret": {Value: "oidc-secret", Env: "PEEK_OIDC_CLIENT_SECRET"},
	}
}

func TestLockedValuesWrittenEncryptedEveryStart(t *testing.T) {
	s := newTestServer(t)
	s.locked = lockedFixture()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := s.applyLockedSettings(ctx); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		// Something edited the row between starts; the next start puts it back.
		raw, err := s.store.GetSetting(ctx, "oauth_oidc_client_secret")
		if err != nil || raw == "" || raw == "oidc-secret" {
			t.Fatalf("stored secret = %q, %v; want ciphertext", raw, err)
		}
		if got := decryptedStoreSetting(ctx, s.store, s.secret, "oauth_oidc_client_secret"); got != "oidc-secret" {
			t.Fatalf("decrypted secret = %q", got)
		}
		if err := s.store.SetSetting(ctx, "oauth_oidc_client_id", "edited"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.applyLockedSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.store.GetSetting(ctx, "oauth_oidc_client_id"); v != "client-id" {
		t.Fatalf("client id = %q", v)
	}
	if v, _ := s.store.GetSetting(ctx, "oauth_oidc_enabled"); v != "true" {
		t.Fatalf("enabled = %q", v)
	}
	if v, _ := s.store.GetSetting(ctx, "oauth_oidc_issuer_url"); v != "https://sso.example.test" {
		t.Fatalf("issuer not normalised: %q", v)
	}
}

func TestLockedWinsOverDatabase(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	if err := s.store.SetSetting(ctx, authAllowedEmailDomainSetting, "old.test"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(ctx, "oauth_google_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	s.locked = map[string]LockedSetting{authAllowedEmailDomainSetting: {Value: "New.Test", Env: "PEEK_ALLOWED_EMAIL_DOMAIN"}}
	if err := s.applyLockedSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.store.GetSetting(ctx, authAllowedEmailDomainSetting); v != "new.test" {
		t.Fatalf("domain = %q", v)
	}
	// Settings that are not locked stay as they were.
	if v, _ := s.store.GetSetting(ctx, "oauth_google_enabled"); v != "true" {
		t.Fatalf("unlocked setting changed: %q", v)
	}
}

func TestLockedInvalidIssuerFailsWithEnvPrefix(t *testing.T) {
	s := newTestServer(t)
	s.locked = map[string]LockedSetting{"oauth_oidc_issuer_url": {Value: "http://sso.example.test", Env: "PEEK_OIDC_ISSUER_URL"}}
	err := s.applyLockedSettings(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "PEEK_OIDC_ISSUER_URL: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestLockedOrgSignupWithoutDomainFails(t *testing.T) {
	s := newTestServer(t)
	s.locked = map[string]LockedSetting{authGoogleOrgSignupSetting: {Value: "true", Env: "PEEK_GOOGLE_ORG_SIGNUP"}}
	err := s.applyLockedSettings(context.Background())
	want := "PEEK_GOOGLE_ORG_SIGNUP: auth_google_org_signup requires auth_allowed_email_domain"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %s", err, want)
	}
	if v, err := s.store.GetSetting(context.Background(), authGoogleOrgSignupSetting); err == nil {
		t.Fatalf("setting written despite error: %q", v)
	}
}

func TestLockedDomainWarnsWhenNoAdminMatches(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	s := newTestServer(t)
	ctx := context.Background()
	s.locked = map[string]LockedSetting{authAllowedEmailDomainSetting: {Value: "corp.test", Env: "PEEK_ALLOWED_EMAIL_DOMAIN"}}
	// No accounts yet: no warning.
	if err := s.applyLockedSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 0 {
		t.Fatalf("unexpected log: %s", logs.String())
	}
	if _, err := s.store.CreateAccount(ctx, "admin@other.test", "Admin", true); err != nil {
		t.Fatal(err)
	}
	if err := s.applyLockedSettings(ctx); err != nil {
		t.Fatalf("a lockout must warn, not fail: %v", err)
	}
	if !strings.Contains(logs.String(), "no active admin is in PEEK_ALLOWED_EMAIL_DOMAIN") {
		t.Fatalf("missing warning: %q", logs.String())
	}
	logs.Reset()
	if _, err := s.store.CreateAccount(ctx, "boss@corp.test", "Boss", true); err != nil {
		t.Fatal(err)
	}
	if err := s.applyLockedSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 0 {
		t.Fatalf("unexpected warning with a matching admin: %s", logs.String())
	}
}

func TestLockedErrorNamesAdminPageSettingWhenNotLocked(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	if err := s.encryptedSetSetting(ctx, authOIDCSignupSetting, "true"); err != nil {
		t.Fatal(err)
	}
	s.locked = map[string]LockedSetting{
		authAllowedEmailDomainSetting: {Value: "example.test", Env: "PEEK_ALLOWED_EMAIL_DOMAIN"},
		"oauth_google_enabled":        {Value: "true", Env: "PEEK_GOOGLE_CLIENT_ID"},
		"oauth_google_client_id":      {Value: "id", Env: "PEEK_GOOGLE_CLIENT_ID"},
		"oauth_google_client_secret":  {Value: "secret", Env: "PEEK_GOOGLE_CLIENT_SECRET"},
		authGoogleOrgSignupSetting:    {Value: "true", Env: "PEEK_GOOGLE_ORG_SIGNUP"},
	}
	err := s.applyLockedSettings(ctx)
	want := "auth_oidc_signup (set on the Admin page): auth_oidc_signup requires SSO login with an issuer and client credentials"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %s", err, want)
	}
}
