package server

import (
	"strings"
	"testing"
)

func lockedOn(keys ...string) map[string]LockedSetting {
	m := map[string]LockedSetting{}
	for _, k := range keys {
		m[k] = LockedSetting{Value: "true", Env: "PEEK_X"}
	}
	return m
}

func TestParseAdminEmailsRejectsInvalid(t *testing.T) {
	got, err := parseAdminEmails(" A@Example.Test, ,b@example.test,")
	if err != nil || len(got) != 2 || got[0] != "a@example.test" || got[1] != "b@example.test" {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := parseAdminEmails(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v, %v", got, err)
	}
	for _, bad := range []string{"nope", "Name <a@example.test>", "a@example.test b@example.test"} {
		_, err := parseAdminEmails("ok@example.test," + bad)
		if err == nil || !strings.HasPrefix(err.Error(), "PEEK_ADMIN_EMAILS has an invalid email: ") {
			t.Fatalf("%q: err = %v", bad, err)
		}
	}
}

func TestAdminEmailOutsideDomainFails(t *testing.T) {
	cfg := Config{LockedSettings: lockedOn("oauth_google_enabled")}
	cfg.LockedSettings[authAllowedEmailDomainSetting] = LockedSetting{Value: "example.test", Env: "PEEK_ALLOWED_EMAIL_DOMAIN"}
	if err := checkAdminEmails(cfg, []string{"a@example.test"}); err != nil {
		t.Fatal(err)
	}
	err := checkAdminEmails(cfg, []string{"a@example.test", "b@other.test"})
	if err == nil || err.Error() != "PEEK_ADMIN_EMAILS has b@other.test, outside PEEK_ALLOWED_EMAIL_DOMAIN" {
		t.Fatalf("err = %v", err)
	}
}

func TestAdminEmailsNeedSignIn(t *testing.T) {
	emails := []string{"a@example.test"}
	want := "PEEK_ADMIN_EMAILS needs a sign-in for the admins: set Google or SSO sign-in in the environment"
	for name, cfg := range map[string]Config{
		"none":          {},
		"oidc with org": {LockedSettings: lockedOn("oauth_oidc_enabled", authGoogleOrgSignupSetting)},
		"signup only":   {LockedSettings: lockedOn(authOIDCSignupSetting)},
	} {
		if err := checkAdminEmails(cfg, emails); err == nil || err.Error() != want {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	for name, cfg := range map[string]Config{
		"google":         {LockedSettings: lockedOn("oauth_google_enabled")},
		"oidc":           {LockedSettings: lockedOn("oauth_oidc_enabled")},
		"google and org": {LockedSettings: lockedOn("oauth_google_enabled", authGoogleOrgSignupSetting)},
	} {
		if err := checkAdminEmails(cfg, emails); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := checkAdminEmails(Config{}, nil); err != nil {
		t.Fatalf("no emails: %v", err)
	}
}

func TestSkipReasonAdminEmails(t *testing.T) {
	r, err := setupSkipReason(Config{AdminEmailsRaw: "a@example.test"})
	if err != nil || r != "PEEK_ADMIN_EMAILS names the admins" {
		t.Fatalf("r = %q, %v", r, err)
	}
}

func TestSkipReasonSignupOrKey(t *testing.T) {
	const want = "sign-in and accounts come from the environment"
	for name, cfg := range map[string]Config{
		"google org":  {LockedSettings: lockedOn("oauth_google_enabled", authGoogleOrgSignupSetting)},
		"oidc signup": {LockedSettings: lockedOn("oauth_oidc_enabled", authOIDCSignupSetting)},
		"oidc key":    {LockedSettings: lockedOn("oauth_oidc_enabled"), ProvisioningKey: "peekprov_x"},
	} {
		r, err := setupSkipReason(cfg)
		if err != nil || r != want {
			t.Fatalf("%s: r = %q, %v", name, r, err)
		}
	}
}

func TestSkipLockedSignInWithoutAccountsSourceFails(t *testing.T) {
	for _, k := range []string{"oauth_google_enabled", "oauth_oidc_enabled"} {
		r, err := setupSkipReason(Config{LockedSettings: lockedOn(k)})
		if r != "" || err == nil || !strings.HasPrefix(err.Error(), "with sign-in from the environment, set PEEK_ADMIN_EMAILS") {
			t.Fatalf("%s: r = %q, err = %v", k, r, err)
		}
	}
}

func TestNoSkipWithoutEnv(t *testing.T) {
	r, err := setupSkipReason(Config{})
	if r != "" || err != nil {
		t.Fatalf("r = %q, %v", r, err)
	}
	// A key or a sign-up alone, without locked sign-in, keeps /setup.
	r, err = setupSkipReason(Config{ProvisioningKey: "peekprov_x", LockedSettings: lockedOn(authOIDCSignupSetting)})
	if r != "" || err != nil {
		t.Fatalf("r = %q, %v", r, err)
	}
}
