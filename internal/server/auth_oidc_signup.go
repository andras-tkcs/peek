package server

import (
	"context"
	"errors"
	"strings"

	"github.com/privacyfence/peek/internal/models"
)

const authOIDCSignupSetting = "auth_oidc_signup"

var oidcSignupRelatedSettings = []string{
	authOIDCSignupSetting,
	authGoogleOrgSignupSetting,
	authAllowedEmailDomainSetting,
	"oauth_oidc_enabled",
	"oauth_oidc_issuer_url",
	"oauth_oidc_client_id",
	"oauth_oidc_client_secret",
}

func (s *Server) oidcSignupEnabled(ctx context.Context) bool {
	return s.settingBool(ctx, authOIDCSignupSetting)
}

// validateOIDCSignupUpdate checks the settings as they would be after applying
// updates, so changing the domain or the SSO settings cannot break a mode that
// is already on.
func (s *Server) validateOIDCSignupUpdate(ctx context.Context, updates map[string]string) error {
	touched := false
	for _, k := range oidcSignupRelatedSettings {
		if _, ok := updates[k]; ok {
			touched = true
			break
		}
	}
	if !touched {
		return nil
	}
	stored, err := s.encryptedGetAllSettings(ctx)
	if err != nil {
		return errors.New("settings lookup failed")
	}
	effective := func(key string) string {
		if v, ok := updates[key]; ok {
			return v
		}
		return stored[key]
	}
	if !settingValueBool(effective(authOIDCSignupSetting)) {
		return nil
	}
	if strings.TrimSpace(effective(authAllowedEmailDomainSetting)) == "" {
		return errors.New("auth_oidc_signup requires auth_allowed_email_domain")
	}
	if !settingValueBool(effective("oauth_oidc_enabled")) ||
		strings.TrimSpace(effective("oauth_oidc_issuer_url")) == "" ||
		strings.TrimSpace(effective("oauth_oidc_client_id")) == "" ||
		strings.TrimSpace(effective("oauth_oidc_client_secret")) == "" {
		return errors.New("auth_oidc_signup requires SSO login with an issuer and client credentials")
	}
	if settingValueBool(effective(authGoogleOrgSignupSetting)) {
		return errors.New("auth_oidc_signup cannot be used with auth_google_org_signup")
	}
	return nil
}

// provisionOIDCSignupAccount creates the non-admin account for a first SSO sign-in.
// The bool is true only when this call created the account, false for the race fallback.
func (s *Server) provisionOIDCSignupAccount(ctx context.Context, profile *oauthProfile) (*models.Account, bool, error) {
	account, err := s.store.CreateAccount(ctx, profile.Email, profile.Name, false)
	if err != nil {
		// Two first sign-ins can race on the unique email.
		if existing, lookupErr := s.store.GetAccountByEmail(ctx, profile.Email); lookupErr == nil && !existing.Disabled {
			return existing, false, nil
		}
		return nil, false, errors.New("account creation failed")
	}
	s.audit("account provisioned %s", auditDetail("provider", "oidc", "email", account.Email))
	return account, true, nil
}
