package server

import (
	"context"
	"errors"
	"strings"
)

const authGoogleOrgSignupSetting = "auth_google_org_signup"

var googleOrgRelatedSettings = []string{
	authGoogleOrgSignupSetting,
	authAllowedEmailDomainSetting,
	"oauth_google_enabled",
	"oauth_google_client_id",
	"oauth_google_client_secret",
}

func (s *Server) googleOrgSignupEnabled(ctx context.Context) bool {
	return s.settingBool(ctx, authGoogleOrgSignupSetting)
}

// validateGoogleOrgSignupUpdate checks the settings as they would be after
// applying updates, so changing the domain or the Google credentials cannot
// break a mode that is already on.
func (s *Server) validateGoogleOrgSignupUpdate(ctx context.Context, updates map[string]string) error {
	touched := false
	for _, k := range googleOrgRelatedSettings {
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
	if !settingValueBool(effective(authGoogleOrgSignupSetting)) {
		return nil
	}
	domain := strings.TrimSpace(effective(authAllowedEmailDomainSetting))
	if domain == "" {
		return errors.New("auth_google_org_signup requires auth_allowed_email_domain")
	}
	if d := strings.ToLower(domain); d == "gmail.com" || d == "googlemail.com" {
		return errors.New("auth_google_org_signup cannot be used with a consumer Google domain")
	}
	if !settingValueBool(effective("oauth_google_enabled")) ||
		strings.TrimSpace(effective("oauth_google_client_id")) == "" ||
		strings.TrimSpace(effective("oauth_google_client_secret")) == "" {
		return errors.New("auth_google_org_signup requires Google login with client credentials")
	}
	return nil
}
