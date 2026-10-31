package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"

	"github.com/privacyfence/peek/internal/models"
)

const adminEmailsEnv = "PEEK_ADMIN_EMAILS"

// parseAdminEmails splits the raw PEEK_ADMIN_EMAILS value on commas, trims,
// lower-cases and drops empty parts.
func parseAdminEmails(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		entry := strings.ToLower(strings.TrimSpace(part))
		if entry == "" {
			continue
		}
		addr, err := mail.ParseAddress(entry)
		if err != nil || addr.Address != entry {
			return nil, fmt.Errorf("%s has an invalid email: %s", adminEmailsEnv, entry)
		}
		out = append(out, entry)
	}
	return out, nil
}

func lockedTrue(cfg Config, key string) bool {
	l, ok := cfg.LockedSettings[key]
	return ok && settingValueBool(l.Value)
}

// checkAdminEmails applies the start-time rules for admin emails. It reads only
// cfg, never the database.
func checkAdminEmails(cfg Config, emails []string) error {
	if len(emails) == 0 {
		return nil
	}
	if d, ok := cfg.LockedSettings[authAllowedEmailDomainSetting]; ok && d.Value != "" {
		// An invalid domain is reported by applyLockedSettings with the right variable.
		domain, err := normalizeAllowedEmailDomain(d.Value)
		if err != nil {
			domain = d.Value
		}
		for _, e := range emails {
			if !emailMatchesAllowedDomain(e, domain) {
				return fmt.Errorf("%s has %s, outside PEEK_ALLOWED_EMAIL_DOMAIN", adminEmailsEnv, e)
			}
		}
	}
	google := lockedTrue(cfg, "oauth_google_enabled")
	oidc := lockedTrue(cfg, "oauth_oidc_enabled") && !lockedTrue(cfg, authGoogleOrgSignupSetting)
	if !google && !oidc {
		return errors.New(adminEmailsEnv + " needs a sign-in for the admins: set Google or SSO sign-in in the environment")
	}
	return nil
}

// setupSkipReason says why first-run /setup is skipped, or "" when it is not.
// It reads only cfg, never the database.
func setupSkipReason(cfg Config) (string, error) {
	if strings.TrimSpace(cfg.AdminEmailsRaw) != "" {
		if emails, err := parseAdminEmails(cfg.AdminEmailsRaw); err == nil && len(emails) > 0 {
			return adminEmailsEnv + " names the admins", nil
		}
	}
	if lockedTrue(cfg, "oauth_google_enabled") || lockedTrue(cfg, "oauth_oidc_enabled") {
		if lockedTrue(cfg, authGoogleOrgSignupSetting) || lockedTrue(cfg, authOIDCSignupSetting) || cfg.ProvisioningKey != "" {
			return "sign-in and accounts come from the environment", nil
		}
		return "", errors.New("with sign-in from the environment, set PEEK_ADMIN_EMAILS, a sign-up (PEEK_GOOGLE_ORG_SIGNUP or PEEK_OIDC_SIGNUP) or PEEK_PROVISIONING_KEY_FILE, or nobody can get in")
	}
	return "", nil
}

func (s *Server) isListedAdminEmail(email string) bool {
	for _, e := range s.adminEmails {
		if e == email {
			return true
		}
	}
	return false
}

// promoteListedAdmin makes the account an admin when it signed in through
// Google or SSO with a verified email that PEEK_ADMIN_EMAILS lists. It returns
// the account to use, which is the argument when nothing changed.
func (s *Server) promoteListedAdmin(ctx context.Context, account *models.Account, profile *oauthProfile) *models.Account {
	if account == nil || account.IsAdmin || len(s.adminEmails) == 0 {
		return account
	}
	if profile.Provider != "google" && profile.Provider != "oidc" {
		return account
	}
	if !profile.EmailVerified || normalizeOAuthEmail(profile.Email) != account.Email || !s.isListedAdminEmail(account.Email) {
		return account
	}
	if err := s.store.SetAccountAdmin(ctx, account.ID, true); err != nil {
		slog.Warn("could not promote listed admin", "email", account.Email, "err", err)
		return account
	}
	account.IsAdmin = true
	detail := auditDetail("email", account.Email, "reason", adminEmailsEnv)
	slog.Info("audit", "actor", adminEmailsEnv, "action", "account promoted", "detail", detail)
	s.persistAuditLog(ctx, adminEmailsEnv, "account promoted", detail, "")
	return account
}

// provisionListedAdminAccount creates the admin account for the first Google or
// SSO sign-in of an email that PEEK_ADMIN_EMAILS lists, when no sign-up applies.
// The bool is true only when this call created the account, false for the race
// fallback, where promoteListedAdmin finishes the job.
func (s *Server) provisionListedAdminAccount(ctx context.Context, profile *oauthProfile) (*models.Account, bool, error) {
	account, err := s.store.CreateAccount(ctx, profile.Email, profile.Name, true)
	if err != nil {
		// Two first sign-ins can race on the unique email.
		if existing, lookupErr := s.store.GetAccountByEmail(ctx, profile.Email); lookupErr == nil && !existing.Disabled {
			return existing, false, nil
		}
		return nil, false, errors.New("account creation failed")
	}
	s.audit("account provisioned %s", auditDetail("provider", profile.Provider, "email", account.Email, "reason", adminEmailsEnv))
	return account, true, nil
}
