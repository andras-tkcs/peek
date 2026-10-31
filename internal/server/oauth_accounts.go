package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/privacyfence/peek/internal/models"
)

var errGoogleWorkspaceRequired = errors.New("google workspace account required")

// checkGoogleOrgProfile enforces Google org sign-in: only Google Workspace
// accounts (hd claim) pass. The email domain itself is checked by the caller.
func (s *Server) checkGoogleOrgProfile(ctx context.Context, profile *oauthProfile) error {
	if profile.Provider != "google" {
		return errAccountNotEligible
	}
	if s.allowedEmailDomain(ctx) == "" {
		return errAccountNotEligible
	}
	if profile.HostedDomain == "" {
		return errGoogleWorkspaceRequired
	}
	return nil
}

// provisionGoogleOrgAccount creates the non-admin account for a first Google org sign-in.
// The bool is true only when this call created the account, false for the race fallback.
func (s *Server) provisionGoogleOrgAccount(ctx context.Context, profile *oauthProfile) (*models.Account, bool, error) {
	account, err := s.store.CreateAccount(ctx, profile.Email, profile.Name, false)
	if err != nil {
		// Two first sign-ins can race on the unique email.
		if existing, lookupErr := s.store.GetAccountByEmail(ctx, profile.Email); lookupErr == nil && !existing.Disabled {
			return existing, false, nil
		}
		return nil, false, errors.New("account creation failed")
	}
	s.audit("account provisioned %s", auditDetail("provider", "google", "email", account.Email))
	return account, true, nil
}

// resolveOAuthAccount is the form tests and older callers use; it drops the created flag.
func (s *Server) resolveOAuthAccount(r *http.Request, profile *oauthProfile) (*models.Account, error) {
	account, _, err := s.resolveOAuthAccountCreated(r, profile)
	return account, err
}

// resolveOAuthAccountCreated resolves the account and promotes a listed admin.
func (s *Server) resolveOAuthAccountCreated(r *http.Request, profile *oauthProfile) (*models.Account, bool, error) {
	account, created, err := s.resolveOAuthAccountBase(r, profile)
	if err != nil {
		return nil, created, err
	}
	return s.promoteListedAdmin(r.Context(), account, profile), created, nil
}

func (s *Server) resolveOAuthAccountBase(r *http.Request, profile *oauthProfile) (*models.Account, bool, error) {
	if profile.ProviderUserID == "" || profile.Email == "" || !profile.EmailVerified {
		return nil, false, errors.New("OAuth account must have a verified email")
	}
	if !s.accountAllowedByEmailDomain(r.Context(), profile.Email) {
		return nil, false, errAccountNotEligible
	}
	if s.googleOrgSignupEnabled(r.Context()) {
		if err := s.checkGoogleOrgProfile(r.Context(), profile); err != nil {
			return nil, false, err
		}
	}
	if oi, err := s.store.GetOAuthIdentity(r.Context(), profile.Provider, profile.ProviderUserID); err == nil {
		account, err := s.store.GetAccountByID(r.Context(), oi.AccountID)
		if err != nil {
			return nil, false, errors.New("linked account not found")
		}
		if account.Disabled {
			return nil, false, errors.New("account disabled")
		}
		if !s.accountAllowedByEmailDomain(r.Context(), account.Email) {
			return nil, false, errAccountNotEligible
		}
		return account, false, nil
	} else if err != sql.ErrNoRows {
		return nil, false, errors.New("OAuth lookup failed")
	}

	if account, err := s.store.GetAccountByEmail(r.Context(), profile.Email); err == nil {
		if account.Disabled {
			return nil, false, errors.New("account disabled")
		}
		if !s.accountAllowedByEmailDomain(r.Context(), account.Email) {
			return nil, false, errAccountNotEligible
		}
		return account, false, nil
	} else if err != sql.ErrNoRows {
		return nil, false, errors.New("account lookup failed")
	}

	if s.isListedAdminEmail(profile.Email) && (profile.Provider == "google" || profile.Provider == "oidc") {
		account, err := s.store.CreateAccount(r.Context(), profile.Email, profile.Name, true)
		if err != nil {
			return nil, false, errors.New("account creation failed")
		}
		s.audit("account provisioned %s", auditDetail("provider", profile.Provider, "email", account.Email, "reason", adminEmailsEnv))
		return account, true, nil
	}
	if s.googleOrgSignupEnabled(r.Context()) {
		return s.provisionGoogleOrgAccount(r.Context(), profile)
	}
	if profile.Provider == "oidc" && s.oidcSignupEnabled(r.Context()) {
		return s.provisionOIDCSignupAccount(r.Context(), profile)
	}

	inviteToken := ""
	if c, err := r.Cookie(inviteCookie); err == nil {
		inviteToken = c.Value
	}
	if inviteToken == "" {
		return nil, false, errors.New("invite required")
	}
	inv, err := s.store.GetInviteByToken(r.Context(), inviteToken)
	if err != nil {
		return nil, false, errors.New("invite not found")
	}
	if !invitePending(inv) || normalizeOAuthEmail(inv.Email) != profile.Email {
		return nil, false, errors.New("invite does not match this account")
	}
	account, err := s.store.CreateAccount(r.Context(), profile.Email, profile.Name, false)
	if err != nil {
		return nil, false, errors.New("account creation failed")
	}
	if err := s.store.ConsumeInvite(r.Context(), inv.ID); err != nil {
		return nil, false, errors.New("invite consumption failed")
	}
	return account, true, nil
}

func invitePending(inv *models.Invite) bool {
	return inv != nil && inv.UsedAt.IsZero() && inv.RevokedAt.IsZero() && time.Now().Before(inv.ExpiresAt)
}

func normalizeOAuthEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func displayName(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return "user"
}
