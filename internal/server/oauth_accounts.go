package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/andras-tkcs/peek/internal/models"
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
func (s *Server) provisionGoogleOrgAccount(ctx context.Context, profile *oauthProfile) (*models.Account, error) {
	account, err := s.store.CreateAccount(ctx, profile.Email, profile.Name, false)
	if err != nil {
		// Two first sign-ins can race on the unique email.
		if existing, lookupErr := s.store.GetAccountByEmail(ctx, profile.Email); lookupErr == nil && !existing.Disabled {
			return existing, nil
		}
		return nil, errors.New("account creation failed")
	}
	s.audit("account provisioned %s", auditDetail("provider", "google", "email", account.Email))
	return account, nil
}

func (s *Server) resolveOAuthAccount(r *http.Request, profile *oauthProfile) (*models.Account, error) {
	if profile.ProviderUserID == "" || profile.Email == "" || !profile.EmailVerified {
		return nil, errors.New("OAuth account must have a verified email")
	}
	if !s.accountAllowedByEmailDomain(r.Context(), profile.Email) {
		return nil, errAccountNotEligible
	}
	if s.googleOrgSignupEnabled(r.Context()) {
		if err := s.checkGoogleOrgProfile(r.Context(), profile); err != nil {
			return nil, err
		}
	}
	if oi, err := s.store.GetOAuthIdentity(r.Context(), profile.Provider, profile.ProviderUserID); err == nil {
		account, err := s.store.GetAccountByID(r.Context(), oi.AccountID)
		if err != nil {
			return nil, errors.New("linked account not found")
		}
		if account.Disabled {
			return nil, errors.New("account disabled")
		}
		if !s.accountAllowedByEmailDomain(r.Context(), account.Email) {
			return nil, errAccountNotEligible
		}
		return account, nil
	} else if err != sql.ErrNoRows {
		return nil, errors.New("OAuth lookup failed")
	}

	if account, err := s.store.GetAccountByEmail(r.Context(), profile.Email); err == nil {
		if account.Disabled {
			return nil, errors.New("account disabled")
		}
		if !s.accountAllowedByEmailDomain(r.Context(), account.Email) {
			return nil, errAccountNotEligible
		}
		return account, nil
	} else if err != sql.ErrNoRows {
		return nil, errors.New("account lookup failed")
	}

	if s.googleOrgSignupEnabled(r.Context()) {
		return s.provisionGoogleOrgAccount(r.Context(), profile)
	}

	inviteToken := ""
	if c, err := r.Cookie(inviteCookie); err == nil {
		inviteToken = c.Value
	}
	if inviteToken == "" {
		return nil, errors.New("invite required")
	}
	inv, err := s.store.GetInviteByToken(r.Context(), inviteToken)
	if err != nil {
		return nil, errors.New("invite not found")
	}
	if !invitePending(inv) || normalizeOAuthEmail(inv.Email) != profile.Email {
		return nil, errors.New("invite does not match this account")
	}
	account, err := s.store.CreateAccount(r.Context(), profile.Email, profile.Name, false)
	if err != nil {
		return nil, errors.New("account creation failed")
	}
	if err := s.store.ConsumeInvite(r.Context(), inv.ID); err != nil {
		return nil, errors.New("invite consumption failed")
	}
	return account, nil
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
