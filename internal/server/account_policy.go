package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/andras-tkcs/peek/internal/models"
)

var (
	errAccountDisabled = errors.New("account disabled")
	errOAuthRequired   = errors.New("oauth login required")
)

// accountActive reports whether account a may use Peek now. Dashboard sessions
// and API tokens use the same rules: not disabled, email in the allowed email
// domain, and, while OAuth login is enabled, a linked OAuth identity unless the
// account is an admin. It returns nil, errAccountDisabled, errAccountNotEligible,
// errOAuthRequired, or the error of the OAuth identity lookup.
func (s *Server) accountActive(ctx context.Context, a *models.Account) error {
	if a.Disabled {
		return errAccountDisabled
	}
	if !s.accountAllowedByEmailDomain(ctx, a.Email) {
		return errAccountNotEligible
	}
	if s.oauthLoginRequired(ctx) && !a.IsAdmin {
		hasOAuth, err := s.store.AccountHasOAuthIdentity(ctx, a.ID)
		if err != nil {
			return err
		}
		if !hasOAuth {
			return errOAuthRequired
		}
	}
	return nil
}

// tokenAccount returns the account fields of t that accountActive checks.
func tokenAccount(t *models.Token) *models.Account {
	return &models.Account{ID: t.AccountID, Email: t.Email, IsAdmin: t.IsAdmin, Disabled: t.Disabled}
}

// tokenAccountActive applies the account policy to the account behind a bearer
// token. Accounts without an email are automation accounts created by
// `peek token create` / POST /api/tokens: they cannot match an allowed email
// domain or link an OAuth identity, so only the disabled check applies to them.
func (s *Server) tokenAccountActive(ctx context.Context, t *models.Token) error {
	if strings.TrimSpace(t.Email) == "" {
		if t.Disabled {
			return errAccountDisabled
		}
		return nil
	}
	return s.accountActive(ctx, tokenAccount(t))
}

// writeTokenPolicyError answers a bearer request whose account failed the policy.
func writeTokenPolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAccountDisabled):
		jsonError(w, http.StatusForbidden, "account disabled")
	case errors.Is(err, errAccountNotEligible):
		jsonError(w, http.StatusForbidden, "account email domain is not allowed")
	case errors.Is(err, errOAuthRequired):
		jsonError(w, http.StatusForbidden, "account must sign in with OAuth")
	default:
		slog.Error("token account check failed", "err", err)
		jsonError(w, http.StatusInternalServerError, "account check failed")
	}
}
