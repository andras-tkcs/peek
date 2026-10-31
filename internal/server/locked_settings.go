package server

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
)

// LockedSetting is a runtime setting whose value comes from the environment.
// Env is the variable the Admin page names.
type LockedSetting struct {
	Value string
	Env   string
}

// lockedKeys returns the locked setting keys in a stable order.
func (s *Server) lockedKeys() []string {
	keys := make([]string, 0, len(s.locked))
	for k := range s.locked {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lockedEnvNames maps each locked setting key to the variable that sets it.
func (s *Server) lockedEnvNames() map[string]string {
	if len(s.locked) == 0 {
		return nil
	}
	out := make(map[string]string, len(s.locked))
	for k, l := range s.locked {
		out[k] = l.Env
	}
	return out
}

// lockedEnvFor names the variable to blame for a validator error that is not
// tied to one key: the one of trigger when locked, else the first locked one.
func (s *Server) lockedEnvFor(trigger string) string {
	if l, ok := s.locked[trigger]; ok {
		return l.Env
	}
	for _, k := range s.lockedKeys() {
		return s.locked[k].Env
	}
	return trigger
}

// applyLockedSettings writes the environment's values over the database at
// every start, so the environment always wins.
func (s *Server) applyLockedSettings(ctx context.Context) error {
	if len(s.locked) == 0 {
		return nil
	}
	values := make(map[string]string, len(s.locked))
	for _, k := range s.lockedKeys() {
		l := s.locked[k]
		v, err := s.normalizeSettingValue(k, l.Value)
		if err != nil {
			return fmt.Errorf("%s: %w", l.Env, err)
		}
		values[k] = v
	}
	if err := s.validateGoogleOrgSignupUpdate(ctx, values); err != nil {
		return fmt.Errorf("%s: %w", s.lockedEnvFor(authGoogleOrgSignupSetting), err)
	}
	if err := s.validateOIDCSignupUpdate(ctx, values); err != nil {
		return fmt.Errorf("%s: %w", s.lockedEnvFor(authOIDCSignupSetting), err)
	}
	for _, k := range s.lockedKeys() {
		if err := s.encryptedSetSetting(ctx, k, values[k]); err != nil {
			return fmt.Errorf("%s: %w", s.locked[k].Env, err)
		}
	}
	s.warnDomainLockout(ctx, values)
	return nil
}

// warnDomainLockout logs when the locked allowed email domain excludes every
// active admin. It does not fail the start: the Admin-page rule guards edits.
func (s *Server) warnDomainLockout(ctx context.Context, values map[string]string) {
	domain := values[authAllowedEmailDomainSetting]
	if _, ok := s.locked[authAllowedEmailDomainSetting]; !ok || domain == "" {
		return
	}
	accounts, err := s.store.ListAccounts(ctx)
	if err != nil || len(accounts) == 0 {
		return
	}
	for _, a := range accounts {
		if a.IsAdmin && !a.Disabled && emailMatchesAllowedDomain(a.Email, domain) {
			return
		}
	}
	slog.Warn("no active admin is in PEEK_ALLOWED_EMAIL_DOMAIN; admins outside it cannot sign in", "domain", domain)
}
