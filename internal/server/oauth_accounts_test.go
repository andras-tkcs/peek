package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func oauthCovProfile(email string) *oauthProfile {
	return &oauthProfile{Provider: "github", ProviderUserID: "gh-1", Email: email, EmailVerified: true, Name: "N"}
}

func oauthCovInviteRequest(t *testing.T, s *Server, raw, email string, expires time.Time) *http.Request {
	t.Helper()
	ctx := context.Background()
	admin, err := s.store.CreateAccount(ctx, "", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encryptSecret(s.secret, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.CreateInvite(ctx, raw, cipher, email, admin.ID, expires); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: inviteCookie, Value: raw})
	return req
}

func oauthCovWantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestOAuthCovResolveRejectsDomainOutsidePolicy(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.test"); err != nil {
		t.Fatal(err)
	}
	_, err := s.resolveOAuthAccount(httptest.NewRequest(http.MethodGet, "/", nil), oauthCovProfile("u@other.test"))
	if err != errAccountNotEligible {
		t.Fatalf("err = %v", err)
	}
}

func TestOAuthCovResolveLinkedIdentity(t *testing.T) {
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	link := func(t *testing.T, s *Server, email string) int64 {
		a, err := s.store.CreateAccount(ctx, email, "Linked", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.store.UpsertOAuthIdentity(ctx, a.ID, "github", "gh-1", email, "Linked"); err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	t.Run("returns linked account", func(t *testing.T) {
		s := newTestServer(t)
		id := link(t, s, "u@example.test")
		a, err := s.resolveOAuthAccount(req, oauthCovProfile("u@example.test"))
		if err != nil || a.ID != id {
			t.Fatalf("a=%v err=%v", a, err)
		}
	})
	t.Run("account lookup fails", func(t *testing.T) {
		s := newTestServer(t)
		link(t, s, "u@example.test")
		if _, err := s.store.Exec(`ALTER TABLE accounts RENAME COLUMN password_hash TO oauth_cov_ph`); err != nil {
			t.Fatal(err)
		}
		_, err := s.resolveOAuthAccount(req, oauthCovProfile("u@example.test"))
		oauthCovWantErr(t, err, "linked account not found")
	})
	t.Run("disabled", func(t *testing.T) {
		s := newTestServer(t)
		id := link(t, s, "u@example.test")
		if err := s.store.SetAccountDisabled(ctx, id, true); err != nil {
			t.Fatal(err)
		}
		_, err := s.resolveOAuthAccount(req, oauthCovProfile("u@example.test"))
		oauthCovWantErr(t, err, "account disabled")
	})
	t.Run("account email outside domain", func(t *testing.T) {
		s := newTestServer(t)
		link(t, s, "u@other.test")
		if err := s.store.SetSetting(ctx, authAllowedEmailDomainSetting, "example.test"); err != nil {
			t.Fatal(err)
		}
		_, err := s.resolveOAuthAccount(req, oauthCovProfile("u@example.test"))
		if err != errAccountNotEligible {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("identity lookup fails", func(t *testing.T) {
		s := newTestServer(t)
		dropTable(t, s.store, "oauth_identities")
		_, err := s.resolveOAuthAccount(req, oauthCovProfile("u@example.test"))
		oauthCovWantErr(t, err, "OAuth lookup failed")
	})
}

func TestOAuthCovResolveEmailMatch(t *testing.T) {
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	t.Run("disabled", func(t *testing.T) {
		s := newTestServer(t)
		a, err := s.store.CreateAccount(ctx, "u@example.test", "U", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.store.SetAccountDisabled(ctx, a.ID, true); err != nil {
			t.Fatal(err)
		}
		_, err = s.resolveOAuthAccount(req, oauthCovProfile("u@example.test"))
		oauthCovWantErr(t, err, "account disabled")
	})
	t.Run("lookup fails", func(t *testing.T) {
		s := newTestServer(t)
		if _, err := s.store.Exec(`ALTER TABLE accounts RENAME COLUMN password_hash TO oauth_cov_ph`); err != nil {
			t.Fatal(err)
		}
		_, err := s.resolveOAuthAccount(req, oauthCovProfile("u@example.test"))
		oauthCovWantErr(t, err, "account lookup failed")
	})
}

func TestOAuthCovResolveInvite(t *testing.T) {
	const email = "u@example.test"
	future := time.Now().Add(time.Hour)
	t.Run("no invite cookie", func(t *testing.T) {
		s := newTestServer(t)
		_, err := s.resolveOAuthAccount(httptest.NewRequest(http.MethodGet, "/", nil), oauthCovProfile(email))
		oauthCovWantErr(t, err, "invite required")
	})
	t.Run("unknown token", func(t *testing.T) {
		s := newTestServer(t)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: inviteCookie, Value: "nope"})
		_, err := s.resolveOAuthAccount(req, oauthCovProfile(email))
		oauthCovWantErr(t, err, "invite not found")
	})
	t.Run("other email", func(t *testing.T) {
		s := newTestServer(t)
		req := oauthCovInviteRequest(t, s, "tok", "someone@example.test", future)
		_, err := s.resolveOAuthAccount(req, oauthCovProfile(email))
		oauthCovWantErr(t, err, "does not match")
	})
	t.Run("expired", func(t *testing.T) {
		s := newTestServer(t)
		req := oauthCovInviteRequest(t, s, "tok", email, time.Now().Add(-time.Hour))
		_, err := s.resolveOAuthAccount(req, oauthCovProfile(email))
		oauthCovWantErr(t, err, "does not match")
	})
	t.Run("create fails", func(t *testing.T) {
		s := newTestServer(t)
		req := oauthCovInviteRequest(t, s, "tok", email, future)
		addFailTrigger(t, s.store, "accounts", "INSERT")
		_, err := s.resolveOAuthAccount(req, oauthCovProfile(email))
		oauthCovWantErr(t, err, "account creation failed")
	})
	t.Run("consume fails", func(t *testing.T) {
		s := newTestServer(t)
		req := oauthCovInviteRequest(t, s, "tok", email, future)
		addFailTrigger(t, s.store, "invites", "UPDATE")
		_, err := s.resolveOAuthAccount(req, oauthCovProfile(email))
		oauthCovWantErr(t, err, "invite consumption failed")
	})
}

func TestOAuthCovDisplayNameFallsBackToUser(t *testing.T) {
	if got := displayName("", "  "); got != "user" {
		t.Fatalf("displayName = %q", got)
	}
	if got := displayName(" ", " Ann ", "x"); got != "Ann" {
		t.Fatalf("displayName = %q", got)
	}
}
