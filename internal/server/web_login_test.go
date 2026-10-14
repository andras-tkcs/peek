package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/andras-tkcs/peek/internal/db"
	webui "github.com/andras-tkcs/peek/internal/web"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginRejectsMalformedForm(t *testing.T) {
	s, _, _ := newWebLoginTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("csrf=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid session.") {
		t.Fatalf("login page did not report invalid session: %s", rec.Body.String())
	}
	if got := rec.Result().Cookies(); hasCookie(got, sessionCookie) {
		t.Fatalf("malformed login created session cookie: %+v", got)
	}
}

func TestLogoutRejectsInvalidCSRFWithoutClearingSession(t *testing.T) {
	s, _, accountID := newWebLoginTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(accountID, 10), sessionTTL)})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	rec := httptest.NewRecorder()

	s.handleLogout(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "Your logout request could not be verified.") {
		t.Fatalf("logout did not render web error: %s", rec.Body.String())
	}
	if got := rec.Result().Cookies(); hasCookie(got, sessionCookie) {
		t.Fatalf("invalid logout cleared session cookie: %+v", got)
	}
}

func newWebLoginTestServer(t *testing.T) (*Server, *db.Store, int64) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	return &Server{store: store, renderer: renderer, secret: strings.Repeat("0", 64)}, store, account.ID
}

func hasCookie(cookies []*http.Cookie, name string) bool {
	for _, c := range cookies {
		if c.Name == name {
			return true
		}
	}
	return false
}

func newLoginLimiterServer(t *testing.T) (*Server, func(email, pw string) error) {
	t.Helper()
	s, _ := newHandlerTestServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("right"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"user@example.test", "other@example.test"} {
		if _, err := s.store.CreateAccountWithPassword(context.Background(), email, "User", string(hash), false); err != nil {
			t.Fatal(err)
		}
	}
	try := func(email, pw string) error {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"email": {email}, "password": {pw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, err := s.loginWithPassword(req)
		return err
	}
	return s, try
}

func TestPasswordLoginFailuresLockAccountAfterLimit(t *testing.T) {
	_, try := newLoginLimiterServer(t)
	for i := 0; i < accountLoginFailureMax; i++ {
		if err := try("user@example.test", "wrong"); err == nil || errors.Is(err, errLoginThrottled) {
			t.Fatalf("attempt %d: err = %v, want plain failure", i, err)
		}
	}
	if err := try("USER@example.test ", "right"); !errors.Is(err, errLoginThrottled) {
		t.Fatalf("locked account err = %v, want errLoginThrottled", err)
	}
	if err := try("other@example.test", "right"); err != nil {
		t.Fatalf("other account err = %v", err)
	}
}

func TestPasswordLoginThrottlesUnknownEmails(t *testing.T) {
	_, try := newLoginLimiterServer(t)
	for i := 0; i < accountLoginFailureMax; i++ {
		if err := try("ghost@example.test", "x"); errors.Is(err, errLoginThrottled) {
			t.Fatalf("attempt %d throttled early", i)
		}
	}
	if err := try("ghost@example.test", "x"); !errors.Is(err, errLoginThrottled) {
		t.Fatalf("err = %v, want errLoginThrottled", err)
	}
}

func TestHandleLoginReturns429WhenAccountThrottled(t *testing.T) {
	s, _ := newLoginLimiterServer(t)
	for i := 0; i < accountLoginFailureMax; i++ {
		s.accountLoginLimiter.recordFailure("user@example.test")
	}
	body := url.Values{"method": {"password"}, "email": {"user@example.test"}, "password": {"right"}, "csrf": {"tok"}}.Encode()
	rec := doRequest(t, s, http.MethodPost, "/login", strings.NewReader(body), func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "tok"})
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Too many requests. Try again shortly.") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestLoginWithPasswordRunsOneBcryptCompareOnEveryFailure(t *testing.T) {
	var calls atomic.Int64
	orig := passwordCompare
	passwordCompare = func(hash, password []byte) error {
		calls.Add(1)
		return bcrypt.CompareHashAndPassword(hash, password)
	}
	t.Cleanup(func() { passwordCompare = orig })

	hash, err := bcrypt.GenerateFromPassword([]byte("right"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	attempt := func(s *Server, email, pw string) error {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"email": {email}, "password": {pw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, err := s.loginWithPassword(req)
		return err
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, s *Server)
		email string
		pw    string
		check func(t *testing.T, err error)
		calls int64
	}{
		{name: "unknown email", email: "nobody@example.test", pw: "right", calls: 1},
		{name: "account without password", email: "user@example.test", pw: "right", calls: 1,
			setup: func(t *testing.T, s *Server) {
				if _, err := s.store.CreateAccount(ctx, "user@example.test", "User", false); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "wrong password", email: "user@example.test", pw: "wrong", calls: 1,
			setup: func(t *testing.T, s *Server) {
				if _, err := s.store.CreateAccountWithPassword(ctx, "user@example.test", "User", string(hash), false); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "disabled account, right password", email: "user@example.test", pw: "right", calls: 1,
			setup: func(t *testing.T, s *Server) {
				a, err := s.store.CreateAccountWithPassword(ctx, "user@example.test", "User", string(hash), false)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.store.SetAccountDisabled(ctx, a.ID, true); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, err error) {
				if err == nil || err.Error() != "account disabled" {
					t.Fatalf("err = %v, want account disabled", err)
				}
			}},
		{name: "off-domain, right password", email: "user@other.test", pw: "right", calls: 1,
			setup: func(t *testing.T, s *Server) {
				if _, err := s.store.CreateAccountWithPassword(ctx, "user@other.test", "User", string(hash), false); err != nil {
					t.Fatal(err)
				}
				setAllowedDomainForTest(t, s, "example.test")
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, errAccountNotEligible) {
					t.Fatalf("err = %v, want errAccountNotEligible", err)
				}
			}},
		{name: "oauth required non-admin, right password", email: "user@example.test", pw: "right", calls: 1,
			setup: func(t *testing.T, s *Server) {
				if _, err := s.store.CreateAccountWithPassword(ctx, "user@example.test", "User", string(hash), false); err != nil {
					t.Fatal(err)
				}
				enableGitHubOAuthForTest(t, s)
			},
			check: func(t *testing.T, err error) {
				if err == nil || err.Error() != "oauth required" {
					t.Fatalf("err = %v, want oauth required", err)
				}
			}},
		{name: "missing password", email: "user@example.test", pw: "", calls: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := newHandlerTestServer(t)
			if tt.setup != nil {
				tt.setup(t, s)
			}
			calls.Store(0)
			err := attempt(s, tt.email, tt.pw)
			if err == nil {
				t.Fatal("login succeeded, want error")
			}
			if tt.check != nil {
				tt.check(t, err)
			}
			if got := calls.Load(); got != tt.calls {
				t.Fatalf("bcrypt comparisons = %d, want %d", got, tt.calls)
			}
		})
	}
}

func TestDummyPasswordHashIsDefaultCost(t *testing.T) {
	cost, err := bcrypt.Cost(dummyPasswordHash())
	if err != nil {
		t.Fatal(err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("cost = %d, want %d", cost, bcrypt.DefaultCost)
	}
}

func TestLoginSetsEpochSessionCookie(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("right"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, err := s.store.CreateAccountWithPassword(ctx, "user@example.test", "User", string(hash), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.BumpSessionEpoch(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"method": {"password"}, "email": {"user@example.test"}, "password": {"right"}, "csrf": {"csrf-token"}}
	rec := doRequest(t, s, http.MethodPost, "/login", strings.NewReader(form.Encode()),
		func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
		func(r *http.Request) { r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"}) })
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got, want := sessionSubjectOf(t, s, rec), sessionSubject(a.ID, 1); got != want {
		t.Fatalf("subject = %q, want %q", got, want)
	}
}
