package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func sessionSubjectOf(t *testing.T, s *Server, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sub, ok := parseSignedSubject(s.secret, c.Value)
			if !ok {
				t.Fatalf("session cookie does not verify")
			}
			return sub
		}
	}
	t.Fatalf("no %s cookie set", sessionCookie)
	return ""
}

func sessionReq(s *Server, sub string) func(*http.Request) {
	return func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, sub, sessionTTL)})
	}
}

func newSessionTestAccount(t *testing.T, s *Server) int64 {
	t.Helper()
	a, err := s.store.CreateAccount(context.Background(), "u@example.test", "U", false)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func TestParseSessionSubject(t *testing.T) {
	cases := []struct {
		in     string
		id, ep int64
		wantOK bool
	}{
		{"42", 42, 0, true},
		{"42:3", 42, 3, true},
		{"42:", 0, 0, false},
		{":3", 0, 0, false},
		{"a:1", 0, 0, false},
		{"42:-1", 0, 0, false},
		{"42:1:2", 0, 0, false},
		{"0:1", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, c := range cases {
		id, ep, ok := parseSessionSubject(c.in)
		if ok != c.wantOK || (ok && (id != c.id || ep != c.ep)) {
			t.Errorf("parseSessionSubject(%q) = %d,%d,%v", c.in, id, ep, ok)
		}
	}
	id, ep, ok := parseSessionSubject(sessionSubject(7, 9))
	if !ok || id != 7 || ep != 9 {
		t.Fatalf("round trip = %d,%d,%v", id, ep, ok)
	}
}

func TestWebAuthRejectsStaleSessionEpoch(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newSessionTestAccount(t, s)
	if _, err := s.store.BumpSessionEpoch(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	check := func(sub string, want bool) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		sessionReq(s, sub)(req)
		if _, ok := s.webAuth(req); ok != want {
			t.Fatalf("webAuth(%q) = %v, want %v", sub, ok, want)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	asSession(s, id)(req)
	if _, ok := s.webAuth(req); ok {
		t.Fatal("legacy cookie accepted after epoch bump")
	}
	check(sessionSubject(id, 0), false)
	check(sessionSubject(id, 1), true)
}

func TestSetWebSessionIncludesEpoch(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newSessionTestAccount(t, s)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := s.store.BumpSessionEpoch(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	account, err := s.store.GetAccountByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.setWebSession(rec, account)
	if got, want := sessionSubjectOf(t, s, rec), sessionSubject(id, 2); got != want {
		t.Fatalf("subject = %q, want %q", got, want)
	}
}

func TestDashboardSessionsRevokeSignsOutOtherSessions(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newSessionTestAccount(t, s)
	rec := dashboardPost(t, s, id, "/dashboard/sessions/revoke", url.Values{}, true)
	assertDashboardRedirect(t, rec, "/dashboard?ok=sessions_revoked")
	newSub := sessionSubjectOf(t, s, rec)
	if newSub != sessionSubject(id, 1) {
		t.Fatalf("subject = %q", newSub)
	}
	old := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, id))
	if old.Code != http.StatusSeeOther || old.Header().Get("Location") != "/login" {
		t.Fatalf("old cookie: %d %q", old.Code, old.Header().Get("Location"))
	}
	fresh := doRequest(t, s, http.MethodGet, "/dashboard", nil, sessionReq(s, newSub))
	if fresh.Code != http.StatusOK {
		t.Fatalf("new cookie status = %d", fresh.Code)
	}
	entries, err := s.store.ListAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == "session.revoke_others" {
			return
		}
	}
	t.Fatal("no session.revoke_others audit entry")
}

func TestDashboardSessionsRevokeRequiresCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newSessionTestAccount(t, s)
	rec := dashboardPost(t, s, id, "/dashboard/sessions/revoke", url.Values{}, false)
	assertDashboardRedirect(t, rec, "/dashboard?err=invalid_session")
	a, err := s.store.GetAccountByID(context.Background(), id)
	if err != nil || a.SessionEpoch != 0 {
		t.Fatalf("epoch = %d err = %v", a.SessionEpoch, err)
	}
}

func TestDashboardSessionsRevokeRequiresSession(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/dashboard/sessions/revoke", strings.NewReader(""))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestReEnabledAccountDoesNotReviveSessions(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newSessionTestAccount(t, s)
	ctx := context.Background()
	for _, disabled := range []bool{true, false} {
		if err := s.store.SetAccountDisabledChecked(ctx, id, disabled); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	asSession(s, id)(req)
	if _, ok := s.webAuth(req); ok {
		t.Fatal("legacy cookie revived after re-enable")
	}
}

func TestDashboardShowsSignOutOtherSessions(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := newSessionTestAccount(t, s)
	rec := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, id))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `action="/dashboard/sessions/revoke"`) || !strings.Contains(body, "Sign out other sessions") {
		t.Fatalf("status %d, button missing", rec.Code)
	}
}
