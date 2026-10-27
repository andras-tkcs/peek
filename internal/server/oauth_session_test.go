package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOAuthCovParseFlowCookieRejectsBadBase64(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: oauthCookieName("oidc"), Value: makeWebSession(s.secret, "!!not-base64!!", time.Minute)})
	if _, _, _, ok := s.parseOAuthFlowCookie(req, "oidc"); ok {
		t.Fatal("cookie with a non-base64 payload was accepted")
	}
}

func TestOAuthCovSetNextPathIgnoresUnsafePath(t *testing.T) {
	s := newTestServer(t)
	for _, next := range []string{"", "https://evil.example/", "//evil.example", "/ok\r\nSet-Cookie: x=y"} {
		rec := httptest.NewRecorder()
		s.setNextPath(rec, next)
		if len(rec.Result().Cookies()) != 0 {
			t.Fatalf("setNextPath(%q) set a cookie", next)
		}
	}
	rec := httptest.NewRecorder()
	s.setNextPath(rec, "/dashboard")
	if c := findOAuthTestCookie(rec.Result().Cookies(), nextCookie); c == nil || c.Value != "/dashboard" {
		t.Fatalf("cookies = %+v", rec.Result().Cookies())
	}
}

func TestSafeNextPathRejectsProtocolRelative(t *testing.T) {
	for _, next := range []string{"", "dashboard", "//evil.com", `/\evil.com`, "/a\r\nb", "https://evil.com"} {
		if safeNextPath(next) {
			t.Errorf("safeNextPath(%q) = true, want false", next)
		}
	}
	for _, next := range []string{"/", "/dashboard", "/u/abc?x=1"} {
		if !safeNextPath(next) {
			t.Errorf("safeNextPath(%q) = false, want true", next)
		}
	}
}
