package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDashCovWebAuthRejectsBadSessions(t *testing.T) {
	s, _, _, _ := newFaultServer(t)
	cases := map[string]string{
		"bad signature":     "not-a-signed-cookie",
		"unparsable":        makeWebSession(s.secret, "not-a-number", sessionTTL),
		"unknown account":   makeWebSession(s.secret, "9999", sessionTTL),
		"negative epoch":    makeWebSession(s.secret, "1.-1", sessionTTL),
		"wrong secret sign": makeWebSession("other-secret", "1", sessionTTL),
	}
	for name, value := range cases {
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: value})
		if a, ok := s.webAuth(req); ok {
			t.Fatalf("%s: webAuth accepted cookie for %+v", name, a)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	if _, ok := s.webAuth(req); ok {
		t.Fatal("webAuth accepted a request without a cookie")
	}
}
