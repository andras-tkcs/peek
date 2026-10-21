package server

import (
	"net/http"
	"strings"
	"testing"
)

func newMetricsTestServer(t *testing.T, metricsToken string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(Config{
		DataDir:      dir,
		BaseURL:      "http://localhost:7700",
		Secret:       strings.Repeat("ab", 32),
		MaxUpload:    10 << 20,
		MetricsToken: metricsToken,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	adminToken := "dev-admin-token"
	if err := s.store.CreateToken(t.Context(), adminToken, "admin", true, 0); err != nil {
		t.Fatalf("seed admin token: %v", err)
	}
	return s, adminToken
}

func TestMetricsRefusesAnonymousWithoutConfiguredToken(t *testing.T) {
	s, adminToken := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodGet, "/metrics", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "peek_requests_total") {
		t.Fatalf("anonymous body leaked metrics: %s", rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="peek-metrics"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	rec = doRequest(t, s, http.MethodGet, "/metrics", nil, asBearer(adminToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin token status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "peek_requests_total") {
		t.Fatalf("body missing peek_requests_total: %s", rec.Body.String())
	}
}

func TestMetricsWithoutConfiguredTokenNeedsActiveAdminToken(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newAccountWithToken(t, s, "user@example.test", "user-token", false)
	admin := newAccountWithToken(t, s, "admin2@example.test", "admin2-token", true)

	for name, auth := range map[string]func(*http.Request){
		"unknown token":    asBearer("no-such-token"),
		"empty bearer":     asBearer(""),
		"non-admin token":  asBearer("user-token"),
		"basic scheme":     func(r *http.Request) { r.Header.Set("Authorization", "Basic admin2-token") },
		"session cookie":   asSession(s, admin.ID),
		"token in query":   func(r *http.Request) { r.URL.RawQuery = "token=admin2-token" },
		"token in header2": func(r *http.Request) { r.Header.Set("X-Api-Key", "admin2-token") },
	} {
		if rec := doRequest(t, s, http.MethodGet, "/metrics", nil, auth); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
	}
	if rec := doRequest(t, s, http.MethodGet, "/metrics", nil, asBearer("admin2-token")); rec.Code != http.StatusOK {
		t.Fatalf("admin token status = %d, want 200", rec.Code)
	}

	if err := s.store.SetAccountDisabled(t.Context(), admin.ID, true); err != nil {
		t.Fatal(err)
	}
	if rec := doRequest(t, s, http.MethodGet, "/metrics", nil, asBearer("admin2-token")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled admin status = %d, want 401", rec.Code)
	}
}

func TestMetricsRequiresConfiguredBearerToken(t *testing.T) {
	token := strings.Repeat("m", 32)
	s, _ := newMetricsTestServer(t, token)

	rec := doRequest(t, s, http.MethodGet, "/metrics", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth status = %d", rec.Code)
	}
	if rec.Body.String() != "unauthorized\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="peek-metrics"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	if rec := doRequest(t, s, http.MethodGet, "/metrics", nil, asBearer("wrong")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, "/metrics", nil, asBearer(token)); rec.Code != http.StatusOK {
		t.Fatalf("right token status = %d", rec.Code)
	}
}

func TestMetricsRejectsAPITokenWhenMetricsTokenConfigured(t *testing.T) {
	s, adminToken := newMetricsTestServer(t, strings.Repeat("m", 32))
	if rec := doRequest(t, s, http.MethodGet, "/metrics", nil, asBearer(adminToken)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestReadyzHidesDatabaseError(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	_ = s.store.Close()
	rec := doRequest(t, s, http.MethodGet, "/readyz", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Body.String() != "not ready" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}
