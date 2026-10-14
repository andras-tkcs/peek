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

func TestMetricsOpenWithoutConfiguredToken(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodGet, "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "peek_requests_total") {
		t.Fatalf("body missing peek_requests_total: %s", rec.Body.String())
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
