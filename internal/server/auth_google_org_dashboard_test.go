package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestGoogleOrgAdminPageReflectsSetting(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	ctx := context.Background()
	admin := newAccountWithToken(t, s, "admin@example.test", "admin-token", true)

	get := func() string {
		rec := doRequest(t, s, http.MethodGet, "/admin", nil, asSession(s, admin.ID))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /admin = %d: %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	if body := get(); !strings.Contains(body, "Create invite") {
		t.Fatalf("mode off should show the invite form")
	}

	for k, v := range map[string]string{
		authAllowedEmailDomainSetting: "example.test",
		"oauth_google_enabled":        "true",
		"oauth_google_client_id":      "google-client",
	} {
		if err := s.store.SetSetting(ctx, k, v); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	if err := s.encryptedSetSetting(ctx, "oauth_google_client_secret", "google-secret"); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	if err := s.store.SetSetting(ctx, authGoogleOrgSignupSetting, "true"); err != nil {
		t.Fatalf("set mode: %v", err)
	}

	body := get()
	if !strings.Contains(body, `name="auth_google_org_signup" value="true" checked`) {
		t.Fatalf("mode on should render the switch checked")
	}
	if strings.Contains(body, "Create invite") {
		t.Fatalf("mode on should hide the invite form")
	}
}
