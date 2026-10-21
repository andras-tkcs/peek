package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAdminPageRendersForAdmin(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	admin := newAccountWithToken(t, s, "admin@example.test", "admin-token", true)

	rec := doRequest(t, s, http.MethodGet, "/admin", nil, asSession(s, admin.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Create invite", "Save settings", "Users"} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin page missing %q: %s", want, body)
		}
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("admin page has no Content-Security-Policy")
	}
}

func TestAdminPageRendersFlash(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	admin := newAccountWithToken(t, s, "admin@example.test", "admin-token", true)

	rec := doRequest(t, s, http.MethodGet, "/admin?ok="+flashSettingsSaved, nil, asSession(s, admin.ID))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), flashMessages[flashSettingsSaved]) {
		t.Fatalf("status = %d, success flash not rendered", rec.Code)
	}
	rec = doRequest(t, s, http.MethodGet, "/admin?err="+flashBadUser, nil, asSession(s, admin.ID))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), flashMessages[flashBadUser]) {
		t.Fatalf("status = %d, error flash not rendered", rec.Code)
	}
}

func TestAdminPageNotFoundForNonAdmin(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newAccountWithToken(t, s, "admin@example.test", "admin-token", true)
	user := newAccountWithToken(t, s, "user@example.test", "user-token", false)

	rec := doRequest(t, s, http.MethodGet, "/admin", nil, asSession(s, user.ID))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /admin as non-admin = %d, want 404", rec.Code)
	}
}

func TestAdminPageRedirectsAnonymous(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newAccountWithToken(t, s, "admin@example.test", "admin-token", true)

	rec := doRequest(t, s, http.MethodGet, "/admin", nil)
	assertDashboardRedirect(t, rec, "/login")
}

func TestAdminPageRedirectsToSetupWhenRequired(t *testing.T) {
	s, store, _, _ := newFaultServer(t)
	if _, err := store.Exec("DELETE FROM accounts"); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodGet, "/admin", nil)
	assertDashboardRedirect(t, rec, "/setup")
}

func TestDashboardShowsAdminLinkOnlyForAdmins(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	admin := newAccountWithToken(t, s, "admin@example.test", "admin-token", true)
	user := newAccountWithToken(t, s, "user@example.test", "user-token", false)

	rec := doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, admin.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard as admin = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="/admin"`) {
		t.Fatalf("admin dashboard missing Admin link: %s", body)
	}
	for _, unwanted := range []string{"Save settings", "Create invite", "Invitations"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("dashboard still renders admin content %q", unwanted)
		}
	}

	rec = doRequest(t, s, http.MethodGet, "/dashboard", nil, asSession(s, user.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard as user = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `href="/admin"`) {
		t.Fatal("non-admin dashboard shows Admin link")
	}
}

func TestAdminFlashRedirects(t *testing.T) {
	rec := httptest.NewRecorder()
	adminError(rec, httptest.NewRequest(http.MethodPost, "/dashboard/settings", nil), flashSettingsFailed)
	assertDashboardRedirect(t, rec, "/admin?err="+flashSettingsFailed)

	rec = httptest.NewRecorder()
	adminOK(rec, httptest.NewRequest(http.MethodPost, "/dashboard/settings", nil), flashSettingsSaved)
	assertDashboardRedirect(t, rec, "/admin?ok="+flashSettingsSaved)

	rec = httptest.NewRecorder()
	adminFlash(rec, httptest.NewRequest(http.MethodPost, "/dashboard/settings", nil), url.Values{"err": {flashBadUser}})
	assertDashboardRedirect(t, rec, "/admin?err="+flashBadUser)
}

func TestAdminPageCSRFGenerationFailure(t *testing.T) {
	s, _, _, adminID := newFaultServer(t)
	stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand failed") })
	rec := doRequest(t, s, http.MethodGet, "/admin", nil, asSession(s, adminID))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestParseAdminFormRedirectsToAdminOnBadForm(t *testing.T) {
	s, _, _, _ := newFaultServer(t)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/settings", strings.NewReader("csrf=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	if s.parseAdminForm(rec, req) {
		t.Fatal("parseAdminForm accepted a malformed body")
	}
	assertDashboardRedirect(t, rec, "/admin?err="+flashInvalidSession)

	req = httptest.NewRequest(http.MethodPost, "/dashboard/settings", strings.NewReader(url.Values{"csrf": {"wrong"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	rec = httptest.NewRecorder()
	if s.parseAdminForm(rec, req) {
		t.Fatal("parseAdminForm accepted a CSRF mismatch")
	}
	assertDashboardRedirect(t, rec, "/admin?err="+flashInvalidSession)
}

func TestParseAdminFormReportsCSRFGenerationFailure(t *testing.T) {
	s, _, _, _ := newFaultServer(t)
	stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand down") })
	form := url.Values{"csrf": {"csrf-token"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	rec := httptest.NewRecorder()
	if s.parseAdminForm(rec, req) {
		t.Fatal("parseAdminForm succeeded without entropy")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
