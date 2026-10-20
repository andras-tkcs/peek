package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
	"github.com/andras-tkcs/peek/internal/models"
	webui "github.com/andras-tkcs/peek/internal/web"
	"golang.org/x/crypto/bcrypt"
)

func TestNormalizeAllowedEmailDomain(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "blank disables", value: " ", want: ""},
		{name: "lowercase", value: "Example.COM", want: "example.com"},
		{name: "leading at", value: "@Example.COM", want: "example.com"},
		{name: "subdomain", value: "team.example.com", want: "team.example.com"},
		{name: "email rejected", value: "user@example.com", wantErr: true},
		{name: "wildcard rejected", value: "*.example.com", wantErr: true},
		{name: "comma rejected", value: "example.com,other.com", wantErr: true},
		{name: "url rejected", value: "https://example.com", wantErr: true},
		{name: "empty label rejected", value: "example..com", wantErr: true},
		{name: "hyphen prefix rejected", value: "-example.com", wantErr: true},
		{name: "hyphen suffix rejected", value: "example-.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAllowedEmailDomain(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeAllowedEmailDomain(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeAllowedEmailDomain(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestEmailMatchesAllowedDomain(t *testing.T) {
	tests := []struct {
		email  string
		domain string
		want   bool
	}{
		{email: "user@example.com", domain: "", want: true},
		{email: "USER@Example.COM", domain: "example.com", want: true},
		{email: "user@team.example.com", domain: "example.com", want: false},
		{email: "user@example.com", domain: "team.example.com", want: false},
		{email: "not-an-email", domain: "example.com", want: false},
		{email: "", domain: "example.com", want: false},
	}
	for _, tt := range tests {
		if got := emailMatchesAllowedDomain(tt.email, tt.domain); got != tt.want {
			t.Fatalf("emailMatchesAllowedDomain(%q, %q) = %t, want %t", tt.email, tt.domain, got, tt.want)
		}
	}
}

func TestValidateAllowedEmailDomainUpdateRequiresActiveMatchingAdmin(t *testing.T) {
	s := newTestServer(t)
	if _, err := s.store.CreateAccount(context.Background(), "admin@example.com", "Admin", true); err != nil {
		t.Fatal(err)
	}
	disabled, err := s.store.CreateAccount(context.Background(), "disabled@other.com", "Disabled", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetAccountDisabled(context.Background(), disabled.ID, true); err != nil {
		t.Fatal(err)
	}

	if err := s.validateAllowedEmailDomainUpdate(context.Background(), map[string]string{authAllowedEmailDomainSetting: "example.com"}); err != nil {
		t.Fatalf("matching active admin rejected: %v", err)
	}
	if err := s.validateAllowedEmailDomainUpdate(context.Background(), map[string]string{authAllowedEmailDomainSetting: "other.com"}); err == nil {
		t.Fatal("expected non-matching domain to be rejected")
	}
	if err := s.validateAllowedEmailDomainUpdate(context.Background(), map[string]string{authAllowedEmailDomainSetting: ""}); err != nil {
		t.Fatalf("clearing domain rejected: %v", err)
	}
}

func TestUpdateSettingsRejectsDomainThatWouldLockOutAdminsBeforeWriting(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateAccount(context.Background(), "admin@example.com", "Admin", true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), "max_upload", "1024"); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, secret: strings.Repeat("0", 64)}

	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"auth_allowed_email_domain":"other.com","max_upload":"2048"}`))
	req = withAPIToken(req, &models.Token{Name: "admin", IsAdmin: true})
	rec := httptest.NewRecorder()

	s.handleUpdateSettings(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := mustGetSetting(t, store, "max_upload"); got != "1024" {
		t.Fatalf("max_upload was partially updated to %q", got)
	}
}

func TestDashboardSettingsRejectsDomainThatWouldLockOutAdminsBeforeWriting(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	account, err := store.CreateAccount(context.Background(), "admin@example.com", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), "max_upload", "1024"); err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store, renderer: renderer, secret: strings.Repeat("0", 64)}
	form := url.Values{
		"csrf":                        {"csrf-token"},
		authAllowedEmailDomainSetting: {"other.com"},
		"max_upload":                  {"2048"},
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(account.ID, 10), sessionTTL)})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	rec := httptest.NewRecorder()

	s.handleDashboardSettings(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := mustGetSetting(t, store, "max_upload"); got != "1024" {
		t.Fatalf("max_upload was partially updated to %q", got)
	}
}

func TestLoginWithPasswordRejectsDisallowedDomain(t *testing.T) {
	s := newTestServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.CreateAccountWithPassword(context.Background(), "user@other.com", "User", string(hash), false); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.com"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{
		"email":    {"user@other.com"},
		"password": {"password"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = s.loginWithPassword(req)
	if !errors.Is(err, errAccountNotEligible) {
		t.Fatalf("error = %v", err)
	}
}

func TestLoginWithTokenRejectsDisallowedDomain(t *testing.T) {
	s := newTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "user@other.com", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateTokenForAccount(context.Background(), "raw-token", account.ID, "web token"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.com"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"token": {"raw-token"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = s.loginWithToken(req)
	if !errors.Is(err, errAccountNotEligible) {
		t.Fatalf("error = %v", err)
	}
}

func TestDirectAPITokenAuthHonoursAllowedEmailDomain(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newAccountWithToken(t, s, "user@other.test", "other-token-0123", false)
	newAccountWithToken(t, s, "user@example.test", "ok-token-0123", false)
	if err := s.store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.test"); err != nil {
		t.Fatal(err)
	}

	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer("other-token-0123"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("off-domain status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "account email domain is not allowed" {
		t.Fatalf("error = %q", body["error"])
	}
	if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer("ok-token-0123")); rec.Code != http.StatusOK {
		t.Fatalf("on-domain status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if tokenLastUsed(t, s, "other-token-0123").Valid {
		t.Fatal("refused token recorded a use")
	}
}

func TestResolveOAuthAccountRejectsDisallowedDomain(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.com"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := s.resolveOAuthAccount(req, &oauthProfile{
		Provider:       "google",
		ProviderUserID: "sub-1",
		Email:          "user@other.com",
		EmailVerified:  true,
		Name:           "User",
	})
	if !errors.Is(err, errAccountNotEligible) {
		t.Fatalf("error = %v", err)
	}
}

func TestWebAuthRejectsExistingSessionAfterDomainChange(t *testing.T) {
	s, store, accountID := newAdminTestServer(t)
	if err := store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "other.com"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(accountID, 10), sessionTTL)})

	if _, ok := s.webAuth(req); ok {
		t.Fatal("webAuth accepted an off-domain existing session")
	}
}

func TestDashboardCreateInviteRejectsDisallowedDomain(t *testing.T) {
	s, store, accountID := newAdminTestServer(t)
	if err := store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.test"); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf": {"csrf-token"}, "email": {"user@other.test"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/invites", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(accountID, 10), sessionTTL)})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	rec := httptest.NewRecorder()

	s.handleDashboardCreateInvite(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/admin?err=invite_domain" {
		t.Fatalf("location = %q", loc)
	}
}

func TestCLILoginPollRejectsDisallowedDomain(t *testing.T) {
	s := newTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "user@other.com", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateCLILoginDevice(context.Background(), "device-code", "ABCDEFGH", time.Now().Add(cliLoginTTL)); err != nil {
		t.Fatal(err)
	}
	device, err := s.store.GetCLILoginByDevice(context.Background(), "device-code")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.ApproveCLILogin(context.Background(), device.ID, account.ID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.handleCLILoginPoll(rec, httptest.NewRequest(http.MethodPost, "/api/cli/login/poll", strings.NewReader(`{"device_code":"device-code"}`)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"denied"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestSetCovNormalizeAllowedEmailDomainRejectsInvalidCharacters(t *testing.T) {
	for _, in := range []string{"exa_mple.com", "exa mple.com", "ex*ample.com", "exämple.com"} {
		if _, err := normalizeAllowedEmailDomain(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

func TestSetCovValidateAllowedEmailDomainUpdateAccountLookupFailure(t *testing.T) {
	s, _, _, _ := newFaultServer(t)
	_ = s.store.Close()
	err := s.validateAllowedEmailDomainUpdate(context.Background(), map[string]string{authAllowedEmailDomainSetting: "example.test"})
	if err == nil || !strings.Contains(err.Error(), "account lookup failed") {
		t.Fatalf("err = %v", err)
	}
}

func TestSetCovAccountActiveOAuthIdentityLookupFailure(t *testing.T) {
	s, _, _, _ := newFaultServer(t)
	enableGitHubOAuthForTest(t, s)
	user, err := s.store.CreateAccount(context.Background(), "setcov-user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	dropTable(t, s.store, "oauth_identities")
	if err := s.accountActive(context.Background(), user); err == nil || errors.Is(err, errOAuthRequired) {
		t.Fatalf("err = %v, want lookup error", err)
	}
	rec := httptest.NewRecorder()
	writeTokenPolicyError(rec, errors.New("lookup failed"))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "account check failed") {
		t.Fatalf("policy error response = %d %s", rec.Code, rec.Body.String())
	}
}
