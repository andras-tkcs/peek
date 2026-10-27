package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func enableGitHubOAuthForTest(t *testing.T, s *Server) {
	t.Helper()
	for k, v := range map[string]string{
		"oauth_github_enabled":       "true",
		"oauth_github_client_id":     "client-id",
		"oauth_github_client_secret": "client-secret",
	} {
		if err := s.store.SetSetting(context.Background(), k, v); err != nil {
			t.Fatal(err)
		}
	}
}

func setAllowedDomainForTest(t *testing.T, s *Server, domain string) {
	t.Helper()
	if err := s.store.SetSetting(context.Background(), authAllowedEmailDomainSetting, domain); err != nil {
		t.Fatal(err)
	}
}

func policyErrorBody(t *testing.T, body []byte) string {
	t.Helper()
	var out map[string]string
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return out["error"]
}

func TestAccountActive(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	ctx := context.Background()

	disabled, err := s.store.CreateAccount(ctx, "off@example.test", "off", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetAccountDisabled(ctx, disabled.ID, true); err != nil {
		t.Fatal(err)
	}
	disabled, err = s.store.GetAccountByID(ctx, disabled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.accountActive(ctx, disabled); !errors.Is(err, errAccountDisabled) {
		t.Fatalf("disabled = %v", err)
	}

	setAllowedDomainForTest(t, s, "example.test")
	offDomain, err := s.store.CreateAccount(ctx, "u@other.test", "u", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.accountActive(ctx, offDomain); !errors.Is(err, errAccountNotEligible) {
		t.Fatalf("off-domain = %v", err)
	}
	botless, err := s.store.CreateAccount(ctx, "", "bot", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.accountActive(ctx, botless); !errors.Is(err, errAccountNotEligible) {
		t.Fatalf("email-less = %v", err)
	}
	setAllowedDomainForTest(t, s, "")

	enableGitHubOAuthForTest(t, s)
	user, err := s.store.CreateAccount(ctx, "user@example.test", "user", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.accountActive(ctx, user); !errors.Is(err, errOAuthRequired) {
		t.Fatalf("no identity = %v", err)
	}
	if err := s.store.UpsertOAuthIdentity(ctx, user.ID, "github", "42", user.Email, "user"); err != nil {
		t.Fatal(err)
	}
	if err := s.accountActive(ctx, user); err != nil {
		t.Fatalf("with identity = %v", err)
	}
	admin, err := s.store.CreateAccount(ctx, "admin@example.test", "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.accountActive(ctx, admin); err != nil {
		t.Fatalf("admin = %v", err)
	}
}

func TestTokenAccountActiveExemptsEmailLessAccounts(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	ctx := context.Background()
	setAllowedDomainForTest(t, s, "example.test")
	enableGitHubOAuthForTest(t, s)
	if err := s.store.CreateToken(ctx, "bot-token-0123", "bot", false, 0); err != nil {
		t.Fatal(err)
	}

	for _, tok := range []string{admin, "bot-token-0123"} {
		if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(tok)); rec.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", tok, rec.Code, rec.Body.String())
		}
	}

	bot, err := s.store.GetToken(ctx, "bot-token-0123")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetAccountDisabled(ctx, bot.AccountID, true); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer("bot-token-0123"))
	if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account disabled" {
		t.Fatalf("disabled bot = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthTokenRequiresOAuthIdentityWhenOAuthEnabled(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	acct := newAccountWithToken(t, s, "user@example.test", "user-token-0123", false)
	enableGitHubOAuthForTest(t, s)

	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer("user-token-0123"))
	if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account must sign in with OAuth" {
		t.Fatalf("no identity = %d: %s", rec.Code, rec.Body.String())
	}
	if err := s.store.UpsertOAuthIdentity(context.Background(), acct.ID, "github", "42", acct.Email, "user"); err != nil {
		t.Fatal(err)
	}
	if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer("user-token-0123")); rec.Code != http.StatusOK {
		t.Fatalf("with identity = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthAdminHonoursAllowedEmailDomain(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newAccountWithToken(t, s, "admin@other.test", "admin2-token-0123", true)
	setAllowedDomainForTest(t, s, "example.test")

	rec := doRequest(t, s, http.MethodGet, "/api/tokens", nil, asBearer("admin2-token-0123"))
	if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account email domain is not allowed" {
		t.Fatalf("off-domain admin = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthTokenDisabledAccountStillAnswersAccountDisabled(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	acct := newAccountWithToken(t, s, "user@example.test", "user-token-0123", false)
	if err := s.store.SetAccountDisabled(context.Background(), acct.ID, true); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer("user-token-0123"))
	if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account disabled" {
		t.Fatalf("disabled = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestListCommentsBearerHonoursAccountPolicy(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newAccountWithToken(t, s, "owner@other.test", "owner-token-0123", false)
	slug := seedVersionPage(t, s, "owner-token-0123")
	setAllowedDomainForTest(t, s, "example.test")

	rec := doRequest(t, s, http.MethodGet, "/api/uploads/"+slug+"/comments", nil, asBearer("owner-token-0123"))
	if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account email domain is not allowed" {
		t.Fatalf("off-domain owner = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenAccountActiveExemptsProvisionedToken(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	f := newProvisionedFixture(t, s, "PF", "u@x.test", "e1")
	enableGitHubOAuthForTest(t, s)
	if rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(f.Token)); rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestTokenAccountActiveDoesNotExemptOtherTokensOfProvisionedAccount(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	f := newProvisionedFixture(t, s, "PF", "u@x.test", "e1")
	if err := s.store.CreateTokenForAccount(context.Background(), "peek_own-token-1234", f.AccountID, "mine"); err != nil {
		t.Fatal(err)
	}
	enableGitHubOAuthForTest(t, s)
	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer("peek_own-token-1234"))
	if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account must sign in with OAuth" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestTokenAccountActiveProvisionedTokenStillChecksDisabled(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	f := newProvisionedFixture(t, s, "PF", "u@x.test", "e1")
	enableGitHubOAuthForTest(t, s)
	if _, err := s.store.Exec(`UPDATE accounts SET disabled=1 WHERE id=?`, f.AccountID); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(f.Token))
	if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account disabled" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestTokenAccountActiveProvisionedTokenStillChecksDomain(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	f := newProvisionedFixture(t, s, "PF", "u@x.test", "e1")
	enableGitHubOAuthForTest(t, s)
	setAllowedDomainForTest(t, s, "other.test")
	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(f.Token))
	if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account email domain is not allowed" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestTokenAccountActiveRefusesProvisionedTokenOfPromotedAccount(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	f := newProvisionedFixture(t, s, "PF", "u@x.test", "e1")
	if err := s.store.SetAccountAdminChecked(context.Background(), f.AccountID, true); err != nil {
		t.Fatal(err)
	}
	for _, oauth := range []bool{false, true} {
		if oauth {
			enableGitHubOAuthForTest(t, s)
		}
		for _, path := range []string{"/api/uploads", "/api/tokens"} {
			rec := doRequest(t, s, http.MethodGet, path, nil, asBearer(f.Token))
			if rec.Code != http.StatusForbidden || policyErrorBody(t, rec.Body.Bytes()) != "account is a Peek admin; connect it by hand" {
				t.Fatalf("oauth=%v %s: got %d %s", oauth, path, rec.Code, rec.Body)
			}
		}
	}
}

func TestTokenAccountActiveOrdinaryAdminTokenUnchanged(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newAccountWithToken(t, s, "root@x.test", "peek_admin-token-1234", true)
	enableGitHubOAuthForTest(t, s)
	for _, path := range []string{"/api/uploads", "/api/tokens"} {
		if rec := doRequest(t, s, http.MethodGet, path, nil, asBearer("peek_admin-token-1234")); rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d %s", path, rec.Code, rec.Body)
		}
	}
}

func TestTokenAccountActiveReportsProvisionedLookupFailure(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	f := newProvisionedFixture(t, s, "PF", "u@x.test", "e1")
	enableGitHubOAuthForTest(t, s)
	if _, err := s.store.Exec(`DROP TABLE provisioned_accounts`); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(f.Token))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}
