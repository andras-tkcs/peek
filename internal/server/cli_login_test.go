package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	webui "github.com/andras-tkcs/peek/internal/web"
)

func TestNormalizeUserCode(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"abcd-efgh", "ABCDEFGH", true},
		{" ABCD EFGH ", "ABCDEFGH", true},
		{"ABCD-EFGH-", "ABCDEFGH", true},
		{"ABCDEFG", "", false},
		{"ABCDEFGI", "", false},
		{"ABCDEFGH1", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		got, ok := normalizeUserCode(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("normalizeUserCode(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	if got := formatUserCode("ABCDEFGH"); got != "ABCD-EFGH" {
		t.Errorf("formatUserCode = %q", got)
	}
	if got := formatUserCode("ABC"); got != "ABC" {
		t.Errorf("formatUserCode short = %q", got)
	}
}

func cliLoginTestDevice(t *testing.T, s *Server, expiresAt time.Time) {
	t.Helper()
	if err := s.store.CreateCLILoginDeviceWithContext(context.Background(), "device-code", "ABCDEFGH", expiresAt, "203.0.113.7", "peek-cli/1.2.3"); err != nil {
		t.Fatal(err)
	}
}

func cliLoginTestAccount(t *testing.T, s *Server) int64 {
	t.Helper()
	a := newAccountWithToken(t, s, "user@example.test", "user-token-0123456789", false)
	return a.ID
}

func TestCLILoginStartReturnsCodeFreeVerificationURL(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/api/cli/login/start", strings.NewReader(`{}`), withJSON(), func(r *http.Request) { r.Header.Set("User-Agent", "peek-test/1.0") })
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.VerificationURL != "http://localhost:7700/cli-login" {
		t.Fatalf("verification_url = %q", resp.VerificationURL)
	}
	if !regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`).MatchString(resp.UserCode) {
		t.Fatalf("user_code = %q", resp.UserCode)
	}
	d, err := s.store.GetCLILoginByUserCode(context.Background(), strings.ReplaceAll(resp.UserCode, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	if d.RequestIP != "192.0.2.1" || d.UserAgent != "peek-test/1.0" {
		t.Fatalf("stored context = %q, %q", d.RequestIP, d.UserAgent)
	}
}

func TestCLILoginLegacyLinkRedirectsWithoutCode(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodGet, "/cli-login/ABCDEFGH", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/cli-login" {
		t.Fatalf("status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestCLILoginEntryRequiresSession(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodGet, "/cli-login", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "hn_next" {
			found = true
			if !strings.Contains(c.Value, "cli-login") {
				t.Fatalf("hn_next = %q", c.Value)
			}
		}
	}
	if !found {
		t.Fatal("hn_next cookie not set")
	}
}

func TestCLILoginEntryRendersCodeForm(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	rec := doRequest(t, s, http.MethodGet, "/cli-login", nil, asSession(s, id))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/cli-login"`) || !strings.Contains(body, `name="code"`) {
		t.Fatalf("body = %s", body)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != webui.DashboardCSP {
		t.Fatalf("CSP = %q", got)
	}
}

func TestCLILoginLookupShowsRequestContext(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
	rec := dashboardPost(t, s, id, "/cli-login", url.Values{"code": {"abcd-efgh"}}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"ABCD-EFGH", "203.0.113.7", "peek-cli/1.2.3", "Only approve if you just ran", `action="/cli-login/ABCD-EFGH"`, "expires after 90 days"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestCLILoginLookupRejectsUnknownExpiredOrMalformedCode(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	cliLoginTestDevice(t, s, time.Now().Add(-time.Minute))
	for name, code := range map[string]string{"unknown": "ZZZZ-ZZZZ", "expired": "ABCD-EFGH", "malformed": "abc"} {
		t.Run(name, func(t *testing.T) {
			rec := dashboardPost(t, s, id, "/cli-login", url.Values{"code": {code}}, true)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "That code is invalid or expired.") || strings.Contains(body, "Approve CLI login") {
				t.Fatalf("body = %s", body)
			}
		})
	}
}

func TestCLILoginLookupRequiresCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
	rec := dashboardPost(t, s, id, "/cli-login", url.Values{"code": {"ABCD-EFGH"}}, false)
	body := rec.Body.String()
	if !strings.Contains(body, "Invalid session. Enter the code again.") || strings.Contains(body, "203.0.113.7") {
		t.Fatalf("body = %s", body)
	}
}

func TestCLILoginLookupIsRateLimited(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	var last int
	for range 11 {
		last = dashboardPost(t, s, id, "/cli-login", url.Values{"code": {"ZZZZ-ZZZZ"}}, true).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("11th status = %d, want 429", last)
	}
}

func cliLoginPoll(t *testing.T, s *Server) map[string]any {
	t.Helper()
	rec := doRequest(t, s, http.MethodPost, "/api/cli/login/poll", strings.NewReader(`{"device_code":"device-code"}`), withJSON())
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("poll body = %s", rec.Body.String())
	}
	return out
}

func TestCLILoginApproveIssuesNinetyDayToken(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
	rec := dashboardPost(t, s, id, "/cli-login/ABCD-EFGH", url.Values{"decision": {"approve"}}, true)
	if !strings.Contains(rec.Body.String(), "CLI login approved") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	out := cliLoginPoll(t, s)
	token, _ := out["token"].(string)
	if out["status"] != "approved" || token == "" {
		t.Fatalf("poll = %v", out)
	}
	tok, err := s.store.GetToken(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Now().Add(cliTokenTTL).Unix()
	if d := tok.ExpiresAt - want; d < -60 || d > 60 {
		t.Fatalf("ExpiresAt = %d, want about %d", tok.ExpiresAt, want)
	}
	keys, err := s.store.ListAccountTokens(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range keys {
		if k.Name == "CLI login" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no CLI login token in %v", keys)
	}
}

func TestCLILoginApproveDeny(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
	rec := dashboardPost(t, s, id, "/cli-login/ABCD-EFGH", url.Values{"decision": {"deny"}}, true)
	if !strings.Contains(rec.Body.String(), "CLI login denied") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if out := cliLoginPoll(t, s); out["status"] != "denied" {
		t.Fatalf("poll = %v", out)
	}
}

func TestCLILoginApproveRequiresCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
	rec := dashboardPost(t, s, id, "/cli-login/ABCD-EFGH", url.Values{"decision": {"approve"}}, false)
	if !strings.Contains(rec.Body.String(), "Invalid session. Enter the code again.") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	d, err := s.store.GetCLILoginByUserCode(context.Background(), "ABCDEFGH")
	if err != nil || d.Status != "pending" {
		t.Fatalf("device = %+v, err = %v", d, err)
	}
}

func TestCLILoginApproveRequiresSession(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
	rec := doRequest(t, s, http.MethodPost, "/cli-login/ABCD-EFGH", strings.NewReader("decision=approve"), func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestCLILoginApproveExpiredCode(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	cliLoginTestDevice(t, s, time.Now().Add(-time.Minute))
	rec := dashboardPost(t, s, id, "/cli-login/ABCD-EFGH", url.Values{"decision": {"approve"}}, true)
	if !strings.Contains(rec.Body.String(), "CLI login expired") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestCLILoginPollDeniesAccountFailingPolicy(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	enableGitHubOAuthForTest(t, s)
	cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
	d, err := s.store.GetCLILoginByDevice(context.Background(), "device-code")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.ApproveCLILogin(context.Background(), d.ID, id); err != nil {
		t.Fatal(err)
	}
	if out := cliLoginPoll(t, s); out["status"] != "denied" {
		t.Fatalf("poll = %v", out)
	}
	keys, err := s.store.ListAccountTokens(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Name == "CLI login" {
			t.Fatal("token was created")
		}
	}
}
