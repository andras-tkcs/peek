package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

// cliLoginCovCall invokes a handler directly on a fault server.
func cliLoginCovCall(s *Server, h http.HandlerFunc, method, path, code, body, contentType string, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if code != "" {
		req.SetPathValue("code", code)
	}
	for _, opt := range opts {
		opt(req)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

const cliLoginCovForm = "application/x-www-form-urlencoded"

// cliLoginCovRandFailFrom makes secureRandomRead fail from its n-th call on.
func cliLoginCovRandFailFrom(t *testing.T, n int) {
	t.Helper()
	calls := 0
	stubSecureRandomRead(t, func(b []byte) (int, error) {
		calls++
		if calls >= n {
			return 0, errors.New("rand failed")
		}
		for i := range b {
			b[i] = byte(i + calls)
		}
		return len(b), nil
	})
}

func cliLoginCovCSRFOpts(s *Server, accountID int64) []func(*http.Request) {
	return []func(*http.Request){
		asSession(s, accountID),
		func(r *http.Request) { r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"}) },
	}
}

func TestCLILoginCovStartFailures(t *testing.T) {
	start := func(s *Server) *httptest.ResponseRecorder {
		return cliLoginCovCall(s, s.handleCLILoginStart, http.MethodPost, "/api/cli/login/start", "", "{}", "application/json")
	}
	t.Run("setup required", func(t *testing.T) {
		s, store, _, _ := newFaultServer(t)
		if _, err := store.Exec("DELETE FROM accounts"); err != nil {
			t.Fatal(err)
		}
		if rec := start(s); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "setup is not complete") {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("device code rand failure", func(t *testing.T) {
		s, _, _, _ := newFaultServer(t)
		cliLoginCovRandFailFrom(t, 1)
		if rec := start(s); rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "device code failed") {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("user code rand failure", func(t *testing.T) {
		s, _, _, _ := newFaultServer(t)
		cliLoginCovRandFailFrom(t, 2)
		if rec := start(s); rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "user code failed") {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("insert failure", func(t *testing.T) {
		s, store, _, _ := newFaultServer(t)
		addFailTrigger(t, store, "cli_login_devices", "INSERT")
		if rec := start(s); rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "login start failed") {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCLILoginCovPollBranches(t *testing.T) {
	ctx := context.Background()
	poll := func(s *Server, body string) (int, map[string]any) {
		rec := cliLoginCovCall(s, s.handleCLILoginPoll, http.MethodPost, "/api/cli/login/poll", "", body, "application/json")
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	const pollBody = `{"device_code":"device-code"}`
	// newDevice seeds a device and returns its id.
	newDevice := func(t *testing.T, s *Server, expiresAt time.Time) int64 {
		t.Helper()
		cliLoginTestDevice(t, s, expiresAt)
		d, err := s.store.GetCLILoginByDevice(ctx, "device-code")
		if err != nil {
			t.Fatal(err)
		}
		return d.ID
	}
	approved := func(t *testing.T, s *Server, accountID int64) int64 {
		t.Helper()
		id := newDevice(t, s, time.Now().Add(cliLoginTTL))
		if err := s.store.ApproveCLILogin(ctx, id, accountID); err != nil {
			t.Fatal(err)
		}
		return id
	}

	t.Run("bad json", func(t *testing.T) {
		s, _, _, _ := newFaultServer(t)
		if code, _ := poll(s, `{`); code != http.StatusBadRequest {
			t.Fatalf("status = %d", code)
		}
	})
	t.Run("empty device code", func(t *testing.T) {
		s, _, _, _ := newFaultServer(t)
		if code, _ := poll(s, `{"device_code":"  "}`); code != http.StatusBadRequest {
			t.Fatalf("status = %d", code)
		}
	})
	t.Run("unknown device code", func(t *testing.T) {
		s, _, _, _ := newFaultServer(t)
		if code, _ := poll(s, pollBody); code != http.StatusBadRequest {
			t.Fatalf("status = %d", code)
		}
	})
	t.Run("expired pending is expired in the store", func(t *testing.T) {
		s, _, _, _ := newFaultServer(t)
		id := newDevice(t, s, time.Now().Add(-time.Minute))
		if _, out := poll(s, pollBody); out["status"] != "expired" {
			t.Fatalf("poll = %v", out)
		}
		d, err := s.store.GetCLILoginByDevice(ctx, "device-code")
		if err != nil || d.ID != id || d.Status != "expired" {
			t.Fatalf("device = %+v, err = %v", d, err)
		}
	})
	t.Run("expired pending with failing store update still answers expired", func(t *testing.T) {
		s, store, _, _ := newFaultServer(t)
		newDevice(t, s, time.Now().Add(-time.Minute))
		addFailTrigger(t, store, "cli_login_devices", "UPDATE")
		if _, out := poll(s, pollBody); out["status"] != "expired" {
			t.Fatalf("poll = %v", out)
		}
	})
	t.Run("pending", func(t *testing.T) {
		s, _, _, _ := newFaultServer(t)
		newDevice(t, s, time.Now().Add(cliLoginTTL))
		if _, out := poll(s, pollBody); out["status"] != "pending" {
			t.Fatalf("poll = %v", out)
		}
	})
	t.Run("denied and stored expired", func(t *testing.T) {
		for _, status := range []string{"denied", "expired"} {
			s, store, _, _ := newFaultServer(t)
			newDevice(t, s, time.Now().Add(cliLoginTTL))
			if _, err := store.Exec("UPDATE cli_login_devices SET status=?", status); err != nil {
				t.Fatal(err)
			}
			if _, out := poll(s, pollBody); out["status"] != status {
				t.Fatalf("poll = %v, want %s", out, status)
			}
		}
	})
	t.Run("unknown status", func(t *testing.T) {
		s, store, _, _ := newFaultServer(t)
		newDevice(t, s, time.Now().Add(cliLoginTTL))
		if _, err := store.Exec("UPDATE cli_login_devices SET status='weird'"); err != nil {
			t.Fatal(err)
		}
		if _, out := poll(s, pollBody); out["status"] != "expired" {
			t.Fatalf("poll = %v", out)
		}
	})
	t.Run("already consumed", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		id := approved(t, s, adminID)
		if err := s.store.ConsumeCLILogin(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, out := poll(s, pollBody); out["status"] != "consumed" {
			t.Fatalf("poll = %v", out)
		}
	})
	t.Run("consume failure", func(t *testing.T) {
		s, store, _, adminID := newFaultServer(t)
		approved(t, s, adminID)
		addFailTrigger(t, store, "cli_login_devices", "UPDATE")
		if _, out := poll(s, pollBody); out["status"] != "consumed" {
			t.Fatalf("poll = %v", out)
		}
	})
	t.Run("account lookup failure", func(t *testing.T) {
		s, store, _, adminID := newFaultServer(t)
		approved(t, s, adminID)
		if _, err := store.Exec("UPDATE cli_login_devices SET account_id=NULL"); err != nil {
			t.Fatal(err)
		}
		if _, out := poll(s, pollBody); out["status"] != "denied" {
			t.Fatalf("poll = %v", out)
		}
	})
	t.Run("token generation failure", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		approved(t, s, adminID)
		cliLoginCovRandFailFrom(t, 1)
		if code, _ := poll(s, pollBody); code != http.StatusInternalServerError {
			t.Fatalf("status = %d", code)
		}
	})
	t.Run("token creation failure", func(t *testing.T) {
		s, store, _, adminID := newFaultServer(t)
		approved(t, s, adminID)
		addFailTrigger(t, store, "tokens", "INSERT")
		if code, _ := poll(s, pollBody); code != http.StatusInternalServerError {
			t.Fatalf("status = %d", code)
		}
	})
}

func TestCLILoginCovEntryAndLookupBranches(t *testing.T) {
	post := func(s *Server, h http.HandlerFunc, path, code, body string, accountID int64) *httptest.ResponseRecorder {
		return cliLoginCovCall(s, h, http.MethodPost, path, code, body, cliLoginCovForm, cliLoginCovCSRFOpts(s, accountID)...)
	}
	t.Run("lookup without session redirects to login", func(t *testing.T) {
		s, _, _, _ := newFaultServer(t)
		rec := cliLoginCovCall(s, s.handleCLILoginLookup, http.MethodPost, "/cli-login", "", "code=ABCD-EFGH", cliLoginCovForm)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Fatalf("status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("lookup with unparsable form", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		rec := post(s, s.handleCLILoginLookup, "/cli-login", "", "%zz=1", adminID)
		if !strings.Contains(rec.Body.String(), cliLoginSessionError) {
			t.Fatalf("body = %s", rec.Body.String())
		}
	})
	t.Run("lookup csrf generation failure", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		cliLoginCovRandFailFrom(t, 1)
		rec := post(s, s.handleCLILoginLookup, "/cli-login", "", "csrf=csrf-token&code=ABCD-EFGH", adminID)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("lookup form render csrf failure", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
		cliLoginCovRandFailFrom(t, 2)
		rec := post(s, s.handleCLILoginLookup, "/cli-login", "", "csrf=csrf-token&code=ABCD-EFGH", adminID)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("entry form render csrf failure", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		cliLoginCovRandFailFrom(t, 1)
		rec := cliLoginCovCall(s, s.handleCLILoginEntry, http.MethodGet, "/cli-login", "", "", "", asSession(s, adminID))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rec.Code)
		}
	})
}

func TestCLILoginCovApproveBranches(t *testing.T) {
	ctx := context.Background()
	approve := func(s *Server, accountID int64, code, body string) *httptest.ResponseRecorder {
		return cliLoginCovCall(s, s.handleCLILoginApprove, http.MethodPost, "/cli-login/"+code, code, body, cliLoginCovForm, cliLoginCovCSRFOpts(s, accountID)...)
	}
	const decision = "csrf=csrf-token&decision="
	t.Run("unparsable form", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		rec := approve(s, adminID, "ABCD-EFGH", "%zz=1")
		if !strings.Contains(rec.Body.String(), cliLoginSessionError) {
			t.Fatalf("body = %s", rec.Body.String())
		}
	})
	t.Run("csrf generation failure", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		cliLoginCovRandFailFrom(t, 1)
		if rec := approve(s, adminID, "ABCD-EFGH", decision+"approve"); rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("malformed code is expired", func(t *testing.T) {
		s, _, _, adminID := newFaultServer(t)
		rec := approve(s, adminID, "abc", decision+"approve")
		if !strings.Contains(rec.Body.String(), "CLI login expired") {
			t.Fatalf("body = %s", rec.Body.String())
		}
	})
	t.Run("deny failure re-renders the form", func(t *testing.T) {
		s, store, _, adminID := newFaultServer(t)
		cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
		addFailTrigger(t, store, "cli_login_devices", "UPDATE")
		rec := approve(s, adminID, "ABCD-EFGH", decision+"deny")
		if !strings.Contains(rec.Body.String(), "Denial failed.") {
			t.Fatalf("body = %s", rec.Body.String())
		}
	})
	t.Run("approve failure re-renders the form", func(t *testing.T) {
		s, store, _, adminID := newFaultServer(t)
		cliLoginTestDevice(t, s, time.Now().Add(cliLoginTTL))
		addFailTrigger(t, store, "cli_login_devices", "UPDATE")
		rec := approve(s, adminID, "ABCD-EFGH", decision+"approve")
		if !strings.Contains(rec.Body.String(), "Approval failed.") {
			t.Fatalf("body = %s", rec.Body.String())
		}
		d, err := s.store.GetCLILoginByUserCode(ctx, "ABCDEFGH")
		if err != nil || d.Status != "pending" {
			t.Fatalf("device = %+v, err = %v", d, err)
		}
	})
}

func TestCLILoginCovRandomUserCodeFailure(t *testing.T) {
	cliLoginCovRandFailFrom(t, 1)
	if code, err := randomUserCode(); err == nil || code != "" {
		t.Fatalf("randomUserCode = %q, %v", code, err)
	}
}

func TestCLILoginCovUserAgentTruncatesAtUTF8Boundary(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("User-Agent", strings.Repeat("a", cliLoginUserAgentMax-1)+"é")
	if got := cliLoginUserAgent(req); got != strings.Repeat("a", cliLoginUserAgentMax-1) {
		t.Fatalf("user agent = %q", got)
	}
}

func TestCLILoginCovLookupShowsUnknownForMissingContext(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	id := cliLoginTestAccount(t, s)
	if err := s.store.CreateCLILoginDevice(context.Background(), "device-code", "ABCDEFGH", time.Now().Add(cliLoginTTL)); err != nil {
		t.Fatal(err)
	}
	rec := dashboardPost(t, s, id, "/cli-login", url.Values{"code": {"ABCD-EFGH"}}, true)
	if !strings.Contains(rec.Body.String(), "unknown") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
