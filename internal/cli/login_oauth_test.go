package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/version"
)

func TestLoginOAuthPollsUntilApproved(t *testing.T) {
	setTestConfigHome(t)
	now := time.Unix(100, 0)
	var sleeps []time.Duration
	var openedURL string
	restoreOAuthTestHooks(t, func() time.Time {
		return now
	}, func(d time.Duration) {
		sleeps = append(sleeps, d)
		now = now.Add(d)
	}, func(url string) error {
		openedURL = url
		return nil
	})

	polls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/cli/login/start":
			if r.Method != http.MethodPost {
				t.Fatalf("start method = %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "device-123",
				"user_code":        "USER-123",
				"verification_url": "http://" + r.Host + "/cli-login",
				"interval":         3,
				"expires_in":       30,
			})
		case "/api/cli/login/poll":
			if r.Method != http.MethodPost {
				t.Fatalf("poll method = %s", r.Method)
			}
			var body struct {
				DeviceCode string `json:"device_code"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode poll body: %v", err)
			}
			if body.DeviceCode != "device-123" {
				t.Fatalf("device code = %q", body.DeviceCode)
			}
			polls++
			if polls == 1 {
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved", "token": "oauth-token"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := &Config{}
	out, err := captureStdout(t, func() error {
		return loginOAuth(cfg, ts.URL+"/")
	})
	if err != nil {
		t.Fatalf("loginOAuth: %v", err)
	}
	if out != "saved.\n" {
		t.Fatalf("stdout = %q", out)
	}
	if cfg.Host != ts.URL || cfg.Token != "oauth-token" {
		t.Fatalf("config = %+v", cfg)
	}
	saved, err := LoadConfig()
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if saved.Host != ts.URL || saved.Token != "oauth-token" {
		t.Fatalf("saved config = %+v", saved)
	}
	if openedURL != ts.URL+"/cli-login" {
		t.Fatalf("opened url = %q", openedURL)
	}
	if polls != 2 {
		t.Fatalf("polls = %d", polls)
	}
	if len(sleeps) != 2 || sleeps[0] != 3*time.Second || sleeps[1] != 3*time.Second {
		t.Fatalf("sleeps = %+v", sleeps)
	}
}

func TestLoginOAuthRejectsApprovedResponseWithoutToken(t *testing.T) {
	setTestConfigHome(t)
	now := time.Unix(100, 0)
	restoreOAuthTestHooks(t, func() time.Time {
		return now
	}, func(d time.Duration) {
		now = now.Add(d)
	}, func(string) error {
		return nil
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/cli/login/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "device-123",
				"user_code":        "USER-123",
				"verification_url": "http://" + r.Host + "/cli-login",
				"interval":         1,
				"expires_in":       30,
			})
		case "/api/cli/login/poll":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	err := loginOAuth(&Config{}, ts.URL)
	if err == nil || err.Error() != "server approved login without a token" {
		t.Fatalf("error = %v", err)
	}
}

func restoreOAuthTestHooks(t *testing.T, now func() time.Time, sleep func(time.Duration), openBrowser func(string) error) {
	t.Helper()

	oldNow := oauthNow
	oldSleep := oauthSleep
	oldOpenBrowser := oauthOpenBrowser
	oauthNow = now
	oauthSleep = sleep
	oauthOpenBrowser = openBrowser
	t.Cleanup(func() {
		oauthNow = oldNow
		oauthSleep = oldSleep
		oauthOpenBrowser = oldOpenBrowser
	})
}

func TestLoginOAuthContinuesWhenBrowserOpenFails(t *testing.T) {
	setTestConfigHome(t)
	now := time.Unix(100, 0)
	restoreOAuthTestHooks(t, func() time.Time {
		return now
	}, func(d time.Duration) {
		now = now.Add(d)
	}, func(string) error {
		return fmt.Errorf("browser unavailable")
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/cli/login/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "device-123",
				"user_code":        "USER-123",
				"verification_url": "http://" + r.Host + "/cli-login",
				"interval":         1,
				"expires_in":       30,
			})
		case "/api/cli/login/poll":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved", "token": "oauth-token"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	if err := loginOAuth(&Config{}, ts.URL); err != nil {
		t.Fatalf("loginOAuth: %v", err)
	}
}

func oauthTestServer(t *testing.T, verificationURL func(r *http.Request) string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/cli/login/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "device-123",
				"user_code":        "ABCD-EFGH",
				"verification_url": verificationURL(r),
				"interval":         1,
				"expires_in":       30,
			})
		case "/api/cli/login/poll":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved", "token": "oauth-token"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestLoginOAuthPrintsCodeAndURL(t *testing.T) {
	setTestConfigHome(t)
	now := time.Unix(100, 0)
	restoreOAuthTestHooks(t, func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }, func(string) error { return nil })
	var stderr bytes.Buffer
	old := oauthStderr
	oauthStderr = &stderr
	t.Cleanup(func() { oauthStderr = old })

	ts := oauthTestServer(t, func(r *http.Request) string { return "http://" + r.Host + "/cli-login" })
	if err := loginOAuth(&Config{}, ts.URL); err != nil {
		t.Fatalf("loginOAuth: %v", err)
	}
	got := stderr.String()
	for _, want := range []string{"URL:  " + ts.URL + "/cli-login", "Code: ABCD-EFGH", "Never enter a code that someone else sent you."} {
		if !strings.Contains(got, want) {
			t.Fatalf("stderr %q missing %q", got, want)
		}
	}
}

func TestPostJSONNoAuthSendsUserAgent(t *testing.T) {
	var ua string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer ts.Close()
	var out map[string]any
	if err := postJSONNoAuth(ts.URL, "/x", nil, &out); err != nil {
		t.Fatalf("postJSONNoAuth: %v", err)
	}
	if want := "peek-cli/" + version.Version; ua != want {
		t.Fatalf("User-Agent = %q, want %q", ua, want)
	}
}

func TestLoginOAuthDoesNotOpenUntrustedVerificationURL(t *testing.T) {
	for _, bad := range []string{"file:///etc/passwd", "http://evil.example/cli-login/X", "-x"} {
		t.Run(bad, func(t *testing.T) {
			setTestConfigHome(t)
			now := time.Unix(100, 0)
			restoreOAuthTestHooks(t, func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }, func(u string) error {
				t.Fatalf("opened %q", u)
				return nil
			})
			var stderr bytes.Buffer
			old := oauthStderr
			oauthStderr = &stderr
			t.Cleanup(func() { oauthStderr = old })

			ts := oauthTestServer(t, func(*http.Request) string { return bad })
			if err := loginOAuth(&Config{}, ts.URL); err != nil {
				t.Fatalf("loginOAuth: %v", err)
			}
			saved, err := LoadConfig()
			if err != nil || saved.Token != "oauth-token" {
				t.Fatalf("saved = %+v, err = %v", saved, err)
			}
			if !strings.Contains(stderr.String(), "Not opening the browser automatically") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}
