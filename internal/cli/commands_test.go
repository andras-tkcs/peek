package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOAuthAvailableDiscovery(t *testing.T) {
	withProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/providers" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"providers":[{"key":"google","name":"Google"}]}`))
	}))
	defer withProvider.Close()
	ok, err := oauthAvailable(withProvider.URL)
	if err != nil || !ok {
		t.Fatalf("expected provider discovery, ok=%v err=%v", ok, err)
	}

	withoutProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"providers":[]}`))
	}))
	defer withoutProvider.Close()
	ok, err = oauthAvailable(withoutProvider.URL)
	if err != nil || ok {
		t.Fatalf("expected no providers, ok=%v err=%v", ok, err)
	}

	browserLogin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"providers":[],"browser_login":true}`))
	}))
	defer browserLogin.Close()
	ok, err = oauthAvailable(browserLogin.URL)
	if err != nil || !ok {
		t.Fatalf("expected browser login discovery, ok=%v err=%v", ok, err)
	}

	oldServer := httptest.NewServer(http.NotFoundHandler())
	defer oldServer.Close()
	ok, err = oauthAvailable(oldServer.URL)
	if err != nil || ok {
		t.Fatalf("expected old server fallback, ok=%v err=%v", ok, err)
	}
}

func runCaptured(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	stderr, _ = captureStderr(t, func() error {
		stdout, _ = captureStdout(t, func() error {
			code = Run(args)
			return nil
		})
		return nil
	})
	return code, stdout, stderr
}

func TestRunSubcommandsFailWithoutConfiguration(t *testing.T) {
	cmds := []string{
		"login", "config", "upload", "list", "delete", "visibility", "rename",
		"grant", "revoke", "grants", "versions", "stats", "comments", "export",
		"delete-all", "token", "backend",
	}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			setTestConfigHome(t)
			t.Setenv("PEEK_HOST", "")
			t.Setenv("PEEK_TOKEN", "")
			withStdin(t, "")
			code, _, stderr := runCaptured(t, cmd)
			if code != 1 || !strings.Contains(stderr, "error:") {
				t.Fatalf("Run(%q) = %d, stderr %q", cmd, code, stderr)
			}
		})
	}
}

func TestRunHelpVersionAndUnknown(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code, _, stderr := runCaptured(t, arg)
		if code != 0 || !strings.Contains(stderr, "Usage:") {
			t.Fatalf("Run(%q) = %d, stderr %q", arg, code, stderr)
		}
	}
	for _, arg := range []string{"version", "-v", "--version"} {
		code, stdout, _ := runCaptured(t, arg)
		if code != 0 || !strings.HasPrefix(stdout, "peek ") {
			t.Fatalf("Run(%q) = %d, stdout %q", arg, code, stdout)
		}
	}
	code, _, stderr := runCaptured(t)
	if code != 1 || !strings.Contains(stderr, "Usage:") {
		t.Fatalf("Run() = %d, stderr %q", code, stderr)
	}
	code, _, stderr = runCaptured(t, "frobnicate")
	if code != 1 || !strings.Contains(stderr, "unknown command: frobnicate") {
		t.Fatalf("Run(unknown) = %d, stderr %q", code, stderr)
	}
}

func TestRunReturnsZeroOnSuccess(t *testing.T) {
	seedConfig(t, "http://h.example", "secret-token")
	code, stdout, _ := runCaptured(t, "config", "show")
	if code != 0 || !strings.Contains(stdout, "host:  http://h.example") {
		t.Fatalf("Run = %d, stdout %q", code, stdout)
	}
}
