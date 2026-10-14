package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdLoginTokenFileSavesConfig(t *testing.T) {
	setTestConfigHome(t)
	tokenFile := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(tokenFile, []byte("tok-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/providers" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"providers":[]}`))
	}))
	defer authServer.Close()

	if err := cmdLogin([]string{"--host", authServer.URL, "--token-file", tokenFile}); err != nil {
		t.Fatalf("cmdLogin: %v", err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != authServer.URL || cfg.Token != "tok-file" {
		t.Fatalf("saved config = %+v", cfg)
	}
}

func TestCmdLoginRejectsTokenWhenOAuthRequired(t *testing.T) {
	setTestConfigHome(t)
	tokenFile := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(tokenFile, []byte("tok-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/providers" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"providers":[{"key":"github","name":"GitHub"}]}`))
	}))
	defer authServer.Close()

	err := cmdLogin([]string{"--host", authServer.URL, "--token-file", tokenFile})
	if err == nil || !strings.Contains(err.Error(), "requires OAuth browser login") {
		t.Fatalf("expected OAuth-required error, got %v", err)
	}
}

func TestCmdLoginRejectsConflictingTokenInputs(t *testing.T) {
	setTestConfigHome(t)
	tokenFile := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(tokenFile, []byte("tok-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := [][]string{
		{"--host", "http://example.test", "--token", "tok", "--token-file", tokenFile},
		{"--host", "http://example.test", "--token", "tok", "--token-stdin"},
		{"--host", "http://example.test", "--token-file", tokenFile, "--token-stdin"},
	}
	for _, args := range tests {
		err := cmdLogin(args)
		if err == nil || err.Error() != "use only one of --token, --token-file, or --token-stdin" {
			t.Fatalf("cmdLogin(%v) error = %v", args, err)
		}
	}
}

func TestReadTokenInteractiveReadsPipedLine(t *testing.T) {
	withStdin(t, "  piped-token  \nsecond\n")
	got, err := readTokenInteractive()
	if err != nil || got != "piped-token" {
		t.Fatalf("got %q, %v", got, err)
	}

	withStdin(t, "no-newline")
	got, err = readTokenInteractive()
	if err != nil || got != "no-newline" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadTokenInteractiveReportsReadError(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	old := os.Stdin
	os.Stdin = dir
	defer func() { os.Stdin = old }()
	if _, err := readTokenInteractive(); err == nil {
		t.Fatal("expected a read error")
	}
}

func TestCmdLoginFlagErrors(t *testing.T) {
	setTestConfigHome(t)
	withStdin(t, "")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--host"}, "--host requires a value"},
		{[]string{"--token"}, "--token requires a value"},
		{[]string{"--token-file"}, "--token-file requires a value"},
		{[]string{"--bogus"}, "unknown flag"},
		{nil, "host is required"},
	}
	for _, tc := range cases {
		err := cmdLogin(tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("cmdLogin(%v) = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestCmdLoginReportsConfigLoadFailure(t *testing.T) {
	setTestConfigHome(t)
	writeBadConfig(t)
	if err := cmdLogin([]string{"--host", "http://x"}); err == nil {
		t.Fatal("expected a config load error")
	}
}

func TestCmdLoginOAuthForcedErrors(t *testing.T) {
	setTestConfigHome(t)
	withStdin(t, "")

	err := cmdLogin([]string{"--oauth", "--host", closedServerURL(t)})
	if err == nil {
		t.Fatal("expected a discovery error")
	}

	noBrowser := jsonServer(t, 200, `{"providers":[]}`)
	err = cmdLogin([]string{"--oauth", "--host", noBrowser.URL})
	if err == nil || !strings.Contains(err.Error(), "browser login is not configured") {
		t.Fatalf("error = %v", err)
	}
}

func TestCmdLoginStartsBrowserLoginWhenAvailable(t *testing.T) {
	setTestConfigHome(t)
	withStdin(t, "")
	// Discovery says browser login exists, but the start endpoint fails.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/providers" {
			w.Write([]byte(`{"providers":[],"browser_login":true}`))
			return
		}
		http.Error(w, `{"error":"no device flow"}`, http.StatusInternalServerError)
	}))
	defer ts.Close()
	err := cmdLogin([]string{"--oauth", "--host", ts.URL})
	if err == nil || !strings.Contains(err.Error(), "no device flow") {
		t.Fatalf("error = %v", err)
	}
}

func TestCmdLoginPromptsForHostOnStdin(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[]}`)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("prompted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withStdin(t, ts.URL+"\n")
	stderr, err := captureStderr(t, func() error {
		_, e := captureStdout(t, func() error { return cmdLogin([]string{"--token-file", tokenFile}) })
		return e
	})
	if err != nil {
		t.Fatalf("cmdLogin: %v", err)
	}
	if !strings.Contains(stderr, "Host (e.g.") {
		t.Fatalf("stderr = %q", stderr)
	}
	if cfg, _ := LoadConfig(); cfg.Host != ts.URL || cfg.Token != "prompted" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestCmdLoginTokenStdin(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[]}`)
	withStdin(t, "stdin-tok\n")
	if _, err := captureStdout(t, func() error { return cmdLogin([]string{"--host", ts.URL, "--token-stdin"}) }); err != nil {
		t.Fatalf("cmdLogin: %v", err)
	}
	if cfg, _ := LoadConfig(); cfg.Token != "stdin-tok" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestCmdLoginTokenStdinReadError(t *testing.T) {
	setTestConfigHome(t)
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	old := os.Stdin
	os.Stdin = dir
	defer func() { os.Stdin = old }()
	if err := cmdLogin([]string{"--host", "http://x.example", "--token-stdin"}); err == nil {
		t.Fatal("expected a stdin read error")
	}
}

func TestCmdLoginRejectsEmptyToken(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[]}`)
	withStdin(t, "")
	err := cmdLogin([]string{"--host", ts.URL, "--token-stdin"})
	if err == nil || !strings.Contains(err.Error(), "no token provided") {
		t.Fatalf("error = %v", err)
	}

	// Without any token flag the token is read from the (non-TTY) stdin.
	withStdin(t, "\n")
	err = cmdLogin([]string{"--host", ts.URL})
	if err == nil || !strings.Contains(err.Error(), "no token provided") {
		t.Fatalf("error = %v", err)
	}
}

func TestCmdLoginTokenFlagWarns(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[]}`)
	withStdin(t, "")
	stderr, err := captureStderr(t, func() error {
		_, e := captureStdout(t, func() error { return cmdLogin([]string{"--host", ts.URL, "--token", "flag-tok"}) })
		return e
	})
	if err != nil || !strings.Contains(stderr, "--token is exposed") {
		t.Fatalf("stderr=%q err=%v", stderr, err)
	}
}

func TestCmdLoginTokenFileReadAndSaveErrors(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[]}`)
	withStdin(t, "")
	if err := cmdLogin([]string{"--host", ts.URL, "--token-file", filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("expected a token file error")
	}

	breakSaveConfig(t)
	err := cmdLogin([]string{"--host", ts.URL, "--token", "t"})
	if err == nil {
		t.Fatal("expected a save error")
	}
}

func TestCmdLoginContinuesWhenDiscoveryFailsInTokenMode(t *testing.T) {
	setTestConfigHome(t)
	withStdin(t, "")
	host := closedServerURL(t)
	if _, err := captureStdout(t, func() error { return cmdLogin([]string{"--host", host, "--token", "t"}) }); err != nil {
		t.Fatalf("cmdLogin: %v", err)
	}
}

func TestCmdLoginReportsInteractiveTokenReadError(t *testing.T) {
	setTestConfigHome(t)
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	old := os.Stdin
	os.Stdin = dir
	defer func() { os.Stdin = old }()
	if err := cmdLogin([]string{"--host", closedServerURL(t)}); err == nil {
		t.Fatal("expected a stdin read error")
	}
}
