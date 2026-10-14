package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdConfigUsageAndUnknownSubcommand(t *testing.T) {
	setTestConfigHome(t)
	if err := cmdConfig(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("no args error = %v", err)
	}
	if err := cmdConfig([]string{"bogus"}); err == nil || !strings.Contains(err.Error(), "unknown config subcommand") {
		t.Fatalf("unknown error = %v", err)
	}
	if err := cmdConfig([]string{"show", "extra"}); err == nil || !strings.Contains(err.Error(), "usage: peek config show") {
		t.Fatalf("show extra error = %v", err)
	}
}

func TestCmdConfigShowReportsConfigLoadFailure(t *testing.T) {
	setTestConfigHome(t)
	writeBadConfig(t)
	if err := cmdConfig([]string{"show"}); err == nil {
		t.Fatal("expected a config load error")
	}
	if err := cmdConfig([]string{"set", "--host", "http://x"}); err == nil {
		t.Fatal("expected a config load error from set")
	}
}

func writeBadConfig(t *testing.T) {
	t.Helper()
	p, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSetFlagErrors(t *testing.T) {
	setTestConfigHome(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--host"}, "--host requires a value"},
		{[]string{"--token"}, "--token requires a value"},
		{[]string{"--token-file"}, "--token-file requires a value"},
		{[]string{"--bogus"}, "unknown flag"},
		{[]string{"--token", "a", "--token-stdin"}, "use only one of"},
		{[]string{"--token", "a"}, "--host is required"},
		{nil, "--host is required"},
	}
	for _, tc := range cases {
		err := configSet(tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("configSet(%v) = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestConfigSetTokenFile(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[]}`)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(" file-token \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error { return configSet([]string{"--host", ts.URL, "--token-file", tokenFile}) }); err != nil {
		t.Fatalf("configSet: %v", err)
	}
	cfg, _ := LoadConfig()
	if cfg.Host != ts.URL || cfg.Token != "file-token" {
		t.Fatalf("cfg = %+v", cfg)
	}

	err := configSet([]string{"--host", ts.URL, "--token-file", filepath.Join(t.TempDir(), "nope")})
	if err == nil {
		t.Fatal("expected a token file read error")
	}
}

func TestConfigSetTokenStdin(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[]}`)
	withStdin(t, "stdin-token\n")
	if _, err := captureStdout(t, func() error { return configSet([]string{"--host", ts.URL, "--token-stdin"}) }); err != nil {
		t.Fatalf("configSet: %v", err)
	}
	cfg, _ := LoadConfig()
	if cfg.Token != "stdin-token" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestConfigSetTokenStdinReadError(t *testing.T) {
	setTestConfigHome(t)
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	old := os.Stdin
	os.Stdin = dir
	defer func() { os.Stdin = old }()
	if err := configSet([]string{"--host", "http://x", "--token-stdin"}); err == nil {
		t.Fatal("expected a stdin read error")
	}
}

func TestConfigSetTokenFlagWarnsAndSaves(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[]}`)
	var out string
	stderr, err := captureStderr(t, func() error {
		var e error
		out, e = captureStdout(t, func() error { return configSet([]string{"--host", ts.URL, "--token", "flag-token"}) })
		return e
	})
	if err != nil {
		t.Fatalf("configSet: %v", err)
	}
	if !strings.Contains(stderr, "--token is exposed") || !strings.Contains(out, "saved.") {
		t.Fatalf("stderr=%q stdout=%q", stderr, out)
	}
}

func TestConfigSetRejectsTokenWhenServerRequiresOAuth(t *testing.T) {
	setTestConfigHome(t)
	ts := jsonServer(t, 200, `{"providers":[{"key":"oidc"}]}`)
	err := configSet([]string{"--host", ts.URL, "--token", "t"})
	if err == nil || !strings.Contains(err.Error(), "requires OAuth browser login") {
		t.Fatalf("error = %v", err)
	}
	if cfg, _ := LoadConfig(); cfg.Token != "" {
		t.Fatalf("token saved despite OAuth requirement: %+v", cfg)
	}
}

func TestConfigSetSaveFailure(t *testing.T) {
	setTestConfigHome(t)
	breakSaveConfig(t)
	if err := configSet([]string{"--host", "http://x.example"}); err == nil {
		t.Fatal("expected a save error")
	}
}

func TestConfigShowPrintsHostAndMaskedToken(t *testing.T) {
	setTestConfigHome(t)
	if err := SaveConfig(&Config{Host: "http://h.example", Token: "abcdefghijklmnop"}); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error { return cmdConfig([]string{"show"}) })
	if err != nil || !strings.Contains(out, "host:  http://h.example") || strings.Contains(out, "abcdefghijklmnop") {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func seedConfig(t *testing.T, host, token string) {
	t.Helper()
	setTestConfigHome(t)
	t.Setenv("PEEK_HOST", "")
	t.Setenv("PEEK_TOKEN", "")
	if err := SaveConfig(&Config{Host: host, Token: token}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSetHostChangeClearsSavedToken(t *testing.T) {
	seedConfig(t, "https://old.example.com", "old-token")
	stderr, err := captureStderr(t, func() error {
		_, err := captureStdout(t, func() error { return configSet([]string{"--host", "https://new.example.com"}) })
		return err
	})
	if err != nil {
		t.Fatalf("configSet: %v", err)
	}
	cfg, _ := LoadConfig()
	if cfg.Host != "https://new.example.com" || cfg.Token != "" {
		t.Fatalf("config = %+v", cfg)
	}
	if !strings.Contains(stderr, "saved token was cleared") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestConfigSetSameHostKeepsToken(t *testing.T) {
	seedConfig(t, "https://old.example.com", "old-token")
	_, err := captureStdout(t, func() error { return configSet([]string{"--host", "https://old.example.com/"}) })
	if err != nil {
		t.Fatalf("configSet: %v", err)
	}
	cfg, _ := LoadConfig()
	if cfg.Token != "old-token" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestConfigSetWarnsForPlainHTTPHost(t *testing.T) {
	seedConfig(t, "", "")
	stderr, err := captureStderr(t, func() error {
		_, err := captureStdout(t, func() error { return configSet([]string{"--host", "http://peek.internal:7700"}) })
		return err
	})
	if err != nil {
		t.Fatalf("configSet: %v", err)
	}
	if !strings.Contains(stderr, "plain http://") {
		t.Fatalf("stderr = %q", stderr)
	}
}
