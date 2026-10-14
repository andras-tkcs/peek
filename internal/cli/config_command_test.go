package cli

import (
	"strings"
	"testing"
)

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
