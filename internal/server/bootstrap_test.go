package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsLocalBaseURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "localhost", url: "http://localhost:7700", want: true},
		{name: "localhost trailing dot", url: "http://localhost.:7700", want: true},
		{name: "ipv4 loopback", url: "http://127.0.0.1:7700", want: true},
		{name: "ipv4 loopback range", url: "http://127.12.34.56:7700", want: true},
		{name: "ipv6 loopback", url: "http://[::1]:7700", want: true},
		{name: "https public", url: "https://peek.example.com", want: false},
		{name: "localhost suffix", url: "http://localhost.evil.test", want: false},
		{name: "loopback suffix", url: "http://127.0.0.1.example.test", want: false},
		{name: "private lan", url: "http://10.0.0.5:7700", want: false},
		{name: "invalid", url: "://bad", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalBaseURL(tt.url); got != tt.want {
				t.Fatalf("isLocalBaseURL(%q) = %t, want %t", tt.url, got, tt.want)
			}
		})
	}
}

func TestLoadOrCreateSecretReadsExistingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	want := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("secret = %q, want %q", got, want)
	}
}

func TestLoadOrCreateSecretPersistsGeneratedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")

	got, err := loadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("generated secret length = %d, want 64", len(got))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != got {
		t.Fatalf("stored secret = %q, want %q", string(b), got)
	}
}

func TestLoadOrCreateSecretReportsInvalidPath(t *testing.T) {
	dir := t.TempDir()

	if _, err := loadOrCreateSecret(dir); err == nil {
		t.Fatal("expected error when secret path is a directory")
	}
}

func TestLoadOrCreateSecretTightensExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	want := strings.Repeat("ab", 32)
	if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("secret = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestLoadOrCreateSecretFailures(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("parent is a regular file", func(t *testing.T) {
		_, err := loadOrCreateSecret(filepath.Join(file, "secret.key"))
		if err == nil || !strings.Contains(err.Error(), "read secret") {
			t.Fatalf("err = %v, want read secret error", err)
		}
	})
	t.Run("rand failure", func(t *testing.T) {
		stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand down") })
		_, err := loadOrCreateSecret(filepath.Join(dir, "rand.key"))
		if err == nil || !strings.Contains(err.Error(), "generate secret") {
			t.Fatalf("err = %v, want generate secret error", err)
		}
	})
	t.Run("write failure", func(t *testing.T) {
		_, err := loadOrCreateSecret(filepath.Join(dir, "missing-dir", "secret.key"))
		if err == nil || !strings.Contains(err.Error(), "write secret") {
			t.Fatalf("err = %v, want write secret error", err)
		}
	})
	t.Run("short existing secret is replaced", func(t *testing.T) {
		path := filepath.Join(dir, "short.key")
		if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadOrCreateSecret(path)
		if err != nil || len(got) != 64 {
			t.Fatalf("secret = %q, err = %v", got, err)
		}
	})
}

func TestBootstrapSetup(t *testing.T) {
	ctx := context.Background()

	t.Run("reuses an existing code file", func(t *testing.T) {
		_, store, _, _ := newFaultServer(t)
		if _, err := store.Exec("DELETE FROM accounts"); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(setupCodePath(dir), []byte("kept-code\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, err := bootstrapSetup(ctx, store, dir, "http://localhost:7700")
		if err != nil || code != "kept-code" {
			t.Fatalf("code = %q, err = %v", code, err)
		}
	})
	t.Run("random failure", func(t *testing.T) {
		_, store, _, _ := newFaultServer(t)
		if _, err := store.Exec("DELETE FROM accounts"); err != nil {
			t.Fatal(err)
		}
		stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand down") })
		if _, err := bootstrapSetup(ctx, store, t.TempDir(), "http://localhost:7700"); err == nil {
			t.Fatal("expected rand error")
		}
	})
	t.Run("write failure when data dir is a file", func(t *testing.T) {
		_, store, _, _ := newFaultServer(t)
		if _, err := store.Exec("DELETE FROM accounts"); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := bootstrapSetup(ctx, store, file, "http://localhost:7700"); err == nil {
			t.Fatal("expected write error")
		}
	})
	t.Run("count failure", func(t *testing.T) {
		_, store, _, _ := newFaultServer(t)
		dropTable(t, store, "accounts")
		if _, err := bootstrapSetup(ctx, store, t.TempDir(), "http://localhost:7700"); err == nil {
			t.Fatal("expected count error")
		}
	})
	t.Run("existing accounts remove a stale code", func(t *testing.T) {
		_, store, _, _ := newFaultServer(t)
		dir := t.TempDir()
		if err := os.WriteFile(setupCodePath(dir), []byte("stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, err := bootstrapSetup(ctx, store, dir, "http://localhost:7700")
		if err != nil || code != "" {
			t.Fatalf("code = %q, err = %v", code, err)
		}
		if _, err := os.Stat(setupCodePath(dir)); !os.IsNotExist(err) {
			t.Fatalf("stale code file still present: %v", err)
		}
	})
}

func TestSetupCodeValidation(t *testing.T) {
	ctx := context.Background()
	s, store, _, _ := newFaultServer(t)
	s.dataDir = t.TempDir()

	if got := s.readSetupCode(); got != "" {
		t.Fatalf("missing code file read as %q", got)
	}
	if err := os.WriteFile(setupCodePath(s.dataDir), []byte("code-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An account exists, so setup is not required and no code is valid.
	if s.validSetupCode(ctx, "code-1") {
		t.Fatal("code accepted although setup is not required")
	}

	if _, err := store.Exec("DELETE FROM accounts"); err != nil {
		t.Fatal(err)
	}
	if !s.validSetupCode(ctx, " code-1 ") {
		t.Fatal("matching code rejected")
	}
	if s.validSetupCode(ctx, "other") {
		t.Fatal("wrong code accepted")
	}
	s.clearSetupCode()
	if s.validSetupCode(ctx, "code-1") {
		t.Fatal("code accepted after the file was cleared")
	}

	dropTable(t, store, "accounts")
	if s.setupRequired(ctx) {
		t.Fatal("setupRequired should be false when the count fails")
	}
}
