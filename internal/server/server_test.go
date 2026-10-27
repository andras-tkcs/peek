package server

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/db"
	"github.com/privacyfence/peek/internal/objectstore"
)

type admGroupStub struct{}

func (admGroupStub) IsMember(context.Context, string, string) (bool, error) { return true, nil }

func TestNewConfigFailures(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, dir string) Config
		wantErr string
	}{
		{
			name: "data dir is a regular file",
			prepare: func(t *testing.T, dir string) Config {
				file := filepath.Join(dir, "file")
				if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return Config{DataDir: file, BaseURL: "http://localhost:7700"}
			},
		},
		{
			name: "s3 without bucket",
			prepare: func(t *testing.T, dir string) Config {
				return Config{DataDir: dir, BaseURL: "http://localhost:7700", Storage: "s3", S3Endpoint: "https://8.8.8.8"}
			},
			wantErr: "s3 storage requires",
		},
		{
			name: "secret file unreadable",
			prepare: func(t *testing.T, dir string) Config {
				// A directory named secret.key makes the read fail with something other than not-exist.
				if err := os.Mkdir(filepath.Join(dir, "secret.key"), 0o700); err != nil {
					t.Fatal(err)
				}
				return Config{DataDir: dir, BaseURL: "http://localhost:7700"}
			},
			wantErr: "read secret",
		},
		{
			name: "database path is a directory",
			prepare: func(t *testing.T, dir string) Config {
				if err := os.Mkdir(filepath.Join(dir, "peek.db"), 0o700); err != nil {
					t.Fatal(err)
				}
				return Config{DataDir: dir, BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32)}
			},
		},
		{
			name: "seeded s3 endpoint is private",
			prepare: func(t *testing.T, dir string) Config {
				admSeedSettings(t, dir, map[string]string{"storage": "s3", "s3_endpoint": "http://127.0.0.1:9"})
				return Config{DataDir: dir, BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32), Storage: "s3", S3Bucket: "bucket", S3Endpoint: "https://8.8.8.8"}
			},
			wantErr: "S3 endpoint",
		},
		{
			name: "seeded s3 bucket is invalid",
			prepare: func(t *testing.T, dir string) Config {
				admSeedSettings(t, dir, map[string]string{"storage": "s3", "s3_bucket": "Not_A_Bucket!"})
				return Config{DataDir: dir, BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32), Storage: "s3", S3Bucket: "bucket", S3Endpoint: "https://8.8.8.8"}
			},
			wantErr: "invalid s3 bucket",
		},
		{
			name: "setup code generation fails",
			prepare: func(t *testing.T, dir string) Config {
				stubSecureRandomRead(t, func(b []byte) (int, error) {
					if len(b) == 24 { // the setup code
						return 0, errors.New("rand down")
					}
					return rand.Read(b)
				})
				return Config{DataDir: dir, BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32)}
			},
			wantErr: "rand down",
		},
		{
			name: "uploads path is a regular file",
			prepare: func(t *testing.T, dir string) Config {
				if err := os.WriteFile(filepath.Join(dir, "uploads"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return Config{DataDir: dir, BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32)}
			},
		},
		{
			name: "settings table is unusable",
			prepare: func(t *testing.T, dir string) Config {
				store, err := db.Open(filepath.Join(dir, "peek.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				addFailTrigger(t, store, "settings", "INSERT")
				return Config{DataDir: dir, BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32)}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.prepare(t, t.TempDir())
			s, err := New(cfg)
			if err == nil {
				_ = s.Close()
				t.Fatal("New succeeded, want an error")
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func admSeedSettings(t *testing.T, dir string, settings map[string]string) {
	t.Helper()
	store, err := db.Open(filepath.Join(dir, "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for k, v := range settings {
		if err := store.SetSetting(context.Background(), k, v); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewConfigSuccesses(t *testing.T) {
	t.Run("generates secret.key when no secret is given", func(t *testing.T) {
		dir := t.TempDir()
		s, err := New(Config{DataDir: dir, BaseURL: "http://localhost:7700"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if b, err := os.ReadFile(filepath.Join(dir, "secret.key")); err != nil || string(b) != s.secret {
			t.Fatalf("secret.key = %q, err = %v, want %q", b, err, s.secret)
		}
	})

	t.Run("s3 storage with a public endpoint", func(t *testing.T) {
		s, err := New(Config{DataDir: t.TempDir(), BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32), Storage: "s3", S3Bucket: "bucket", S3Endpoint: "https://8.8.8.8"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if _, ok := s.storage.(*objectstore.S3Storage); !ok {
			t.Fatalf("storage = %T, want *objectstore.S3Storage", s.storage)
		}
	})

	t.Run("blank storage setting falls back to the configured backend", func(t *testing.T) {
		dir := t.TempDir()
		admSeedSettings(t, dir, map[string]string{"storage": ""})
		s, err := New(Config{DataDir: dir, BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if _, ok := s.storage.(*objectstore.FileStorage); !ok {
			t.Fatalf("storage = %T, want *objectstore.FileStorage", s.storage)
		}
	})

	t.Run("s3 storage reads its settings through the store", func(t *testing.T) {
		s, err := New(Config{DataDir: t.TempDir(), BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32), Storage: "s3", S3Bucket: "bucket", S3Endpoint: "http://127.0.0.1:1", S3AllowPrivateEndpoint: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if rc, err := s.storage.Open(ctx, "slug"); err == nil {
			rc.Close()
			t.Fatal("Open succeeded against a closed port")
		}
	})

	t.Run("public https base url with groups and default proxy cidrs", func(t *testing.T) {
		s, err := New(Config{DataDir: t.TempDir(), BaseURL: "https://peek.example.com/", Secret: strings.Repeat("ab", 32), TrustedProxy: true, Groups: admGroupStub{}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if !s.secure || s.baseURL != "https://peek.example.com" || s.groups == nil || len(s.trustedProxyCIDRs) == 0 {
			t.Fatalf("server = secure:%v base:%q groups:%v cidrs:%v", s.secure, s.baseURL, s.groups, s.trustedProxyCIDRs)
		}
	})

	t.Run("plain http public base url without trusted proxy", func(t *testing.T) {
		s, err := New(Config{DataDir: t.TempDir(), BaseURL: "http://peek.example.com", Secret: strings.Repeat("ab", 32)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if s.secure || s.trustedProxy {
			t.Fatalf("secure=%v trustedProxy=%v, want both false", s.secure, s.trustedProxy)
		}
	})

	t.Run("explicit trusted proxy cidrs", func(t *testing.T) {
		cidr := netip.MustParsePrefix("10.1.0.0/16")
		s, err := New(Config{DataDir: t.TempDir(), BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32), TrustedProxy: true, TrustedProxyCIDRs: []netip.Prefix{cidr}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if len(s.trustedProxyCIDRs) != 1 || s.trustedProxyCIDRs[0] != cidr {
			t.Fatalf("cidrs = %v", s.trustedProxyCIDRs)
		}
	})
}
