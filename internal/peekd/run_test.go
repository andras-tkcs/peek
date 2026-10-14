package peekd

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
	"github.com/andras-tkcs/peek/internal/uploadquota"
)

func TestHealthcheckURL(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "bare port", addr: ":7700", want: "http://localhost:7700/healthz"},
		{name: "host port", addr: "127.0.0.1:7700", want: "http://127.0.0.1:7700/healthz"},
		{name: "http url", addr: "http://example.test:7700/", want: "http://example.test:7700/healthz"},
		{name: "https url", addr: "https://peek.example.com", want: "https://peek.example.com/healthz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := healthcheckURL(tt.addr); got != tt.want {
				t.Fatalf("healthcheckURL(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestRunHealthcheckReturnsSuccessForHealthyServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if got := runHealthcheck([]string{"--addr", ts.URL}); got != 0 {
		t.Fatalf("runHealthcheck = %d, want 0", got)
	}
}

func TestRunHealthcheckReturnsFailureForUnhealthyServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	if got := runHealthcheck([]string{"--addr", ts.URL}); got != 1 {
		t.Fatalf("runHealthcheck = %d, want 1", got)
	}
}

func TestRunHealthcheckReturnsUsageForBadArgs(t *testing.T) {
	if got := runHealthcheck([]string{"--bad"}); got != 2 {
		t.Fatalf("runHealthcheck = %d, want 2", got)
	}
}

func TestBackupArgs(t *testing.T) {
	dir := t.TempDir()
	dataDir, backupPath, err := backupArgs([]string{"--data", dir})
	if err != nil {
		t.Fatalf("backupArgs: %v", err)
	}
	if dataDir != dir {
		t.Fatalf("dataDir = %q, want %q", dataDir, dir)
	}
	if backupPath != filepath.Join(dir, "peek-backup.db") {
		t.Fatalf("backupPath = %q", backupPath)
	}

	custom := filepath.Join(t.TempDir(), "custom.db")
	_, backupPath, err = backupArgs([]string{"--data", dir, custom})
	if err != nil {
		t.Fatalf("backupArgs custom: %v", err)
	}
	if backupPath != custom {
		t.Fatalf("backupPath = %q, want %q", backupPath, custom)
	}
}

func TestBackupArgsRejectsExtraArgs(t *testing.T) {
	if _, _, err := backupArgs([]string{"one.db", "two.db"}); err == nil {
		t.Fatal("expected extra backup args to fail")
	}
}

func TestBackupDatabaseCreatesRestorableSnapshot(t *testing.T) {
	dataDir := t.TempDir()
	source, err := db.Open(filepath.Join(dataDir, "peek.db"))
	if err != nil {
		t.Fatalf("open source store: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if err := source.CreateToken(context.Background(), "admin-token", "admin", true, 0); err != nil {
		t.Fatalf("seed source token: %v", err)
	}
	token, err := source.GetToken(context.Background(), "admin-token")
	if err != nil {
		t.Fatalf("get source token: %v", err)
	}
	if err := source.CreateUploadChecked(context.Background(), "snapshot-page", token.AccountID, token.ID, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatalf("seed source upload: %v", err)
	}

	backupPath := filepath.Join(t.TempDir(), "peek-backup.db")
	if err := backupDatabase(dataDir, backupPath); err != nil {
		t.Fatalf("backupDatabase: %v", err)
	}
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("backup is empty")
	}

	backup, err := db.Open(backupPath)
	if err != nil {
		t.Fatalf("open backup store: %v", err)
	}
	defer backup.Close()
	if got, err := backup.GetToken(context.Background(), "admin-token"); err != nil || got.Name != "admin" || !got.IsAdmin {
		t.Fatalf("backup token = %+v, err=%v", got, err)
	}
	if got, err := backup.GetUpload(context.Background(), "snapshot-page"); err != nil || got.Name != "page.html" || got.Size != 42 {
		t.Fatalf("backup upload = %+v, err=%v", got, err)
	}
}

func TestParseServeConfigMapsFlagsAndEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PEEK_ADDR", ":8800")
	t.Setenv("PEEK_S3_REGION", "auto")
	t.Setenv("PEEK_TRUSTED_PROXY", "true")
	t.Setenv("PEEK_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.0.2.7")

	cfg, showVersion, err := parseServeConfig([]string{
		"--data", dir,
		"--base-url", "https://peek.example.test",
		"--max-upload", "12345",
		"--storage", "s3",
		"--s3-endpoint", "https://s3.example.test",
		"--s3-bucket", "peek",
		"--s3-access-key", "access",
		"--s3-secret-key", "secret",
		"--s3-allow-private-endpoint",
		"--oidc-allow-private-issuer",
		"--max-total-size", "999",
		"--retention-days", "7",
	})
	if err != nil {
		t.Fatalf("parseServeConfig: %v", err)
	}
	if showVersion {
		t.Fatal("showVersion = true")
	}
	if cfg.Addr != ":8800" || cfg.DataDir != dir || cfg.BaseURL != "https://peek.example.test" {
		t.Fatalf("basic config = %+v", cfg)
	}
	if cfg.MaxUpload != 12345 || cfg.MaxTotalSize != 999 || cfg.RetentionDays != 7 {
		t.Fatalf("limits = %+v", cfg)
	}
	if cfg.Storage != "s3" || cfg.S3Endpoint != "https://s3.example.test" || cfg.S3Bucket != "peek" {
		t.Fatalf("s3 config = %+v", cfg)
	}
	if cfg.S3Region != "auto" || cfg.S3AccessKey != "access" || cfg.S3SecretKey != "secret" || !cfg.S3AllowPrivateEndpoint {
		t.Fatalf("s3 credentials/config = %+v", cfg)
	}
	if !cfg.OIDCAllowPrivateIssuer {
		t.Fatal("OIDCAllowPrivateIssuer = false")
	}
	if !cfg.TrustedProxy {
		t.Fatal("TrustedProxy = false")
	}
	if len(cfg.TrustedProxyCIDRs) != 2 || cfg.TrustedProxyCIDRs[1].String() != "192.0.2.7/32" {
		t.Fatalf("TrustedProxyCIDRs = %v", cfg.TrustedProxyCIDRs)
	}
}

func TestParseServeConfigDefaultsTrustedProxyCIDRsToLoopback(t *testing.T) {
	t.Setenv("PEEK_TRUSTED_PROXY_CIDRS", "")
	cfg, _, err := parseServeConfig([]string{"--data", t.TempDir()})
	if err != nil {
		t.Fatalf("parseServeConfig: %v", err)
	}
	var got []string
	for _, p := range cfg.TrustedProxyCIDRs {
		got = append(got, p.String())
	}
	if len(got) != 2 || got[0] != "127.0.0.0/8" || got[1] != "::1/128" {
		t.Fatalf("TrustedProxyCIDRs = %v", got)
	}
}

func TestParseServeConfigRejectsInvalidTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("PEEK_TRUSTED_PROXY_CIDRS", "10.0.0.0/33")
	_, _, err := parseServeConfig([]string{"--data", t.TempDir()})
	want := `trusted-proxy-cidrs: invalid trusted proxy CIDR "10.0.0.0/33"`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want containing %q", err, want)
	}
}

func TestParseServeConfigRejectsEmptyTrustedProxyCIDRs(t *testing.T) {
	_, _, err := parseServeConfig([]string{"--data", t.TempDir(), "--trusted-proxy", "--trusted-proxy-cidrs", ""})
	want := "trusted-proxy-cidrs must list at least one CIDR when trusted-proxy is set"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want containing %q", err, want)
	}
}

func TestParseServeConfigRejectsInvalidIntegerEnv(t *testing.T) {
	t.Setenv("PEEK_MAX_UPLOAD", "two-mib")

	_, _, err := parseServeConfig(nil)
	if err == nil || err.Error() != "PEEK_MAX_UPLOAD must be an integer" {
		t.Fatalf("error = %v", err)
	}
}

func TestParseServeConfigRejectsInvalidBoolEnv(t *testing.T) {
	t.Setenv("PEEK_TRUSTED_PROXY", "maybe")

	_, _, err := parseServeConfig(nil)
	if err == nil || err.Error() != "PEEK_TRUSTED_PROXY must be a boolean" {
		t.Fatalf("error = %v", err)
	}
}

func TestParseServeConfigAcceptsCaseInsensitiveBoolEnv(t *testing.T) {
	t.Setenv("PEEK_TRUSTED_PROXY", "ON")
	t.Setenv("PEEK_S3_ALLOW_PRIVATE_ENDPOINT", "Yes")
	t.Setenv("PEEK_OIDC_ALLOW_PRIVATE_ISSUER", "true")

	cfg, showVersion, err := parseServeConfig([]string{"--data", t.TempDir()})
	if err != nil {
		t.Fatalf("parseServeConfig: %v", err)
	}
	if showVersion {
		t.Fatal("showVersion = true")
	}
	if !cfg.TrustedProxy || !cfg.S3AllowPrivateEndpoint || !cfg.OIDCAllowPrivateIssuer {
		t.Fatalf("bool config = %+v", cfg)
	}
}

func TestParseServeConfigRejectsInvalidOperationalConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "relative base url",
			args: []string{"--base-url", "localhost:7700"},
			want: "base-url must be an absolute http or https URL",
		},
		{
			name: "unsupported base url scheme",
			args: []string{"--base-url", "ftp://peek.example.test"},
			want: "base-url must use http or https",
		},
		{
			name: "zero upload limit",
			args: []string{"--max-upload", "0"},
			want: "max-upload must be greater than zero",
		},
		{
			name: "negative total quota",
			args: []string{"--max-total-size", "-1"},
			want: "max-total-size must be zero or greater",
		},
		{
			name: "negative retention",
			args: []string{"--retention-days", "-1"},
			want: "retention-days must be zero or greater",
		},
		{
			name: "unknown storage backend",
			args: []string{"--storage", "postgres"},
			want: "storage must be file or s3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"--data", t.TempDir()}, tt.args...)
			_, _, err := parseServeConfig(args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseServeConfigGoogleFlagsMustBeSetTogether(t *testing.T) {
	for _, args := range [][]string{
		{"--google-sa-key-file", "/tmp/key.json"},
		{"--google-admin-email", "admin@example.com"},
	} {
		_, _, err := parseServeConfig(args)
		if err == nil || err.Error() != "PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL must be set together" {
			t.Fatalf("args %v: err = %v", args, err)
		}
	}
	cfg, _, err := parseServeConfig([]string{"--google-sa-key-file", "/tmp/key.json", "--google-admin-email", "admin@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GoogleSAKeyFile != "/tmp/key.json" || cfg.GoogleAdminEmail != "admin@example.com" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestParseServeConfigGoogleCacheTTLBounds(t *testing.T) {
	for _, ttl := range []string{"500ms", "2h"} {
		_, _, err := parseServeConfig([]string{"--google-group-cache-ttl", ttl})
		if err == nil || err.Error() != "google group cache ttl must be between 1s and 1h" {
			t.Fatalf("ttl %s: err = %v", ttl, err)
		}
	}
	if _, _, err := parseServeConfig([]string{"--google-group-cache-ttl", "1s"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PEEK_GOOGLE_GROUP_CACHE_TTL", "nonsense")
	_, _, err := parseServeConfig(nil)
	if err == nil || !strings.HasPrefix(err.Error(), "invalid PEEK_GOOGLE_GROUP_CACHE_TTL: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseServeConfigGoogleDefaults(t *testing.T) {
	cfg, _, err := parseServeConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GoogleSAKeyFile != "" || cfg.GoogleAdminEmail != "" || cfg.GoogleGroupCacheTTL != 5*time.Minute {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestParseServeConfigMetricsTokenFromEnv(t *testing.T) {
	token := strings.Repeat("x", 16)
	t.Setenv("PEEK_METRICS_TOKEN", token)
	cfg, _, err := parseServeConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MetricsToken != token {
		t.Fatalf("MetricsToken = %q", cfg.MetricsToken)
	}
}

func TestParseServeConfigRejectsShortMetricsToken(t *testing.T) {
	t.Setenv("PEEK_METRICS_TOKEN", "")
	_, _, err := parseServeConfig([]string{"--metrics-token", "short"})
	if err == nil || !strings.Contains(err.Error(), "at least 16 characters") {
		t.Fatalf("error = %v", err)
	}
}

func writeSecretFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGetenvSecretReadsFile(t *testing.T) {
	t.Setenv("PEEK_SECRET", "")
	t.Setenv("PEEK_SECRET_FILE", writeSecretFile(t, "s3cr3t\n"))
	cfg, _, err := parseServeConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Secret != "s3cr3t" {
		t.Fatalf("Secret = %q", cfg.Secret)
	}
}

func TestGetenvSecretRejectsBothVarAndFile(t *testing.T) {
	t.Setenv("PEEK_SECRET", "direct")
	t.Setenv("PEEK_SECRET_FILE", writeSecretFile(t, "s3cr3t"))
	_, _, err := parseServeConfig(nil)
	if err == nil || !strings.Contains(err.Error(), "set only one of PEEK_SECRET and PEEK_SECRET_FILE") {
		t.Fatalf("error = %v", err)
	}
}

func TestGetenvSecretRejectsEmptyFile(t *testing.T) {
	t.Setenv("PEEK_SECRET", "")
	t.Setenv("PEEK_SECRET_FILE", writeSecretFile(t, " \n"))
	_, _, err := parseServeConfig(nil)
	if err == nil || !strings.Contains(err.Error(), "points to an empty file") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseServeConfigS3SecretKeyFromFile(t *testing.T) {
	t.Setenv("PEEK_S3_SECRET_KEY", "")
	t.Setenv("PEEK_S3_SECRET_KEY_FILE", writeSecretFile(t, "key123\n"))
	cfg, _, err := parseServeConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.S3SecretKey != "key123" {
		t.Fatalf("S3SecretKey = %q", cfg.S3SecretKey)
	}
}

func TestSecretFlagWarnings(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("secret", "", "")
	fs.String("s3-secret-key", "", "")
	fs.String("addr", "", "")
	if err := fs.Parse([]string{"--secret", "x", "--addr", ":1"}); err != nil {
		t.Fatal(err)
	}
	got := secretFlagWarnings(fs)
	if len(got) != 1 || !strings.Contains(got[0], "--secret") || !strings.Contains(got[0], "PEEK_SECRET_FILE") {
		t.Fatalf("warnings = %v", got)
	}
}

func TestRunVersionReturnsZero(t *testing.T) {
	if got := Run([]string{"--version"}); got != 0 {
		t.Fatalf("Run --version = %d, want 0", got)
	}
}

func TestRunUnknownFlagReturnsUsageError(t *testing.T) {
	if got := Run([]string{"--nope"}); got != 2 {
		t.Fatalf("Run --nope = %d, want 2", got)
	}
}

func TestRunDispatchesHealthcheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	if got := Run([]string{"healthcheck", "--addr", ts.URL}); got != 0 {
		t.Fatalf("Run healthcheck = %d, want 0", got)
	}
}

func TestRunDispatchesBackup(t *testing.T) {
	dataDir := seedBackupSource(t)
	dest := filepath.Join(t.TempDir(), "snap.db")
	if got := Run([]string{"backup", "--data", dataDir, dest}); got != 0 {
		t.Fatalf("Run backup = %d, want 0", got)
	}
}

func TestParseServeConfigRejectsEveryBadEnvSource(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"s3 secret file", map[string]string{"PEEK_S3_SECRET_KEY_FILE": missing}, "PEEK_S3_SECRET_KEY_FILE"},
		{"metrics token file", map[string]string{"PEEK_METRICS_TOKEN_FILE": missing}, "PEEK_METRICS_TOKEN_FILE"},
		{"secret file", map[string]string{"PEEK_SECRET_FILE": missing}, "PEEK_SECRET_FILE"},
		{"s3 private endpoint", map[string]string{"PEEK_S3_ALLOW_PRIVATE_ENDPOINT": "maybe"}, "PEEK_S3_ALLOW_PRIVATE_ENDPOINT must be a boolean"},
		{"oidc private issuer", map[string]string{"PEEK_OIDC_ALLOW_PRIVATE_ISSUER": "maybe"}, "PEEK_OIDC_ALLOW_PRIVATE_ISSUER must be a boolean"},
		{"max total size", map[string]string{"PEEK_MAX_TOTAL_SIZE": "lots"}, "PEEK_MAX_TOTAL_SIZE must be an integer"},
		{"retention days", map[string]string{"PEEK_RETENTION_DAYS": "forever"}, "PEEK_RETENTION_DAYS must be an integer"},
		{"google ttl", map[string]string{"PEEK_GOOGLE_GROUP_CACHE_TTL": "soon"}, "invalid PEEK_GOOGLE_GROUP_CACHE_TTL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, _, err := parseServeConfig(nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseServeConfigRejectsUnknownFlag(t *testing.T) {
	if _, _, err := parseServeConfig([]string{"--nope"}); err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestParseServeConfigVersionFlag(t *testing.T) {
	_, showVersion, err := parseServeConfig([]string{"--version"})
	if err != nil || !showVersion {
		t.Fatalf("showVersion = %v, err = %v", showVersion, err)
	}
}

func TestParseServeConfigAcceptsMetricsTokenFlag(t *testing.T) {
	cfg, _, err := parseServeConfig([]string{"--data", t.TempDir(), "--metrics-token", "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MetricsToken != "0123456789abcdef" {
		t.Fatalf("MetricsToken = %q", cfg.MetricsToken)
	}
}
