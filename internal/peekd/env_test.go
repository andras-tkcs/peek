package peekd

import (
	"flag"
	"strings"
	"testing"
)

func TestGetenv(t *testing.T) {
	t.Setenv("PEEKD_TEST_SET", "value")
	t.Setenv("PEEKD_TEST_EMPTY", "")
	if got := getenv("PEEKD_TEST_SET", "fallback"); got != "value" {
		t.Fatalf("getenv set = %q", got)
	}
	if got := getenv("PEEKD_TEST_EMPTY", "fallback"); got != "fallback" {
		t.Fatalf("getenv empty = %q", got)
	}
}

func TestGetenvInt(t *testing.T) {
	t.Setenv("PEEKD_TEST_INT", " 42 ")
	if got, err := getenvInt("PEEKD_TEST_INT", 7); err != nil || got != 42 {
		t.Fatalf("getenvInt = %d, %v", got, err)
	}
	t.Setenv("PEEKD_TEST_INT", "")
	if got, err := getenvInt("PEEKD_TEST_INT", 7); err != nil || got != 7 {
		t.Fatalf("getenvInt default = %d, %v", got, err)
	}
	t.Setenv("PEEKD_TEST_INT", "forty")
	if _, err := getenvInt("PEEKD_TEST_INT", 7); err == nil || err.Error() != "PEEKD_TEST_INT must be an integer" {
		t.Fatalf("getenvInt error = %v", err)
	}
}

func TestGetenvInt64(t *testing.T) {
	t.Setenv("PEEKD_TEST_INT64", "9000000000")
	if got, err := getenvInt64("PEEKD_TEST_INT64", 1); err != nil || got != 9000000000 {
		t.Fatalf("getenvInt64 = %d, %v", got, err)
	}
	t.Setenv("PEEKD_TEST_INT64", "")
	if got, err := getenvInt64("PEEKD_TEST_INT64", 1); err != nil || got != 1 {
		t.Fatalf("getenvInt64 default = %d, %v", got, err)
	}
	t.Setenv("PEEKD_TEST_INT64", "1.5")
	if _, err := getenvInt64("PEEKD_TEST_INT64", 1); err == nil {
		t.Fatal("expected error for non-integer")
	}
}

func TestGetenvBool(t *testing.T) {
	tests := []struct {
		value   string
		want    bool
		wantErr bool
	}{
		{"", false, false},
		{"1", true, false},
		{"TRUE", true, false},
		{" yes ", true, false},
		{"on", true, false},
		{"0", false, false},
		{"False", false, false},
		{"no", false, false},
		{"OFF", false, false},
		{"maybe", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("PEEKD_TEST_BOOL", tt.value)
			got, err := getenvBool("PEEKD_TEST_BOOL")
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("getenvBool(%q) = %v, %v", tt.value, got, err)
			}
		})
	}
}

func TestGetenvSecretPrefersDirectValueWithoutFile(t *testing.T) {
	t.Setenv("PEEKD_TEST_SECRET", "direct")
	t.Setenv("PEEKD_TEST_SECRET_FILE", "")
	got, err := getenvSecret("PEEKD_TEST_SECRET")
	if err != nil || got != "direct" {
		t.Fatalf("getenvSecret = %q, %v", got, err)
	}
}

func TestGetenvSecretReportsUnreadableFile(t *testing.T) {
	t.Setenv("PEEKD_TEST_SECRET", "")
	t.Setenv("PEEKD_TEST_SECRET_FILE", t.TempDir()+"/missing")
	_, err := getenvSecret("PEEKD_TEST_SECRET")
	if err == nil || !strings.Contains(err.Error(), "read PEEKD_TEST_SECRET_FILE") {
		t.Fatalf("error = %v", err)
	}
}

func TestSecretFlagWarningsCoversAllSecretFlags(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("secret", "", "")
	fs.String("s3-secret-key", "", "")
	fs.String("metrics-token", "", "")
	if err := fs.Parse([]string{"--s3-secret-key", "a", "--metrics-token", "b"}); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(secretFlagWarnings(fs), "\n")
	for _, want := range []string{"PEEK_S3_SECRET_KEY_FILE", "PEEK_METRICS_TOKEN_FILE"} {
		if !strings.Contains(got, want) {
			t.Fatalf("warnings %q missing %s", got, want)
		}
	}
	if strings.Contains(got, "PEEK_SECRET_FILE") {
		t.Fatalf("unexpected --secret warning: %q", got)
	}
}

func TestSecretFlagWarningsSignInSecrets(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("google-client-secret", "", "")
	fs.String("oidc-client-secret", "", "")
	if err := fs.Parse([]string{"--google-client-secret", "a", "--oidc-client-secret", "b"}); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(secretFlagWarnings(fs), "\n")
	for _, want := range []string{"--google-client-secret", "PEEK_GOOGLE_CLIENT_SECRET_FILE", "--oidc-client-secret", "PEEK_OIDC_CLIENT_SECRET_FILE"} {
		if !strings.Contains(got, want) {
			t.Fatalf("warnings %q missing %s", got, want)
		}
	}
}
