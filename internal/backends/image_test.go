package backends

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateImageRef(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("a", 64)
	for _, ref := range []string{"alpine", "alpine:3.20", "ghcr.io/acme/app:1.2", "localhost:5000/x/y" + digest, "a/b__c-d.e"} {
		if err := ValidateImageRef(ref); err != nil {
			t.Errorf("ValidateImageRef(%q) = %v, want nil", ref, err)
		}
	}
	for _, ref := range []string{"", "Alpine", "a b", "ghcr.io/acme/app:", strings.Repeat("a", 256), "a@sha256:abc"} {
		err := ValidateImageRef(ref)
		if err == nil || err.Error() != "invalid image reference" {
			t.Errorf("ValidateImageRef(%q) = %v, want invalid image reference", ref, err)
		}
	}
}

func TestRepository(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("b", 64)
	for in, want := range map[string]string{
		"ghcr.io/acme/app:1.2":        "ghcr.io/acme/app",
		"localhost:5000/app":          "localhost:5000/app",
		"localhost:5000/app:2":        "localhost:5000/app",
		"alpine":                      "alpine",
		"ghcr.io/acme/app" + digest:   "ghcr.io/acme/app",
		"ghcr.io/acme/app:1" + digest: "ghcr.io/acme/app",
	} {
		if got := Repository(in); got != want {
			t.Errorf("Repository(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAllowedImages(t *testing.T) {
	got := ParseAllowedImages(" ghcr.io/acme/ ,\nlocal/app\r\n,, ")
	if len(got) != 2 || got[0] != "ghcr.io/acme/" || got[1] != "local/app" {
		t.Fatalf("got %q", got)
	}
	if len(ParseAllowedImages("")) != 0 {
		t.Fatal("empty setting should yield no entries")
	}
}

func TestImageAllowed(t *testing.T) {
	tests := []struct {
		ref     string
		allowed []string
		want    bool
	}{
		{"ghcr.io/acme/app:1", []string{"ghcr.io/acme/"}, true},
		{"ghcr.io/acme-evil/app", []string{"ghcr.io/acme/"}, false},
		{"ghcr.io/acme/app:2", []string{"ghcr.io/acme/app"}, true},
		{"ghcr.io/acme/app2", []string{"ghcr.io/acme/app"}, false},
		{"ghcr.io/acme/app", nil, false},
	}
	for _, tt := range tests {
		if got := ImageAllowed(tt.ref, tt.allowed); got != tt.want {
			t.Errorf("ImageAllowed(%q, %q) = %v, want %v", tt.ref, tt.allowed, got, tt.want)
		}
	}
}

func TestRegistryHost(t *testing.T) {
	for in, want := range map[string]string{
		"alpine":      "docker.io",
		"acme/app":    "docker.io",
		"ghcr.io/a/b": "ghcr.io",
		"localhost/x": "localhost",
		"host:5000/x": "host:5000",
	} {
		if got := RegistryHost(in); got != want {
			t.Errorf("RegistryHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistryAuth(t *testing.T) {
	if got := RegistryAuth("", "pw", "ghcr.io"); got != "" {
		t.Fatalf("empty username gave %q", got)
	}
	raw, err := base64.URLEncoding.DecodeString(RegistryAuth("bot", "pw", "ghcr.io"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["username"] != "bot" || got["password"] != "pw" || got["serveraddress"] != "ghcr.io" {
		t.Fatalf("decoded %v", got)
	}
}
