package cli

import (
	"strings"
	"testing"
)

func TestOpenBrowserRefusesUnsafeURLs(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, raw := range []string{"-flag", "file:///etc/passwd", "ftp://x/y"} {
		if err := openBrowser(raw); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("openBrowser(%q) = %v, want refusal", raw, err)
		}
	}
}

func TestOpenBrowserFailsWhenNoOpenerIsInstalled(t *testing.T) {
	// An empty PATH guarantees no real browser is ever launched.
	t.Setenv("PATH", t.TempDir())
	if err := openBrowser("http://x"); err == nil {
		t.Fatal("openBrowser succeeded without an opener on PATH")
	}
}
