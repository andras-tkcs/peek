package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSlugPathAcceptsServerSlugs(t *testing.T) {
	for _, s := range []string{"page", "q3-reorg-plan", "AbC_12-x"} {
		got, err := slugPath(s)
		if err != nil || got != s {
			t.Errorf("slugPath(%q) = %q, %v", s, got, err)
		}
	}
}

func TestSlugPathRejectsUnsafeSlugs(t *testing.T) {
	for _, s := range []string{"", "x/../../tokens/5", "..", "a b", "a%2f", "a?b", "a#b", "ü"} {
		if _, err := slugPath(s); err == nil || !strings.Contains(err.Error(), "invalid slug") {
			t.Errorf("slugPath(%q) err = %v, want invalid slug", s, err)
		}
	}
}

func TestTokenIDPath(t *testing.T) {
	if got, err := tokenIDPath("42"); err != nil || got != "42" {
		t.Fatalf("tokenIDPath(42) = %q, %v", got, err)
	}
	for _, s := range []string{"0", "-1", "5/../x", "abc", ""} {
		if _, err := tokenIDPath(s); err == nil || !strings.Contains(err.Error(), "invalid token id") {
			t.Errorf("tokenIDPath(%q) err = %v", s, err)
		}
	}
}

func TestCommandsRejectTraversalSlugBeforeRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)

	bad := "x/../../tokens/5"
	cases := map[string]func() error{
		"delete":     func() error { return cmdDelete([]string{bad}) },
		"versions":   func() error { return cmdVersions([]string{bad}) },
		"stats":      func() error { return cmdStats([]string{bad}) },
		"comments":   func() error { return cmdComments([]string{bad}) },
		"export":     func() error { return cmdExport([]string{bad}) },
		"grants":     func() error { return cmdGrants([]string{bad}) },
		"grant":      func() error { return cmdGrant([]string{bad, "a@example.test"}) },
		"revoke":     func() error { return cmdRevoke([]string{bad, "a@example.test"}) },
		"rename":     func() error { return cmdRename([]string{bad, "New name"}) },
		"visibility": func() error { return cmdVisibility([]string{bad, "public"}) },
	}
	for name, fn := range cases {
		if err := fn(); err == nil || !strings.Contains(err.Error(), "invalid slug") {
			t.Errorf("%s: err = %v, want invalid slug", name, err)
		}
	}
	if err := cmdToken([]string{"revoke", "5/../x"}); err == nil || !strings.Contains(err.Error(), "invalid token id") {
		t.Errorf("token revoke: err = %v", err)
	}
}
