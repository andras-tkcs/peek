package cli

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/privacyfence/peek/internal/db"
	"github.com/privacyfence/peek/internal/server"
)

// TestCLIAgainstRealServer runs the CLI against a real in-process server so
// that a JSON field renamed on one side and not the other fails here.
func TestCLIAgainstRealServer(t *testing.T) {
	dir := t.TempDir()
	store, err := db.Open(filepath.Join(dir, "peek.db"))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	if err := store.CreateToken(context.Background(), "contract-admin-token", "admin", true, 0); err != nil {
		t.Fatalf("seed admin token: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close test store: %v", err)
	}
	srv, err := server.New(server.Config{
		DataDir:   dir,
		BaseURL:   "http://localhost:7700",
		Secret:    strings.Repeat("ab", 32),
		MaxUpload: 10 << 20,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	setTestConfigHome(t)
	t.Setenv("PEEK_HOST", ts.URL)
	t.Setenv("PEEK_TOKEN", "contract-admin-token")

	page := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(page, []byte(`<html><body><p id="t">contract</p></body></html>`), 0o600); err != nil {
		t.Fatalf("write page: %v", err)
	}

	run := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := runCaptured(t, args...)
		if code != 0 {
			t.Fatalf("peek %s exited %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), code, stdout, stderr)
		}
		return stdout
	}
	mustContain := func(step, out string, wants ...string) {
		t.Helper()
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Fatalf("%s: stdout missing %q:\n%s", step, want, out)
			}
		}
	}

	out := run("upload", page, "--visibility", "public", "--name", "Contract")
	mustContain("upload", out, "uploaded: http://localhost:7700/p/", "version:  1", "visibility: public")
	m := regexp.MustCompile(`(?m)^\s*slug:\s+(\S+)\s*$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("upload: no slug line in stdout:\n%s", out)
	}
	slug := m[1]

	out = run("upload", page, "--slug", slug)
	mustContain("re-upload", out, "version url: http://localhost:7700/p/"+slug+"/v/2")

	out = run("list")
	found := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, slug) && strings.Contains(line, "public") && strings.Contains(line, "Contract") {
			found = true
		}
	}
	if !found {
		t.Fatalf("list: no line with slug, public and Contract:\n%s", out)
	}

	out = run("stats", slug)
	mustContain("stats", out, "slug:            "+slug, "name:            Contract", "total visits:")

	out = run("grants", slug)
	mustContain("grants", out, "no grants")

	out = run("delete", slug)
	mustContain("delete", out, "deleted: "+slug)

	out = run("list")
	if strings.TrimSpace(out) != "no uploads yet." {
		t.Fatalf("list after delete = %q, want %q", out, "no uploads yet.")
	}
}
