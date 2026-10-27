package e2e

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	csrfRe   = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	apiKeyRe = regexp.MustCompile(`id="hn-api-key"[^>]*>(peek_[^<]+)<`)
	slugRe   = regexp.MustCompile(`(?m)^slug:\s+(\S+)`)
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestE2EBinaries(t *testing.T) {
	if os.Getenv("PEEK_E2E") != "1" {
		t.Skip("set PEEK_E2E=1 to run the end-to-end test of the built binaries")
	}

	root := moduleRoot(t)
	bin := t.TempDir()
	peekd := filepath.Join(bin, "peekd")
	peek := filepath.Join(bin, "peek")
	goBuild(t, root, peekd, "./cmd/peekd")
	goBuild(t, root, peek, "./cmd/peek")

	home := t.TempDir()
	data := t.TempDir()
	base := startPeekd(t, peekd, data)

	apiKey := setupAdminAndAPIKey(t, base, data)

	env := cliEnv(home)
	runCmd(t, env, apiKey+"\n", peek, "login", "--host", base, "--token-stdin")

	page := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(page, []byte(`<html><body><p id="t">e2e</p></body></html>`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runCmd(t, env, "", peek, "upload", page, "--visibility", "public", "--name", "e2e-page")
	m := slugRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no slug in upload output:\n%s", out)
	}
	slug := m[1]

	if out := runCmd(t, env, "", peek, "list"); !strings.Contains(out, slug) {
		t.Fatalf("list does not contain %q:\n%s", slug, out)
	}
	if out := runCmd(t, env, "", peek, "stats", slug); !strings.Contains(out, "total visits:") {
		t.Fatalf("stats output lacks %q:\n%s", "total visits:", out)
	}

	backup := filepath.Join(t.TempDir(), "backup.db")
	if out := runCmd(t, nil, "", peekd, "backup", "--data", data, backup); !strings.Contains(out, "backup written to") {
		t.Fatalf("backup output lacks %q:\n%s", "backup written to", out)
	}

	if out := runCmd(t, env, "", peek, "delete", slug); !strings.Contains(out, "deleted: "+slug) {
		t.Fatalf("delete output lacks %q:\n%s", "deleted: "+slug, out)
	}

	// Restore into a fresh data directory.
	data2 := t.TempDir()
	copyFile(t, backup, filepath.Join(data2, "peek.db"))
	copyFile(t, filepath.Join(data, "secret.key"), filepath.Join(data2, "secret.key"))
	copyTree(t, filepath.Join(data, "uploads"), filepath.Join(data2, "uploads"))
	base2 := startPeekd(t, peekd, data2)

	env2 := append(append([]string{}, env...), "PEEK_HOST="+base2)
	if out := runCmd(t, env2, "", peek, "list"); !strings.Contains(out, slug) {
		t.Fatalf("restored list does not contain %q:\n%s", slug, out)
	}
	resp, err := http.Get(base2 + "/p/" + slug)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /p/%s on restored server = %d, want 200", slug, resp.StatusCode)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func goBuild(t *testing.T, root, out, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
}

// cliEnv returns the process environment with config isolated under home and
// any PEEK_HOST / PEEK_TOKEN removed.
func cliEnv(home string) []string {
	var env []string
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "PEEK_HOST="), strings.HasPrefix(kv, "PEEK_TOKEN="),
			strings.HasPrefix(kv, "HOME="), strings.HasPrefix(kv, "XDG_CONFIG_HOME="):
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"))
}

// runCmd runs a command to completion and returns its combined output; a
// non-zero exit fails the test. A nil env inherits the test process environment.
func runCmd(t *testing.T, env []string, stdin, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(name), strings.Join(args, " "), err, b)
	}
	return string(b)
}

// startPeekd runs peekd on a free loopback port and returns its base URL.
func startPeekd(t *testing.T, peekd, dataDir string) string {
	t.Helper()
	var lastOut string
	for attempt := 0; attempt < 3; attempt++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		base := "http://" + addr

		out := &syncBuffer{}
		cmd := exec.Command(peekd, "--addr", addr, "--data", dataDir, "--base-url", base)
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatalf("start peekd: %v", err)
		}
		exited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(exited) }()
		t.Cleanup(func() {
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-exited
			}
		})

		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-exited:
				lastOut = out.String()
				goto retry
			default:
			}
			if resp, err := http.Get(base + "/healthz"); err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return base
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		lastOut = out.String()
		t.Fatalf("peekd not healthy within 15s:\n%s", lastOut)
	retry:
	}
	t.Fatalf("peekd exited during startup on 3 attempts:\n%s", lastOut)
	return ""
}

func getBody(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d:\n%s", u, resp.StatusCode, b)
	}
	return string(b)
}

func csrfOf(t *testing.T, html string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no csrf token in page:\n%s", html)
	}
	return m[1]
}

// setupAdminAndAPIKey completes first-run setup and creates an API key.
func setupAdminAndAPIKey(t *testing.T, base, dataDir string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	raw, err := os.ReadFile(filepath.Join(dataDir, "setup.key"))
	if err != nil {
		t.Fatalf("read setup.key: %v", err)
	}
	code := strings.TrimSpace(string(raw))

	csrf := csrfOf(t, getBody(t, c, base+"/setup?code="+url.QueryEscape(code)))
	resp, err := c.PostForm(base+"/setup", url.Values{
		"email":    {"admin@example.com"},
		"name":     {"Admin"},
		"password": {"e2e-admin-password"},
		"code":     {code},
		"csrf":     {csrf},
	})
	if err != nil {
		t.Fatalf("POST /setup: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/dashboard" {
		t.Fatalf("setup ended at %s with %d, want /dashboard 200:\n%s", resp.Request.URL.Path, resp.StatusCode, body)
	}

	csrf = csrfOf(t, getBody(t, c, base+"/dashboard"))
	resp, err = c.PostForm(base+"/dashboard/api-keys", url.Values{"name": {"e2e"}, "csrf": {csrf}})
	if err != nil {
		t.Fatalf("POST /dashboard/api-keys: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := apiKeyRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no API key in response (%d):\n%s", resp.StatusCode, body)
	}
	return string(m[1])
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		copyFile(t, p, filepath.Join(dst, rel))
		return nil
	})
	if err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
}
