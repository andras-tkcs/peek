//go:build unix

package peekd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/backends"
	"github.com/privacyfence/peek/internal/backends/backendstest"
)

// restoreSlogDefault undoes configureLogging, which replaces slog.Default().
func restoreSlogDefault(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
}

func serveTestConfig(t *testing.T) serveConfig {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return serveConfig{
		Listener:            ln,
		Addr:                ln.Addr().String(),
		DataDir:             t.TempDir(),
		BaseURL:             "http://localhost:7700",
		MaxUpload:           2 << 20,
		Storage:             "file",
		GoogleGroupCacheTTL: time.Minute,
	}
}

func writeServiceAccountKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "peek@example-project.iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":    "https://oauth2.example.test/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(path, keyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runServeUntilSIGTERM starts runServe, waits for /healthz, delivers SIGTERM
// and returns the exit code and the base URL for extra requests made before
// shutdown through the probe callback.
func runServeUntilSIGTERM(t *testing.T, cfg serveConfig, probe func(base string)) int {
	t.Helper()
	// The guard keeps the default SIGTERM action (killing the test binary)
	// disabled for the whole test; it must be registered before runServe starts.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)

	done := make(chan int, 1)
	go func() { done <- runServe(cfg) }()

	base := "http://" + cfg.Addr
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			ok := resp.StatusCode == http.StatusOK
			_ = resp.Body.Close()
			if ok {
				break
			}
		}
		select {
		case code := <-done:
			t.Fatalf("runServe exited early with %d", code)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not become healthy")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if probe != nil {
		probe(base)
	}

	// runServe registers its own Notify after the listener goroutine starts;
	// /healthz answering means that goroutine ran, but retry the signal until
	// runServe returns so a delivery before its Notify cannot be lost.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case code := <-done:
			return code
		case <-ticker.C:
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		case <-timeout:
			t.Fatal("runServe did not stop after SIGTERM")
		}
	}
}

func TestRunServeShutsDownOnSIGTERM(t *testing.T) {
	restoreSlogDefault(t)
	t.Setenv("PEEK_LOG_LEVEL", "debug")
	cfg := serveTestConfig(t)
	cfg.GoogleSAKeyFile = writeServiceAccountKey(t)
	cfg.GoogleAdminEmail = "admin@example.test"
	cfg.MetricsToken = "0123456789abcdef"

	code := runServeUntilSIGTERM(t, cfg, func(base string) {
		resp, err := http.Get(base + "/metrics")
		if err != nil {
			t.Errorf("GET /metrics: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("/metrics without token = %d, want it refused", resp.StatusCode)
		}
	})
	if code != 0 {
		t.Fatalf("runServe = %d, want 0", code)
	}
}

func TestRunServeWarnLogLevel(t *testing.T) {
	restoreSlogDefault(t)
	t.Setenv("PEEK_LOG_LEVEL", "warn")
	if code := runServeUntilSIGTERM(t, serveTestConfig(t), nil); code != 0 {
		t.Fatalf("runServe = %d, want 0", code)
	}
	if slog.Default().Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info logging should be disabled at warn level")
	}
}

func TestRunServeRejectsMissingGoogleKeyFile(t *testing.T) {
	restoreSlogDefault(t)
	cfg := serveTestConfig(t)
	cfg.GoogleSAKeyFile = filepath.Join(t.TempDir(), "missing.json")
	cfg.GoogleAdminEmail = "admin@example.test"
	if code := runServe(cfg); code != 1 {
		t.Fatalf("runServe = %d, want 1", code)
	}
}

func TestRunServeRejectsInvalidGoogleKey(t *testing.T) {
	restoreSlogDefault(t)
	cfg := serveTestConfig(t)
	cfg.GoogleSAKeyFile = filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(cfg.GoogleSAKeyFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.GoogleAdminEmail = "admin@example.test"
	if code := runServe(cfg); code != 1 {
		t.Fatalf("runServe = %d, want 1", code)
	}
}

func TestRunServeRejectsDataDirThatIsAFile(t *testing.T) {
	restoreSlogDefault(t)
	cfg := serveTestConfig(t)
	cfg.DataDir = filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(cfg.DataDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runServe(cfg); code != 1 {
		t.Fatalf("runServe = %d, want 1", code)
	}
}

func TestRunServeFailsWhenAddressInUse(t *testing.T) {
	restoreSlogDefault(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := serveTestConfig(t)
	cfg.Addr = ln.Addr().String()
	cfg.Listener = nil
	if code := runServe(cfg); code != 1 {
		t.Fatalf("runServe on %s = %d, want 1", cfg.Addr, code)
	}
}

func TestRunServeHealthcheckRoundTrip(t *testing.T) {
	restoreSlogDefault(t)
	cfg := serveTestConfig(t)
	code := runServeUntilSIGTERM(t, cfg, func(base string) {
		if got := Run([]string{"healthcheck", "--addr", base}); got != 0 {
			t.Errorf("healthcheck against running server = %d, want 0", got)
		}
	})
	if code != 0 {
		t.Fatalf("runServe = %d", code)
	}
}

func TestRunServeWithDockerBackendsPassesRuntime(t *testing.T) {
	restoreSlogDefault(t)
	fake := backendstest.NewFakeRuntime()
	var gotHost string
	prev := newBackendRuntime
	newBackendRuntime = func(host string) (backends.Runtime, error) {
		gotHost = host
		return fake, nil
	}
	t.Cleanup(func() { newBackendRuntime = prev })

	cfg := serveTestConfig(t)
	cfg.Backends = "docker"
	cfg.DockerHost = "unix:///tmp/test-docker.sock"
	cfg.BackendNetwork = "peek-it"
	if code := runServeUntilSIGTERM(t, cfg, nil); code != 0 {
		t.Fatalf("runServe = %d, want 0", code)
	}
	if gotHost != cfg.DockerHost {
		t.Fatalf("runtime host = %q, want %q", gotHost, cfg.DockerHost)
	}
	fake.Lock()
	defer fake.Unlock()
	if len(fake.Networks) != 1 || fake.Networks[0] != "peek-it" {
		t.Fatalf("Networks = %v, want [peek-it]", fake.Networks)
	}
}

func TestRunServeBackendsOffNeverBuildsRuntime(t *testing.T) {
	restoreSlogDefault(t)
	prev := newBackendRuntime
	newBackendRuntime = func(string) (backends.Runtime, error) {
		t.Error("runtime built with --backends off")
		return nil, nil
	}
	t.Cleanup(func() { newBackendRuntime = prev })
	cfg := serveTestConfig(t)
	cfg.Backends = "off"
	if code := runServeUntilSIGTERM(t, cfg, nil); code != 0 {
		t.Fatalf("runServe = %d, want 0", code)
	}
}

func TestRunServeStopsWhenDockerIsNotReachable(t *testing.T) {
	restoreSlogDefault(t)
	fake := backendstest.NewFakeRuntime()
	fake.PingErr = errors.New("connection refused")
	prev := newBackendRuntime
	newBackendRuntime = func(string) (backends.Runtime, error) { return fake, nil }
	t.Cleanup(func() { newBackendRuntime = prev })

	cfg := serveTestConfig(t)
	cfg.Backends = "docker"
	cfg.DockerHost = "unix:///nope.sock"
	rt, err := connectBackends(cfg)
	if rt != nil || err == nil || !strings.Contains(err.Error(), "docker is not reachable at unix:///nope.sock: connection refused") {
		t.Fatalf("connectBackends = %v, %v", rt, err)
	}
	if code := runServe(cfg); code != 1 {
		t.Fatalf("runServe = %d, want 1", code)
	}
}

func TestRunServeStopsWhenRuntimeCannotBeBuilt(t *testing.T) {
	restoreSlogDefault(t)
	prev := newBackendRuntime
	newBackendRuntime = func(string) (backends.Runtime, error) { return nil, errors.New("unsupported docker host") }
	t.Cleanup(func() { newBackendRuntime = prev })
	cfg := serveTestConfig(t)
	cfg.Backends = "docker"
	cfg.DockerHost = "https://x"
	if code := runServe(cfg); code != 1 {
		t.Fatalf("runServe = %d, want 1", code)
	}
}
