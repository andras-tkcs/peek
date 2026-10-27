package server

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privacyfence/peek/internal/backends/backendstest"
	"github.com/privacyfence/peek/internal/db"
)

const backendTestAdminToken = "dev-admin-token"

// newBackendTestServer builds a Server like newHandlerTestServer but with page
// backends on, backed by a FakeRuntime on network "peek-test". It returns the
// server, the fake and the admin bearer token.
func newBackendTestServer(t *testing.T) (*Server, *backendstest.FakeRuntime, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := db.Open(filepath.Join(dir, "peek.db"))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	if err := store.CreateToken(context.Background(), backendTestAdminToken, "admin", true, 0); err != nil {
		t.Fatalf("seed admin token: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close test store: %v", err)
	}
	fake := backendstest.NewFakeRuntime()
	s := newBackendTestServerIn(t, dir, fake)
	return s, fake, backendTestAdminToken
}

// newBackendTestServerIn builds a Server on an existing data directory with
// the given runtime, and closes it when the test ends.
func newBackendTestServerIn(t *testing.T, dir string, fake *backendstest.FakeRuntime) *Server {
	t.Helper()
	s, err := New(Config{
		DataDir:        dir,
		BaseURL:        "http://localhost:7700",
		Secret:         strings.Repeat("ab", 32),
		MaxUpload:      10 << 20,
		BackendRuntime: fake,
		BackendNetwork: "peek-test",
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// newBackendListener starts a TCP listener that accepts and drops
// connections, so the manager's readiness probe (127.0.0.1:<port>) succeeds.
// It returns the port.
func newBackendListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}
