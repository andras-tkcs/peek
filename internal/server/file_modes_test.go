package server_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/andras-tkcs/peek/internal/server"
)

func TestNewCreatesOwnerOnlyDataFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not enforced on windows")
	}
	dir := filepath.Join(t.TempDir(), "data")
	srv, err := server.New(server.Config{DataDir: dir, BaseURL: "http://localhost:7700", MaxUpload: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	want := map[string]os.FileMode{
		dir:                              0o700,
		filepath.Join(dir, "uploads"):    0o700,
		filepath.Join(dir, "peek.db"):    0o600,
		filepath.Join(dir, "secret.key"): 0o600,
		filepath.Join(dir, "setup.key"):  0o600,
	}
	for path, mode := range want {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != mode {
			t.Errorf("%s mode = %#o, want %#o", path, got, mode)
		}
	}
}
