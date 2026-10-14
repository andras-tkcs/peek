package peekd

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/db"
)

func seedBackupSource(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	source, err := db.Open(filepath.Join(dataDir, "peek.db"))
	if err != nil {
		t.Fatalf("open source store: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if err := source.CreateToken(context.Background(), "admin-token", "admin", true, 0); err != nil {
		t.Fatalf("seed source token: %v", err)
	}
	return dataDir
}

func TestBackupDatabaseWritesOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	dataDir := seedBackupSource(t)
	dest := filepath.Join(t.TempDir(), "peek-backup.db")
	if err := backupDatabase(dataDir, dest); err != nil {
		t.Fatalf("backup: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("backup mode = %#o, want 0600", got)
	}
}

func TestBackupDatabaseRefusesExistingDestination(t *testing.T) {
	dataDir := seedBackupSource(t)
	dest := filepath.Join(t.TempDir(), "peek-backup.db")
	if err := os.WriteFile(dest, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := backupDatabase(dataDir, dest)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %v, want already exists", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "keep me" {
		t.Fatalf("destination changed: %q", got)
	}
}

func TestBackupDatabaseRemovesFileOnFailure(t *testing.T) {
	// The source path is a directory, so VACUUM INTO fails after the
	// destination has been pre-created.
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, "peek.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "peek-backup.db")
	if err := backupDatabase(dataDir, dest); err == nil {
		t.Fatal("expected backup to fail")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("destination should be removed, stat err = %v", err)
	}
}

func TestRunBackupWritesSnapshot(t *testing.T) {
	dataDir := seedBackupSource(t)
	dest := filepath.Join(t.TempDir(), "snap.db")
	if got := runBackup([]string{"--data", dataDir, dest}); got != 0 {
		t.Fatalf("runBackup = %d, want 0", got)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("backup not written: %v", err)
	}
}

func TestRunBackupDefaultsDestinationInsideDataDir(t *testing.T) {
	dataDir := seedBackupSource(t)
	if got := runBackup([]string{"--data", dataDir}); got != 0 {
		t.Fatalf("runBackup = %d, want 0", got)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "peek-backup.db")); err != nil {
		t.Fatalf("default backup not written: %v", err)
	}
}

func TestRunBackupReturnsUsageForBadArgs(t *testing.T) {
	if got := runBackup([]string{"--nope"}); got != 2 {
		t.Fatalf("bad flag: runBackup = %d, want 2", got)
	}
	if got := runBackup([]string{"a", "b"}); got != 2 {
		t.Fatalf("extra args: runBackup = %d, want 2", got)
	}
}

func TestRunBackupFailsForUnusableDataDir(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, "peek.db"), 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snap.db")
	if got := runBackup([]string{"--data", dataDir, dest}); got != 1 {
		t.Fatalf("runBackup = %d, want 1", got)
	}
}

func TestBackupDatabaseFailsWhenDestinationDirectoryIsMissing(t *testing.T) {
	dataDir := seedBackupSource(t)
	dest := filepath.Join(t.TempDir(), "no-such-dir", "snap.db")
	err := backupDatabase(dataDir, dest)
	if err == nil || !strings.Contains(err.Error(), "create backup file") {
		t.Fatalf("error = %v, want create backup file", err)
	}
}
