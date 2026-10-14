package objectstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStorageSaveFailsWhenDirIsAFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&FileStorage{Dir: dir}).Save(context.Background(), "abc", []byte("x")); err == nil {
		t.Fatal("expected MkdirAll error")
	}
}

func TestFileStorageSaveFailsWhenTempPathIsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "abc.html.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&FileStorage{Dir: dir}).Save(context.Background(), "abc", []byte("x")); err == nil {
		t.Fatal("expected WriteFile error")
	}
}

func TestFileStorageSaveFailsWhenTargetIsNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "abc.html")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&FileStorage{Dir: dir}).Save(context.Background(), "abc", []byte("x")); err == nil {
		t.Fatal("expected Rename error")
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
}

func TestFileStorageDeleteMissingIsNil(t *testing.T) {
	if err := (&FileStorage{Dir: t.TempDir()}).Delete(context.Background(), "nope"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}
