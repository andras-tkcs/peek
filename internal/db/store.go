package db

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"

	_ "modernc.org/sqlite"
)

type Store struct {
	*sql.DB
}

// preparePrivateDBFile creates the database file owner-only before SQLite opens it,
// so SQLite also creates -wal/-shm owner-only, and tightens files left by older versions.
func preparePrivateDBFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("restrict database file permissions (run chmod 600 on %s): %w", p, err)
		}
	}
	return nil
}

func Open(path string) (*Store, error) {
	if err := preparePrivateDBFile(path); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	store := &Store{db}
	if err := store.runMigrations(); err != nil {
		return nil, err
	}
	if err := store.migrateAccounts(); err != nil {
		return nil, err
	}
	if err := store.migrateUploadsOwner(); err != nil {
		return nil, err
	}
	if err := store.migrateInviteTokenCipher(); err != nil {
		return nil, err
	}
	if _, err := store.Exec(`CREATE INDEX IF NOT EXISTS idx_uploads_owner_account ON uploads(owner_account_id)`); err != nil {
		return nil, err
	}
	closeOnError = false
	return store, nil
}
