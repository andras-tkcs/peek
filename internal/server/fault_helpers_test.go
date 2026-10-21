package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
	webui "github.com/andras-tkcs/peek/internal/web"
)

// faultStorage is an in-memory objectstore.Storage whose operations can be
// made to fail.
type faultStorage struct {
	mu                          sync.Mutex
	objects                     map[string][]byte
	saveErr, openErr, deleteErr error
}

func (f *faultStorage) Save(_ context.Context, slug string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.objects == nil {
		f.objects = map[string][]byte{}
	}
	f.objects[slug] = append([]byte(nil), data...)
	return nil
}

func (f *faultStorage) Open(_ context.Context, slug string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.openErr != nil {
		return nil, f.openErr
	}
	data, ok := f.objects[slug]
	if !ok {
		return nil, errors.New("object not found")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *faultStorage) Delete(_ context.Context, slug string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.objects, slug)
	return nil
}

// failingWriter is a ResponseRecorder whose Write always fails.
type failingWriter struct{ httptest.ResponseRecorder }

func (*failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// addFailTrigger makes every INSERT, UPDATE or DELETE (op) on table abort.
func addFailTrigger(t *testing.T, store *db.Store, table, op string) {
	t.Helper()
	stmt := fmt.Sprintf(`CREATE TRIGGER cov_fail_%s_%s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT,'injected failure'); END`, table, strings.ToLower(op), op, table)
	if _, err := store.Exec(stmt); err != nil {
		t.Fatalf("add fail trigger on %s %s: %v", table, op, err)
	}
}

// dropTable drops a table so later queries against it fail.
func dropTable(t *testing.T, store *db.Store, name string) {
	t.Helper()
	if _, err := store.Exec("DROP TABLE " + name); err != nil {
		t.Fatalf("drop table %s: %v", name, err)
	}
}

// newFaultServer builds a hand-assembled Server over a fresh store with a
// failable storage, every limiter set high, and a seeded admin account.
func newFaultServer(t *testing.T) (s *Server, store *db.Store, storage *faultStorage, adminID int64) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	admin, err := store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	storage = &faultStorage{}
	lim := func() *limiter { return newLimiter(1000, time.Minute) }
	s = &Server{
		store:                   store,
		renderer:                renderer,
		secret:                  strings.Repeat("0", 64),
		storage:                 storage,
		baseURL:                 "http://localhost:7700",
		loginLimiter:            lim(),
		commentLimiter:          lim(),
		uploadLimiter:           lim(),
		globalLimiter:           lim(),
		cliLoginLimiter:         lim(),
		apiKeyLimiter:           lim(),
		accountLoginLimiter:     lim(),
	}
	return s, store, storage, admin.ID
}
