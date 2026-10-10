package groups

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestDirectory(t *testing.T, status int, body string) (*Directory, *atomic.Int32, *clock) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	return newDirectoryWithClient(ts.Client(), ts.URL, time.Minute, c.now), &hits, c
}

func TestIsMemberTrueAndCached(t *testing.T) {
	d, hits, _ := newTestDirectory(t, 200, `{"isMember":true}`)
	for i := 0; i < 2; i++ {
		ok, err := d.IsMember(context.Background(), "eng@example.com", "bob@example.com")
		if err != nil || !ok {
			t.Fatalf("call %d: ok=%v err=%v", i, ok, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("requests = %d, want 1", hits.Load())
	}
}

func TestIsMemberCacheExpires(t *testing.T) {
	d, hits, c := newTestDirectory(t, 200, `{"isMember":true}`)
	if _, err := d.IsMember(context.Background(), "eng@example.com", "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(2 * time.Minute)
	if _, err := d.IsMember(context.Background(), "eng@example.com", "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("requests = %d, want 2", hits.Load())
	}
}

func TestIsMember404IsFalseAndCached(t *testing.T) {
	d, hits, _ := newTestDirectory(t, 404, `{}`)
	for i := 0; i < 2; i++ {
		ok, err := d.IsMember(context.Background(), "eng@example.com", "bob@example.com")
		if err != nil || ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("requests = %d, want 1", hits.Load())
	}
}

func TestIsMember400IsFalse(t *testing.T) {
	d, _, _ := newTestDirectory(t, 400, `{}`)
	ok, err := d.IsMember(context.Background(), "eng@example.com", "bob@other.org")
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestIsMember500IsErrorAndNotCached(t *testing.T) {
	d, hits, _ := newTestDirectory(t, 500, `{}`)
	for i := 0; i < 2; i++ {
		ok, err := d.IsMember(context.Background(), "eng@example.com", "bob@example.com")
		if err == nil || ok {
			t.Fatalf("ok=%v err=%v, want error", ok, err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("requests = %d, want 2", hits.Load())
	}
}

func TestIsMemberEscapesPathAndLowercases(t *testing.T) {
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.EscapedPath())
		_, _ = w.Write([]byte(`{"isMember":false}`))
	}))
	t.Cleanup(ts.Close)
	d := newDirectoryWithClient(ts.Client(), ts.URL, time.Minute, time.Now)
	if _, err := d.IsMember(context.Background(), "Eng+Team@Example.com", "Bob@Example.com"); err != nil {
		t.Fatal(err)
	}
	want := "/admin/directory/v1/groups/eng+team@example.com/hasMember/bob@example.com"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("path = %v, want %s", got, want)
	}
}

func TestCacheBoundedAtMaxEntries(t *testing.T) {
	d, _, _ := newTestDirectory(t, 200, `{"isMember":true}`)
	for i := 0; i < maxCacheEntries+5; i++ {
		d.store(fmt.Sprintf("g|u%d", i), true)
	}
	d.mu.Lock()
	n := len(d.cache)
	d.mu.Unlock()
	if n > maxCacheEntries {
		t.Fatalf("cache size = %d, want <= %d", n, maxCacheEntries)
	}
}

func TestNewDirectoryRejectsInvalidKey(t *testing.T) {
	_, err := NewDirectory([]byte(`{}`), "admin@example.com", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "parse google service account key") {
		t.Fatalf("err = %v", err)
	}
}
