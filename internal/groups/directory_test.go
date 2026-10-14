package groups

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

func TestNewDirectoryAcceptsServiceAccountKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	js, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "sa@example.iam.gserviceaccount.com",
		"private_key":  string(pemKey),
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDirectory(js, "admin@example.com", time.Minute)
	if err != nil || d == nil {
		t.Fatalf("d=%v err=%v", d, err)
	}
}

func TestIsMemberRequestErrors(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	bad := newDirectoryWithClient(http.DefaultClient, "http://host\x7f", time.Minute, c.now)
	if _, err := bad.IsMember(context.Background(), "g@x.com", "u@x.com"); err == nil {
		t.Fatal("expected NewRequest error")
	}

	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL
	ts.Close()
	closed := newDirectoryWithClient(http.DefaultClient, url, time.Minute, c.now)
	if _, err := closed.IsMember(context.Background(), "g@x.com", "u@x.com"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestIsMemberInvalidJSONBody(t *testing.T) {
	d, _, _ := newTestDirectory(t, 200, "not json")
	_, err := d.IsMember(context.Background(), "g@x.com", "u@x.com")
	if err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("err = %v", err)
	}
}

func TestStorePrunesExpiredEntriesWhenFull(t *testing.T) {
	d, _, c := newTestDirectory(t, 200, `{"isMember":true}`)
	d.store("old|u", true)
	c.t = c.t.Add(2 * time.Minute) // "old|u" is now expired
	for i := 0; i < maxCacheEntries-1; i++ {
		d.cache[fmt.Sprintf("g|u%d", i)] = cacheEntry{member: true, expires: c.t.Add(time.Hour)}
	}
	d.store("new|u", true)
	d.mu.Lock()
	_, oldOK := d.cache["old|u"]
	_, newOK := d.cache["new|u"]
	n := len(d.cache)
	d.mu.Unlock()
	if oldOK || !newOK || n != maxCacheEntries {
		t.Fatalf("old=%v new=%v size=%d", oldOK, newOK, n)
	}
}
