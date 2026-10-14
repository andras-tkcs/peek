package objectstore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeS3 is a minimal path-style S3 holding objects in memory.
type fakeS3 struct {
	*httptest.Server
	mu       sync.Mutex
	objects  map[string][]byte
	signed   int
	failPath string
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			f.signed++
		}
		if f.failPath != "" && r.URL.Path == f.failPath {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<Error>boom</Error>"))
			return
		}
		switch r.Method {
		case http.MethodPut:
			data, _ := io.ReadAll(r.Body)
			f.objects[r.URL.Path] = data
		case http.MethodGet:
			data, ok := f.objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(data)
		case http.MethodDelete:
			if _, ok := f.objects[r.URL.Path]; !ok {
				http.NotFound(w, r)
				return
			}
			delete(f.objects, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(f.Server.Close)
	return f
}

func (f *fakeS3) storage(endpoint string) *S3Storage {
	return NewS3Storage(true, func(k string) string {
		return map[string]string{"s3_endpoint": endpoint, "s3_bucket": "bucket", "s3_access_key": "AK", "s3_secret_key": "SK"}[k]
	})
}

func TestS3StorageRoundTripAgainstFakeS3(t *testing.T) {
	ctx := context.Background()
	f := newFakeS3(t)
	s := f.storage(f.URL)

	if got := s.endpoint(); got != f.URL {
		t.Fatalf("endpoint = %q", got)
	}
	if got := s.region(); got != "us-east-1" {
		t.Fatalf("default region = %q", got)
	}
	if err := s.Save(ctx, "abc", []byte("<html>hi</html>")); err != nil {
		t.Fatalf("save: %v", err)
	}
	if string(f.objects["/bucket/uploads/abc.html"]) != "<html>hi</html>" {
		t.Fatalf("objects = %v", f.objects)
	}
	rc, err := s.Open(ctx, "abc")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "<html>hi</html>" {
		t.Fatalf("read = %q", got)
	}
	if err := s.Delete(ctx, "abc"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if f.signed != 3 {
		t.Fatalf("signed requests = %d, want 3", f.signed)
	}
	if _, err := s.Open(ctx, "abc"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open missing err = %v", err)
	}
	if err := s.Delete(ctx, "abc"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestS3StorageServerErrorsCarryBody(t *testing.T) {
	ctx := context.Background()
	f := newFakeS3(t)
	f.failPath = "/bucket/uploads/bad.html"
	s := f.storage(f.URL)

	if err := s.Save(ctx, "bad", []byte("x")); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("save err = %v", err)
	}
	if _, err := s.Open(ctx, "bad"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("open err = %v", err)
	}
	if err := s.Delete(ctx, "bad"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("delete err = %v", err)
	}
}

func TestS3StorageRejectsInvalidSlugs(t *testing.T) {
	ctx := context.Background()
	s := newFakeS3(t).storage("http://127.0.0.1:1")
	if err := s.Save(ctx, "../x", nil); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("save err = %v", err)
	}
	if _, err := s.Open(ctx, "../x"); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("open err = %v", err)
	}
	if err := s.Delete(ctx, "../x"); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("delete err = %v", err)
	}
}

func TestS3StorageTransportErrors(t *testing.T) {
	ctx := context.Background()
	f := newFakeS3(t)
	s := f.storage(f.URL)
	f.Close()
	if err := s.Save(ctx, "abc", []byte("x")); err == nil {
		t.Fatal("save: expected error")
	}
	if _, err := s.Open(ctx, "abc"); err == nil {
		t.Fatal("open: expected error")
	}
	if err := s.Delete(ctx, "abc"); err == nil {
		t.Fatal("delete: expected error")
	}
}

func TestS3StorageRequestBuildErrors(t *testing.T) {
	ctx := context.Background()
	s := newFakeS3(t).storage("http://bad\x7fhost")
	if err := s.Save(ctx, "abc", []byte("x")); err == nil {
		t.Fatal("save: expected error")
	}
	if _, err := s.Open(ctx, "abc"); err == nil {
		t.Fatal("open: expected error")
	}
	if err := s.Delete(ctx, "abc"); err == nil {
		t.Fatal("delete: expected error")
	}
}

func TestS3StorageHTTPClientBuiltLazily(t *testing.T) {
	f := newFakeS3(t)
	s := &S3Storage{allowPrivateEndpoint: true, getSetting: func(k string) string {
		return map[string]string{"s3_endpoint": f.URL, "s3_bucket": "bucket", "s3_region": "eu-west-1"}[k]
	}}
	if s.httpClient() == nil {
		t.Fatal("httpClient returned nil")
	}
	if s.region() != "eu-west-1" {
		t.Fatalf("region = %q", s.region())
	}
	if err := s.Save(context.Background(), "abc", []byte("x")); err != nil {
		t.Fatalf("save: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken") }

func TestReadS3ErrorBodyReportsReadFailure(t *testing.T) {
	if got := readS3ErrorBody(errReader{}); !strings.Contains(got, "read response body: broken") {
		t.Fatalf("got %q", got)
	}
}

func TestS3SignRequestReplacesExistingAuthorization(t *testing.T) {
	s := newFakeS3(t).storage("http://example.test")
	req, err := http.NewRequest(http.MethodGet, "http://example.test/bucket/uploads/abc.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "stale")
	s.signRequest(req, "uploads/abc.html", nil)
	if got := req.Header.Get("Authorization"); !strings.HasPrefix(got, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("Authorization = %q", got)
	}
}
