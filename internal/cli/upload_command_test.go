package cli

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStreamMultipartUploadEncodesFileAndVisibility(t *testing.T) {
	body, contentType := streamMultipartUpload(strings.NewReader("<html></html>"), "page.html", "restricted", "")
	defer body.Close()

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("parse content type: %v", err)
	}
	if mediaType != "multipart/form-data" {
		t.Fatalf("media type = %q", mediaType)
	}
	form, err := multipart.NewReader(body, params["boundary"]).ReadForm(1 << 20)
	if err != nil {
		t.Fatalf("read multipart form: %v", err)
	}
	defer form.RemoveAll()
	if got := form.Value["visibility"]; len(got) != 1 || got[0] != "restricted" {
		t.Fatalf("visibility field = %+v", got)
	}
	files := form.File["file"]
	if len(files) != 1 {
		t.Fatalf("file fields = %+v", files)
	}
	if files[0].Filename != "page.html" {
		t.Fatalf("filename = %q", files[0].Filename)
	}
	file, err := files[0].Open()
	if err != nil {
		t.Fatalf("open file part: %v", err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read file part: %v", err)
	}
	if string(data) != "<html></html>" {
		t.Fatalf("file body = %q", data)
	}
}

func TestUploadDefaultsToRestricted(t *testing.T) {
	type observedRequest struct {
		Auth          string
		ContentLength int64
		Filename      string
		Visibility    string
		Body          string
	}
	observed := make(chan observedRequest, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := observedRequest{
			Auth:          r.Header.Get("Authorization"),
			ContentLength: r.ContentLength,
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			observed <- got
			return
		}
		got.Visibility = r.FormValue("visibility")
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			observed <- got
			return
		}
		defer file.Close()
		got.Filename = header.Filename
		data, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			observed <- got
			return
		}
		got.Body = string(data)
		observed <- got
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"slug":       "page",
			"url":        "http://example.test/p/page",
			"visibility": "restricted",
		})
	}))
	defer ts.Close()

	setTestConfigHome(t)
	t.Setenv("PEEK_HOST", ts.URL)
	t.Setenv("PEEK_TOKEN", "token")
	file := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(file, []byte("<!doctype html><html></html>"), 0o600); err != nil {
		t.Fatalf("write upload file: %v", err)
	}

	if err := cmdUpload([]string{file}); err != nil {
		t.Fatalf("cmdUpload: %v", err)
	}
	got := <-observed
	if got.Auth != "Bearer token" {
		t.Fatalf("authorization = %q", got.Auth)
	}
	if got.ContentLength != -1 {
		t.Fatalf("content length = %d, want streamed request", got.ContentLength)
	}
	if got.Filename != "page" {
		t.Fatalf("filename = %q", got.Filename)
	}
	if got.Visibility != "restricted" {
		t.Fatalf("visibility = %q", got.Visibility)
	}
	if got.Body != "<!doctype html><html></html>" {
		t.Fatalf("body = %q", got.Body)
	}
}

func TestUploadWithSlugSendsSlugAndNoVisibility(t *testing.T) {
	type observed struct {
		Slug          string
		HasVisibility bool
		Filename      string
	}
	got := make(chan observed, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			got <- observed{}
			return
		}
		_, header, _ := r.FormFile("file")
		o := observed{Slug: r.FormValue("slug")}
		_, o.HasVisibility = r.MultipartForm.Value["visibility"]
		if header != nil {
			o.Filename = header.Filename
		}
		got <- o
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"slug": "page", "url": "http://example.test/p/page", "visibility": "public",
			"version": 2, "version_url": "http://example.test/p/page/v/2",
		})
	}))
	defer ts.Close()

	setTestConfigHome(t)
	t.Setenv("PEEK_HOST", ts.URL)
	t.Setenv("PEEK_TOKEN", "token")
	file := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(file, []byte("<!doctype html><html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdUpload([]string{file, "--slug", "page"}); err != nil {
		t.Fatalf("cmdUpload: %v", err)
	}
	o := <-got
	if o.Slug != "page" || o.HasVisibility || o.Filename != "page" {
		t.Fatalf("observed = %+v", o)
	}
}

func TestUploadWithSlugRejectsVisibilityFlag(t *testing.T) {
	err := cmdUpload([]string{"page.html", "--slug", "page", "--visibility", "public"})
	want := "--slug adds a new version to an existing page; change visibility with 'peek visibility'"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestUploadWithSlugRejectsNameFlag(t *testing.T) {
	err := cmdUpload([]string{"page.html", "--slug", "page", "--name", "x"})
	want := "--name cannot be used with --slug; the page keeps its name"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestUploadPasswordFlagRemoved(t *testing.T) {
	var requests int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++ }))
	defer ts.Close()
	configureTestClient(t, ts.URL)
	file := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(file, []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{file, "--password", "secret"},
		{file, "--password-stdin"},
	} {
		flag := args[1]
		want := flag + " is no longer supported: password-protected pages were removed; use --visibility restricted and 'peek grant'"
		if err := cmdUpload(args); err == nil || err.Error() != want {
			t.Fatalf("%v: error = %v, want %q", args, err, want)
		}
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func TestUploadWithSlugRejectsInvalidSlug(t *testing.T) {
	err := cmdUpload([]string{"page.html", "--slug", "../x"})
	if err == nil || !strings.Contains(err.Error(), "invalid slug") {
		t.Fatalf("err = %v, want invalid slug", err)
	}
}

func TestCovUploadFlagAndValidationErrors(t *testing.T) {
	configureTestClient(t, "http://127.0.0.1:1")
	file := filepath.Join(t.TempDir(), "p.html")
	if err := os.WriteFile(file, []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"name value":          {"--name"},
		"visibility value":    {"--visibility"},
		"slug value":          {"--slug"},
		"unknown flag":        {"--nope"},
		"two files":           {file, file},
		"no file":             {},
		"slug and name":       {file, "--slug", "demo", "--name", "n"},
		"invalid visibility":  {file, "--visibility", "weird"},
		"password visibility": {file, "--visibility", "password"},
		"missing file":        {filepath.Join(t.TempDir(), "nope.html"), "--visibility", "public"},
		"directory as file":   {t.TempDir(), "--visibility", "public"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := captureStdout(t, func() error { return cmdUpload(args) }); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCovUploadEnvFailures(t *testing.T) {
	file := filepath.Join(t.TempDir(), "p.html")
	if err := os.WriteFile(file, []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	covEnvFailures(t, func() error { return cmdUpload([]string{file, "--visibility", "public"}) })
}

func TestCovFileNameWithoutExtFallsBackToPage(t *testing.T) {
	if got := fileNameWithoutExt(".html"); got != "page" {
		t.Fatalf("got %q", got)
	}
	if got := fileNameWithoutExt("dir/noext"); got != "noext" {
		t.Fatalf("got %q", got)
	}
}
