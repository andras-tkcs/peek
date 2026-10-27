package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/backends"
	"github.com/privacyfence/peek/internal/models"
)

const uploadTestHTML = "<html><body>hello</body></html>"

// uploadForm posts a multipart upload with the given extra fields.
func uploadForm(t *testing.T, s *Server, token string, fields map[string]string) (int, uploadResp, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := mw.CreateFormFile("file", "page.html")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(uploadTestHTML))
	_ = mw.Close()
	rec := doRequest(t, s, http.MethodPost, "/api/upload", &buf, asBearer(token), func(r *http.Request) {
		r.Header.Set("Content-Type", mw.FormDataContentType())
	})
	var resp uploadResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp, rec.Body.String()
}

func allowBackendImages(t *testing.T, s *Server) {
	t.Helper()
	if err := s.encryptedSetSetting(context.Background(), "backend_allowed_images", "ghcr.io/acme/"); err != nil {
		t.Fatal(err)
	}
}

func TestUploadWithBackendCreatesRow(t *testing.T) {
	s, _, tok := newBackendTestServer(t)
	allowBackendImages(t, s)
	code, resp, body := uploadForm(t, s, tok, map[string]string{"visibility": "public", "backend_image": backendTestImage, "backend_port": "9000"})
	if code != http.StatusOK {
		t.Fatalf("upload = %d %s", code, body)
	}
	if resp.BackendImage != backendTestImage {
		t.Fatalf("backend_image = %q", resp.BackendImage)
	}
	u, err := s.store.GetUpload(context.Background(), resp.Slug)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.store.GetUploadBackend(context.Background(), u.ID, 1)
	if err != nil || b.Image != backendTestImage || b.Port != 9000 {
		t.Fatalf("backend row = %+v err=%v", b, err)
	}

	// Default port, and raw-HTML upload with query parameters.
	rec := doRequest(t, s, http.MethodPost, "/api/upload?backend_image="+backendTestImage, bytes.NewBufferString(uploadTestHTML), asBearer(tok), func(r *http.Request) {
		r.Header.Set("Content-Type", "text/html")
	})
	var raw uploadResp
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	if rec.Code != http.StatusOK || raw.BackendImage != backendTestImage {
		t.Fatalf("raw upload = %d %s", rec.Code, rec.Body.String())
	}
	u2, _ := s.store.GetUpload(context.Background(), raw.Slug)
	if b2, err := s.store.GetUploadBackend(context.Background(), u2.ID, 1); err != nil || b2.Port != 8080 {
		t.Fatalf("default port row = %+v err=%v", b2, err)
	}
}

func TestUploadWithoutBackendHasNoRow(t *testing.T) {
	s, _, tok := newBackendTestServer(t)
	code, resp, body := uploadForm(t, s, tok, map[string]string{"visibility": "public"})
	if code != http.StatusOK || resp.BackendImage != "" {
		t.Fatalf("upload = %d %s", code, body)
	}
	u, _ := s.store.GetUpload(context.Background(), resp.Slug)
	if _, err := s.store.GetUploadBackend(context.Background(), u.ID, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("backend row err = %v, want ErrNoRows", err)
	}
}

func TestUploadBackendRejected(t *testing.T) {
	s, _, tok := newBackendTestServer(t)
	allowBackendImages(t, s)
	cases := []struct {
		name   string
		fields map[string]string
		want   int
	}{
		{"invalid ref", map[string]string{"backend_image": "Not A Ref"}, http.StatusBadRequest},
		{"not allowed", map[string]string{"backend_image": "docker.io/evil/app:1"}, http.StatusBadRequest},
		{"bad port", map[string]string{"backend_image": backendTestImage, "backend_port": "70000"}, http.StatusBadRequest},
		{"non-numeric port", map[string]string{"backend_image": backendTestImage, "backend_port": "abc"}, http.StatusBadRequest},
	}
	for _, c := range cases {
		c.fields["visibility"] = "public"
		if code, _, body := uploadForm(t, s, tok, c.fields); code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, code, body, c.want)
		}
	}
	list, err := s.store.ListAllUploads(context.Background())
	if err != nil || len(list) != 0 {
		t.Fatalf("pages after rejected uploads = %d err=%v, want none", len(list), err)
	}
}

func TestUploadBackendOff(t *testing.T) {
	s, tok := newHandlerTestServer(t)
	code, _, body := uploadForm(t, s, tok, map[string]string{"visibility": "public", "backend_image": backendTestImage})
	if code != http.StatusConflict {
		t.Fatalf("upload with backends off = %d %s, want 409", code, body)
	}
	if list, _ := s.store.ListAllUploads(context.Background()); len(list) != 0 {
		t.Fatalf("page created despite 409: %d", len(list))
	}
}

func TestUploadVersionInheritsAndReplacesBackend(t *testing.T) {
	s, _, tok := newBackendTestServer(t)
	allowBackendImages(t, s)
	ctx := context.Background()
	_, first, body := uploadForm(t, s, tok, map[string]string{"visibility": "public", "backend_image": backendTestImage, "backend_port": "9000"})
	if first.Slug == "" {
		t.Fatalf("first upload: %s", body)
	}
	u, _ := s.store.GetUpload(ctx, first.Slug)

	code, v2, body := uploadForm(t, s, tok, map[string]string{"slug": first.Slug})
	if code != http.StatusOK || v2.Version != 2 || v2.BackendImage != backendTestImage {
		t.Fatalf("v2 upload = %d %s", code, body)
	}
	b2, err := s.store.GetUploadBackend(ctx, u.ID, 2)
	if err != nil || b2.Image != backendTestImage || b2.Port != 9000 {
		t.Fatalf("inherited row = %+v err=%v", b2, err)
	}

	other := "ghcr.io/acme/other:2"
	code, v3, body := uploadForm(t, s, tok, map[string]string{"slug": first.Slug, "backend_image": other})
	if code != http.StatusOK || v3.Version != 3 || v3.BackendImage != other {
		t.Fatalf("v3 upload = %d %s", code, body)
	}
	b3, err := s.store.GetUploadBackend(ctx, u.ID, 3)
	if err != nil || b3.Image != other || b3.Port != 8080 {
		t.Fatalf("replaced row = %+v err=%v", b3, err)
	}
	// The older versions keep their own rows.
	if b1, err := s.store.GetUploadBackend(ctx, u.ID, 1); err != nil || b1.Image != backendTestImage {
		t.Fatalf("v1 row = %+v err=%v", b1, err)
	}
}

func TestUploadVersionWithoutPreviousBackend(t *testing.T) {
	s, _, tok := newBackendTestServer(t)
	_, first, _ := uploadForm(t, s, tok, map[string]string{"visibility": "public"})
	code, v2, body := uploadForm(t, s, tok, map[string]string{"slug": first.Slug})
	if code != http.StatusOK || v2.BackendImage != "" {
		t.Fatalf("v2 upload = %d %s", code, body)
	}
	u, _ := s.store.GetUpload(context.Background(), first.Slug)
	if _, err := s.store.GetUploadBackend(context.Background(), u.ID, 2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unexpected row: %v", err)
	}
}

func TestUploadBackendSaveFailure(t *testing.T) {
	s, _, tok := newBackendTestServer(t)
	allowBackendImages(t, s)
	if _, err := s.store.ExecContext(context.Background(), `DROP TABLE upload_backends`); err != nil {
		t.Fatal(err)
	}
	code, _, body := uploadForm(t, s, tok, map[string]string{"visibility": "public", "backend_image": backendTestImage})
	if code != http.StatusInternalServerError {
		t.Fatalf("upload = %d %s, want 500", code, body)
	}
	if list, _ := s.store.ListAllUploads(context.Background()); len(list) != 1 {
		t.Fatalf("page should stay after backend save failure, have %d", len(list))
	}
}

func TestDeleteUploadRemovesBackendData(t *testing.T) {
	s, fake, _ := newBackendTestServer(t)
	_, u, _ := backendFixtureOn(t, s, "del-backend")
	ctx := context.Background()
	if err := s.store.SetUploadBackend(ctx, models.UploadBackend{UploadID: u.ID, Version: 1, Image: backendTestImage, Port: 8080}); err != nil {
		t.Fatal(err)
	}
	instance, err := s.store.GetSetting(ctx, backendInstanceSetting)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.deleteUpload(ctx, *u); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.GetUpload(ctx, u.Slug); err == nil {
		t.Fatal("upload still present")
	}
	fake.Lock()
	defer fake.Unlock()
	if !slices.Contains(fake.VolumesRemoved, backends.VolumeName(instance, u.ID)) {
		t.Fatalf("VolumesRemoved = %v, want %s", fake.VolumesRemoved, backends.VolumeName(instance, u.ID))
	}
}

func TestPruneOldVersionsStopsBackend(t *testing.T) {
	s, _, _ := newBackendTestServer(t)
	_, u, _ := backendFixtureOn(t, s, "prune-backend")
	ctx := context.Background()
	if err := s.store.SetUploadBackend(ctx, models.UploadBackend{UploadID: u.ID, Version: 1, Image: backendTestImage, Port: 8080}); err != nil {
		t.Fatal(err)
	}
	port := newBackendListener(t)
	if _, err := s.backends.Ensure(ctx, backends.Spec{UploadID: u.ID, Version: 1, Image: backendTestImage, Port: port}); err != nil {
		t.Fatal(err)
	}
	if !s.backends.Running(u.ID, 1) {
		t.Fatal("backend should be running before prune")
	}
	s.pruneOldVersions(ctx, time.Now().Add(time.Hour))
	if s.backends.Running(u.ID, 1) {
		t.Fatal("backend of the pruned version still running")
	}
	if _, err := s.store.GetUploadVersion(ctx, u.ID, 1); err == nil {
		t.Fatal("version 1 not pruned")
	}
}
