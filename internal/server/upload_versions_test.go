package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	versionTestHTML1 = "<!doctype html><html><body>one</body></html>"
	versionTestHTML2 = "<!doctype html><html><body>version two is longer</body></html>"
)

func multipartBody(t *testing.T, filename, content string, fields map[string]string) (*bytes.Buffer, func(*http.Request)) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(content))
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, func(r *http.Request) { r.Header.Set("Content-Type", mw.FormDataContentType()) }
}

func uploadPage(t *testing.T, s *Server, token, content string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, ct := multipartBody(t, "page.html", content, fields)
	return doRequest(t, s, http.MethodPost, "/api/upload", body, asBearer(token), ct)
}

func seedVersionPage(t *testing.T, s *Server, token string) string {
	t.Helper()
	rec := uploadPage(t, s, token, versionTestHTML1, map[string]string{"visibility": "public"})
	if rec.Code != http.StatusOK {
		t.Fatalf("seed upload = %d: %s", rec.Code, rec.Body.String())
	}
	var out uploadResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Version != 1 {
		t.Fatalf("new page version = %d, want 1", out.Version)
	}
	return out.Slug
}

func TestUploadWithSlugCreatesNextVersion(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	slug := seedVersionPage(t, s, admin)

	rec := uploadPage(t, s, admin, versionTestHTML2, map[string]string{"slug": slug})
	if rec.Code != http.StatusOK {
		t.Fatalf("version upload = %d: %s", rec.Code, rec.Body.String())
	}
	var out uploadResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Version != 2 || out.Slug != slug || out.VersionURL != "http://localhost:7700/p/"+slug+"/v/2" {
		t.Fatalf("response = %+v", out)
	}

	rec = doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(admin))
	var list []struct {
		Slug    string `json:"slug"`
		Size    int64  `json:"size"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Size != int64(len(versionTestHTML2)) || list[0].Version != 2 {
		t.Fatalf("list = %+v", list)
	}
}

func TestUploadWithSlugRejectsVisibility(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	slug := seedVersionPage(t, s, admin)

	rec := uploadPage(t, s, admin, versionTestHTML2, map[string]string{"slug": slug, "visibility": "public"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	want := "visibility and password cannot be set when uploading a new version; use the visibility endpoint"
	if !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
		t.Fatalf("body = %s, want %q", rec.Body.String(), want)
	}
}

func TestUploadWithSlugRequiresOwner(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	newAccountWithToken(t, s, "owner@example.test", "owner-token", false)
	newAccountWithToken(t, s, "other@example.test", "other-token", false)

	rec := uploadPage(t, s, "owner-token", versionTestHTML1, map[string]string{"visibility": "public"})
	if rec.Code != http.StatusOK {
		t.Fatalf("seed = %d: %s", rec.Code, rec.Body.String())
	}
	var seeded uploadResp
	_ = json.Unmarshal(rec.Body.Bytes(), &seeded)

	rec = uploadPage(t, s, "other-token", versionTestHTML2, map[string]string{"slug": seeded.Slug})
	if rec.Code != http.StatusForbidden || !bytes.Contains(rec.Body.Bytes(), []byte("not owner")) {
		t.Fatalf("other = %d: %s", rec.Code, rec.Body.String())
	}
	rec = uploadPage(t, s, admin, versionTestHTML2, map[string]string{"slug": seeded.Slug})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadWithUnknownSlugReturns404(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	rec := uploadPage(t, s, admin, versionTestHTML2, map[string]string{"slug": "missing"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteUploadRemovesAllVersionObjects(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	slug := seedVersionPage(t, s, admin)
	if rec := uploadPage(t, s, admin, versionTestHTML2, map[string]string{"slug": slug}); rec.Code != http.StatusOK {
		t.Fatalf("version upload = %d: %s", rec.Code, rec.Body.String())
	}
	u, err := s.store.GetUpload(t.Context(), slug)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := s.store.ListUploadVersions(t.Context(), u.ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("versions = %+v, err = %v", versions, err)
	}
	for _, v := range versions {
		rc, err := s.storage.Open(t.Context(), v.ObjectKey)
		if err != nil {
			t.Fatalf("open %s before delete: %v", v.ObjectKey, err)
		}
		_ = rc.Close()
	}

	rec := doRequest(t, s, http.MethodDelete, "/api/uploads/"+slug, nil, asBearer(admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	for _, v := range versions {
		if rc, err := s.storage.Open(t.Context(), v.ObjectKey); err == nil {
			_ = rc.Close()
			t.Fatalf("object %s still exists after delete", v.ObjectKey)
		}
	}
}
