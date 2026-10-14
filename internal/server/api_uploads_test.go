package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const pageCovHTML = "<!doctype html><html><body>hello</body></html>"

// pageCovMultipart builds a multipart body with the given form fields and, when
// fileName is not empty, a "file" part.
func pageCovMultipart(t *testing.T, fields map[string]string, fileName, content string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if fileName != "" {
		fw, err := mw.CreateFormFile("file", fileName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func pageCovContentType(ct string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Content-Type", ct) }
}

// pageCovUpload uploads HTML through the API as the given token and returns the slug.
func pageCovUpload(t *testing.T, s *Server, token, query string) string {
	t.Helper()
	rec := doRequest(t, s, http.MethodPost, "/api/upload?visibility=public"+query, strings.NewReader(pageCovHTML), asBearer(token), pageCovContentType("text/html"))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Slug
}

func TestPageCovAPIHandlersRequireAuthContext(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	handlers := map[string]http.HandlerFunc{
		"upload":     s.handleUpload,
		"list":       s.handleListUploads,
		"delete":     s.handleDeleteUpload,
		"visibility": s.handleSetVisibility,
		"delete-all": s.handleDeleteAllByOwner,
		"account-co": s.handleAddAccountComment,
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
		})
	}
}

func TestPageCovUploadBodyKindRejectsEmptyContentType(t *testing.T) {
	if _, ok := uploadBodyKindFromContentType(""); ok {
		t.Fatal("empty content type accepted")
	}
}

func TestPageCovUploadRequestErrors(t *testing.T) {
	s, token := newHandlerTestServer(t)
	if err := s.store.SetSetting(context.Background(), "max_upload", "100"); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("a", 101)
	noFile, noFileCT := pageCovMultipart(t, map[string]string{"visibility": "public"}, "", "")
	bigFile, bigFileCT := pageCovMultipart(t, nil, "big.html", big)
	tests := []struct {
		name string
		path string
		body *bytes.Buffer
		ct   string
		want int
	}{
		{"malformed multipart", "/api/upload", bytes.NewBufferString("not multipart"), "multipart/form-data; boundary=zzz", http.StatusBadRequest},
		{"missing file", "/api/upload", noFile, noFileCT, http.StatusBadRequest},
		{"multipart too large", "/api/upload", bigFile, bigFileCT, http.StatusRequestEntityTooLarge},
		{"raw password visibility", "/api/upload?visibility=password", bytes.NewBufferString(pageCovHTML), "text/html", http.StatusBadRequest},
		{"raw too large", "/api/upload", bytes.NewBufferString(big), "text/html", http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(t, s, http.MethodPost, tt.path, tt.body, asBearer(token), pageCovContentType(tt.ct))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestPageCovUploadVersionServiceFailure(t *testing.T) {
	s, token := newHandlerTestServer(t)
	slug := pageCovUpload(t, s, token, "")
	s.storage = &faultStorage{saveErr: errors.New("disk full")}
	rec := doRequest(t, s, http.MethodPost, "/api/upload?slug="+slug, strings.NewReader(pageCovHTML), asBearer(token), pageCovContentType("text/html"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPageCovListUploadsStoreFailure(t *testing.T) {
	s, token := newHandlerTestServer(t)
	dropTable(t, s.store, "uploads")
	rec := doRequest(t, s, http.MethodGet, "/api/uploads", nil, asBearer(token))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPageCovDeleteUploadBranches(t *testing.T) {
	s, token := newHandlerTestServer(t)
	newAccountWithToken(t, s, "other@example.test", "other-token", false)
	slug := pageCovUpload(t, s, token, "")

	if rec := doRequest(t, s, http.MethodDelete, "/api/uploads/missing", nil, asBearer(token)); rec.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodDelete, "/api/uploads/"+slug, nil, asBearer("other-token")); rec.Code != http.StatusForbidden {
		t.Fatalf("non-owner status = %d", rec.Code)
	}
	good := s.storage
	s.storage = &faultStorage{deleteErr: errors.New("store down")}
	if rec := doRequest(t, s, http.MethodDelete, "/api/uploads/"+slug, nil, asBearer(token)); rec.Code != http.StatusInternalServerError {
		t.Fatalf("storage failure status = %d", rec.Code)
	}
	s.storage = good
	if rec := doRequest(t, s, http.MethodDelete, "/api/uploads/"+slug, nil, asBearer(token)); rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d", rec.Code)
	}
}

func TestPageCovSetVisibilityBranches(t *testing.T) {
	s, token := newHandlerTestServer(t)
	newAccountWithToken(t, s, "other@example.test", "other-token", false)
	slug := pageCovUpload(t, s, token, "")
	path := "/api/uploads/" + slug + "/visibility"

	if rec := doRequest(t, s, http.MethodPost, "/api/uploads/missing/visibility", strings.NewReader(`{}`), asBearer(token), withJSON()); rec.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodPost, path, strings.NewReader(`{"visibility":"public"}`), asBearer("other-token"), withJSON()); rec.Code != http.StatusForbidden {
		t.Fatalf("non-owner status = %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodPost, path, strings.NewReader(`{`), asBearer(token), withJSON()); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json status = %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodPost, path, strings.NewReader(`{"visibility":"bogus"}`), asBearer(token), withJSON()); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad visibility status = %d", rec.Code)
	}
	addFailTrigger(t, s.store, "uploads", "UPDATE")
	if rec := doRequest(t, s, http.MethodPost, path, strings.NewReader(`{"visibility":"private"}`), asBearer(token), withJSON()); rec.Code != http.StatusInternalServerError {
		t.Fatalf("store failure status = %d", rec.Code)
	}
}

func TestPageCovDeleteAllByOwner(t *testing.T) {
	s, token := newHandlerTestServer(t)
	pageCovUpload(t, s, token, "")
	pageCovUpload(t, s, token, "")

	good := s.storage
	s.storage = &faultStorage{deleteErr: errors.New("store down")}
	rec := doRequest(t, s, http.MethodDelete, "/api/uploads-by-owner", nil, asBearer(token))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deleted":0`) {
		t.Fatalf("failing delete-all = %d %s", rec.Code, rec.Body.String())
	}

	s.storage = good
	rec = doRequest(t, s, http.MethodDelete, "/api/uploads-by-owner", nil, asBearer(token))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deleted":2`) {
		t.Fatalf("delete-all = %d %s", rec.Code, rec.Body.String())
	}

	dropTable(t, s.store, "uploads")
	rec = doRequest(t, s, http.MethodDelete, "/api/uploads-by-owner", nil, asBearer(token))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list failure status = %d", rec.Code)
	}
}
