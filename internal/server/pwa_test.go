package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privacyfence/peek/internal/db"
	"github.com/privacyfence/peek/internal/uploadquota"
	webui "github.com/privacyfence/peek/internal/web"
)

const tinyPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

func TestScanPageMeta(t *testing.T) {
	head := `<head><meta name="theme-color" content="#112233"><link rel="shortcut icon" href='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22/%3E'></head>`
	m := scanPageMeta([]byte(head))
	if m.themeColor != "#112233" || m.iconMIME != "image/svg+xml" || !strings.HasPrefix(string(m.iconData), "<svg") {
		t.Fatalf("meta = %+v", m)
	}
	for _, bad := range []string{
		`<link rel="icon" href="https://evil.example/x.png">`,
		`<link rel="icon" href="data:text/html,<script>alert(1)</script>">`,
		`<link rel="icon" href="data:image/png;base64,!!!">`,
		`<meta name="theme-color" content="red;background:url(x)">`,
	} {
		if m := scanPageMeta([]byte(bad)); m.iconData != nil || m.themeColor != "" {
			t.Fatalf("%s accepted: %+v", bad, m)
		}
	}
	if m := scanPageMeta([]byte(`<link rel="apple-touch-icon" href="data:image/png;base64,` + tinyPNG + `">`)); m.iconMIME != "image/png" {
		t.Fatalf("apple icon = %+v", m)
	}
}

func newPWAServer(t *testing.T, visibility, body string) *Server {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "My App.html", 42, visibility, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	return &Server{store: store, storage: &rawPageStorage{body: body}, renderer: renderer, secret: strings.Repeat("0", 64)}
}

func TestPageManifestAndIcon(t *testing.T) {
	body := `<html><head><meta name="theme-color" content="#abc"><link rel="icon" href="data:image/png;base64,` + tinyPNG + `"></head><body></body></html>`
	s := newPWAServer(t, "public", body)

	req := httptest.NewRequest(http.MethodGet, "/p/page/manifest.webmanifest", nil)
	req.SetPathValue("slug", "page")
	rec := httptest.NewRecorder()
	s.handlePageManifest(rec, req)
	var m webManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	if m.Name != "My App" || m.StartURL != "/p/page" || m.Display != "standalone" || m.ThemeColor != "#abc" ||
		len(m.Icons) != 1 || m.Icons[0].Src != "/p/page/icon" || m.Icons[0].Sizes != "1x1" {
		t.Fatalf("manifest = %+v", m)
	}

	rec = httptest.NewRecorder()
	s.handlePageIcon(rec, req)
	want, _ := base64.StdEncoding.DecodeString(tinyPNG)
	if rec.Header().Get("Content-Type") != "image/png" || rec.Body.String() != string(want) {
		t.Fatalf("icon = %q %d bytes", rec.Header().Get("Content-Type"), rec.Body.Len())
	}

	page := httptest.NewRecorder()
	preq := httptest.NewRequest(http.MethodGet, "/p/page", nil)
	preq.SetPathValue("slug", "page")
	s.handlePage(page, preq)
	out := page.Body.String()
	for _, w := range []string{`rel="manifest"`, `href="/p/page/manifest.webmanifest"`, `href="/p/page/icon"`, `rel="apple-touch-icon"`, `name="theme-color" content="#abc"`} {
		if !strings.Contains(out, w) {
			t.Fatalf("page missing %s:\n%s", w, out)
		}
	}
}

func TestPageManifestDefaultsToPeekIcons(t *testing.T) {
	s := newPWAServer(t, "public", "<html><head></head><body></body></html>")
	req := httptest.NewRequest(http.MethodGet, "/p/page/manifest.webmanifest", nil)
	req.SetPathValue("slug", "page")
	rec := httptest.NewRecorder()
	s.handlePageManifest(rec, req)
	var m webManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || len(m.Icons) != 2 || m.Icons[1].Sizes != "512x512" {
		t.Fatalf("manifest = %+v, %v", m, err)
	}
	rec = httptest.NewRecorder()
	s.handlePageIcon(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("default icon = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestPageManifestHiddenWithoutAccess(t *testing.T) {
	s := newPWAServer(t, "signed_in", `<head><link rel="icon" href="data:image/png;base64,`+tinyPNG+`">`)
	for _, h := range []http.HandlerFunc{s.handlePageManifest, s.handlePageIcon} {
		req := httptest.NewRequest(http.MethodGet, "/p/page/icon", nil)
		req.SetPathValue("slug", "page")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rec.Code)
		}
	}
}
