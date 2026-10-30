package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/privacyfence/peek/internal/models"
	webui "github.com/privacyfence/peek/internal/web"
)

// Uploaded pages are sandboxed, so they cannot register their own manifest or
// favicon. The wrapper reads the page's <head> instead and serves a favicon and a
// web app manifest from its own origin, which lets browsers install the page as
// an app on iOS and Android.

const (
	// pageHeadScanLimit bounds how much of an upload is read to find <head> metadata.
	pageHeadScanLimit = 1 << 20
	// pageIconLimit bounds a decoded favicon.
	pageIconLimit = 256 << 10
)

// pageMeta is the wrapper-relevant metadata declared in an uploaded page's <head>.
type pageMeta struct {
	iconMIME   string
	iconData   []byte
	themeColor string
}

var (
	headEndRe   = regexp.MustCompile(`(?i)</head\s*>|<body[\s>]`)
	headTagRe   = regexp.MustCompile(`(?is)<(link|meta)\b([^>]*)>`)
	attrRe      = regexp.MustCompile(`(?is)([a-z][a-z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	themeHexRe  = regexp.MustCompile(`^#[0-9a-fA-F]{3,8}$`)
	iconMIMEs   = map[string]bool{"image/png": true, "image/svg+xml": true, "image/jpeg": true, "image/gif": true, "image/webp": true, "image/x-icon": true, "image/vnd.microsoft.icon": true}
	svgIconSand = "sandbox; default-src 'none'; style-src 'unsafe-inline'"
)

func readPageHead(r io.Reader) []byte {
	var buf []byte
	chunk := make([]byte, 32*1024)
	for len(buf) < pageHeadScanLimit {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if loc := headEndRe.FindIndex(buf); loc != nil {
			return buf[:loc[0]]
		}
		if err != nil {
			break
		}
	}
	return buf
}

func parseAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(s, -1) {
		v := m[2] + m[3] + m[4]
		if _, dup := out[strings.ToLower(m[1])]; !dup {
			out[strings.ToLower(m[1])] = html.UnescapeString(v)
		}
	}
	return out
}

// scanPageMeta finds the first usable data: URI icon (rel="icon" preferred over
// rel="apple-touch-icon") and a hex theme-color. Only data: URIs are honoured:
// an upload is a single file, and a remote icon URL would make every viewer's
// browser contact a third party from Peek's own origin.
func scanPageMeta(head []byte) pageMeta {
	var m pageMeta
	var appleMIME string
	var appleData []byte
	for _, tag := range headTagRe.FindAllStringSubmatch(string(head), -1) {
		attrs := parseAttrs(tag[2])
		if strings.EqualFold(tag[1], "meta") {
			if m.themeColor == "" && strings.EqualFold(attrs["name"], "theme-color") && themeHexRe.MatchString(strings.TrimSpace(attrs["content"])) {
				m.themeColor = strings.TrimSpace(attrs["content"])
			}
			continue
		}
		var isIcon, isApple bool
		for _, tok := range strings.Fields(strings.ToLower(attrs["rel"])) {
			isIcon = isIcon || tok == "icon"
			isApple = isApple || tok == "apple-touch-icon"
		}
		if !isIcon && !isApple {
			continue
		}
		mime, data, ok := decodeDataIcon(attrs["href"])
		if !ok {
			continue
		}
		if isIcon && m.iconData == nil {
			m.iconMIME, m.iconData = mime, data
		} else if isApple && appleData == nil {
			appleMIME, appleData = mime, data
		}
	}
	if m.iconData == nil {
		m.iconMIME, m.iconData = appleMIME, appleData
	}
	return m
}

func decodeDataIcon(href string) (string, []byte, bool) {
	href = strings.TrimSpace(href)
	if len(href) < 6 || !strings.EqualFold(href[:5], "data:") {
		return "", nil, false
	}
	header, payload, ok := strings.Cut(href[5:], ",")
	if !ok {
		return "", nil, false
	}
	params := strings.Split(header, ";")
	mime := strings.ToLower(strings.TrimSpace(params[0]))
	if !iconMIMEs[mime] {
		return "", nil, false
	}
	b64 := false
	for _, p := range params[1:] {
		b64 = b64 || strings.EqualFold(strings.TrimSpace(p), "base64")
	}
	raw, err := url.PathUnescape(payload)
	if err != nil {
		return "", nil, false
	}
	data := []byte(raw)
	if b64 {
		data, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(raw), ""))
		if err != nil {
			return "", nil, false
		}
	}
	if len(data) == 0 || len(data) > pageIconLimit {
		return "", nil, false
	}
	return mime, data, true
}

// loadPageMeta reads the head of one stored version. It returns an empty pageMeta
// when storage or the version is unavailable, so a page never fails to render
// over its icon.
func (s *Server) loadPageMeta(r *http.Request, u *models.Upload, version int) pageMeta {
	if s.storage == nil || s.store == nil {
		return pageMeta{}
	}
	ver, err := s.store.GetUploadVersion(r.Context(), u.ID, version)
	if err != nil {
		return pageMeta{}
	}
	rc, err := s.storage.Open(r.Context(), ver.ObjectKey)
	if err != nil {
		return pageMeta{}
	}
	defer rc.Close()
	return scanPageMeta(readPageHead(rc))
}

// applyPageMeta fills the favicon, theme color and manifest fields of the viewer page.
func (s *Server) applyPageMeta(r *http.Request, d *pageData, u *models.Upload, version int, live bool) {
	meta := s.loadPageMeta(r, u, version)
	base := "/p/" + u.Slug
	if meta.iconData != nil {
		d.IconURL = base + "/icon" + iconQuery(version, u.LatestVersion)
		if meta.iconMIME != "image/svg+xml" {
			d.AppleIconURL = d.IconURL
		}
	}
	d.ThemeColor = meta.themeColor
	if live {
		d.ManifestURL = base + "/manifest.webmanifest"
	}
}

func iconQuery(version, latest int) string {
	if version == latest {
		return ""
	}
	return "?v=" + strconv.Itoa(version)
}

// pageForMeta resolves the page and version for the icon and manifest routes and
// applies the same access rule as the page itself, without login redirects.
func (s *Server) pageForMeta(w http.ResponseWriter, r *http.Request) (*models.Upload, int, bool) {
	u, err := s.store.GetUpload(r.Context(), r.PathValue("slug"))
	if err != nil || !s.viewerCanAccessUpload(r, u) {
		http.NotFound(w, r)
		return nil, 0, false
	}
	version := u.LatestVersion
	if v := r.URL.Query().Get("v"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.NotFound(w, r)
			return nil, 0, false
		}
		if _, err := s.store.GetUploadVersion(r.Context(), u.ID, n); err != nil {
			http.NotFound(w, r)
			return nil, 0, false
		}
		version = n
	}
	return u, version, true
}

func (s *Server) handlePageIcon(w http.ResponseWriter, r *http.Request) {
	u, version, ok := s.pageForMeta(w, r)
	if !ok {
		return
	}
	meta := s.loadPageMeta(r, u, version)
	if meta.iconData == nil {
		webui.ServeAsset(w, r, "favicon.png")
		return
	}
	w.Header().Set("Content-Type", meta.iconMIME)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=60")
	if meta.iconMIME == "image/svg+xml" {
		w.Header().Set("Content-Security-Policy", svgIconSand)
	}
	if _, err := w.Write(meta.iconData); err != nil {
		slog.Warn("write page icon", "slug", u.Slug, "err", err)
	}
}

type manifestIcon struct {
	Src   string `json:"src"`
	Sizes string `json:"sizes"`
	Type  string `json:"type"`
}

type webManifest struct {
	Name            string         `json:"name"`
	ShortName       string         `json:"short_name"`
	ID              string         `json:"id"`
	StartURL        string         `json:"start_url"`
	Scope           string         `json:"scope"`
	Display         string         `json:"display"`
	BackgroundColor string         `json:"background_color"`
	ThemeColor      string         `json:"theme_color,omitempty"`
	Icons           []manifestIcon `json:"icons"`
}

func appName(name, slug string) string {
	n := strings.TrimSpace(name)
	lower := strings.ToLower(n)
	for _, ext := range []string{".html", ".htm"} {
		if strings.HasSuffix(lower, ext) {
			n = strings.TrimSpace(n[:len(n)-len(ext)])
			break
		}
	}
	if n == "" {
		return slug
	}
	return n
}

func shortName(name string) string {
	r := []rune(name)
	if len(r) > 12 {
		return string(r[:12])
	}
	return name
}

func (s *Server) handlePageManifest(w http.ResponseWriter, r *http.Request) {
	u, _, ok := s.pageForMeta(w, r)
	if !ok {
		return
	}
	// The manifest always describes the latest version, like the page link it installs.
	meta := s.loadPageMeta(r, u, u.LatestVersion)
	base := "/p/" + u.Slug
	name := appName(u.Name, u.Slug)
	m := webManifest{
		Name: name, ShortName: shortName(name),
		ID: base, StartURL: base, Scope: base,
		Display: "standalone", BackgroundColor: "#ffffff", ThemeColor: meta.themeColor,
	}
	if meta.iconData != nil {
		m.Icons = []manifestIcon{{Src: base + "/icon", Sizes: iconSizes(meta), Type: meta.iconMIME}}
	} else {
		m.Icons = []manifestIcon{
			{Src: webui.AssetURL("icon-192.png"), Sizes: "192x192", Type: "image/png"},
			{Src: webui.AssetURL("icon-512.png"), Sizes: "512x512", Type: "image/png"},
		}
	}
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "private, max-age=60")
	if err := json.NewEncoder(w).Encode(m); err != nil {
		slog.Warn("write page manifest", "slug", u.Slug, "err", err)
	}
}

// iconSizes reports "WxH" for raster formats Go can read, and "any" otherwise.
func iconSizes(m pageMeta) string {
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(m.iconData)); err == nil && cfg.Width > 0 && cfg.Height > 0 {
		return strconv.Itoa(cfg.Width) + "x" + strconv.Itoa(cfg.Height)
	}
	return "any"
}
