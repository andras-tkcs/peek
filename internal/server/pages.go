package server

import (
	"bytes"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/andras-tkcs/peek/internal/models"
	webui "github.com/andras-tkcs/peek/internal/web"
)

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		if cur, aerr := s.store.ResolveSlugAlias(r.Context(), slug); aerr == nil {
			redirectRenamedPage(w, r, "/p/"+cur)
			return
		}
		s.renderWebError(w, http.StatusNotFound, "Page not found", "This shared page does not exist or is no longer available.")
		return
	}
	s.servePage(w, r, u, u.LatestVersion, "/p/"+slug)
}

// redirectRenamedPage sends an old link to the page's current link. 302, not 301:
// a page can be renamed back, and a cached permanent redirect would then loop.
func redirectRenamedPage(w http.ResponseWriter, r *http.Request, path string) {
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, path, http.StatusFound)
}

func (s *Server) handlePageVersion(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		if cur, aerr := s.store.ResolveSlugAlias(r.Context(), slug); aerr == nil {
			n, err := strconv.Atoi(r.PathValue("n"))
			if err != nil || n < 1 {
				s.renderVersionNotFound(w)
				return
			}
			redirectRenamedPage(w, r, "/p/"+cur+"/v/"+strconv.Itoa(n))
			return
		}
		s.renderWebError(w, http.StatusNotFound, "Page not found", "This shared page does not exist or is no longer available.")
		return
	}
	n, ok := s.parseExistingVersion(r, u)
	if !ok {
		s.renderVersionNotFound(w)
		return
	}
	s.servePage(w, r, u, n, "/p/"+slug+"/v/"+strconv.Itoa(n))
}

func (s *Server) renderVersionNotFound(w http.ResponseWriter) {
	s.renderWebError(w, http.StatusNotFound, "Version not found", "This version of the page does not exist or is no longer available.")
}

// parseExistingVersion parses the {n} path value and checks the version exists.
func (s *Server) parseExistingVersion(r *http.Request, u *models.Upload) (int, bool) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 {
		return 0, false
	}
	if _, err := s.store.GetUploadVersion(r.Context(), u.ID, n); err != nil {
		return 0, false
	}
	return n, true
}

func (s *Server) servePage(w http.ResponseWriter, r *http.Request, u *models.Upload, version int, pagePath string) {
	slug := u.Slug
	pageQuery := pagePath
	if r.URL.RawQuery != "" {
		pageQuery += "?" + r.URL.RawQuery
	}
	if u.Visibility == models.UploadVisibilityPassword && !s.viewerCanAccessUpload(r, u) {
		s.renderHTML(w, http.StatusOK, webui.TemplateGate, webui.GateData{Slug: slug, Action: pageQuery})
		return
	}
	if u.Visibility == models.UploadVisibilitySignedIn && !s.viewerCanAccessUpload(r, u) {
		s.setNextPath(w, nextPathWithQuery(pagePath, r.URL.RawQuery))
		if _, err := r.Cookie(sessionCookie); err == nil {
			s.clearCookie(w, sessionCookie, "/")
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if u.Visibility == models.UploadVisibilityRestricted && !s.viewerCanAccessUpload(r, u) {
		a, ok := s.webAuth(r)
		if !ok {
			s.setNextPath(w, nextPathWithQuery(pagePath, r.URL.RawQuery))
			if _, err := r.Cookie(sessionCookie); err == nil {
				s.clearCookie(w, sessionCookie, "/")
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		who := a.Email
		if who == "" {
			who = a.Name
		}
		s.auditRequest(r, who, "page.access.denied", "slug="+slug)
		s.renderWebError(w, http.StatusForbidden, "Access denied", "You are signed in as "+who+", which has not been given access to this page. Ask the page owner to share it with you.")
		return
	}
	// Fail closed: any visibility the branches above do not handle (an unknown
	// stored value) is served only to viewers viewerCanAccessUpload admits, which
	// is nobody.
	if !s.viewerCanAccessUpload(r, u) {
		s.renderWebError(w, http.StatusForbidden, "Access denied", "This page is not available.")
		return
	}
	if u.Visibility == models.UploadVisibilityPassword {
		s.setPageAuthCookie(w, u)
	}
	vid := s.visitorID(w, r)
	s.recordVisit(r, u, vid, version)

	rawURL := "/raw/" + slug + "/v/" + strconv.Itoa(version) + "?t=" + makeViewToken(s.secret, viewSubject(slug, version), vid)
	d := pageData{
		Name: u.Name, Slug: slug,
		RawURL: rawURL, FrameURL: frameURL(rawURL, r.URL.RawQuery), Visibility: u.Visibility,
		Version: version, LatestVersion: u.LatestVersion,
	}
	w.Header().Set("Content-Security-Policy", webui.PageCSP)
	s.renderHTML(w, http.StatusOK, webui.TemplatePage, d)
}

func querysuffix(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

// frameURL appends the page's query string to the iframe URL as a fragment.
// Fragments are never sent to the server, and the sandboxed page can read them
// synchronously from location.hash, so on-page filters survive reloads and
// shared links without the query reaching /raw.
func frameURL(rawURL, query string) string {
	if query == "" {
		return rawURL
	}
	return rawURL + "#" + query
}

// nextPathWithQuery keeps the query across a login redirect, unless it holds
// bytes a cookie value cannot carry.
func nextPathWithQuery(path, query string) string {
	if query == "" || strings.ContainsAny(query, " \",;\\") {
		return path
	}
	return path + "?" + query
}

func (s *Server) handlePagePassword(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		s.renderWebError(w, http.StatusNotFound, "Page not found", "This shared page does not exist or is no longer available.")
		return
	}
	pagePath := "/p/" + slug
	if r.PathValue("n") != "" {
		n, ok := s.parseExistingVersion(r, u)
		if !ok {
			s.renderVersionNotFound(w)
			return
		}
		pagePath += "/v/" + strconv.Itoa(n)
	}
	if u.Visibility != models.UploadVisibilityPassword {
		http.Redirect(w, r, pagePath, http.StatusSeeOther)
		return
	}
	failKey := strconv.FormatInt(u.ID, 10) // upload id: stable across renames
	if s.pagePasswordFailLimiter.blocked(failKey) {
		rateLimitError(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderWebError(w, http.StatusBadRequest, "Bad request", "The password form could not be read.")
		return
	}
	pw := r.FormValue("password")
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) != nil {
		s.pagePasswordFailLimiter.recordFailure(failKey)
		s.renderHTML(w, http.StatusUnauthorized, webui.TemplateGate, webui.GateData{Slug: slug, Action: pagePath + querysuffix(r), Error: true})
		return
	}
	s.setPageAuthCookie(w, u)
	if r.URL.RawQuery != "" {
		pagePath += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, pagePath, http.StatusSeeOther)
}

func (s *Server) setPageAuthCookie(w http.ResponseWriter, u *models.Upload) {
	s.setCookie(w, &http.Cookie{
		Name:     authCookieName(u.Slug),
		Value:    makePageAuthCookieValue(s.secret, u.Slug, u.PasswordHash, sessionTTL),
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})
}

// rawViewerID returns the visitor id from the HttpOnly hn_vid cookie. The raw URL
// alone is never a credential: without the cookie that /p set, it is refused.
func rawViewerID(r *http.Request) string {
	if c, err := r.Cookie(visitorCookie); err == nil {
		return c.Value
	}
	return ""
}

// rawFetchAllowed reports whether a /raw request may be served. Browsers that send
// Sec-Fetch-Dest must be loading the page into an iframe; a top-level navigation
// ("document"), fetch ("empty") or any other destination is refused. Requests
// without the header (older browsers, non-browser clients) still need a valid
// view token and visitor cookie. A download=1 request is the toolbar's top-level
// attachment link, so it may also arrive as "document" or "empty"; the response
// is an attachment and the token, cookie and access checks still apply.
func rawFetchAllowed(r *http.Request) bool {
	dest := r.Header.Get("Sec-Fetch-Dest")
	if dest == "" || dest == "iframe" {
		return true
	}
	return r.URL.Query().Get("download") == "1" && (dest == "document" || dest == "empty")
}

func (s *Server) handleRawVersion(w http.ResponseWriter, r *http.Request) {
	if !rawFetchAllowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	slug := r.PathValue("slug")
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 {
		http.NotFound(w, r)
		return
	}
	// Verify the token before any DB lookup so the response does not reveal
	// which versions exist.
	if !verifyViewToken(s.secret, r.URL.Query().Get("t"), viewSubject(slug, n), rawViewerID(r)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Re-check access on every load so a visibility, password or grant change
	// applies to raw URLs minted before it.
	if !s.viewerCanAccessUpload(r, u) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ver, err := s.store.GetUploadVersion(r.Context(), u.ID, n)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.serveRawObject(w, r, slug, u.Name, ver.ObjectKey)
}

func (s *Server) serveRawObject(w http.ResponseWriter, r *http.Request, slug, name, objectKey string) {
	if r.URL.Query().Get("download") == "1" {
		s.serveDownload(w, r, slug, name, objectKey)
		return
	}
	rc, err := s.storage.Open(r.Context(), objectKey)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	insertOffset, err := bridgeInsertOffset(rc)
	closeErr := rc.Close()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if closeErr != nil {
		slog.Warn("close raw html scan", "slug", slug, "err", closeErr)
	}
	rc, err = s.storage.Open(r.Context(), objectKey)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer rc.Close()
	writeRawHTML(w, slug, rc, insertOffset)
}

// serveDownload sends the original uploaded HTML, without the injected bridge,
// as an attachment.
func (s *Server) serveDownload(w http.ResponseWriter, r *http.Request, slug, name, objectKey string) {
	rc, err := s.storage.Open(r.Context(), objectKey)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", rawContentCSP)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": downloadFilename(name, slug)}))
	if _, err := io.Copy(w, rc); err != nil {
		slog.Error("write download response", "slug", slug, "err", err)
	}
}

func downloadFilename(name, slug string) string {
	name = strings.TrimSpace(filepath.Base(strings.ReplaceAll(name, "\\", "/")))
	if name == "" || name == "." || name == "/" {
		name = slug
	}
	if ext := strings.ToLower(filepath.Ext(name)); ext != ".html" && ext != ".htm" {
		name += ".html"
	}
	return name
}

// rawSandbox is the sandbox applied to uploaded HTML. It must stay identical to
// the sandbox attribute of #hn-frame in internal/web/templates/page.gohtml;
// TestRawSandboxMatchesIframeAttribute enforces this.
const rawSandbox = "allow-scripts allow-popups"

// rawContentCSP starts with "sandbox allow-scripts allow-popups" and lets uploaded HTML run inline scripts/styles and load remote
// resources. The sandbox directive gives the document an opaque origin even when
// /raw is opened as a top-level page, so it can never act as Peek's origin.
const rawContentCSP = "sandbox " + rawSandbox + "; " +
	"default-src 'none'; " +
	"script-src 'unsafe-inline' 'unsafe-eval' https: http: data: blob:; " +
	"style-src 'unsafe-inline' https: http:; " +
	"img-src https: http: data: blob:; " +
	"media-src https: http: data: blob:; " +
	"font-src https: http: data:; " +
	"connect-src https: http:; " +
	"frame-ancestors 'self'"

func writeRawHTML(w http.ResponseWriter, slug string, body io.Reader, insertOffset int64) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", rawContentCSP)
	if insertOffset > 0 {
		if _, err := io.CopyN(w, body, insertOffset); err != nil {
			slog.Error("write raw html response", "slug", slug, "err", err)
			return
		}
	}
	if _, err := w.Write(bridgeScriptTag()); err != nil {
		slog.Error("write raw html response", "slug", slug, "err", err)
		return
	}
	if _, err := io.Copy(w, body); err != nil {
		slog.Error("write raw html response", "slug", slug, "err", err)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.renderWebError(w, http.StatusNotFound, "Page not found", "The requested page does not exist.")
		return
	}
	if s.setupRequired(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.renderHTML(w, http.StatusOK, webui.TemplateIndex, webui.IndexData{BaseURL: s.baseURL})
}

// injectBridge appends the picker script so the parent can drive element
// selection over postMessage. Runs inside the sandboxed iframe.
func injectBridge(b []byte) []byte {
	offset, err := bridgeInsertOffset(bytes.NewReader(b))
	if err != nil {
		return b
	}
	tag := bridgeScriptTag()
	return append(append(append([]byte{}, b[:offset]...), tag...), b[offset:]...)
}

func bridgeScriptTag() []byte {
	return []byte(`<script src="` + webui.AssetURL("bridge.js") + `"></script>`)
}

func bridgeInsertOffset(r io.Reader) (int64, error) {
	marker := []byte("</body>")
	marker2 := []byte("</html>")
	const maxTail = len("</body>") - 1
	buf := make([]byte, 32*1024)
	tail := make([]byte, 0, maxTail)
	var (
		total    int64
		lastBody int64 = -1
		lastHTML int64 = -1
	)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			prevTotal := total
			combined := make([]byte, 0, len(tail)+n)
			combined = append(combined, tail...)
			combined = append(combined, buf[:n]...)
			combinedStart := total - int64(len(tail))
			lower := bytes.ToLower(combined)
			lastBody = lastMarkerOffset(lower, marker, combinedStart, prevTotal, lastBody)
			lastHTML = lastMarkerOffset(lower, marker2, combinedStart, prevTotal, lastHTML)
			total += int64(n)
			if len(combined) > maxTail {
				tail = append(tail[:0], combined[len(combined)-maxTail:]...)
			} else {
				tail = append(tail[:0], combined...)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if lastBody >= 0 {
		return lastBody, nil
	}
	if lastHTML >= 0 {
		return lastHTML, nil
	}
	return total, nil
}

func lastMarkerOffset(lower, marker []byte, combinedStart, previousTotal, current int64) int64 {
	for searchFrom := 0; searchFrom < len(lower); {
		idx := bytes.Index(lower[searchFrom:], marker)
		if idx < 0 {
			return current
		}
		idx += searchFrom
		absolute := combinedStart + int64(idx)
		if absolute+int64(len(marker)) > previousTotal {
			current = absolute
		}
		searchFrom = idx + 1
	}
	return current
}
