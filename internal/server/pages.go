package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	"github.com/puemos/peek/internal/models"
	webui "github.com/puemos/peek/internal/web"
)

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		s.renderWebError(w, http.StatusNotFound, "Page not found", "This shared page does not exist or is no longer available.")
		return
	}
	s.servePage(w, r, u, u.LatestVersion, "/p/"+slug)
}

func (s *Server) handlePageVersion(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
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
	if u.Visibility == models.UploadVisibilityPassword && !s.viewerCanAccessUpload(r, u) {
		s.renderHTML(w, http.StatusOK, webui.TemplateGate, webui.GateData{Slug: slug, Action: pagePath})
		return
	}
	if u.Visibility == models.UploadVisibilityPrivate && !s.viewerCanAccessUpload(r, u) {
		s.setNextPath(w, pagePath)
		if _, err := r.Cookie(sessionCookie); err == nil {
			s.clearCookie(w, sessionCookie, "/")
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if u.Visibility == models.UploadVisibilityRestricted && !s.viewerCanAccessUpload(r, u) {
		a, ok := s.webAuth(r)
		if !ok {
			s.setNextPath(w, pagePath)
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
	if u.Visibility == models.UploadVisibilityPassword {
		s.setPageAuthCookie(w, u)
	}
	vid := s.visitorID(w, r)
	s.recordVisit(r, u, vid, version)

	rawURL := "/raw/" + slug + "/v/" + strconv.Itoa(version) + "?t=" + makeViewToken(s.secret, viewSubject(slug, version), vid) + "&v=" + vid
	d := pageData{
		Name: u.Name, Slug: slug,
		RawURL: rawURL, Visibility: u.Visibility,
		Version: version, LatestVersion: u.LatestVersion,
	}
	w.Header().Set("Content-Security-Policy", webui.PageCSP)
	s.renderHTML(w, http.StatusOK, webui.TemplatePage, d)
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
	if err := r.ParseForm(); err != nil {
		s.renderWebError(w, http.StatusBadRequest, "Bad request", "The password form could not be read.")
		return
	}
	pw := r.FormValue("password")
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) != nil {
		s.renderHTML(w, http.StatusUnauthorized, webui.TemplateGate, webui.GateData{Slug: slug, Action: pagePath, Error: true})
		return
	}
	s.setPageAuthCookie(w, u)
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

// rawViewerID resolves the visitor id a raw view token is bound to.
func rawViewerID(r *http.Request) string {
	vid := r.URL.Query().Get("v")
	if vid == "" {
		// Fall back to cookie-based vid for backward compat.
		if c, err := r.Cookie(visitorCookie); err == nil {
			vid = c.Value
		}
	}
	return vid
}

// handleRaw serves the latest version for tokens minted before versioned raw
// URLs existed; those tokens are bound to the bare slug.
func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Require a valid view token (issued by /p) so /raw cannot be hot-linked
	// or used to bypass the password gate. The token is bound to the visitor
	// id so a shared raw URL won't work for a different viewer.
	if !verifyViewToken(s.secret, r.URL.Query().Get("t"), slug, rawViewerID(r)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ver, err := s.store.GetUploadVersion(r.Context(), u.ID, u.LatestVersion)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.serveRawObject(w, r, slug, ver.ObjectKey)
}

func (s *Server) handleRawVersion(w http.ResponseWriter, r *http.Request) {
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
	ver, err := s.store.GetUploadVersion(r.Context(), u.ID, n)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.serveRawObject(w, r, slug, ver.ObjectKey)
}

func (s *Server) serveRawObject(w http.ResponseWriter, r *http.Request, slug, objectKey string) {
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

func writeRawHTML(w http.ResponseWriter, slug string, body io.Reader, insertOffset int64) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Allow the user's HTML to run inline scripts/styles & load resources, but
	// only permit embedding by our own origin. The iframe sandbox already
	// gives it an opaque origin so it cannot touch the server or parent.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; "+
			"script-src 'unsafe-inline' 'unsafe-eval' https: http: data: blob:; "+
			"style-src 'unsafe-inline' https: http:; "+
			"img-src https: http: data: blob:; "+
			"media-src https: http: data: blob:; "+
			"font-src https: http: data:; "+
			"connect-src https: http:; "+
			"frame-ancestors 'self'")
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
