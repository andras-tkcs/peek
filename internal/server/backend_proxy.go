package server

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/andras-tkcs/peek/internal/backends"
	"github.com/andras-tkcs/peek/internal/models"
)

const (
	backendMaxBody     = 1 << 20
	backendMaxResponse = 8 << 20
)

// handleBackendProxy relays a page's peek.fetch call to its backend container
// after the same access check that guards the page.
func (s *Server) handleBackendProxy(w http.ResponseWriter, r *http.Request) {
	if s.backends == nil {
		jsonError(w, http.StatusNotFound, "backends are not enabled on this server")
		return
	}
	if r.ContentLength > backendMaxBody {
		jsonError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, backendMaxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			jsonError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			jsonError(w, http.StatusBadRequest, "bad request body")
		}
		return
	}

	if r.Header.Get("X-Peek-Svc") != "1" {
		jsonError(w, http.StatusForbidden, "backend requests must come from the page viewer")
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		jsonError(w, http.StatusForbidden, "backend requests must come from the page viewer")
		return
	}
	if !s.backendLimiter.allow(s.rateLimitKey(r)) {
		jsonError(w, http.StatusTooManyRequests, "too many backend requests, slow down")
		return
	}

	slug := r.PathValue("slug")
	rawVersion := r.PathValue("n")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	version, err := strconv.Atoi(rawVersion)
	if err != nil || version < 1 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.viewerCanAccessUpload(r, u) {
		jsonError(w, s.uploadAccessStatus(r, u), uploadAccessRequiredMessage(u))
		return
	}

	b, err := s.store.GetUploadBackend(r.Context(), u.ID, version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "this page version has no backend")
		} else {
			jsonError(w, http.StatusInternalServerError, "db error")
		}
		return
	}
	spec, err := s.backendSpec(r.Context(), b)
	var ep backends.Endpoint
	if err == nil {
		ep, err = s.backends.Ensure(r.Context(), spec)
	}
	if err != nil {
		slog.Error("backend start failed", "slug", slug, "version", version, "err", err)
		jsonError(w, http.StatusBadGateway, "backend failed to start")
		return
	}

	// The still-escaped remainder: the decoded PathValue would turn %3F into "?".
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/svc/"+slug+"/v/"+rawVersion)
	target := ep.URL + rest
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		jsonError(w, http.StatusBadGateway, "backend unavailable")
		return
	}
	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	uploadID := strconv.FormatInt(u.ID, 10)
	req.Header.Set("X-Peek-Backend-Token", ep.Token)
	req.Header.Set("X-Peek-Upload-Id", uploadID)
	req.Header.Set("X-Peek-Version", strconv.Itoa(version))
	if vid := rawViewerID(r); vid != "" {
		req.Header.Set("X-Peek-Viewer", hmacSHA256(s.secret, "backend-viewer:"+uploadID+":"+vid)[:32])
	}
	if u.Visibility == models.UploadVisibilitySignedIn || u.Visibility == models.UploadVisibilityRestricted {
		if a, ok := s.webAuth(r); ok {
			req.Header.Set("X-Peek-User-Id", strconv.FormatInt(a.ID, 10))
			if a.Email != "" {
				req.Header.Set("X-Peek-User-Email", a.Email)
			}
		}
	}

	resp, err := s.backendClient.Do(req)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			jsonError(w, http.StatusGatewayTimeout, "backend timed out")
		} else {
			jsonError(w, http.StatusBadGateway, "backend unavailable")
		}
		return
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, backendMaxResponse+1))
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			jsonError(w, http.StatusGatewayTimeout, "backend timed out")
		} else {
			jsonError(w, http.StatusBadGateway, "backend unavailable")
		}
		return
	}
	if len(out) > backendMaxResponse {
		jsonError(w, http.StatusBadGateway, "backend response too large")
		return
	}
	h := w.Header()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		h.Set("Content-Type", ct)
	}
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}
