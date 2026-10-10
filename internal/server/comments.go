package server

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/puemos/peek/internal/models"
)

type commentIn struct {
	Selector   string `json:"selector"`
	Text       string `json:"element_text"`
	AnchorKind string `json:"anchor_kind"`
	Name       string `json:"name"`
	Body       string `json:"body"`
}

type commentOut struct {
	ID         int64  `json:"id"`
	Selector   string `json:"selector"`
	Text       string `json:"element_text"`
	AnchorKind string `json:"anchor_kind"`
	Author     string `json:"author"`
	Body       string `json:"body"`
	CreatedAt  int64  `json:"created_at"`
}

func (s *Server) handleListComments(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	// API callers (the CLI) authenticate with a bearer token and may only read
	// comments for uploads they own. Browser viewers send no token and go
	// through the public / password-cookie gate instead.
	if tok := bearerToken(r); tok != "" {
		owner, err := s.store.GetToken(r.Context(), tok)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if owner.Disabled {
			jsonError(w, http.StatusForbidden, "account disabled")
			return
		}
		if u.OwnerAccountID != owner.AccountID && !owner.IsAdmin {
			jsonError(w, http.StatusForbidden, "not owner")
			return
		}
	} else if !s.viewerCanAccessUpload(r, u) {
		jsonError(w, http.StatusUnauthorized, uploadAccessRequiredMessage(u))
		return
	}
	list, err := s.store.ListComments(r.Context(), u.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	out := make([]commentOut, 0, len(list))
	for _, c := range list {
		out = append(out, commentOut{
			ID: c.ID, Selector: c.ElementSelector, Text: c.ElementText,
			AnchorKind: commentAnchorKind(c.ElementSelector, c.ElementText, c.AnchorKind),
			Author:     c.AuthorName, Body: c.Body, CreatedAt: c.CreatedAt.Unix(),
		})
	}
	jsonOK(w, out)
}

func (s *Server) handleAddComment(w http.ResponseWriter, r *http.Request) {
	if !s.commentLimiter.allow(s.clientIP(r)) {
		jsonError(w, http.StatusTooManyRequests, "too many comments, slow down")
		return
	}
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.viewerCanAccessUpload(r, u) {
		jsonError(w, http.StatusUnauthorized, uploadAccessRequiredMessage(u))
		return
	}

	var in commentIn
	if err := decodeJSON(w, r, &in, defaultJSONBodyLimit); err != nil {
		jsonError(w, http.StatusBadRequest, "bad json")
		return
	}
	if status, msg := in.normalize(); status != 0 {
		jsonError(w, status, msg)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) > 100 {
		jsonError(w, http.StatusRequestEntityTooLarge, "field too long")
		return
	}
	if in.Name == "" {
		in.Name = "anonymous"
	}

	vid := s.visitorID(w, r)
	if in.Name != "anonymous" {
		if err := s.store.UpsertVisitor(r.Context(), vid, in.Name); err != nil {
			slog.Warn("comment visitor upsert failed", "upload_id", u.ID, "err", err)
		}
		s.setNameCookie(w, in.Name)
	}

	if _, err := s.store.AddComment(r.Context(), u.ID, in.Selector, in.Text, in.AnchorKind, in.Name, s.commentVisitorHash(vid), in.Body); err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}

	list, err := s.store.ListComments(r.Context(), u.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	out := make([]commentOut, 0, len(list))
	for _, c := range list {
		out = append(out, commentOut{
			ID: c.ID, Selector: c.ElementSelector, Text: c.ElementText,
			AnchorKind: commentAnchorKind(c.ElementSelector, c.ElementText, c.AnchorKind),
			Author:     c.AuthorName, Body: c.Body, CreatedAt: c.CreatedAt.Unix(),
		})
	}
	jsonOK(w, out)
}

// normalize trims and validates the fields shared by the browser and account
// comment routes. It returns (0, "") when the input is valid.
func (in *commentIn) normalize() (int, string) {
	in.Selector = strings.TrimSpace(in.Selector)
	in.Body = strings.TrimSpace(in.Body)
	in.Text = strings.TrimSpace(in.Text)
	in.AnchorKind = strings.TrimSpace(in.AnchorKind)
	anchorKind, ok := normalizeCommentAnchorKind(in.Selector, in.Text, in.AnchorKind)
	if !ok {
		return http.StatusBadRequest, "invalid anchor kind"
	}
	in.AnchorKind = anchorKind
	if in.Body == "" {
		return http.StatusBadRequest, "comment body required"
	}
	if len(in.Body) > 4000 || len(in.Selector) > 500 || len(in.Text) > 200 || len(in.AnchorKind) > 20 {
		return http.StatusRequestEntityTooLarge, "field too long"
	}
	return 0, ""
}

func (s *Server) commentVisitorHash(key string) string {
	h := sha256.Sum256([]byte(s.secret + "|" + key))
	return hex.EncodeToString(h[:])[:16]
}

// handleAddAccountComment posts a comment as the token's account. It is a
// separate route from handleAddComment so a server without it answers 404/405
// instead of silently posting as "anonymous".
func (s *Server) handleAddAccountComment(w http.ResponseWriter, r *http.Request) {
	owner, ok := requireAPIToken(w, r)
	if !ok {
		return
	}
	if !s.commentLimiter.allow(s.clientIP(r)) {
		jsonError(w, http.StatusTooManyRequests, "too many comments, slow down")
		return
	}
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if u.OwnerAccountID != owner.AccountID && !owner.IsAdmin {
		jsonError(w, http.StatusForbidden, "not owner")
		return
	}
	var in commentIn
	if err := decodeJSON(w, r, &in, defaultJSONBodyLimit); err != nil {
		jsonError(w, http.StatusBadRequest, "bad json")
		return
	}
	if status, msg := in.normalize(); status != 0 {
		jsonError(w, status, msg)
		return
	}
	c, err := s.store.AddComment(r.Context(), u.ID, in.Selector, in.Text, in.AnchorKind, owner.Name,
		s.commentVisitorHash("account:"+strconv.FormatInt(owner.AccountID, 10)), in.Body)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.auditRequest(r, owner.Name, "comment.create", "slug="+slug)
	jsonOK(w, commentOut{
		ID: c.ID, Selector: c.ElementSelector, Text: c.ElementText,
		AnchorKind: commentAnchorKind(c.ElementSelector, c.ElementText, c.AnchorKind),
		Author:     c.AuthorName, Body: c.Body, CreatedAt: c.CreatedAt.Unix(),
	})
}

func normalizeCommentAnchorKind(selector, text, kind string) (string, bool) {
	switch kind {
	case "":
		return commentAnchorKind(selector, text, ""), true
	case "text":
		return kind, selector != "" && text != ""
	case "element":
		return kind, selector != ""
	case "page":
		return kind, selector == ""
	default:
		return "", false
	}
}

func commentAnchorKind(selector, text, kind string) string {
	switch kind {
	case "text", "element", "page":
		return kind
	}
	if selector == "" {
		return "page"
	}
	if text != "" {
		return "text"
	}
	return "element"
}

func (s *Server) viewerCanAccessUpload(r *http.Request, u *models.Upload) bool {
	switch u.Visibility {
	case models.UploadVisibilityPublic:
		return true
	case models.UploadVisibilityPassword:
		c, err := r.Cookie(authCookieName(u.Slug))
		if err != nil {
			return false
		}
		return verifySessionCookie(s.secret, c.Value, u.Slug)
	case models.UploadVisibilityPrivate:
		_, ok := s.webAuth(r)
		return ok
	default:
		return false
	}
}

func uploadAccessRequiredMessage(u *models.Upload) string {
	if u.Visibility == models.UploadVisibilityPrivate {
		return "login required"
	}
	return "password required"
}

func authCookieName(slug string) string {
	return "hn_auth_" + slug
}

// setNameCookie sets a long-lived, JS-readable cookie so the name is remembered.
func (s *Server) setNameCookie(w http.ResponseWriter, name string) {
	s.setCookie(w, &http.Cookie{
		Name:     nameCookie,
		Value:    name,
		Path:     "/",
		MaxAge:   int((365 * 24 * time.Hour).Seconds()),
		SameSite: http.SameSiteLaxMode,
		HttpOnly: false,
	})
}
