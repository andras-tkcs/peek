package server

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/andras-tkcs/peek/internal/models"
)

// dashboardGrantUpload runs the shared prefix of the grant handlers: session, CSRF,
// upload lookup and owner-or-admin check. It writes the redirect itself on failure.
func (s *Server) dashboardGrantUpload(w http.ResponseWriter, r *http.Request) (*models.Account, *models.Upload, bool) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, nil, false
	}
	if !s.parseDashboardForm(w, r) {
		return nil, nil, false
	}
	u, err := s.store.GetUpload(r.Context(), r.PathValue("slug"))
	if err != nil {
		dashboardError(w, r, flashNotFound)
		return nil, nil, false
	}
	if u.OwnerAccountID != owner.ID && !owner.IsAdmin {
		dashboardError(w, r, flashNotOwner)
		return nil, nil, false
	}
	return owner, u, true
}

func (s *Server) handleDashboardGrantAdd(w http.ResponseWriter, r *http.Request) {
	owner, u, ok := s.dashboardGrantUpload(w, r)
	if !ok {
		return
	}
	slug := u.Slug
	kind := r.FormValue("kind")
	email, msg := s.normalizeGrantInput(kind, r.FormValue("email"), true)
	if msg != "" {
		dashboardFlashManage(w, r, "err", grantFlashCode(msg), slug)
		return
	}
	g, created, err := s.store.AddUploadGrant(r.Context(), u.ID, kind, email, owner.ID)
	if err != nil {
		slog.Error("dashboard grant add failed", "slug", slug, "err", err)
		dashboardFlashManage(w, r, "err", flashGrantFailed, slug)
		return
	}
	s.auditRequest(r, owner.Name, "upload.grant.add", auditDetail("slug", u.Slug, "kind", kind, "email", email))
	q := url.Values{"ok": {flashGrantAdded}, "manage": {slug}, "slug": {slug}, "email": {email}}
	if created && u.Visibility == models.UploadVisibilityRestricted {
		if _, err := s.notifyShare(r, owner.Name, owner.Email, u, []models.UploadGrant{*g}); err != nil {
			q.Set("err", flashShareNotifyFailed)
		}
	}
	dashboardFlash(w, r, q)
}

func (s *Server) handleDashboardGrantRemove(w http.ResponseWriter, r *http.Request) {
	owner, u, ok := s.dashboardGrantUpload(w, r)
	if !ok {
		return
	}
	slug := u.Slug
	kind := r.FormValue("kind")
	email, msg := s.normalizeGrantInput(kind, r.FormValue("email"), false)
	if msg != "" {
		dashboardFlashManage(w, r, "err", grantFlashCode(msg), slug)
		return
	}
	if err := s.store.RemoveUploadGrant(r.Context(), u.ID, kind, email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			dashboardFlashManage(w, r, "err", flashGrantNotFound, slug)
			return
		}
		slog.Error("dashboard grant remove failed", "slug", slug, "err", err)
		dashboardFlashManage(w, r, "err", flashGrantFailed, slug)
		return
	}
	s.auditRequest(r, owner.Name, "upload.grant.remove", auditDetail("slug", u.Slug, "kind", kind, "email", email))
	dashboardFlashManage(w, r, "ok", flashGrantRemoved, slug)
}
