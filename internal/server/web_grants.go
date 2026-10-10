package server

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"

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
		dashboardError(w, r, "not found")
		return nil, nil, false
	}
	if u.OwnerAccountID != owner.ID && !owner.IsAdmin {
		dashboardError(w, r, "not owner")
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
		dashboardFlashManage(w, r, "err", msg, slug)
		return
	}
	if _, err := s.store.AddUploadGrant(r.Context(), u.ID, kind, email, owner.ID); err != nil {
		slog.Error("dashboard grant add failed", "slug", slug, "err", err)
		dashboardFlashManage(w, r, "err", "grant update failed", slug)
		return
	}
	s.auditRequest(r, owner.Name, "upload.grant.add", "slug="+u.Slug+" kind="+kind+" email="+email)
	dashboardFlashManage(w, r, "ok", "Shared /p/"+slug+" with "+email, slug)
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
		dashboardFlashManage(w, r, "err", msg, slug)
		return
	}
	if err := s.store.RemoveUploadGrant(r.Context(), u.ID, kind, email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			dashboardFlashManage(w, r, "err", "grant not found", slug)
			return
		}
		slog.Error("dashboard grant remove failed", "slug", slug, "err", err)
		dashboardFlashManage(w, r, "err", "grant update failed", slug)
		return
	}
	s.auditRequest(r, owner.Name, "upload.grant.remove", "slug="+u.Slug+" kind="+kind+" email="+email)
	dashboardFlashManage(w, r, "ok", "Removed "+email+" from /p/"+slug, slug)
}
