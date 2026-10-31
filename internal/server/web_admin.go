package server

import (
	"net/http"
	"net/url"

	"github.com/privacyfence/peek/internal/models"
	webui "github.com/privacyfence/peek/internal/web"
)

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	if s.setupRequired(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !owner.IsAdmin {
		s.renderWebError(w, http.StatusNotFound, "Not found", "This page could not be found.")
		return
	}
	s.renderAdmin(w, r, owner, http.StatusOK, r.URL.Query(), "")
}

// renderAdmin renders the admin page for owner. Flash codes come from q; when
// inlineError is set it is shown as the error toast instead (used by handlers
// that answer a POST with the page rather than a redirect).
func (s *Server) renderAdmin(w http.ResponseWriter, r *http.Request, owner *models.Account, status int, q url.Values, inlineError string) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	csrf, ok := s.csrfToken(w)
	if !ok {
		return
	}
	panel := dashboardSettingsPanel(s.dashboardSettingsMap(r.Context()), s.lockedEnvNames())
	panel.Backends.Enabled = s.backends != nil
	data := adminData{
		CSRF:            csrf,
		User:            owner.Name,
		GoogleOrgSignup: s.googleOrgSignupEnabled(r.Context()),
		SettingsPanel:   panel,
		Invites:         s.dashboardInviteRows(r.Context()),
		Accounts:        s.dashboardAccountRows(r.Context(), owner.ID),
		Provisioners:    s.dashboardProvisionerRows(r.Context()),
	}
	flash := resolveFlash(q, nil, s.baseURL)
	data.Error = flash.Error
	data.FlashSuccess = flash.Success
	if inlineError != "" {
		data.Error = inlineError
	}
	s.renderHTML(w, status, webui.TemplateAdmin, data)
}
