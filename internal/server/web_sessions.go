package server

import (
	"log/slog"
	"net/http"
)

const (
	flashSessionsRevoked      = "sessions_revoked"
	flashSessionsRevokeFailed = "sessions_revoke_failed"
)

// handleDashboardSessionsRevoke ends every other dashboard session of the
// signed-in account: it bumps the account's session epoch, which invalidates
// all earlier session cookies, and gives this browser a new cookie.
func (s *Server) handleDashboardSessionsRevoke(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseDashboardForm(w, r) {
		return
	}
	epoch, err := s.store.BumpSessionEpoch(r.Context(), owner.ID)
	if err != nil {
		slog.Error("session revoke failed", "account_id", owner.ID, "err", err)
		dashboardError(w, r, flashSessionsRevokeFailed)
		return
	}
	owner.SessionEpoch = epoch
	s.setWebSession(w, owner)
	s.auditRequest(r, owner.Name, "session.revoke_others", "")
	dashboardOK(w, r, flashSessionsRevoked)
}
