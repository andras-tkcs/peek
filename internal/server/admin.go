package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/privacyfence/peek/internal/db"
)

const inviteTTL = 7 * 24 * time.Hour

func (s *Server) handleInviteLink(w http.ResponseWriter, r *http.Request) {
	if s.googleOrgSignupEnabled(r.Context()) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	raw := strings.TrimSpace(r.PathValue("token"))
	inv, err := s.store.GetInviteByToken(r.Context(), raw)
	if err != nil || !invitePending(inv) {
		s.renderWebError(w, http.StatusNotFound, "Invite not found", "This invite link is invalid, expired, or already used.")
		return
	}
	s.setCookie(w, &http.Cookie{
		Name:     inviteCookie,
		Value:    raw,
		Path:     "/",
		MaxAge:   int(inviteTTL.Seconds()),
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboardCreateInvite(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok || !owner.IsAdmin {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseAdminForm(w, r) {
		return
	}
	if s.googleOrgSignupEnabled(r.Context()) {
		adminError(w, r, flashInviteNotUsed)
		return
	}
	email := normalizeOAuthEmail(r.FormValue("email"))
	if email == "" || !strings.Contains(email, "@") {
		adminError(w, r, flashInviteEmailRequired)
		return
	}
	if !s.accountAllowedByEmailDomain(r.Context(), email) {
		adminError(w, r, flashInviteDomain)
		return
	}
	raw, err := randID(24)
	if err != nil {
		adminError(w, r, flashInviteFailed)
		return
	}
	ciphertext, err := encryptSecret(s.secret, raw)
	if err != nil {
		adminError(w, r, flashInviteFailed)
		return
	}
	if _, err := s.store.CreateInvite(r.Context(), raw, ciphertext, email, owner.ID, time.Now().Add(inviteTTL)); err != nil {
		adminError(w, r, flashInviteFailed)
		return
	}
	s.audit("invite created %s", auditDetail("email", email, "by", owner.Name))
	adminOK(w, r, flashInviteCreated)
}

func (s *Server) handleDashboardRevokeInvite(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok || !owner.IsAdmin {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseAdminForm(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		adminError(w, r, flashBadInvite)
		return
	}
	if err := s.store.RevokeInvite(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			adminError(w, r, flashBadInvite)
			return
		}
		adminError(w, r, flashInviteRevokeFailed)
		return
	}
	s.audit("invite revoked %s", auditDetail("id", strconv.FormatInt(id, 10), "by", owner.Name))
	adminOK(w, r, flashInviteRevoked)
}

func (s *Server) handleDashboardUserAdmin(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok || !owner.IsAdmin {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseAdminForm(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		adminError(w, r, flashBadUser)
		return
	}
	makeAdmin := r.FormValue("admin") == "true"
	if err := s.store.SetAccountAdminChecked(r.Context(), id, makeAdmin); err != nil {
		if errors.Is(err, db.ErrLastAdmin) {
			adminError(w, r, flashLastAdminRemove)
			return
		}
		adminError(w, r, flashUserUpdateFailed)
		return
	}
	s.audit("account %s", auditDetail("admin", strconv.FormatBool(makeAdmin), "id", strconv.FormatInt(id, 10), "by", owner.Name))
	adminOK(w, r, flashUserUpdated)
}

func (s *Server) handleDashboardUserDisabled(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok || !owner.IsAdmin {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseAdminForm(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		adminError(w, r, flashBadUser)
		return
	}
	disabled := r.FormValue("disabled") == "true"
	if err := s.store.SetAccountDisabledChecked(r.Context(), id, disabled); err != nil {
		if errors.Is(err, db.ErrLastAdmin) {
			adminError(w, r, flashLastAdminDisable)
			return
		}
		adminError(w, r, flashUserUpdateFailed)
		return
	}
	s.audit("account %s", auditDetail("disabled", strconv.FormatBool(disabled), "id", strconv.FormatInt(id, 10), "by", owner.Name))
	adminOK(w, r, flashUserUpdated)
}

func (s *Server) dashboardInviteRows(ctx context.Context) []inviteDashRow {
	invites, err := s.store.ListInvites(ctx)
	if err != nil {
		slog.Error("dashboard invite list failed", "err", err)
		return nil
	}
	out := make([]inviteDashRow, 0, len(invites))
	for _, inv := range invites {
		status := "pending"
		canRevoke := true
		raw, err := decryptSecret(s.secret, inv.Token)
		if err != nil {
			slog.Warn("dashboard invite decrypt failed", "invite_id", inv.ID, "err", err)
		}
		link := ""
		if raw != "" {
			link = s.baseURL + "/invite/" + raw
		}
		if !inv.UsedAt.IsZero() {
			status = "used"
			canRevoke = false
			link = ""
		} else if !inv.RevokedAt.IsZero() {
			status = "revoked"
			canRevoke = false
			link = ""
		} else if time.Now().After(inv.ExpiresAt) {
			status = "expired"
			canRevoke = false
			link = ""
		}
		out = append(out, inviteDashRow{
			ID:        inv.ID,
			Email:     inv.Email,
			Status:    status,
			Expires:   inv.ExpiresAt.Format("2006-01-02 15:04"),
			Link:      link,
			CanRevoke: canRevoke,
		})
	}
	return out
}

func (s *Server) dashboardAccountRows(ctx context.Context, selfID int64) []accountDashRow {
	accounts, err := s.store.ListAccounts(ctx)
	if err != nil {
		slog.Error("dashboard account list failed", "err", err)
		return nil
	}
	managedBy, err := s.store.ProvisionedByAccount(ctx)
	if err != nil {
		slog.Error("dashboard provisioned accounts failed", "err", err)
	}
	out := make([]accountDashRow, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, accountDashRow{
			ID:        a.ID,
			Name:      a.Name,
			Email:     a.Email,
			Admin:     a.IsAdmin,
			Disabled:  a.Disabled,
			IsSelf:    a.ID == selfID,
			ManagedBy: managedBy[a.ID],
		})
	}
	return out
}

func (s *Server) dashboardProvisionerRows(ctx context.Context) []provisionerDashRow {
	list, err := s.store.ListProvisioners(ctx)
	if err != nil {
		slog.Error("dashboard provisioner list failed", "err", err)
		return nil
	}
	out := make([]provisionerDashRow, 0, len(list))
	for _, p := range list {
		lastUsed := "never"
		if p.LastUsedAt > 0 {
			lastUsed = time.Unix(p.LastUsedAt, 0).UTC().Format(time.RFC3339)
		}
		out = append(out, provisionerDashRow{
			ID:       p.ID,
			Name:     p.Name,
			Hint:     p.Hint,
			Created:  time.Unix(p.CreatedAt, 0).UTC().Format(time.RFC3339),
			LastUsed: lastUsed,
			Accounts: p.Accounts,
		})
	}
	return out
}

func (s *Server) handleDashboardProvisionerRevoke(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok || !owner.IsAdmin {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseAdminForm(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		adminError(w, r, flashNotFound)
		return
	}
	name, err := s.revokeProvisioner(r, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			adminError(w, r, flashNotFound)
			return
		}
		adminError(w, r, flashProvisionerRevokeFailed)
		return
	}
	s.auditRequest(r, owner.Name, "provisioner.revoke", auditDetail("id", strconv.FormatInt(id, 10), "name", name))
	adminOK(w, r, flashProvisionerRevoked)
}
