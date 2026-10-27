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
	"unicode"
	"unicode/utf8"

	"github.com/privacyfence/peek/internal/models"
	webui "github.com/privacyfence/peek/internal/web"
)

const (
	apiKeyPrefix     = "peek_"
	apiKeyNameMaxLen = 100
	apiKeyNameError  = "API key name must be 1 to 100 characters"
	apiKeyTimeLayout = "2006-01-02 15:04"
)

func newAPIKey() (string, error) {
	id, err := randID(24)
	if err != nil {
		return "", err
	}
	return apiKeyPrefix + id, nil
}

func apiKeyLimitKey(accountID int64) string {
	return "account:" + strconv.FormatInt(accountID, 10)
}

func apiKeyAuditDetail(id int64, name string) string {
	return auditDetail("id", strconv.FormatInt(id, 10), "name", name)
}

func validAPIKeyName(name string) bool {
	n := utf8.RuneCountInString(name)
	if n == 0 || n > apiKeyNameMaxLen {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func dashboardAPIKeyRow(k models.APIKey, now time.Time) dashAPIKey {
	row := dashAPIKey{
		ID:       k.ID,
		Name:     k.Name,
		Hint:     "—",
		Created:  k.CreatedAt.Format(apiKeyTimeLayout),
		LastUsed: "Never",
		Expires:  "Never",
	}
	if k.Hint != "" {
		row.Hint = "…" + k.Hint
	}
	if k.LastUsedAt != 0 {
		row.LastUsed = time.Unix(k.LastUsedAt, 0).Format(apiKeyTimeLayout)
	}
	if k.ExpiresAt != 0 {
		row.Expires = time.Unix(k.ExpiresAt, 0).Format(apiKeyTimeLayout)
		if k.ExpiresAt < now.Unix() {
			row.Expires += " (expired)"
		}
	}
	return row
}

func (s *Server) dashboardAPIKeyRows(ctx context.Context, accountID int64) []dashAPIKey {
	keys, err := s.store.ListAccountTokens(ctx, accountID)
	if err != nil {
		slog.Error("dashboard api key list failed", "account_id", accountID, "err", err)
		return nil
	}
	now := time.Now()
	rows := make([]dashAPIKey, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, dashboardAPIKeyRow(k, now))
	}
	return rows
}

func (s *Server) renderAPIKeyShown(w http.ResponseWriter, data apiKeyShownData) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	s.renderHTML(w, http.StatusOK, webui.TemplateAPIKeyShown, data)
}

func (s *Server) renderAPIKeyNotFound(w http.ResponseWriter) {
	s.renderWebError(w, http.StatusNotFound, "API key not found", "This API key does not exist or does not belong to your account.")
}

func (s *Server) handleDashboardAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseDashboardForm(w, r) {
		return
	}
	if !s.apiKeyLimiter.allow(apiKeyLimitKey(owner.ID)) {
		rateLimitError(w, r)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !validAPIKeyName(name) {
		dashboardError(w, r, flashAPIKeyName)
		return
	}
	key, err := newAPIKey()
	var id int64
	if err == nil {
		id, err = s.store.CreateAccountToken(r.Context(), owner.ID, key, name)
	}
	if err != nil {
		slog.Error("api key create failed", "account_id", owner.ID, "err", err)
		dashboardError(w, r, flashAPIKeyCreateFailed)
		return
	}
	s.auditRequest(r, owner.Name, "token.create", apiKeyAuditDetail(id, name))
	s.renderAPIKeyShown(w, apiKeyShownData{Title: "API key created", Name: name, Key: key})
}

func (s *Server) handleDashboardAPIKeyRegenerate(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseDashboardForm(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderAPIKeyNotFound(w)
		return
	}
	if !s.apiKeyLimiter.allow(apiKeyLimitKey(owner.ID)) {
		rateLimitError(w, r)
		return
	}
	key, err := newAPIKey()
	var k *models.APIKey
	if err == nil {
		k, err = s.store.RegenerateAccountToken(r.Context(), owner.ID, id, key)
	}
	if errors.Is(err, sql.ErrNoRows) {
		s.renderAPIKeyNotFound(w)
		return
	}
	if err != nil {
		slog.Error("api key regenerate failed", "account_id", owner.ID, "token_id", id, "err", err)
		dashboardError(w, r, flashAPIKeyRegenerateFailed)
		return
	}
	s.auditRequest(r, owner.Name, "token.regenerate", apiKeyAuditDetail(k.ID, k.Name))
	s.renderAPIKeyShown(w, apiKeyShownData{Title: "API key regenerated", Name: k.Name, Key: key, Regenerated: true})
}

func (s *Server) handleDashboardAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseDashboardForm(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderAPIKeyNotFound(w)
		return
	}
	k, err := s.store.DeleteAccountToken(r.Context(), owner.ID, id)
	if errors.Is(err, sql.ErrNoRows) {
		s.renderAPIKeyNotFound(w)
		return
	}
	if err != nil {
		slog.Error("api key revoke failed", "account_id", owner.ID, "token_id", id, "err", err)
		dashboardError(w, r, flashAPIKeyRevokeFailed)
		return
	}
	s.auditRequest(r, owner.Name, "token.revoke", apiKeyAuditDetail(k.ID, k.Name))
	dashboardOK(w, r, flashAPIKeyRevoked)
}
