package server

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/andras-tkcs/peek/internal/db"
)

var externalIDPattern = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,200}$`)

const (
	provisionedTokenDefaultDays = 90
	provisionedTokenMaxDays     = 365
	errProvisionAdminText       = "account is a Peek admin; connect it by hand"
)

// provisioningRequest authenticates the shared start of every /api/provisioning
// account route: the provisioner, a valid external id and the audit actor.
func provisioningRequest(w http.ResponseWriter, r *http.Request) (provisionerName string, providerID int64, externalID string, ok bool) {
	p, ok := requireProvisioner(w, r)
	if !ok {
		return "", 0, "", false
	}
	ext := r.PathValue("external_id")
	if !externalIDPattern.MatchString(ext) {
		jsonError(w, http.StatusBadRequest, "invalid external id")
		return "", 0, "", false
	}
	return p.Name, p.ID, ext, true
}

func (s *Server) handleProvisioningSelf(w http.ResponseWriter, r *http.Request) {
	p, ok := requireProvisioner(w, r)
	if !ok {
		return
	}
	n, err := s.store.CountProvisionedAccounts(r.Context(), p.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	jsonOK(w, map[string]any{"name": p.Name, "accounts": n})
}

func validProvisioningEmail(email string) bool {
	if len(email) > 254 || strings.Count(email, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(email, "@")
	return local != "" && domain != ""
}

func (s *Server) handleProvisioningUpsert(w http.ResponseWriter, r *http.Request) {
	pname, pid, ext, ok := provisioningRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := decodeJSON(w, r, &body, smallJSONBodyLimit); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid json")
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if !validProvisioningEmail(email) {
		jsonError(w, http.StatusBadRequest, "invalid email")
		return
	}
	name := strings.TrimSpace(body.Name)
	if utf8.RuneCountInString(name) > apiKeyNameMaxLen {
		jsonError(w, http.StatusBadRequest, "name too long")
		return
	}
	if !s.accountAllowedByEmailDomain(r.Context(), email) {
		jsonError(w, http.StatusForbidden, "account email domain is not allowed")
		return
	}
	// Whether this request created the account: no link existed beforehand.
	_, linkErr := s.store.GetProvisionedAccount(r.Context(), pid, ext)
	existed := linkErr == nil
	if linkErr != nil && !errors.Is(linkErr, sql.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	link, acct, err := s.store.UpsertProvisionedAccount(r.Context(), pid, ext, email, name)
	switch {
	case errors.Is(err, db.ErrProvisionAdmin):
		jsonError(w, http.StatusConflict, errProvisionAdminText)
		return
	case errors.Is(err, db.ErrProvisionConflict):
		jsonError(w, http.StatusConflict, "account is linked to another external id or email")
		return
	case err != nil:
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	created := link.CreatedAccount && !existed
	adopted := !link.CreatedAccount
	hasToken := link.TokenID != 0 && (link.TokenExpiresAt == 0 || link.TokenExpiresAt > time.Now().Unix())
	var expires int64
	if hasToken {
		expires = link.TokenExpiresAt
	}
	s.auditRequest(r, "provisioner:"+pname, "provisioning.account_upsert", auditDetail(
		"external_id", ext, "account", strconv.FormatInt(acct.ID, 10),
		"created", strconv.FormatBool(created), "adopted", strconv.FormatBool(adopted)))
	jsonOK(w, map[string]any{
		"external_id":      ext,
		"account_id":       acct.ID,
		"email":            acct.Email,
		"name":             acct.Name,
		"created":          created,
		"adopted":          adopted,
		"disabled":         acct.Disabled,
		"has_token":        hasToken,
		"token_expires_at": expires,
	})
}

func (s *Server) handleProvisioningToken(w http.ResponseWriter, r *http.Request) {
	pname, pid, ext, ok := provisioningRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		ExpiresDays int `json:"expires_days"`
	}
	if err := decodeJSON(w, r, &body, smallJSONBodyLimit); err != nil && !errors.Is(err, io.EOF) {
		jsonError(w, http.StatusBadRequest, "invalid json")
		return
	}
	days := body.ExpiresDays
	if days == 0 {
		days = provisionedTokenDefaultDays
	}
	if days < 1 || days > provisionedTokenMaxDays {
		jsonError(w, http.StatusBadRequest, "expires_days must be 1 to 365")
		return
	}
	link, err := s.store.GetProvisionedAccount(r.Context(), pid, ext)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	acct, err := s.store.GetAccountByID(r.Context(), link.AccountID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	switch {
	case acct.Disabled:
		jsonError(w, http.StatusForbidden, "account disabled")
		return
	case acct.IsAdmin:
		jsonError(w, http.StatusConflict, errProvisionAdminText)
		return
	case !s.accountAllowedByEmailDomain(r.Context(), acct.Email):
		jsonError(w, http.StatusForbidden, "account email domain is not allowed")
		return
	}
	token, err := newAPIKey()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "token gen failed")
		return
	}
	expiresAt := time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
	tokenID, err := s.store.ReplaceProvisionedToken(r.Context(), pid, ext, token, pname, expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.auditRequest(r, "provisioner:"+pname, "provisioning.token_issue", auditDetail(
		"external_id", ext, "account", strconv.FormatInt(acct.ID, 10), "token_id", strconv.FormatInt(tokenID, 10)))
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "token_id": tokenID, "expires_at": expiresAt})
}

func (s *Server) handleProvisioningRelease(w http.ResponseWriter, r *http.Request) {
	pname, pid, ext, ok := provisioningRequest(w, r)
	if !ok {
		return
	}
	link, err := s.store.GetProvisionedAccount(r.Context(), pid, ext)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	err = s.store.ReleaseProvisionedAccount(r.Context(), pid, ext)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.auditRequest(r, "provisioner:"+pname, "provisioning.account_release", auditDetail(
		"external_id", ext, "account", strconv.FormatInt(link.AccountID, 10)))
	jsonOK(w, map[string]any{"released": true})
}
