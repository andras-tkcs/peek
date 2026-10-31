package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

func (s *Server) handleCreateProvisioner(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAPIToken(w, r)
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	err := decodeJSON(w, r, &body, smallJSONBodyLimit)
	name := strings.TrimSpace(body.Name)
	if err != nil || name == "" || utf8.RuneCountInString(name) > apiKeyNameMaxLen {
		jsonError(w, http.StatusBadRequest, "name required")
		return
	}
	key, err := newProvisioningKey()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "key gen failed")
		return
	}
	p, err := s.store.CreateProvisioner(r.Context(), name, key, actor.AccountID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db failed")
		return
	}
	id := strconv.FormatInt(p.ID, 10)
	s.auditRequest(r, actorName(actor), "provisioner.create", auditDetail("id", id, "name", p.Name))
	writeJSON(w, http.StatusCreated, map[string]any{"id": p.ID, "name": p.Name, "key": key})
}

func (s *Server) handleListProvisioners(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListProvisioners(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	type row struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		Hint       string `json:"hint"`
		CreatedAt  int64  `json:"created_at"`
		LastUsedAt int64  `json:"last_used_at"`
		Accounts   int64  `json:"accounts"`
	}
	out := make([]row, 0, len(list))
	for _, p := range list {
		out = append(out, row{p.ID, p.Name, p.Hint, p.CreatedAt, p.LastUsedAt, p.Accounts})
	}
	jsonOK(w, out)
}

func (s *Server) handleDeleteProvisioner(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAPIToken(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if s.isFileProvisioner(id) {
		jsonError(w, http.StatusConflict, flashMessages[flashProvisionerFromFile])
		return
	}
	name, err := s.revokeProvisioner(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.auditRequest(r, actorName(actor), "provisioner.revoke", auditDetail("id", strconv.FormatInt(id, 10), "name", name))
	jsonOK(w, map[string]any{"revoked": id})
}

// revokeProvisioner deletes provisioner id and returns its name for the audit entry.
func (s *Server) revokeProvisioner(r *http.Request, id int64) (string, error) {
	list, err := s.store.ListProvisioners(r.Context())
	if err != nil {
		return "", err
	}
	name := ""
	for _, p := range list {
		if p.ID == id {
			name = p.Name
		}
	}
	return name, s.store.DeleteProvisioner(r.Context(), id)
}
