package server

import (
	"database/sql"
	"net/http"
	"net/mail"
	"strings"

	"github.com/andras-tkcs/peek/internal/models"
)

type grantBody struct {
	Kind  string `json:"kind"`
	Email string `json:"email"`
}

type grantOut struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	Email     string `json:"email"`
	CreatedAt int64  `json:"created_at"`
}

func grantToOut(g models.UploadGrant) grantOut {
	return grantOut{ID: g.ID, Kind: g.Kind, Email: g.Email, CreatedAt: g.CreatedAt.Unix()}
}

// grantUpload loads the page named in the path and checks that the caller owns it or is an admin.
func (s *Server) grantUpload(w http.ResponseWriter, r *http.Request) (*models.Token, *models.Upload, bool) {
	owner, ok := requireAPIToken(w, r)
	if !ok {
		return nil, nil, false
	}
	u, err := s.store.GetUpload(r.Context(), r.PathValue("slug"))
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return nil, nil, false
	}
	if u.OwnerAccountID != owner.AccountID && !owner.IsAdmin {
		jsonError(w, http.StatusForbidden, "not owner")
		return nil, nil, false
	}
	return owner, u, true
}

// normalizeGrantInput validates a grant kind and email address and returns the
// lowercased, trimmed email, or a non-empty user-facing error message. Group grants
// need Google group lookup only when requireGroupLookup is true, so a stored group
// grant can always be removed.
func (s *Server) normalizeGrantInput(kind, email string, requireGroupLookup bool) (string, string) {
	if kind != models.UploadGrantUser && kind != models.UploadGrantGroup {
		return "", "kind must be user or group"
	}
	email = strings.ToLower(strings.TrimSpace(email))
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || len(email) > 254 {
		return "", "invalid email address"
	}
	if requireGroupLookup && kind == models.UploadGrantGroup && s.groups == nil {
		return "", "group grants need Google group lookup; set PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL on the server"
	}
	return email, ""
}

// decodeGrantBody reads and validates {"kind","email"}, writing the 400 itself on failure.
func (s *Server) decodeGrantBody(w http.ResponseWriter, r *http.Request) (grantBody, bool) {
	var body grantBody
	if err := decodeJSON(w, r, &body, smallJSONBodyLimit); err != nil {
		return body, false
	}
	email, msg := s.normalizeGrantInput(body.Kind, body.Email, true)
	if msg != "" {
		jsonError(w, http.StatusBadRequest, msg)
		return body, false
	}
	body.Email = email
	return body, true
}

func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.grantUpload(w, r)
	if !ok {
		return
	}
	grants, err := s.store.ListUploadGrants(r.Context(), u.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	out := make([]grantOut, 0, len(grants))
	for _, g := range grants {
		out = append(out, grantToOut(g))
	}
	jsonOK(w, out)
}

func (s *Server) handleAddGrant(w http.ResponseWriter, r *http.Request) {
	owner, u, ok := s.grantUpload(w, r)
	if !ok {
		return
	}
	body, ok := s.decodeGrantBody(w, r)
	if !ok {
		return
	}
	g, err := s.store.AddUploadGrant(r.Context(), u.ID, body.Kind, body.Email, owner.AccountID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.auditRequest(r, owner.Name, "upload.grant.add", auditDetail("slug", u.Slug, "kind", body.Kind, "email", body.Email))
	jsonOK(w, grantToOut(*g))
}

func (s *Server) handleRemoveGrant(w http.ResponseWriter, r *http.Request) {
	owner, u, ok := s.grantUpload(w, r)
	if !ok {
		return
	}
	body, ok := s.decodeGrantBody(w, r)
	if !ok {
		return
	}
	if err := s.store.RemoveUploadGrant(r.Context(), u.ID, body.Kind, body.Email); err != nil {
		if err == sql.ErrNoRows {
			jsonError(w, http.StatusNotFound, "grant not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.auditRequest(r, owner.Name, "upload.grant.remove", auditDetail("slug", u.Slug, "kind", body.Kind, "email", body.Email))
	jsonOK(w, map[string]any{"removed": true})
}
