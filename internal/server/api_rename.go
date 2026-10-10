package server

import (
	"net/http"

	"github.com/andras-tkcs/peek/internal/uploads"
)

func renameAuditDetail(oldSlug string, res *uploads.RenameResult) string {
	return "slug=" + oldSlug + " new_slug=" + res.Slug + " name=" + res.Name
}

func (s *Server) handleRenameUpload(w http.ResponseWriter, r *http.Request) {
	owner, ok := requireAPIToken(w, r)
	if !ok {
		return
	}
	u, err := s.store.GetUpload(r.Context(), r.PathValue("slug"))
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if u.OwnerAccountID != owner.AccountID && !owner.IsAdmin {
		jsonError(w, http.StatusForbidden, "not owner")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &body, smallJSONBodyLimit); err != nil {
		jsonError(w, http.StatusBadRequest, "bad json")
		return
	}
	res, err := uploads.Rename(r.Context(), s.store, s.baseURL, uploads.RenameInput{UploadID: u.ID, CurrentSlug: u.Slug, CurrentName: u.Name, Name: body.Name})
	if err != nil {
		logUploadError(err)
		status, msg := uploadHTTPError(err)
		jsonError(w, status, msg)
		return
	}
	s.auditRequest(r, owner.Name, "upload.rename", renameAuditDetail(u.Slug, res))
	jsonOK(w, map[string]any{"slug": res.Slug, "url": res.URL, "name": res.Name})
}
