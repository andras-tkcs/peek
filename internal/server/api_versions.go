package server

import (
	"net/http"
	"strconv"
)

func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	owner, ok := requireAPIToken(w, r)
	if !ok {
		return
	}
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if u.OwnerAccountID != owner.AccountID && !owner.IsAdmin {
		jsonError(w, http.StatusForbidden, "not owner")
		return
	}
	versions, err := s.store.ListUploadVersions(r.Context(), u.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	type versionOut struct {
		Version   int    `json:"version"`
		Size      int64  `json:"size"`
		CreatedAt int64  `json:"created_at"`
		URL       string `json:"url"`
	}
	out := make([]versionOut, 0, len(versions))
	for _, v := range versions {
		out = append(out, versionOut{
			Version: v.Version, Size: v.Size, CreatedAt: v.CreatedAt.Unix(),
			URL: s.baseURL + "/p/" + slug + "/v/" + strconv.Itoa(v.Version),
		})
	}
	jsonOK(w, out)
}
