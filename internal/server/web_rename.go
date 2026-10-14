package server

import (
	"net/http"

	"github.com/andras-tkcs/peek/internal/uploads"
)

func (s *Server) handleDashboardRename(w http.ResponseWriter, r *http.Request) {
	owner, u, ok := s.dashboardGrantUpload(w, r)
	if !ok {
		return
	}
	slug := u.Slug
	res, err := uploads.Rename(r.Context(), s.store, s.baseURL, uploads.RenameInput{UploadID: u.ID, CurrentSlug: u.Slug, CurrentName: u.Name, Name: r.FormValue("name")})
	if err != nil {
		code := uploadFlashCode(err)
		if code == flashUploadPersistenceFailure {
			code = flashRenameFailed
		}
		dashboardFlashManage(w, r, "err", code, slug)
		return
	}
	s.auditRequest(r, owner.Name, "upload.rename", renameAuditDetail(u.Slug, res))
	dashboardFlashManage(w, r, "ok", flashRenamed, res.Slug)
}
