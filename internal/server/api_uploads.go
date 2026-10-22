package server

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/andras-tkcs/peek/internal/models"
	"github.com/andras-tkcs/peek/internal/uploads"
)

type uploadResp struct {
	Slug       string `json:"slug"`
	URL        string `json:"url"`
	Visibility string `json:"visibility"`
	Version    int    `json:"version"`
	VersionURL string `json:"version_url"`
	// BackendImage is the container image attached to this version, if any.
	BackendImage string `json:"backend_image,omitempty"`
}

// uploadBackendInput is the optional backend of an upload request.
type uploadBackendInput struct {
	Image string
	Port  int // already normalized by validateBackendInput
}

type uploadBodyKind int

const (
	uploadBodyUnknown uploadBodyKind = iota
	uploadBodyMultipart
	uploadBodyRawHTML
)

const passwordRemovedMessage = "password-protected pages were removed; use restricted visibility and grants"

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	owner, ok := requireAPIToken(w, r)
	if !ok {
		return
	}
	bodyKind, ok := uploadBodyKindFromContentType(r.Header.Get("Content-Type"))
	if !ok {
		jsonError(w, http.StatusUnsupportedMediaType, "unsupported content type")
		return
	}

	maxUpload := s.settingInt64(r.Context(), "max_upload", 2<<20)

	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+1024)

	var (
		data       []byte
		name       string
		visibility string
		slug       string
		backendImg string
		backendRaw string
	)

	if bodyKind == uploadBodyMultipart {
		if err := r.ParseMultipartForm(maxUpload); err != nil {
			jsonError(w, http.StatusBadRequest, "file too large or invalid form")
			return
		}
		if strings.TrimSpace(r.FormValue("password")) != "" {
			jsonError(w, http.StatusBadRequest, passwordRemovedMessage)
			return
		}
		visibility = strings.TrimSpace(r.FormValue("visibility"))
		slug = strings.TrimSpace(r.FormValue("slug"))
		backendImg = strings.TrimSpace(r.FormValue("backend_image"))
		backendRaw = strings.TrimSpace(r.FormValue("backend_port"))
		file, header, err := r.FormFile("file")
		if err != nil {
			jsonError(w, http.StatusBadRequest, "missing 'file'")
			return
		}
		defer file.Close()
		data, err = io.ReadAll(io.LimitReader(file, maxUpload+1))
		if err != nil || int64(len(data)) > maxUpload {
			jsonError(w, http.StatusRequestEntityTooLarge, "file too large")
			return
		}
		name = header.Filename
	} else {
		visibility = strings.TrimSpace(r.URL.Query().Get("visibility"))
		slug = strings.TrimSpace(r.URL.Query().Get("slug"))
		backendImg = strings.TrimSpace(r.URL.Query().Get("backend_image"))
		backendRaw = strings.TrimSpace(r.URL.Query().Get("backend_port"))
		name = r.URL.Query().Get("filename")
		if name == "" {
			name = "page"
		}
		var err error
		data, err = io.ReadAll(io.LimitReader(r.Body, maxUpload+1))
		if err != nil || int64(len(data)) > maxUpload {
			jsonError(w, http.StatusRequestEntityTooLarge, "file too large")
			return
		}
	}

	var backend *uploadBackendInput
	if backendImg != "" {
		port := 0
		if backendRaw != "" {
			var err error
			if port, err = strconv.Atoi(backendRaw); err != nil {
				jsonError(w, http.StatusBadRequest, "backend port must be between 1 and 65535")
				return
			}
		}
		if !s.requireBackendsEnabled(w) {
			return
		}
		port, status, msg := s.validateBackendInput(r.Context(), backendImg, port)
		if status != 0 {
			jsonError(w, status, msg)
			return
		}
		backend = &uploadBackendInput{Image: backendImg, Port: port}
	}

	if slug != "" {
		s.handleUploadVersion(w, r, owner, slug, visibility, data, backend)
		return
	}

	up, err := s.uploadService().Create(r.Context(), uploads.CreateInput{
		OwnerAccountID: owner.AccountID,
		OwnerTokenID:   owner.ID,
		Name:           name,
		Visibility:     visibility,
		Data:           data,
		Limits:         s.uploadLimits(r.Context()),
	})
	if err != nil {
		logUploadError(err)
		status, msg := uploadHTTPError(err)
		jsonError(w, status, msg)
		return
	}
	s.auditRequest(r, owner.Name, "upload.create", auditDetail("slug", up.Slug, "name", up.Name, "size", strconv.Itoa(up.Size)))

	resp := uploadResp{Slug: up.Slug, URL: up.URL, Visibility: up.Visibility, Version: up.Version, VersionURL: up.URL + "/v/" + strconv.Itoa(up.Version)}
	if backend != nil {
		created, err := s.store.GetUpload(r.Context(), up.Slug)
		if err != nil || !s.saveUploadBackend(r, owner, created.ID, up.Version, *backend) {
			jsonError(w, http.StatusInternalServerError, uploadBackendSaveFailed)
			return
		}
		resp.BackendImage = backend.Image
	}
	jsonOK(w, resp)
}

const uploadBackendSaveFailed = "page uploaded but its backend could not be saved"

// saveUploadBackend writes the backend row of a freshly uploaded version.
func (s *Server) saveUploadBackend(r *http.Request, owner *models.Token, uploadID int64, version int, b uploadBackendInput) bool {
	err := s.store.SetUploadBackend(r.Context(), models.UploadBackend{
		UploadID:           uploadID,
		Version:            version,
		Image:              b.Image,
		Port:               b.Port,
		CreatedByAccountID: owner.AccountID,
	})
	if err != nil {
		slog.Error("upload backend save failed", "upload_id", uploadID, "version", version, "err", err)
		return false
	}
	return true
}

func (s *Server) handleUploadVersion(w http.ResponseWriter, r *http.Request, owner *models.Token, slug, visibility string, data []byte, backend *uploadBackendInput) {
	if visibility != "" {
		jsonError(w, http.StatusBadRequest, "visibility cannot be set when uploading a new version; use the visibility endpoint")
		return
	}
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		if cur, aerr := s.store.ResolveSlugAlias(r.Context(), slug); aerr == nil {
			jsonError(w, http.StatusNotFound, "page was renamed; use slug "+cur)
			return
		}
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if u.OwnerAccountID != owner.AccountID && !owner.IsAdmin {
		jsonError(w, http.StatusForbidden, "not owner")
		return
	}
	prevVersion := u.LatestVersion
	res, err := s.uploadService().AddVersion(r.Context(), uploads.AddVersionInput{
		UploadID:       u.ID,
		Slug:           slug,
		ActorAccountID: owner.AccountID,
		Data:           data,
		Limits:         s.uploadLimits(r.Context()),
	})
	if err != nil {
		logUploadError(err)
		status, msg := uploadHTTPError(err)
		jsonError(w, status, msg)
		return
	}
	s.auditRequest(r, owner.Name, "upload.version.create", auditDetail("slug", slug, "version", strconv.Itoa(res.Version), "size", strconv.Itoa(res.Size)))
	resp := uploadResp{Slug: slug, URL: res.URL, Visibility: u.Visibility, Version: res.Version, VersionURL: res.VersionURL}
	if backend == nil {
		// A new version keeps the backend of the version it follows.
		prev, err := s.store.GetUploadBackend(r.Context(), u.ID, prevVersion)
		switch {
		case err == nil:
			backend = &uploadBackendInput{Image: prev.Image, Port: prev.Port}
		case !errors.Is(err, sql.ErrNoRows):
			slog.Error("upload backend inherit failed", "upload_id", u.ID, "version", prevVersion, "err", err)
			jsonError(w, http.StatusInternalServerError, uploadBackendSaveFailed)
			return
		}
	}
	if backend != nil {
		if !s.saveUploadBackend(r, owner, u.ID, res.Version, *backend) {
			jsonError(w, http.StatusInternalServerError, uploadBackendSaveFailed)
			return
		}
		resp.BackendImage = backend.Image
	}
	jsonOK(w, resp)
}

func uploadBodyKindFromContentType(contentType string) (uploadBodyKind, bool) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return uploadBodyUnknown, false
	}
	switch strings.ToLower(mediaType) {
	case "multipart/form-data":
		return uploadBodyMultipart, true
	case "text/html", "application/xhtml+xml":
		return uploadBodyRawHTML, true
	default:
		return uploadBodyUnknown, false
	}
}

func (s *Server) handleListUploads(w http.ResponseWriter, r *http.Request) {
	owner, ok := requireAPIToken(w, r)
	if !ok {
		return
	}
	var (
		list []models.Upload
		err  error
	)
	if owner.IsAdmin {
		list, err = s.store.ListAllUploads(r.Context())
	} else {
		list, err = s.store.ListUploadsByOwner(r.Context(), owner.AccountID)
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	type item struct {
		Slug       string `json:"slug"`
		Name       string `json:"name"`
		Owner      string `json:"owner"`
		Size       int64  `json:"size"`
		Visibility string `json:"visibility"`
		URL        string `json:"url"`
		CreatedAt  int64  `json:"created_at"`
		Version    int    `json:"version"`
	}
	out := make([]item, 0, len(list))
	for _, u := range list {
		out = append(out, item{
			Slug: u.Slug, Name: u.Name, Owner: u.OwnerName,
			Size: u.Size, Visibility: u.Visibility,
			URL: s.baseURL + "/p/" + u.Slug, CreatedAt: u.CreatedAt.Unix(),
			Version: u.LatestVersion,
		})
	}
	jsonOK(w, out)
}

func (s *Server) handleDeleteUpload(w http.ResponseWriter, r *http.Request) {
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
	if err := s.deleteUpload(r.Context(), *u); err != nil {
		slog.Error("api upload delete failed", "slug", slug, "err", err)
		jsonError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.auditRequest(r, owner.Name, "upload.delete", auditDetail("slug", slug, "name", u.Name))
	jsonOK(w, map[string]any{"deleted": slug})
}

func (s *Server) handleSetVisibility(w http.ResponseWriter, r *http.Request) {
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
	var body struct {
		Visibility string `json:"visibility"`
		Password   string `json:"password"`
	}
	if err := decodeJSON(w, r, &body, smallJSONBodyLimit); err != nil {
		jsonError(w, http.StatusBadRequest, "bad json")
		return
	}
	if strings.TrimSpace(body.Password) != "" {
		jsonError(w, http.StatusBadRequest, passwordRemovedMessage)
		return
	}
	v, err := uploads.PrepareVisibility(body.Visibility)
	if err != nil {
		status, msg := uploadHTTPError(err)
		jsonError(w, status, msg)
		return
	}
	oldVisibility := u.Visibility
	if err := s.store.SetUploadVisibility(r.Context(), u.ID, v); err != nil {
		jsonError(w, http.StatusInternalServerError, "db failed")
		return
	}
	s.auditRequest(r, owner.Name, "upload.visibility.set", auditDetail("slug", slug, "visibility", v))
	sent := false
	if oldVisibility != models.UploadVisibilityRestricted && v == models.UploadVisibilityRestricted {
		if grants, err := s.store.ListUploadGrants(r.Context(), u.ID); err != nil {
			slog.Error("share notification grant list failed", "slug", slug, "err", err)
		} else {
			sent, _ = s.notifyShare(r, owner.Name, owner.Email, u, grants)
		}
	}
	jsonOK(w, map[string]any{"visibility": v, "notified": sent})
}

func (s *Server) handleDeleteAllByOwner(w http.ResponseWriter, r *http.Request) {
	owner, ok := requireAPIToken(w, r)
	if !ok {
		return
	}
	uploads, err := s.store.ListUploadsByOwner(r.Context(), owner.AccountID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "db error")
		return
	}
	deleted := 0
	for _, u := range uploads {
		if err := s.deleteUpload(r.Context(), u); err != nil {
			slog.Warn("api upload delete_all failed", "slug", u.Slug, "err", err)
			continue
		}
		deleted++
	}
	s.auditRequest(r, owner.Name, "upload.delete_all", auditDetail("count", strconv.Itoa(deleted)))
	jsonOK(w, map[string]any{"deleted": deleted})
}
