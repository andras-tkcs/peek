package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/privacyfence/peek/internal/uploadquota"
	"github.com/privacyfence/peek/internal/uploads"
)

func (s *Server) uploadService() uploads.Service {
	return uploads.Service{Repository: s.store, Storage: s.storage, BaseURL: s.baseURL}
}

func (s *Server) uploadLimits(ctx context.Context) uploadquota.Limits {
	return uploadquota.Limits{
		MaxTotalSize:       s.settingInt64(ctx, "max_total_size", 0),
		MaxUploadsPerOwner: s.settingInt(ctx, "max_uploads_per_token", 0),
		MaxStoragePerOwner: s.settingInt64(ctx, "max_storage_per_token", 0),
	}
}

func uploadHTTPError(err error) (int, string) {
	var uploadErr *uploads.Error
	if !errors.As(err, &uploadErr) {
		return http.StatusInternalServerError, "upload failed"
	}
	switch uploadErr.Kind {
	case uploads.KindEmptyFile, uploads.KindInvalidVisibility, uploads.KindNameRequired, uploads.KindNameTooLong:
		return http.StatusBadRequest, uploadErr.Message
	case uploads.KindInvalidHTML:
		return http.StatusUnsupportedMediaType, uploadErr.Message
	case uploads.KindTotalQuotaExceeded, uploads.KindOwnerCountExceeded, uploads.KindOwnerStorageExceeded:
		return http.StatusRequestEntityTooLarge, uploadErr.Message
	default:
		return http.StatusInternalServerError, uploadErr.Message
	}
}

// uploadFlashCode maps an upload error to a dashboard flash code.
func uploadFlashCode(err error) string {
	var uploadErr *uploads.Error
	if errors.As(err, &uploadErr) {
		code := "upload_" + string(uploadErr.Kind)
		if _, ok := flashMessages[code]; ok {
			return code
		}
	}
	return flashUploadFailed
}

func logUploadError(err error) {
	var cleanupErr *uploads.CleanupError
	if errors.As(err, &cleanupErr) {
		slog.Warn("upload storage cleanup failed", "slug", cleanupErr.Slug, "err", cleanupErr.Err)
	}
}
