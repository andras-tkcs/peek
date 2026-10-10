package server

import (
	"context"
	"fmt"

	"github.com/andras-tkcs/peek/internal/models"
)

func (s *Server) deleteUpload(ctx context.Context, u models.Upload) error {
	versions, err := s.store.ListUploadVersions(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("list upload versions %q: %w", u.Slug, err)
	}
	keys := make([]string, 0, len(versions))
	for _, v := range versions {
		keys = append(keys, v.ObjectKey)
	}
	if len(keys) == 0 {
		keys = append(keys, u.Slug)
	}
	for _, key := range keys {
		if err := s.storage.Delete(ctx, key); err != nil {
			return fmt.Errorf("delete upload object %q: %w", key, err)
		}
	}
	if err := s.store.DeleteUpload(ctx, u.ID); err != nil {
		return fmt.Errorf("delete upload record %q: %w", u.Slug, err)
	}
	return nil
}
