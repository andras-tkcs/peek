package db

import (
	"context"
	"time"
)

// RenameUpload sets an upload's slug and display name in one transaction. When the
// slug changes, the old slug becomes an alias that redirects to the upload and stays
// reserved; an alias the upload itself already owns is reclaimed. It returns
// ErrSlugTaken when newSlug belongs to another upload or another upload's alias, and
// sql.ErrNoRows when the upload does not exist.
func (s *Store) RenameUpload(ctx context.Context, uploadID int64, newSlug, newName string) error {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var oldSlug string
	if err := tx.QueryRowContext(ctx, `SELECT slug FROM uploads WHERE id=?`, uploadID).Scan(&oldSlug); err != nil {
		return err
	}
	if newSlug != oldSlug {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads WHERE slug=? AND id<>?`, newSlug, uploadID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrSlugTaken
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_slug_aliases WHERE slug=? AND upload_id<>?`, newSlug, uploadID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrSlugTaken
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM upload_slug_aliases WHERE slug=? AND upload_id=?`, newSlug, uploadID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO upload_slug_aliases(slug,upload_id,created_at) VALUES(?,?,?)`, oldSlug, uploadID, time.Now().Unix()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uploads SET slug=?, filename=? WHERE id=?`, newSlug, newName, uploadID); err != nil {
		return err
	}
	return tx.Commit()
}

// ResolveSlugAlias returns the current slug of the upload that slug used to name,
// or sql.ErrNoRows.
func (s *Store) ResolveSlugAlias(ctx context.Context, slug string) (string, error) {
	var cur string
	err := s.QueryRowContext(ctx, `SELECT u.slug FROM upload_slug_aliases a JOIN uploads u ON u.id=a.upload_id WHERE a.slug=?`, slug).Scan(&cur)
	return cur, err
}
