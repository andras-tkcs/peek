package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/puemos/peek/internal/models"
	"github.com/puemos/peek/internal/uploadquota"
)

const (
	sumVersionSizesSQL        = `SELECT COALESCE(SUM(size), 0) FROM upload_versions`
	sumVersionSizesByOwnerSQL = `SELECT COALESCE(SUM(v.size), 0) FROM upload_versions v JOIN uploads u ON u.id=v.upload_id WHERE u.owner_account_id=?`
)

func (s *Store) CreateUploadChecked(ctx context.Context, slug string, ownerAccountID, ownerTokenID int64, name string, size int64, visibility, passwordHash string, limits uploadquota.Limits) error {
	if visibility == "" {
		visibility = models.UploadVisibilityPassword
	}
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if limits.MaxTotalSize > 0 {
		var total int64
		if err := tx.QueryRowContext(ctx, sumVersionSizesSQL).Scan(&total); err != nil {
			return err
		}
		if total+size > limits.MaxTotalSize {
			return uploadquota.ErrTotalExceeded
		}
	}
	if limits.MaxUploadsPerOwner > 0 {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads WHERE owner_account_id=?`, ownerAccountID).Scan(&count); err != nil {
			return err
		}
		if count >= limits.MaxUploadsPerOwner {
			return uploadquota.ErrOwnerCountExceeded
		}
	}
	if limits.MaxStoragePerOwner > 0 {
		var total int64
		if err := tx.QueryRowContext(ctx, sumVersionSizesByOwnerSQL, ownerAccountID).Scan(&total); err != nil {
			return err
		}
		if total+size > limits.MaxStoragePerOwner {
			return uploadquota.ErrOwnerStorageExceeded
		}
	}

	var tokenArg any
	if ownerTokenID > 0 {
		tokenArg = ownerTokenID
	}
	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx, `INSERT INTO uploads(slug,owner_account_id,owner_token_id,filename,size,visibility,password_hash,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		slug, ownerAccountID, tokenArg, name, size, visibility, passwordHash, now)
	if err != nil {
		return err
	}
	uploadID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO upload_versions(upload_id,version,object_key,size,created_by_account_id,created_at) VALUES(?,1,?,?,?,?)`,
		uploadID, slug, size, ownerAccountID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetUpload(ctx context.Context, slug string) (*models.Upload, error) {
	return scanUpload(s.QueryRowContext(ctx, uploadSelect+` WHERE u.slug=?`, slug))
}

func (s *Store) UploadSlugExists(ctx context.Context, slug string) (bool, error) {
	var exists bool
	err := s.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uploads WHERE slug=?) OR EXISTS(SELECT 1 FROM upload_slug_aliases WHERE slug=?)`, slug, slug).Scan(&exists)
	return exists, err
}

func (s *Store) GetUploadByID(ctx context.Context, id int64) (*models.Upload, error) {
	return scanUpload(s.QueryRowContext(ctx, uploadSelect+` WHERE u.id=?`, id))
}

func (s *Store) ListUploadsByOwner(ctx context.Context, ownerID int64) ([]models.Upload, error) {
	rows, err := s.QueryContext(ctx, uploadSelect+` WHERE u.owner_account_id=? ORDER BY u.created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	return scanUploads(rows)
}

func (s *Store) ListAllUploads(ctx context.Context) ([]models.Upload, error) {
	rows, err := s.QueryContext(ctx, uploadSelect+` ORDER BY u.created_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanUploads(rows)
}

func (s *Store) SetUploadVisibility(ctx context.Context, id int64, visibility, hash string) error {
	res, err := s.ExecContext(ctx, `UPDATE uploads SET visibility=?, password_hash=? WHERE id=?`, visibility, hash, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res)
}

func (s *Store) DeleteUpload(ctx context.Context, id int64) error {
	res, err := s.ExecContext(ctx, `DELETE FROM uploads WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res)
}

const uploadSelect = `SELECT u.id,u.slug,u.owner_account_id,u.owner_token_id,a.name,u.filename,u.size,u.visibility,u.password_hash,u.created_at,
	COALESCE((SELECT MAX(v.version) FROM upload_versions v WHERE v.upload_id=u.id),1)
	FROM uploads u JOIN accounts a ON a.id=u.owner_account_id`

func scanUpload(row interface{ Scan(...any) error }) (*models.Upload, error) {
	var u models.Upload
	var ts int64
	var tokenID sql.NullInt64
	if err := row.Scan(&u.ID, &u.Slug, &u.OwnerAccountID, &tokenID, &u.OwnerName, &u.Name, &u.Size, &u.Visibility, &u.PasswordHash, &ts, &u.LatestVersion); err != nil {
		return nil, err
	}
	u.OwnerTokenID = tokenID.Int64
	u.CreatedAt = time.Unix(ts, 0)
	return &u, nil
}

func scanUploads(rows *sql.Rows) ([]models.Upload, error) {
	defer rows.Close()
	var out []models.Upload
	for rows.Next() {
		u, err := scanUpload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) CountUploads(ctx context.Context) (int, error) {
	var n int
	err := s.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads`).Scan(&n)
	return n, err
}

func (s *Store) SumUploadSizes(ctx context.Context) (int64, error) {
	var total int64
	err := s.QueryRowContext(ctx, sumVersionSizesSQL).Scan(&total)
	return total, err
}

func (s *Store) CountUploadsByOwner(ctx context.Context, ownerID int64) (int, error) {
	var n int
	err := s.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads WHERE owner_account_id=?`, ownerID).Scan(&n)
	return n, err
}

func (s *Store) SumUploadSizesByOwner(ctx context.Context, ownerID int64) (int64, error) {
	var total int64
	err := s.QueryRowContext(ctx, sumVersionSizesByOwnerSQL, ownerID).Scan(&total)
	return total, err
}

func (s *Store) ListUploadsOlderThan(ctx context.Context, cutoff time.Time) ([]models.Upload, error) {
	rows, err := s.QueryContext(ctx, uploadSelect+` WHERE COALESCE((SELECT MAX(v.created_at) FROM upload_versions v WHERE v.upload_id=u.id), u.created_at) < ? ORDER BY u.created_at ASC`,
		cutoff.Unix())
	if err != nil {
		return nil, err
	}
	return scanUploads(rows)
}
