package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/privacyfence/peek/internal/models"
	"github.com/privacyfence/peek/internal/uploadquota"
)

// CreateVersionChecked appends a new version to an existing upload and returns
// its number. Storage quotas are the page owner's, not the actor's. There is no
// count check because versions are not pages.
func (s *Store) CreateVersionChecked(ctx context.Context, uploadID int64, objectKey string, size int64, actorAccountID int64, limits uploadquota.Limits) (int, error) {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var ownerID int64
	if err := tx.QueryRowContext(ctx, `SELECT owner_account_id FROM uploads WHERE id=?`, uploadID).Scan(&ownerID); err != nil {
		return 0, err
	}
	if limits.MaxTotalSize > 0 {
		var total int64
		if err := tx.QueryRowContext(ctx, sumVersionSizesSQL).Scan(&total); err != nil {
			return 0, err
		}
		if total+size > limits.MaxTotalSize {
			return 0, uploadquota.ErrTotalExceeded
		}
	}
	if limits.MaxStoragePerOwner > 0 {
		var total int64
		if err := tx.QueryRowContext(ctx, sumVersionSizesByOwnerSQL, ownerID).Scan(&total); err != nil {
			return 0, err
		}
		if total+size > limits.MaxStoragePerOwner {
			return 0, uploadquota.ErrOwnerStorageExceeded
		}
	}

	var next int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM upload_versions WHERE upload_id=?`, uploadID).Scan(&next); err != nil {
		return 0, err
	}
	var actorArg any
	if actorAccountID > 0 {
		actorArg = actorAccountID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO upload_versions(upload_id,version,object_key,size,created_by_account_id,created_at) VALUES(?,?,?,?,?,?)`,
		uploadID, next, objectKey, size, actorArg, time.Now().Unix()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uploads SET size=? WHERE id=?`, size, uploadID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

const uploadVersionSelect = `SELECT id,upload_id,version,object_key,size,COALESCE(created_by_account_id,0),created_at FROM upload_versions`

func scanUploadVersion(row interface{ Scan(...any) error }) (models.UploadVersion, error) {
	var v models.UploadVersion
	var ts int64
	if err := row.Scan(&v.ID, &v.UploadID, &v.Version, &v.ObjectKey, &v.Size, &v.CreatedByAccountID, &ts); err != nil {
		return v, err
	}
	v.CreatedAt = time.Unix(ts, 0)
	return v, nil
}

func scanUploadVersions(rows *sql.Rows) ([]models.UploadVersion, error) {
	defer rows.Close()
	var out []models.UploadVersion
	for rows.Next() {
		v, err := scanUploadVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetUploadVersion(ctx context.Context, uploadID int64, version int) (*models.UploadVersion, error) {
	v, err := scanUploadVersion(s.QueryRowContext(ctx, uploadVersionSelect+` WHERE upload_id=? AND version=?`, uploadID, version))
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Store) ListUploadVersions(ctx context.Context, uploadID int64) ([]models.UploadVersion, error) {
	rows, err := s.QueryContext(ctx, uploadVersionSelect+` WHERE upload_id=? ORDER BY version ASC`, uploadID)
	if err != nil {
		return nil, err
	}
	return scanUploadVersions(rows)
}

// ListPrunableVersions returns versions older than cutoff that are not the
// newest version of their upload.
func (s *Store) ListPrunableVersions(ctx context.Context, cutoff time.Time) ([]models.UploadVersion, error) {
	rows, err := s.QueryContext(ctx, uploadVersionSelect+` WHERE created_at < ?
		AND version < (SELECT MAX(m.version) FROM upload_versions m WHERE m.upload_id=upload_versions.upload_id)
		ORDER BY created_at ASC`, cutoff.Unix())
	if err != nil {
		return nil, err
	}
	return scanUploadVersions(rows)
}

// DeleteUploadVersion removes one version row and the comments written on it.
func (s *Store) DeleteUploadVersion(ctx context.Context, uploadID int64, version int) error {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM comments WHERE upload_id=? AND version=?`, uploadID, version); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM upload_versions WHERE upload_id=? AND version=?`, uploadID, version)
	if err != nil {
		return err
	}
	if err := requireRowsAffected(res); err != nil {
		return err
	}
	return tx.Commit()
}
