package db

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/puemos/peek/internal/models"
)

func normalizeGrantEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// AddUploadGrant grants kind/email access to an upload. It is idempotent: a
// duplicate returns the existing row. Emails are stored lowercased and trimmed;
// address validation is the caller's job.
func (s *Store) AddUploadGrant(ctx context.Context, uploadID int64, kind, email string, createdBy int64) (*models.UploadGrant, error) {
	email = normalizeGrantEmail(email)
	var creatorArg any
	if createdBy > 0 {
		creatorArg = createdBy
	}
	if _, err := s.ExecContext(ctx, `INSERT INTO upload_grants(upload_id,kind,email,created_by_account_id,created_at) VALUES(?,?,?,?,?)
		ON CONFLICT(upload_id,kind,email) DO NOTHING`,
		uploadID, kind, email, creatorArg, time.Now().Unix()); err != nil {
		return nil, err
	}
	var g models.UploadGrant
	var creator sql.NullInt64
	var created int64
	err := s.QueryRowContext(ctx, `SELECT id,upload_id,kind,email,created_by_account_id,created_at FROM upload_grants WHERE upload_id=? AND kind=? AND email=?`,
		uploadID, kind, email).Scan(&g.ID, &g.UploadID, &g.Kind, &g.Email, &creator, &created)
	if err != nil {
		return nil, err
	}
	g.CreatedByAccountID = creator.Int64
	g.CreatedAt = time.Unix(created, 0)
	return &g, nil
}

// RemoveUploadGrant deletes one grant and returns sql.ErrNoRows if none matched.
func (s *Store) RemoveUploadGrant(ctx context.Context, uploadID int64, kind, email string) error {
	res, err := s.ExecContext(ctx, `DELETE FROM upload_grants WHERE upload_id=? AND kind=? AND email=?`,
		uploadID, kind, normalizeGrantEmail(email))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListUploadGrants returns an upload's grants ordered by kind, then email.
func (s *Store) ListUploadGrants(ctx context.Context, uploadID int64) ([]models.UploadGrant, error) {
	rows, err := s.QueryContext(ctx, `SELECT id,upload_id,kind,email,created_by_account_id,created_at FROM upload_grants WHERE upload_id=? ORDER BY kind, email`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.UploadGrant
	for rows.Next() {
		var g models.UploadGrant
		var creator sql.NullInt64
		var created int64
		if err := rows.Scan(&g.ID, &g.UploadID, &g.Kind, &g.Email, &creator, &created); err != nil {
			return nil, err
		}
		g.CreatedByAccountID = creator.Int64
		g.CreatedAt = time.Unix(created, 0)
		out = append(out, g)
	}
	return out, rows.Err()
}
