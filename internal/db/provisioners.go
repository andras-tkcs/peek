package db

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/andras-tkcs/peek/internal/models"
)

const provisionerColumns = `id,name,COALESCE(hint,''),COALESCE(created_by_account_id,0),created_at,last_used_at`

func scanProvisioner(row interface{ Scan(...any) error }) (*models.Provisioner, error) {
	p := &models.Provisioner{}
	if err := row.Scan(&p.ID, &p.Name, &p.Hint, &p.CreatedByAccountID, &p.CreatedAt, &p.LastUsedAt); err != nil {
		return nil, err
	}
	return p, nil
}

// CreateProvisioner stores a provisioning key (hashed) for a named key holder.
func (s *Store) CreateProvisioner(ctx context.Context, name, key string, createdBy int64) (*models.Provisioner, error) {
	var by any
	if createdBy != 0 {
		by = createdBy
	}
	res, err := s.ExecContext(ctx, `INSERT INTO provisioners(name,key_hash,hint,created_by_account_id,created_at) VALUES(?,?,?,?,?)`,
		strings.TrimSpace(name), HashToken(key), nullableHint(key), by, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return scanProvisioner(s.QueryRowContext(ctx, `SELECT `+provisionerColumns+` FROM provisioners WHERE id=?`, id))
}

// GetProvisionerByKey hashes key and returns its provisioner; sql.ErrNoRows when unknown.
func (s *Store) GetProvisionerByKey(ctx context.Context, key string) (*models.Provisioner, error) {
	return scanProvisioner(s.QueryRowContext(ctx, `SELECT `+provisionerColumns+` FROM provisioners WHERE key_hash=?`, HashToken(key)))
}

// ListProvisioners returns every provisioner by id, with Accounts set to its link count.
func (s *Store) ListProvisioners(ctx context.Context) ([]models.Provisioner, error) {
	rows, err := s.QueryContext(ctx, `SELECT p.id,p.name,COALESCE(p.hint,''),COALESCE(p.created_by_account_id,0),p.created_at,p.last_used_at,
		(SELECT COUNT(*) FROM provisioned_accounts pa WHERE pa.provisioner_id=p.id)
		FROM provisioners p ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Provisioner
	for rows.Next() {
		var p models.Provisioner
		if err := rows.Scan(&p.ID, &p.Name, &p.Hint, &p.CreatedByAccountID, &p.CreatedAt, &p.LastUsedAt, &p.Accounts); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TouchProvisionerLastUsed records a use at now.
func (s *Store) TouchProvisionerLastUsed(ctx context.Context, id int64, now time.Time) error {
	_, err := s.ExecContext(ctx, `UPDATE provisioners SET last_used_at=? WHERE id=?`, now.Unix(), id)
	return err
}

// DeleteProvisioner removes a provisioner, every token its links hold and the
// links themselves. The accounts stay. sql.ErrNoRows when unknown.
func (s *Store) DeleteProvisioner(ctx context.Context, id int64) error {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM provisioners WHERE id=?`, id).Scan(&exists); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT token_id FROM provisioned_accounts WHERE provisioner_id=? AND token_id IS NOT NULL`, id)
	if err != nil {
		return err
	}
	var tokenIDs []int64
	for rows.Next() {
		var tid int64
		if err := rows.Scan(&tid); err != nil {
			rows.Close()
			return err
		}
		tokenIDs = append(tokenIDs, tid)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, tid := range tokenIDs {
		if err := deleteTokenTx(ctx, tx, tid); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM provisioners WHERE id=?`, id)
	if err != nil {
		return err
	}
	if err := requireRowsAffected(res); err != nil {
		return err
	}
	return tx.Commit()
}

// deleteTokenTx detaches a token's uploads and deletes the token inside tx.
func deleteTokenTx(ctx context.Context, tx *sql.Tx, tokenID int64) error {
	if err := detachTokenUploads(ctx, tx, tokenID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE id=?`, tokenID)
	return err
}
