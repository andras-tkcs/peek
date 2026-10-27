package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/andras-tkcs/peek/internal/models"
)

const provisionedAccountSelect = `SELECT pa.provisioner_id,pa.external_id,pa.account_id,pa.created_account,COALESCE(pa.token_id,0),COALESCE(tk.expires_at,0),pa.created_at,pa.updated_at
	FROM provisioned_accounts pa LEFT JOIN tokens tk ON tk.id=pa.token_id`

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func scanProvisionedAccount(row interface{ Scan(...any) error }) (*models.ProvisionedAccount, error) {
	pa := &models.ProvisionedAccount{}
	var created int64
	if err := row.Scan(&pa.ProvisionerID, &pa.ExternalID, &pa.AccountID, &created, &pa.TokenID, &pa.TokenExpiresAt, &pa.CreatedAt, &pa.UpdatedAt); err != nil {
		return nil, err
	}
	pa.CreatedAccount = created == 1
	return pa, nil
}

func getProvisionedAccount(ctx context.Context, q queryRower, provisionerID int64, externalID string) (*models.ProvisionedAccount, error) {
	return scanProvisionedAccount(q.QueryRowContext(ctx, provisionedAccountSelect+` WHERE pa.provisioner_id=? AND pa.external_id=?`, provisionerID, externalID))
}

func getAccountTx(ctx context.Context, q queryRower, where string, arg any) (*models.Account, error) {
	a := &models.Account{}
	var isAdmin, disabled int64
	var email sql.NullString
	err := q.QueryRowContext(ctx, `SELECT id,email,name,is_admin,disabled FROM accounts WHERE `+where, arg).
		Scan(&a.ID, &email, &a.Name, &isAdmin, &disabled)
	if err != nil {
		return nil, err
	}
	a.Email = email.String
	a.IsAdmin = isAdmin == 1
	a.Disabled = disabled == 1
	return a, nil
}

// GetProvisionedAccount returns one provisioner's link; sql.ErrNoRows without one.
func (s *Store) GetProvisionedAccount(ctx context.Context, provisionerID int64, externalID string) (*models.ProvisionedAccount, error) {
	return getProvisionedAccount(ctx, s, provisionerID, externalID)
}

// UpsertProvisionedAccount creates or adopts the account for email and links it
// to externalID. email arrives validated and lower-cased.
func (s *Store) UpsertProvisionedAccount(ctx context.Context, provisionerID int64, externalID, email, name string) (*models.ProvisionedAccount, *models.Account, error) {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()

	link, err := getProvisionedAccount(ctx, tx, provisionerID, externalID)
	switch {
	case err == nil:
		acct, err := getAccountTx(ctx, tx, `id=?`, link.AccountID)
		if err != nil {
			return nil, nil, err
		}
		if strings.ToLower(acct.Email) != email {
			return nil, nil, ErrProvisionConflict
		}
		if acct.IsAdmin {
			return nil, nil, ErrProvisionAdmin
		}
		if name != "" && name != acct.Name {
			if _, err := tx.ExecContext(ctx, `UPDATE accounts SET name=?,updated_at=? WHERE id=?`, name, now, acct.ID); err != nil {
				return nil, nil, err
			}
			acct.Name = name
		}
		if _, err := tx.ExecContext(ctx, `UPDATE provisioned_accounts SET updated_at=? WHERE provisioner_id=? AND external_id=?`, now, provisionerID, externalID); err != nil {
			return nil, nil, err
		}
		link.UpdatedAt = now
		if err := tx.Commit(); err != nil {
			return nil, nil, err
		}
		return link, acct, nil
	case !errors.Is(err, sql.ErrNoRows):
		return nil, nil, err
	}

	created := false
	acct, err := getAccountTx(ctx, tx, `lower(email)=?`, email)
	switch {
	case err == nil:
		if acct.IsAdmin {
			return nil, nil, ErrProvisionAdmin
		}
		var other string
		err := tx.QueryRowContext(ctx, `SELECT external_id FROM provisioned_accounts WHERE provisioner_id=? AND account_id=?`, provisionerID, acct.ID).Scan(&other)
		if err == nil {
			return nil, nil, ErrProvisionConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, err
		}
	case errors.Is(err, sql.ErrNoRows):
		if name == "" {
			name, _, _ = strings.Cut(email, "@")
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO accounts(email,name,password_hash,is_admin,disabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			email, name, "", 0, 0, now, now)
		if err != nil {
			return nil, nil, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, nil, err
		}
		acct = &models.Account{ID: id, Email: email, Name: name}
		created = true
	default:
		return nil, nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO provisioned_accounts(provisioner_id,external_id,account_id,created_account,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
		provisionerID, externalID, acct.ID, boolToInt(created), now, now); err != nil {
		return nil, nil, err
	}
	link, err = getProvisionedAccount(ctx, tx, provisionerID, externalID)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return link, acct, nil
}

// ReplaceProvisionedToken stores token as the link's only token, deleting the
// previous one, and returns the new token id. sql.ErrNoRows without a link.
func (s *Store) ReplaceProvisionedToken(ctx context.Context, provisionerID int64, externalID, token, tokenName string, expiresAt int64) (int64, error) {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	link, err := getProvisionedAccount(ctx, tx, provisionerID, externalID)
	if err != nil {
		return 0, err
	}
	if link.TokenID != 0 {
		if err := deleteTokenTx(ctx, tx, link.TokenID); err != nil {
			return 0, err
		}
	}
	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx, `INSERT INTO tokens(account_id,token,name,is_admin,created_at,expires_at,hint) VALUES(?,?,?,0,?,?,?)`,
		link.AccountID, HashToken(token), strings.TrimSpace(tokenName), now, expiresAt, nullableHint(token))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE provisioned_accounts SET token_id=?,updated_at=? WHERE provisioner_id=? AND external_id=?`, id, now, provisionerID, externalID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// ReleaseProvisionedAccount deletes the link's token and the link. The account stays.
func (s *Store) ReleaseProvisionedAccount(ctx context.Context, provisionerID int64, externalID string) error {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	link, err := getProvisionedAccount(ctx, tx, provisionerID, externalID)
	if err != nil {
		return err
	}
	if link.TokenID != 0 {
		if err := deleteTokenTx(ctx, tx, link.TokenID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM provisioned_accounts WHERE provisioner_id=? AND external_id=?`, provisionerID, externalID); err != nil {
		return err
	}
	return tx.Commit()
}

// IsProvisionedToken reports whether tokenID is the token some link currently
// holds. Token ids are never reused (AUTOINCREMENT), so the answer cannot pass
// to a later token.
func (s *Store) IsProvisionedToken(ctx context.Context, tokenID int64) (bool, error) {
	var one int
	err := s.QueryRowContext(ctx, `SELECT 1 FROM provisioned_accounts WHERE token_id=? LIMIT 1`, tokenID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ProvisionedByAccount returns account id → provisioner names joined with ", " in provisioner id order.
func (s *Store) ProvisionedByAccount(ctx context.Context) (map[int64]string, error) {
	rows, err := s.QueryContext(ctx, `SELECT pa.account_id,p.name FROM provisioned_accounts pa JOIN provisioners p ON p.id=pa.provisioner_id ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		if prev, ok := out[id]; ok {
			name = prev + ", " + name
		}
		out[id] = name
	}
	return out, rows.Err()
}

// CountProvisionedAccounts returns how many accounts a provisioner links.
func (s *Store) CountProvisionedAccounts(ctx context.Context, provisionerID int64) (int64, error) {
	var n int64
	err := s.QueryRowContext(ctx, `SELECT COUNT(*) FROM provisioned_accounts WHERE provisioner_id=?`, provisionerID).Scan(&n)
	return n, err
}
