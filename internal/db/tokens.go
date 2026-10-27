package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/privacyfence/peek/internal/models"
)

// HashToken returns the lookup hash of a randomly generated, high-entropy bearer
// token or key. A fast unsalted hash is intended here because the input is not a
// guessable secret and the hash is used as an indexed lookup key. Passwords use a
// slow hash elsewhere.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func isHashed(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
func (s *Store) CreateToken(ctx context.Context, token, name string, isAdmin bool, expiresAt int64) error {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx, `INSERT INTO accounts(email,name,is_admin,disabled,created_at,updated_at) VALUES(NULL,?,?,?,?,?)`,
		strings.TrimSpace(name), boolToInt(isAdmin), 0, now, now)
	if err != nil {
		return err
	}
	accountID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tokens(account_id,token,name,is_admin,created_at,expires_at,hint) VALUES(?,?,?,?,?,?,?)`,
		accountID, HashToken(token), strings.TrimSpace(name), boolToInt(isAdmin), now, expiresAt, nullableHint(token)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateTokenForAccount(ctx context.Context, token string, accountID int64, name string) error {
	if strings.TrimSpace(name) == "" {
		name = "API token"
	}
	_, err := s.CreateAccountToken(ctx, accountID, token, name)
	return err
}

// TokenLastUsedInterval is how often, in seconds, a token's last use is written.
const TokenLastUsedInterval = 60

// TokenHint returns the last four characters of token for display, or "" for
// tokens shorter than 8 characters.
func TokenHint(token string) string {
	if len(token) < 8 {
		return ""
	}
	return token[len(token)-4:]
}

// nullableHint maps an empty hint to NULL.
func nullableHint(token string) any {
	if h := TokenHint(token); h != "" {
		return h
	}
	return nil
}

// CreateAccountToken stores a new token for an existing account and returns its id.
func (s *Store) CreateAccountToken(ctx context.Context, accountID int64, token, name string) (int64, error) {
	return s.CreateAccountTokenExpiring(ctx, accountID, token, name, 0)
}

// CreateAccountTokenExpiring stores a new token for an existing account that
// stops working at expiresAt (unix seconds, 0 = never) and returns its id.
func (s *Store) CreateAccountTokenExpiring(ctx context.Context, accountID int64, token, name string, expiresAt int64) (int64, error) {
	res, err := s.ExecContext(ctx, `INSERT INTO tokens(account_id,token,name,is_admin,created_at,expires_at,hint) VALUES(?,?,?,0,?,?,?)`,
		accountID, HashToken(token), strings.TrimSpace(name), time.Now().Unix(), expiresAt, nullableHint(token))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const apiKeyColumns = `id,account_id,name,hint,created_at,expires_at,last_used_at`

func scanAPIKey(row interface{ Scan(...any) error }) (*models.APIKey, error) {
	k := &models.APIKey{}
	var hint sql.NullString
	var lastUsed sql.NullInt64
	var created int64
	if err := row.Scan(&k.ID, &k.AccountID, &k.Name, &hint, &created, &k.ExpiresAt, &lastUsed); err != nil {
		return nil, err
	}
	k.Hint = hint.String
	k.CreatedAt = time.Unix(created, 0)
	k.LastUsedAt = lastUsed.Int64
	return k, nil
}

// ListAccountTokens returns accountID's tokens, newest first, including expired ones.
func (s *Store) ListAccountTokens(ctx context.Context, accountID int64) ([]models.APIKey, error) {
	rows, err := s.QueryContext(ctx, `SELECT `+apiKeyColumns+` FROM tokens WHERE account_id=? ORDER BY created_at DESC, id DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// RegenerateAccountToken replaces the secret of accountID's token tokenID in one
// transaction and returns the updated key. sql.ErrNoRows when the token does not
// exist or belongs to another account.
func (s *Store) RegenerateAccountToken(ctx context.Context, accountID, tokenID int64, token string) (*models.APIKey, error) {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	k, err := scanAPIKey(tx.QueryRowContext(ctx, `SELECT `+apiKeyColumns+` FROM tokens WHERE id=? AND account_id=?`, tokenID, accountID))
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tokens SET token=?, hint=?, last_used_at=NULL WHERE id=? AND account_id=?`,
		HashToken(token), nullableHint(token), tokenID, accountID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	k.Hint = TokenHint(token)
	k.LastUsedAt = 0
	return k, nil
}

// DeleteAccountToken deletes accountID's token tokenID and returns what it was.
// sql.ErrNoRows when the token does not exist or belongs to another account.
func (s *Store) DeleteAccountToken(ctx context.Context, accountID, tokenID int64) (*models.APIKey, error) {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	k, err := scanAPIKey(tx.QueryRowContext(ctx, `SELECT `+apiKeyColumns+` FROM tokens WHERE id=? AND account_id=?`, tokenID, accountID))
	if err != nil {
		return nil, err
	}
	if err := detachTokenUploads(ctx, tx, tokenID); err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE id=? AND account_id=?`, tokenID, accountID)
	if err != nil {
		return nil, err
	}
	if err := requireRowsAffected(res); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return k, nil
}

// detachTokenUploads clears uploads.owner_token_id for a token about to be deleted.
func detachTokenUploads(ctx context.Context, tx *sql.Tx, tokenID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE uploads SET owner_token_id=NULL WHERE owner_token_id=?`, tokenID)
	return err
}

// TouchTokenLastUsed records a use at now unless one was recorded in the last
// TokenLastUsedInterval seconds.
func (s *Store) TouchTokenLastUsed(ctx context.Context, tokenID int64, now time.Time) error {
	_, err := s.ExecContext(ctx, `UPDATE tokens SET last_used_at=? WHERE id=? AND (last_used_at IS NULL OR last_used_at<=?)`,
		now.Unix(), tokenID, now.Unix()-TokenLastUsedInterval)
	return err
}

func (s *Store) GetToken(ctx context.Context, token string) (*models.Token, error) {
	return s.getTokenWhere(ctx, `tk.token=?`, HashToken(token))
}

func (s *Store) GetTokenByID(ctx context.Context, id int64) (*models.Token, error) {
	return s.getTokenWhere(ctx, `tk.id=?`, id)
}

func (s *Store) getTokenWhere(ctx context.Context, where string, arg any) (*models.Token, error) {
	t := &models.Token{}
	var isAdmin, disabled, ts, exp int64
	var email sql.NullString
	var lastUsed sql.NullInt64
	err := s.QueryRowContext(ctx, `SELECT tk.id,tk.account_id,tk.token,a.name,a.email,a.is_admin,a.disabled,tk.created_at,tk.expires_at,tk.last_used_at
		FROM tokens tk JOIN accounts a ON a.id=tk.account_id WHERE `+where, arg).
		Scan(&t.ID, &t.AccountID, &t.Token, &t.Name, &email, &isAdmin, &disabled, &ts, &exp, &lastUsed)
	if err != nil {
		return nil, err
	}
	t.LastUsedAt = lastUsed.Int64
	t.Email = email.String
	t.IsAdmin = isAdmin == 1
	t.Disabled = disabled == 1
	t.CreatedAt = time.Unix(ts, 0)
	t.ExpiresAt = exp
	// Check expiry: 0 means no expiry.
	if exp > 0 && time.Now().Unix() > exp {
		return nil, errors.New("token expired")
	}
	return t, nil
}

func (s *Store) DeleteToken(ctx context.Context, id int64) error {
	res, err := s.ExecContext(ctx, `DELETE FROM tokens WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res)
}

func (s *Store) DeleteTokenChecked(ctx context.Context, id int64) (*models.Token, error) {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	t := &models.Token{}
	var isAdmin, disabled, ts, exp int64
	var email sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT tk.id,tk.account_id,tk.token,a.name,a.email,a.is_admin,a.disabled,tk.created_at,tk.expires_at
		FROM tokens tk JOIN accounts a ON a.id=tk.account_id WHERE tk.id=?`, id).
		Scan(&t.ID, &t.AccountID, &t.Token, &t.Name, &email, &isAdmin, &disabled, &ts, &exp)
	if err != nil {
		return nil, err
	}
	t.Email = email.String
	t.IsAdmin = isAdmin == 1
	t.Disabled = disabled == 1
	t.CreatedAt = time.Unix(ts, 0)
	t.ExpiresAt = exp

	if t.IsAdmin && !t.Disabled {
		n, err := countActiveAdminTokens(ctx, tx)
		if err != nil {
			return nil, err
		}
		if n <= 1 {
			return nil, ErrLastAdmin
		}
	}
	if err := detachTokenUploads(ctx, tx, id); err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	if err := requireRowsAffected(res); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) CountAdminTokens(ctx context.Context) (int, error) {
	var n int
	err := s.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens tk JOIN accounts a ON a.id=tk.account_id WHERE a.is_admin=1 AND a.disabled=0`).Scan(&n)
	return n, err
}

func countActiveAdminTokens(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens tk JOIN accounts a ON a.id=tk.account_id WHERE a.is_admin=1 AND a.disabled=0`).Scan(&n)
	return n, err
}

func (s *Store) ListTokens(ctx context.Context) ([]models.Token, error) {
	rows, err := s.QueryContext(ctx, `SELECT tk.id,tk.account_id,tk.token,a.name,a.email,a.is_admin,a.disabled,tk.created_at,tk.expires_at
		FROM tokens tk JOIN accounts a ON a.id=tk.account_id ORDER BY tk.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Token
	for rows.Next() {
		var t models.Token
		var isAdmin, disabled, ts, exp int64
		var email sql.NullString
		if err := rows.Scan(&t.ID, &t.AccountID, &t.Token, &t.Name, &email, &isAdmin, &disabled, &ts, &exp); err != nil {
			return nil, err
		}
		t.Email = email.String
		t.IsAdmin = isAdmin == 1
		t.Disabled = disabled == 1
		t.CreatedAt = time.Unix(ts, 0)
		t.ExpiresAt = exp
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) CountTokens(ctx context.Context) (int, error) {
	var n int
	err := s.QueryRowContext(ctx, `SELECT COUNT(*) FROM tokens`).Scan(&n)
	return n, err
}
