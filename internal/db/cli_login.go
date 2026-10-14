package db

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/andras-tkcs/peek/internal/models"
)

func (s *Store) CreateCLILoginDevice(ctx context.Context, deviceCode, userCode string, expiresAt time.Time) error {
	return s.CreateCLILoginDeviceWithContext(ctx, deviceCode, userCode, expiresAt, "", "")
}

// CreateCLILoginDeviceWithContext stores a pending CLI login together with the
// client IP and User-Agent of the request that started it.
func (s *Store) CreateCLILoginDeviceWithContext(ctx context.Context, deviceCode, userCode string, expiresAt time.Time, requestIP, userAgent string) error {
	_, err := s.ExecContext(ctx, `INSERT INTO cli_login_devices(device_hash,user_code,status,created_at,expires_at,request_ip,request_user_agent) VALUES(?,?,?,?,?,?,?)`,
		HashToken(deviceCode), userCode, "pending", time.Now().Unix(), expiresAt.Unix(), requestIP, userAgent)
	return err
}

func (s *Store) GetCLILoginByDevice(ctx context.Context, deviceCode string) (*models.CLILoginDevice, error) {
	return s.getCLILoginWhere(ctx, `device_hash=?`, HashToken(deviceCode))
}

func (s *Store) GetCLILoginByUserCode(ctx context.Context, userCode string) (*models.CLILoginDevice, error) {
	return s.getCLILoginWhere(ctx, `user_code=?`, strings.ToUpper(strings.TrimSpace(userCode)))
}

func (s *Store) getCLILoginWhere(ctx context.Context, where string, arg any) (*models.CLILoginDevice, error) {
	d := &models.CLILoginDevice{}
	var accountID sql.NullInt64
	var created, expires, consumed int64
	err := s.QueryRowContext(ctx, `SELECT id,user_code,status,account_id,created_at,expires_at,consumed_at,request_ip,request_user_agent FROM cli_login_devices WHERE `+where, arg).
		Scan(&d.ID, &d.UserCode, &d.Status, &accountID, &created, &expires, &consumed, &d.RequestIP, &d.UserAgent)
	if err != nil {
		return nil, err
	}
	d.AccountID = accountID.Int64
	d.CreatedAt = time.Unix(created, 0)
	d.ExpiresAt = time.Unix(expires, 0)
	if consumed > 0 {
		d.ConsumedAt = time.Unix(consumed, 0)
	}
	return d, nil
}

func (s *Store) ApproveCLILogin(ctx context.Context, id, accountID int64) error {
	res, err := s.ExecContext(ctx, `UPDATE cli_login_devices SET status='approved', account_id=? WHERE id=? AND status='pending'`, accountID, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res)
}

func (s *Store) DenyCLILogin(ctx context.Context, id int64) error {
	res, err := s.ExecContext(ctx, `UPDATE cli_login_devices SET status='denied' WHERE id=? AND status='pending'`, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res)
}

func (s *Store) ConsumeCLILogin(ctx context.Context, id int64) error {
	res, err := s.ExecContext(ctx, `UPDATE cli_login_devices SET consumed_at=? WHERE id=? AND consumed_at=0`, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res)
}

func (s *Store) ExpireCLILogin(ctx context.Context, id int64) error {
	res, err := s.ExecContext(ctx, `UPDATE cli_login_devices SET status='expired' WHERE id=? AND status='pending'`, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res)
}
