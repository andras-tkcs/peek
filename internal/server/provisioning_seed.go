package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

const provisioningKeyEnv = "PEEK_PROVISIONING_KEY_FILE"

// fileProvisionerName is the name of the provisioner the environment registers,
// or "" when no key file is set.
func fileProvisionerName(cfg Config) string {
	if cfg.ProvisioningKey == "" {
		return ""
	}
	return strings.TrimSpace(cfg.ProvisioningKeyName)
}

// seedProvisioner registers key as a provisioner called name, or rotates the
// provisioner of that name to key in place. It runs at every start and does
// nothing when key is empty or already registered. It needs no admin account.
func (s *Server) seedProvisioner(ctx context.Context, name, key string) error {
	if key == "" {
		return nil
	}
	name = strings.TrimSpace(name)
	if _, err := s.store.GetProvisionerByKey(ctx, key); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w", provisioningKeyEnv, err)
	}
	list, err := s.store.ListProvisioners(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", provisioningKeyEnv, err)
	}
	var matches []int64
	for _, p := range list {
		if p.Name == name {
			matches = append(matches, p.ID)
		}
	}
	switch len(matches) {
	case 0:
		p, err := s.store.CreateProvisioner(ctx, name, key, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", provisioningKeyEnv, err)
		}
		s.seedAudit(ctx, "provisioner registered", p.ID, name)
		slog.Info(fmt.Sprintf("provisioning key %q registered from %s", name, provisioningKeyEnv))
	case 1:
		if err := s.store.RotateProvisionerKey(ctx, matches[0], key); err != nil {
			return fmt.Errorf("%s: %w", provisioningKeyEnv, err)
		}
		s.seedAudit(ctx, "provisioner rotated", matches[0], name)
		slog.Info(fmt.Sprintf("provisioning key %q rotated from %s", name, provisioningKeyEnv))
	default:
		return errors.New("PEEK_PROVISIONING_KEY_NAME matches more than one provisioner; revoke the extra ones on the Admin page")
	}
	return nil
}

func (s *Server) seedAudit(ctx context.Context, action string, id int64, name string) {
	detail := auditDetail("id", fmt.Sprint(id), "name", name)
	slog.Info("audit", "actor", provisioningKeyEnv, "action", action, "detail", detail)
	s.persistAuditLog(ctx, provisioningKeyEnv, action, detail, "")
}
