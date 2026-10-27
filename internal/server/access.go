package server

import (
	"context"
	"log/slog"
	"strings"

	"github.com/privacyfence/peek/internal/models"
)

// GroupChecker reports whether userEmail is a (direct or nested) member of groupEmail.
type GroupChecker interface {
	IsMember(ctx context.Context, groupEmail, userEmail string) (bool, error)
}

// accountCanViewRestricted reports whether a may view the restricted upload u:
// the owner, an admin, or an account matching a user or group grant.
func (s *Server) accountCanViewRestricted(ctx context.Context, a *models.Account, u *models.Upload) bool {
	if a.IsAdmin || a.ID == u.OwnerAccountID {
		return true
	}
	email := strings.ToLower(strings.TrimSpace(a.Email))
	if email == "" {
		return false
	}
	grants, err := s.store.ListUploadGrants(ctx, u.ID)
	if err != nil {
		slog.Error("grant lookup failed", "upload_id", u.ID, "err", err)
		return false
	}
	for _, g := range grants {
		if g.Kind == models.UploadGrantUser && g.Email == email {
			return true
		}
	}
	if s.groups != nil {
		for _, g := range grants {
			if g.Kind != models.UploadGrantGroup {
				continue
			}
			ok, err := s.groups.IsMember(ctx, g.Email, email)
			if err != nil {
				slog.Warn("group membership check failed", "group", g.Email, "err", err)
				continue
			}
			if ok {
				return true
			}
		}
	}
	return false
}

// maxSharedGroupChecks bounds the group lookups one dashboard render makes.
const maxSharedGroupChecks = 25

// sharedWithAccount returns the restricted uploads owned by someone else that a
// may view through a user grant or a group grant.
func (s *Server) sharedWithAccount(ctx context.Context, a *models.Account) ([]models.Upload, error) {
	email := strings.ToLower(strings.TrimSpace(a.Email))
	if email == "" {
		return nil, nil
	}
	var memberGroups []string
	if s.groups != nil {
		groups, err := s.store.ListRestrictedGroupGrantEmails(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		if len(groups) > maxSharedGroupChecks {
			slog.Warn("shared-with-me group check limit reached", "groups", len(groups))
			groups = groups[:maxSharedGroupChecks]
		}
		for _, g := range groups {
			ok, err := s.groups.IsMember(ctx, g, email)
			if err != nil {
				slog.Warn("group membership check failed", "group", g, "err", err)
				continue
			}
			if ok {
				memberGroups = append(memberGroups, g)
			}
		}
	}
	list, err := s.store.ListUploadsSharedWith(ctx, email, memberGroups, a.ID)
	if err != nil {
		slog.Error("dashboard shared list failed", "account_id", a.ID, "err", err)
		return nil, err
	}
	return list, nil
}
