package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/uploadquota"
)

// failOn makes every statement of kind op (INSERT, UPDATE or DELETE) on table
// fail with "injected" while reads keep working. Install it after seeding.
func failOn(t *testing.T, s *Store, table, op string) {
	t.Helper()
	name := fmt.Sprintf("fail_%s_%s", strings.ToLower(op), table)
	stmt := fmt.Sprintf(`CREATE TRIGGER %s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT,'injected'); END`, name, op, table)
	if _, err := s.Exec(stmt); err != nil {
		t.Fatalf("install %s: %v", name, err)
	}
}

// corruptInt stores text in an INTEGER column so that scanning the row into an
// integer fails.
func corruptInt(t *testing.T, s *Store, table, col string) {
	t.Helper()
	if _, err := s.Exec(fmt.Sprintf(`UPDATE %s SET %s='abc'`, table, col)); err != nil {
		t.Fatalf("corrupt %s.%s: %v", table, col, err)
	}
}

// wantErr fails the test unless err is non-nil.
func wantErr(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error", what)
	}
}

func TestStoreMethodsFailOnClosedStore(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	lim := uploadquota.Limits{}
	calls := map[string]func() error{
		"CreateAccount":               func() error { _, err := s.CreateAccount(ctx, "a@x.test", "a", false); return err },
		"CreateAccountWithPassword":   func() error { _, err := s.CreateAccountWithPassword(ctx, "a@x.test", "a", "h", false); return err },
		"GetAccountByID":              func() error { _, err := s.GetAccountByID(ctx, 1); return err },
		"GetAccountByEmail":           func() error { _, err := s.GetAccountByEmail(ctx, "a@x.test"); return err },
		"ListAccounts":                func() error { _, err := s.ListAccounts(ctx); return err },
		"SetAccountAdmin":             func() error { return s.SetAccountAdmin(ctx, 1, true) },
		"SetAccountAdminChecked":      func() error { return s.SetAccountAdminChecked(ctx, 1, true) },
		"SetAccountDisabled":          func() error { return s.SetAccountDisabled(ctx, 1, true) },
		"SetAccountDisabledChecked":   func() error { return s.SetAccountDisabledChecked(ctx, 1, true) },
		"CountAdminAccounts":          func() error { _, err := s.CountAdminAccounts(ctx); return err },
		"CountAccounts":               func() error { _, err := s.CountAccounts(ctx); return err },
		"BumpSessionEpoch":            func() error { _, err := s.BumpSessionEpoch(ctx, 1); return err },
		"AddAuditLog":                 func() error { return s.AddAuditLog(ctx, "a", "act", "d", "ip") },
		"ListAuditLog":                func() error { _, err := s.ListAuditLog(ctx, 10); return err },
		"CreateCLILoginDevice":        func() error { return s.CreateCLILoginDevice(ctx, "d", "U", now) },
		"CreateCLILoginDeviceWithCtx": func() error { return s.CreateCLILoginDeviceWithContext(ctx, "d", "U", now, "ip", "ua") },
		"GetCLILoginByDevice":         func() error { _, err := s.GetCLILoginByDevice(ctx, "d"); return err },
		"GetCLILoginByUserCode":       func() error { _, err := s.GetCLILoginByUserCode(ctx, "U"); return err },
		"ApproveCLILogin":             func() error { return s.ApproveCLILogin(ctx, 1, 1) },
		"DenyCLILogin":                func() error { return s.DenyCLILogin(ctx, 1) },
		"ConsumeCLILogin":             func() error { return s.ConsumeCLILogin(ctx, 1) },
		"ExpireCLILogin":              func() error { return s.ExpireCLILogin(ctx, 1) },
		"AddComment":                  func() error { _, err := s.AddComment(ctx, 1, 1, "s", "t", "k", "a", "c", "b", 0); return err },
		"ListComments":                func() error { _, err := s.ListComments(ctx, 1, 0); return err },
		"AddUploadGrant":              func() error { _, err := s.AddUploadGrant(ctx, 1, "user", "a@x.test", 0); return err },
		"RemoveUploadGrant":           func() error { return s.RemoveUploadGrant(ctx, 1, "user", "a@x.test") },
		"ListUploadGrants":            func() error { _, err := s.ListUploadGrants(ctx, 1); return err },
		"ListUploadGrantsForUploads":  func() error { _, err := s.ListUploadGrantsForUploads(ctx, []int64{1}); return err },
		"CreateInvite":                func() error { _, err := s.CreateInvite(ctx, "r", "c", "a@x.test", 1, now); return err },
		"GetInviteByID":               func() error { _, err := s.GetInviteByID(ctx, 1); return err },
		"GetInviteByToken":            func() error { _, err := s.GetInviteByToken(ctx, "r"); return err },
		"ListInvites":                 func() error { _, err := s.ListInvites(ctx); return err },
		"ConsumeInvite":               func() error { return s.ConsumeInvite(ctx, 1) },
		"RevokeInvite":                func() error { return s.RevokeInvite(ctx, 1) },
		"GetOAuthIdentity":            func() error { _, err := s.GetOAuthIdentity(ctx, "github", "1"); return err },
		"UpsertOAuthIdentity":         func() error { return s.UpsertOAuthIdentity(ctx, 1, "github", "1", "a@x.test", "a") },
		"AccountHasOAuthIdentity":     func() error { _, err := s.AccountHasOAuthIdentity(ctx, 1); return err },
		"GetSetting":                  func() error { _, err := s.GetSetting(ctx, "k"); return err },
		"SetSetting":                  func() error { return s.SetSetting(ctx, "k", "v") },
		"GetAllSettings":              func() error { _, err := s.GetAllSettings(ctx); return err },
		"RenameUpload":                func() error { return s.RenameUpload(ctx, 1, "new", "n") },
		"ResolveSlugAlias":            func() error { _, err := s.ResolveSlugAlias(ctx, "old"); return err },
		"CreateToken":                 func() error { return s.CreateToken(ctx, "tok", "n", false, 0) },
		"CreateTokenForAccount":       func() error { return s.CreateTokenForAccount(ctx, "tok", 1, "n") },
		"CreateAccountToken":          func() error { _, err := s.CreateAccountToken(ctx, 1, "tok", "n"); return err },
		"CreateAccountTokenExpiring":  func() error { _, err := s.CreateAccountTokenExpiring(ctx, 1, "tok", "n", 5); return err },
		"ListAccountTokens":           func() error { _, err := s.ListAccountTokens(ctx, 1); return err },
		"RegenerateAccountToken":      func() error { _, err := s.RegenerateAccountToken(ctx, 1, 1, "tok"); return err },
		"DeleteAccountToken":          func() error { _, err := s.DeleteAccountToken(ctx, 1, 1); return err },
		"TouchTokenLastUsed":          func() error { return s.TouchTokenLastUsed(ctx, 1, now) },
		"GetToken":                    func() error { _, err := s.GetToken(ctx, "tok"); return err },
		"GetTokenByID":                func() error { _, err := s.GetTokenByID(ctx, 1); return err },
		"DeleteToken":                 func() error { return s.DeleteToken(ctx, 1) },
		"DeleteTokenChecked":          func() error { _, err := s.DeleteTokenChecked(ctx, 1); return err },
		"CountAdminTokens":            func() error { _, err := s.CountAdminTokens(ctx); return err },
		"ListTokens":                  func() error { _, err := s.ListTokens(ctx); return err },
		"CountTokens":                 func() error { _, err := s.CountTokens(ctx); return err },
		"CreateUploadChecked":         func() error { return s.CreateUploadChecked(ctx, "s", 1, 0, "n", 1, "public", lim) },
		"GetUpload":                   func() error { _, err := s.GetUpload(ctx, "s"); return err },
		"UploadSlugExists":            func() error { _, err := s.UploadSlugExists(ctx, "s"); return err },
		"GetUploadByID":               func() error { _, err := s.GetUploadByID(ctx, 1); return err },
		"ListUploadsByOwner":          func() error { _, err := s.ListUploadsByOwner(ctx, 1); return err },
		"ListAllUploads":              func() error { _, err := s.ListAllUploads(ctx); return err },
		"SetUploadVisibility":         func() error { return s.SetUploadVisibility(ctx, 1, "public") },
		"DeleteUpload":                func() error { return s.DeleteUpload(ctx, 1) },
		"CountUploads":                func() error { _, err := s.CountUploads(ctx); return err },
		"SumUploadSizes":              func() error { _, err := s.SumUploadSizes(ctx); return err },
		"CountUploadsByOwner":         func() error { _, err := s.CountUploadsByOwner(ctx, 1); return err },
		"SumUploadSizesByOwner":       func() error { _, err := s.SumUploadSizesByOwner(ctx, 1); return err },
		"ListUploadsOlderThan":        func() error { _, err := s.ListUploadsOlderThan(ctx, now); return err },
		"CreateVersionChecked":        func() error { _, err := s.CreateVersionChecked(ctx, 1, "k", 1, 1, lim); return err },
		"GetUploadVersion":            func() error { _, err := s.GetUploadVersion(ctx, 1, 1); return err },
		"ListUploadVersions":          func() error { _, err := s.ListUploadVersions(ctx, 1); return err },
		"ListPrunableVersions":        func() error { _, err := s.ListPrunableVersions(ctx, now); return err },
		"DeleteUploadVersion":         func() error { return s.DeleteUploadVersion(ctx, 1, 1) },
		"RecordVisit":                 func() error { return s.RecordVisit(ctx, 1, 1, "c", "n", "ip", "ua") },
		"CountVisits":                 func() error { _, _, err := s.CountVisits(ctx, 1); return err },
		"VisitBuckets":                func() error { _, err := s.VisitBuckets(ctx, 1, now, 60); return err },
		"RecentVisits":                func() error { _, err := s.RecentVisits(ctx, 1, 5); return err },
		"UpsertVisitor":               func() error { return s.UpsertVisitor(ctx, "c", "n") },
		"GetVisitor":                  func() error { _, err := s.GetVisitor(ctx, "c"); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			wantErr(t, name, call())
		})
	}
}

type errResult struct{}

func (errResult) LastInsertId() (int64, error) { return 0, errors.New("no id") }
func (errResult) RowsAffected() (int64, error) { return 0, errors.New("no rows count") }

func TestRequireRowsAffectedReportsDriverError(t *testing.T) {
	wantErr(t, "requireRowsAffected", requireRowsAffected(errResult{}))
}
