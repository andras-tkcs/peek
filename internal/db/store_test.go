package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/models"
	"github.com/privacyfence/peek/internal/uploadquota"

	_ "modernc.org/sqlite"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "peek.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

func TestCreateGetToken(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	token := "token-secret-abc"
	if err := s.CreateToken(context.Background(), token, "test", false, 0); err != nil {
		t.Fatalf("create token: %v", err)
	}
	got, err := s.GetToken(context.Background(), token)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if got.Name != "test" || got.IsAdmin || got.Token == token || got.AccountID == 0 {
		t.Fatalf("token mismatch: %+v", got)
	}
	if got.Token != HashToken(token) {
		t.Fatalf("expected token to be stored as hash")
	}
}

func TestTokenExpiry(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	expired := "expired-token"
	if err := s.CreateToken(context.Background(), expired, "expired", false, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, err := s.GetToken(context.Background(), expired); err == nil {
		t.Fatalf("expected expired token to be rejected")
	}
	fresh := "fresh-token"
	if err := s.CreateToken(context.Background(), fresh, "fresh", false, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, err := s.GetToken(context.Background(), fresh); err != nil {
		t.Fatalf("expected valid token to be returned: %v", err)
	}
}

func TestTokenNoExpiry(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateToken(context.Background(), "no-exp", "no-exp", false, 0); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, err := s.GetToken(context.Background(), "no-exp"); err != nil {
		t.Fatalf("token with no expiry should be valid: %v", err)
	}
}

func TestCreateGetUpload(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateToken(context.Background(), "owner", "owner", false, 0); err != nil {
		t.Fatalf("create token: %v", err)
	}
	tok, err := s.GetToken(context.Background(), "owner")
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if err := s.CreateUploadChecked(context.Background(), "slug1", tok.AccountID, tok.ID, "page.html", 42, "public", uploadquota.Limits{}); err != nil {
		t.Fatalf("create upload: %v", err)
	}
	got, err := s.GetUpload(context.Background(), "slug1")
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if got.Slug != "slug1" || got.Name != "page.html" || got.Size != 42 || got.Visibility != "public" || got.OwnerTokenID != tok.ID || got.OwnerAccountID != tok.AccountID {
		t.Fatalf("upload mismatch: %+v", got)
	}
	list, err := s.ListUploadsByOwner(context.Background(), tok.AccountID)
	if err != nil {
		t.Fatalf("list uploads: %v", err)
	}
	if len(list) != 1 || list[0].Visibility != "public" {
		t.Fatalf("list visibility mismatch: %+v", list)
	}
	total, err := s.SumUploadSizesByOwner(context.Background(), tok.AccountID)
	if err != nil {
		t.Fatalf("sum owner sizes: %v", err)
	}
	if total != 42 {
		t.Fatalf("expected owner size 42, got %d", total)
	}
}

func TestUploadRepositoryHonorsCanceledContext(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.UploadSlugExists(ctx, "page"); !errors.Is(err, context.Canceled) {
		t.Fatalf("upload slug lookup should honor canceled context, got %v", err)
	}
	if err := s.CreateUploadChecked(ctx, "page", 1, 0, "page.html", 42, "public", uploadquota.Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("upload creation should honor canceled context, got %v", err)
	}
}

func TestUploadMutationsReportMissingRows(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	if err := s.SetUploadVisibility(context.Background(), 999, "restricted"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("set visibility on missing upload should fail with sql.ErrNoRows, got %v", err)
	}
	if err := s.DeleteUpload(context.Background(), 999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("delete missing upload should fail with sql.ErrNoRows, got %v", err)
	}
}

func TestAccountAndTokenMutationsReportMissingRows(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	if err := s.SetAccountAdmin(context.Background(), 999, true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("set admin on missing account should fail with sql.ErrNoRows, got %v", err)
	}
	if err := s.SetAccountAdminChecked(context.Background(), 999, true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("checked set admin on missing account should fail with sql.ErrNoRows, got %v", err)
	}
	if err := s.SetAccountDisabled(context.Background(), 999, true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("set disabled on missing account should fail with sql.ErrNoRows, got %v", err)
	}
	if err := s.SetAccountDisabledChecked(context.Background(), 999, false); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("checked set disabled on missing account should fail with sql.ErrNoRows, got %v", err)
	}
	if err := s.DeleteToken(context.Background(), 999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("delete missing token should fail with sql.ErrNoRows, got %v", err)
	}
	if _, err := s.DeleteTokenChecked(context.Background(), 999); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("checked delete missing token should fail with sql.ErrNoRows, got %v", err)
	}
}

func TestAddListComments(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateToken(context.Background(), "owner", "owner", false, 0); err != nil {
		t.Fatalf("create token: %v", err)
	}
	tok, _ := s.GetToken(context.Background(), "owner")
	if err := s.CreateUploadChecked(context.Background(), "slug2", tok.AccountID, tok.ID, "page.html", 0, "public", uploadquota.Limits{}); err != nil {
		t.Fatalf("create upload: %v", err)
	}
	up, _ := s.GetUpload(context.Background(), "slug2")
	if _, err := s.AddComment(context.Background(), up.ID, 1, "#id", "text", "text", "Alice", "cookie-a", "comment body", 0); err != nil {
		t.Fatalf("add comment: %v", err)
	}
	if _, err := s.AddComment(context.Background(), up.ID, 1, "#id2", "text2", "element", "Bob", "cookie-b", "second", 0); err != nil {
		t.Fatalf("add comment: %v", err)
	}
	comments, err := s.ListComments(context.Background(), up.ID, 0)
	if err != nil {
		t.Fatalf("list comments: %v", err)
	}
	if len(comments) != 2 {
		t.Fatalf("expected 2 comments, got %d", len(comments))
	}
	if comments[0].AuthorName != "Alice" || comments[1].AuthorName != "Bob" {
		t.Fatalf("comment order or content mismatch: %+v", comments)
	}
	if comments[0].AnchorKind != "text" || comments[1].AnchorKind != "element" {
		t.Fatalf("comment anchor kinds mismatch: %+v", comments)
	}
}

func TestAddCommentReturnsStoredComment(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	if err := s.CreateToken(ctx, "owner", "owner", false, 0); err != nil {
		t.Fatalf("create token: %v", err)
	}
	tok, _ := s.GetToken(ctx, "owner")
	if err := s.CreateUploadChecked(ctx, "slug3", tok.AccountID, tok.ID, "page.html", 0, "public", uploadquota.Limits{}); err != nil {
		t.Fatalf("create upload: %v", err)
	}
	up, _ := s.GetUpload(ctx, "slug3")
	c, err := s.AddComment(ctx, up.ID, 1, "#id", "text", "text", "Alice", "cookie-a", "comment body", 0)
	if err != nil {
		t.Fatalf("add comment: %v", err)
	}
	comments, err := s.ListComments(ctx, up.ID, 0)
	if err != nil || len(comments) != 1 {
		t.Fatalf("list comments: %v %+v", err, comments)
	}
	if c.Version != 1 || comments[0].Version != 1 {
		t.Fatalf("returned version %d, listed version %d, want 1", c.Version, comments[0].Version)
	}
	if c.ID == 0 || c.ID != comments[0].ID {
		t.Fatalf("returned id %d, listed id %d", c.ID, comments[0].ID)
	}
	if c.CreatedAt.IsZero() || c.CreatedAt.Unix() != comments[0].CreatedAt.Unix() {
		t.Fatalf("returned created_at %v, listed %v", c.CreatedAt, comments[0].CreatedAt)
	}
}

func TestAddListAuditLog(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.AddAuditLog(context.Background(), "admin", "settings.update", "key=retention", "127.0.0.1"); err != nil {
		t.Fatalf("add audit log: %v", err)
	}
	if err := s.AddAuditLog(context.Background(), "user", "upload.create", "slug=foo", "127.0.0.1"); err != nil {
		t.Fatalf("add audit log: %v", err)
	}
	entries, err := s.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("list audit log: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	actions := map[string]bool{}
	for _, e := range entries {
		actions[e.Action] = true
	}
	if !actions["settings.update"] || !actions["upload.create"] {
		t.Fatalf("expected both actions, got %+v", entries)
	}
}

func TestSettingsGetSet(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.SetSetting(context.Background(), "foo", "bar"); err != nil {
		t.Fatalf("set setting: %v", err)
	}
	got, err := s.GetSetting(context.Background(), "foo")
	if err != nil {
		t.Fatalf("get setting: %v", err)
	}
	if got != "bar" {
		t.Fatalf("expected setting value bar, got %q", got)
	}
	if err := s.SetSetting(context.Background(), "foo", "baz"); err != nil {
		t.Fatalf("update setting: %v", err)
	}
	got, _ = s.GetSetting(context.Background(), "foo")
	if got != "baz" {
		t.Fatalf("expected updated value baz, got %q", got)
	}
	all, err := s.GetAllSettings(context.Background())
	if err != nil {
		t.Fatalf("get all settings: %v", err)
	}
	if all["foo"] != "baz" {
		t.Fatalf("expected all settings to include foo=baz, got %+v", all)
	}
}

func TestGetMissingSetting(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if _, err := s.GetSetting(context.Background(), "missing"); err == nil {
		t.Fatalf("expected error for missing setting")
	}
}

func TestListTokens(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateToken(context.Background(), "a", "first", false, 0); err != nil {
		t.Fatalf("create token: %v", err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	if err := s.CreateToken(context.Background(), "b", "second", true, exp); err != nil {
		t.Fatalf("create token: %v", err)
	}
	tokens, err := s.ListTokens(context.Background())
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if !tokens[0].IsAdmin && !tokens[1].IsAdmin {
		t.Fatalf("expected one admin token")
	}
	if tokens[0].AccountID == 0 || tokens[1].AccountID == 0 {
		t.Fatalf("expected account-backed tokens: %+v", tokens)
	}
	if tokens[1].ExpiresAt != exp && tokens[0].ExpiresAt != exp {
		t.Fatalf("expected list to include expiry %d, got %+v", exp, tokens)
	}
}

func TestLegacyAuthMigrationPreservesTokenAndUploadOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peek.db")
	legacy, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
CREATE TABLE tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	token TEXT UNIQUE NOT NULL,
	name TEXT NOT NULL,
	is_admin INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);
CREATE TABLE uploads (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	slug TEXT UNIQUE NOT NULL,
	owner_token_id INTEGER NOT NULL REFERENCES tokens(id),
	filename TEXT NOT NULL,
	size INTEGER NOT NULL,
	password_hash TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE TABLE comments (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
	element_selector TEXT NOT NULL,
	element_text TEXT NOT NULL DEFAULT '',
	author_name TEXT NOT NULL,
	author_cookie TEXT NOT NULL,
	body TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE visits (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
	visitor_cookie TEXT NOT NULL,
	visitor_name TEXT NOT NULL DEFAULT '',
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	visited_at INTEGER NOT NULL
);
CREATE TABLE visitors (
	cookie TEXT PRIMARY KEY,
	name TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	last_seen INTEGER NOT NULL
);
CREATE TABLE settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
INSERT INTO tokens(token,name,is_admin,created_at) VALUES('legacy-admin','Admin',1,100);
INSERT INTO uploads(slug,owner_token_id,filename,size,created_at) VALUES('abc',1,'page.html',10,101);
INSERT INTO comments(upload_id,element_selector,element_text,author_name,author_cookie,body,created_at) VALUES(1,'#hero','Important','Ada','visitor','Looks good',102);
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	tok, err := store.GetToken(context.Background(), "legacy-admin")
	if err != nil {
		t.Fatalf("legacy token should still authenticate: %v", err)
	}
	if !tok.IsAdmin || tok.AccountID == 0 || tok.Token == "legacy-admin" || tok.ExpiresAt != 0 {
		t.Fatalf("unexpected migrated token: %+v", tok)
	}
	up, err := store.GetUpload(context.Background(), "abc")
	if err != nil {
		t.Fatal(err)
	}
	if up.OwnerAccountID != tok.AccountID || up.OwnerTokenID != tok.ID {
		t.Fatalf("upload ownership not migrated: upload=%+v token=%+v", up, tok)
	}
	comments, err := store.ListComments(context.Background(), up.ID, 0)
	if err != nil {
		t.Fatalf("list migrated comments: %v", err)
	}
	if len(comments) != 1 || comments[0].ElementText != "Important" || comments[0].AnchorKind != "" {
		t.Fatalf("unexpected migrated comments: %+v", comments)
	}
	if err := store.CreateUploadChecked(context.Background(), "oauth", tok.AccountID, 0, "oauth.html", 5, "public", uploadquota.Limits{}); err != nil {
		t.Fatalf("account-owned upload without token should be allowed: %v", err)
	}
	n, err := store.CountUploadsByOwner(context.Background(), tok.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 account uploads, got %d", n)
	}
}

func TestIsMigrationAppliedReportsMetadataReadFailure(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	applied, err := store.isMigrationApplied(1)
	if err == nil {
		t.Fatal("expected migration metadata read failure")
	}
	if applied {
		t.Fatal("closed store should not report migration as applied")
	}
}

func TestInviteAndCLILoginConsumptionAreOneTime(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateToken(context.Background(), "admin-token", "Admin", true, 0); err != nil {
		t.Fatal(err)
	}
	admin, err := store.GetToken(context.Background(), "admin-token")
	if err != nil {
		t.Fatal(err)
	}

	inv, err := store.CreateInvite(context.Background(), "raw-invite", "ciphertext", "USER@Example.COM", admin.AccountID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetInviteByToken(context.Background(), "raw-invite")
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "user@example.com" || got.Token != "ciphertext" {
		t.Fatalf("unexpected invite: %+v", got)
	}
	if err := store.ConsumeInvite(context.Background(), inv.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeInvite(context.Background(), inv.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second consume should fail, got %v", err)
	}
	if err := store.RevokeInvite(context.Background(), inv.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("revoking consumed invite should fail, got %v", err)
	}

	revoked, err := store.CreateInvite(context.Background(), "raw-revoke", "ciphertext", "revoke@example.com", admin.AccountID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeInvite(context.Background(), revoked.ID); err != nil {
		t.Fatalf("revoke invite: %v", err)
	}
	if err := store.RevokeInvite(context.Background(), revoked.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second revoke should fail, got %v", err)
	}

	if err := store.CreateCLILoginDevice(context.Background(), "device", "ABCDEFGH", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	device, err := store.GetCLILoginByDevice(context.Background(), "device")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveCLILogin(context.Background(), device.ID, admin.AccountID); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveCLILogin(context.Background(), device.ID, admin.AccountID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second CLI approve should fail, got %v", err)
	}
	if err := store.DenyCLILogin(context.Background(), device.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("denying approved CLI login should fail, got %v", err)
	}
	if err := store.ExpireCLILogin(context.Background(), device.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expiring approved CLI login should fail, got %v", err)
	}
	if err := store.ConsumeCLILogin(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeCLILogin(context.Background(), device.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second CLI consume should fail, got %v", err)
	}

	if err := store.CreateCLILoginDevice(context.Background(), "deny-device", "HJKLMNPQ", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	denyDevice, err := store.GetCLILoginByDevice(context.Background(), "deny-device")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DenyCLILogin(context.Background(), denyDevice.ID); err != nil {
		t.Fatalf("deny CLI login: %v", err)
	}
	if err := store.DenyCLILogin(context.Background(), denyDevice.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second CLI deny should fail, got %v", err)
	}
	if err := store.ApproveCLILogin(context.Background(), denyDevice.ID, admin.AccountID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("approving denied CLI login should fail, got %v", err)
	}

	if err := store.CreateCLILoginDevice(context.Background(), "expire-device", "RSTUVWXY", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	expireDevice, err := store.GetCLILoginByDevice(context.Background(), "expire-device")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ExpireCLILogin(context.Background(), expireDevice.ID); err != nil {
		t.Fatalf("expire CLI login: %v", err)
	}
	if err := store.ExpireCLILogin(context.Background(), expireDevice.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second CLI expire should fail, got %v", err)
	}
	if err := store.ApproveCLILogin(context.Background(), expireDevice.ID, admin.AccountID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("approving expired CLI login should fail, got %v", err)
	}
}

func TestCreateUploadCheckedEnforcesQuotas(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateToken(context.Background(), "owner", "owner", false, 0); err != nil {
		t.Fatal(err)
	}
	tok, err := s.GetToken(context.Background(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	limits := uploadquota.Limits{MaxTotalSize: 15, MaxUploadsPerOwner: 1, MaxStoragePerOwner: 12}
	if err := s.CreateUploadChecked(context.Background(), "one", tok.AccountID, tok.ID, "one.html", 10, "public", limits); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	if err := s.CreateUploadChecked(context.Background(), "two", tok.AccountID, tok.ID, "two.html", 1, "public", limits); !errors.Is(err, uploadquota.ErrOwnerCountExceeded) {
		t.Fatalf("expected owner count quota, got %v", err)
	}

	if err := s.CreateToken(context.Background(), "second", "second", false, 0); err != nil {
		t.Fatal(err)
	}
	tok2, err := s.GetToken(context.Background(), "second")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUploadChecked(context.Background(), "three", tok2.AccountID, tok2.ID, "three.html", 10, "public", limits); !errors.Is(err, uploadquota.ErrTotalExceeded) {
		t.Fatalf("expected total quota, got %v", err)
	}
}

func TestUploadSlugExists(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateToken(context.Background(), "owner", "owner", false, 0); err != nil {
		t.Fatal(err)
	}
	tok, err := s.GetToken(context.Background(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	exists, err := s.UploadSlugExists(context.Background(), "page")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("slug should not exist before upload")
	}
	if err := s.CreateUploadChecked(context.Background(), "page", tok.AccountID, tok.ID, "page.html", 10, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	exists, err = s.UploadSlugExists(context.Background(), "page")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("slug should exist after upload")
	}
}

func TestCheckedAdminUpdatesPreserveLastAdmin(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateToken(context.Background(), "admin", "admin", true, 0); err != nil {
		t.Fatal(err)
	}
	admin, err := s.GetToken(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdminChecked(context.Background(), admin.AccountID, false); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected last admin error, got %v", err)
	}
	if err := s.SetAccountDisabledChecked(context.Background(), admin.AccountID, true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected last admin disable error, got %v", err)
	}

	if err := s.CreateToken(context.Background(), "admin2", "admin2", true, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdminChecked(context.Background(), admin.AccountID, false); err != nil {
		t.Fatalf("demote with second admin: %v", err)
	}
}

func TestDeleteTokenCheckedPreservesLastAdminAndAllowsExpiredDelete(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.CreateToken(context.Background(), "admin", "admin", true, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	tokens, err := s.ListTokens(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	admin := tokens[0]
	if _, err := s.DeleteTokenChecked(context.Background(), admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected last admin token error, got %v", err)
	}
	if err := s.CreateToken(context.Background(), "admin2", "admin2", true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteTokenChecked(context.Background(), admin.ID); err != nil {
		t.Fatalf("delete expired admin token with another admin present: %v", err)
	}
}

func seedVersionTestUpload(t *testing.T, s *Store, slug string) *models.Upload {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateToken(ctx, "owner-"+slug, "owner", false, 0); err != nil {
		t.Fatalf("create token: %v", err)
	}
	tok, err := s.GetToken(ctx, "owner-"+slug)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if err := s.CreateUploadChecked(ctx, slug, tok.AccountID, tok.ID, "page.html", 1, "public", uploadquota.Limits{}); err != nil {
		t.Fatalf("create upload: %v", err)
	}
	up, err := s.GetUpload(ctx, slug)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	return up
}

func TestListCommentsFiltersByVersion(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	up := seedVersionTestUpload(t, s, "verc")
	if _, err := s.AddComment(ctx, up.ID, 1, "#a", "a", "text", "Alice", "ca", "on v1", 0); err != nil {
		t.Fatalf("add v1 comment: %v", err)
	}
	if _, err := s.AddComment(ctx, up.ID, 2, "#b", "b", "text", "Bob", "cb", "on v2", 0); err != nil {
		t.Fatalf("add v2 comment: %v", err)
	}
	all, err := s.ListComments(ctx, up.ID, 0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("version 0 returned %d comments, want 2", len(all))
	}
	v2, err := s.ListComments(ctx, up.ID, 2)
	if err != nil {
		t.Fatalf("list v2: %v", err)
	}
	if len(v2) != 1 || v2[0].Body != "on v2" || v2[0].Version != 2 {
		t.Fatalf("version 2 comments = %+v", v2)
	}
}

func TestRecordVisitStoresVersion(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	up := seedVersionTestUpload(t, s, "verv")
	if err := s.RecordVisit(ctx, up.ID, 3, "cookie", "Alice", "iphash", "ua"); err != nil {
		t.Fatalf("record visit: %v", err)
	}
	visits, err := s.RecentVisits(ctx, up.ID, 10)
	if err != nil {
		t.Fatalf("recent visits: %v", err)
	}
	if len(visits) != 1 || visits[0].Version != 3 {
		t.Fatalf("visits = %+v, want one with Version 3", visits)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %#o, want %#o", path, got, want)
	}
}

func TestOpenCreatesDatabaseOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	path := filepath.Join(t.TempDir(), "peek.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	assertMode(t, path, 0o600)
	for _, p := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			assertMode(t, p, 0o600)
		}
	}
}

func TestOpenTightensExistingDatabaseMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	path := filepath.Join(t.TempDir(), "peek.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store.Close()
	assertMode(t, path, 0o600)
}

func TestCommentAccountIDRoundTrip(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	acct, err := s.CreateAccount(ctx, "ada@example.test", "Ada", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, "owner", "owner", false, 0); err != nil {
		t.Fatal(err)
	}
	tok, _ := s.GetToken(ctx, "owner")
	if err := s.CreateUploadChecked(ctx, "slug-acct", tok.AccountID, tok.ID, "page.html", 0, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	up, _ := s.GetUpload(ctx, "slug-acct")
	signed, err := s.AddComment(ctx, up.ID, 1, "", "", "page", "Ada", "c1", "signed", acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := s.AddComment(ctx, up.ID, 1, "", "", "page", "Ada", "c2", "typed", 0)
	if err != nil {
		t.Fatal(err)
	}
	if signed.AccountID != acct.ID || typed.AccountID != 0 {
		t.Fatalf("returned account ids: %d %d", signed.AccountID, typed.AccountID)
	}
	list, err := s.ListComments(ctx, up.ID, 0)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %+v", err, list)
	}
	byID := map[int64]int64{}
	for _, c := range list {
		byID[c.ID] = c.AccountID
	}
	if byID[signed.ID] != acct.ID || byID[typed.ID] != 0 {
		t.Fatalf("listed account ids: %+v", byID)
	}
}

func TestMigrationAddsCommentAccountID(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "peek.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, "owner", "owner", false, 0); err != nil {
		t.Fatal(err)
	}
	tok, _ := s.GetToken(ctx, "owner")
	if err := s.CreateUploadChecked(ctx, "slug-mig", tok.AccountID, tok.ID, "page.html", 0, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	up, _ := s.GetUpload(ctx, "slug-mig")
	if _, err := s.AddComment(ctx, up.ID, 1, "", "", "page", "Ada", "c", "old", tok.AccountID); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`ALTER TABLE comments DROP COLUMN account_id`,
		`DELETE FROM schema_migrations WHERE id=13`,
	} {
		if _, err := s.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if exists, _, err := s.columnInfo("comments", "account_id"); err != nil || !exists {
		t.Fatalf("account_id column: exists=%v err=%v", exists, err)
	}
	list, err := s.ListComments(ctx, up.ID, 0)
	if err != nil || len(list) != 1 || list[0].AccountID != 0 {
		t.Fatalf("list: %v %+v", err, list)
	}
}
