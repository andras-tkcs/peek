package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The fixture is a real database written by the oldest supported release; regenerate it with
// scripts/make-release-fixture.sh.
const releaseFixtureTag = "v0.10.0"

type fixtureInfo struct {
	Release        string `json:"release"`
	AdminEmail     string `json:"admin_email"`
	APIToken       string `json:"api_token"`
	PublicSlug     string `json:"public_slug"`
	PrivateSlug    string `json:"private_slug"`
	PasswordSlug   string `json:"password_slug"`
	RestrictedSlug string `json:"restricted_slug"`
	GrantEmail     string `json:"grant_email"`
	InviteEmail    string `json:"invite_email"`
	CommentBody    string `json:"comment_body"`
}

func openReleaseFixture(t *testing.T) (*Store, fixtureInfo) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "peek-"+releaseFixtureTag+".db"))
	if err != nil {
		t.Fatalf("read fixture database: %v", err)
	}
	path := filepath.Join(t.TempDir(), "peek.db")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("copy fixture database: %v", err)
	}
	meta, err := os.ReadFile(filepath.Join("testdata", "peek-"+releaseFixtureTag+".json"))
	if err != nil {
		t.Fatalf("read fixture info: %v", err)
	}
	var info fixtureInfo
	if err := json.Unmarshal(meta, &info); err != nil {
		t.Fatalf("parse fixture info: %v", err)
	}
	if info.Release != releaseFixtureTag {
		t.Fatalf("fixture release = %q, want %q", info.Release, releaseFixtureTag)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open upgraded fixture: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, info
}

func TestOpenUpgradesReleaseFixture(t *testing.T) {
	s, info := openReleaseFixture(t)
	ctx := context.Background()

	acct, err := s.GetAccountByEmail(ctx, info.AdminEmail)
	if err != nil {
		t.Fatalf("admin account: %v", err)
	}
	if !acct.IsAdmin {
		t.Fatalf("account %s is not admin", info.AdminEmail)
	}
	tok, err := s.GetToken(ctx, info.APIToken)
	if err != nil {
		t.Fatalf("fixture token does not resolve: %v", err)
	}
	if tok.AccountID != acct.ID {
		t.Fatalf("token account = %d, want %d", tok.AccountID, acct.ID)
	}

	pub, err := s.GetUpload(ctx, info.PublicSlug)
	if err != nil {
		t.Fatalf("public upload: %v", err)
	}
	if pub.Visibility != "public" {
		t.Fatalf("public visibility = %q", pub.Visibility)
	}
	versions, err := s.ListUploadVersions(ctx, pub.ID)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("public versions = %d, want 2", len(versions))
	}
	comments, err := s.ListComments(ctx, pub.ID, 0)
	if err != nil {
		t.Fatalf("comments: %v", err)
	}
	if len(comments) != 1 || comments[0].Body != info.CommentBody {
		t.Fatalf("comments = %+v, want one with body %q", comments, info.CommentBody)
	}

	priv, err := s.GetUpload(ctx, info.PrivateSlug)
	if err != nil {
		t.Fatalf("private upload: %v", err)
	}
	if priv.Visibility != "signed-in" {
		t.Fatalf("private upload visibility = %q, want signed-in (migration 14)", priv.Visibility)
	}

	pw, err := s.GetUpload(ctx, info.PasswordSlug)
	if err != nil {
		t.Fatalf("password upload: %v", err)
	}
	if pw.Visibility != "restricted" {
		t.Fatalf("password upload visibility = %q, want restricted (migration 15)", pw.Visibility)
	}
	var hash string
	if err := s.QueryRowContext(ctx, `SELECT password_hash FROM uploads WHERE id=?`, pw.ID).Scan(&hash); err != nil {
		t.Fatalf("password_hash: %v", err)
	}
	if hash != "" {
		t.Fatalf("password_hash not cleared by migration 15")
	}

	restricted, err := s.GetUpload(ctx, info.RestrictedSlug)
	if err != nil {
		t.Fatalf("restricted upload: %v", err)
	}
	grants, err := s.ListUploadGrants(ctx, restricted.ID)
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	foundGrant := false
	for _, g := range grants {
		if g.Email == info.GrantEmail {
			foundGrant = true
		}
	}
	if !foundGrant {
		t.Fatalf("no grant for %s in %+v", info.GrantEmail, grants)
	}

	invites, err := s.ListInvites(ctx)
	if err != nil {
		t.Fatalf("invites: %v", err)
	}
	foundInvite := false
	for _, inv := range invites {
		if inv.Email == info.InviteEmail {
			foundInvite = true
		}
	}
	if !foundInvite {
		t.Fatalf("no invite for %s", info.InviteEmail)
	}

	var maxID int
	if err := s.QueryRowContext(ctx, `SELECT MAX(id) FROM schema_migrations`).Scan(&maxID); err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	if want := migrations[len(migrations)-1].id; maxID != want {
		t.Fatalf("MAX(schema_migrations.id) = %d, want %d", maxID, want)
	}
}

// schemaSnapshot lists every schema object and column property of a store as sortable strings.
func schemaSnapshot(t *testing.T, s *Store) map[string]bool {
	t.Helper()
	ctx := context.Background()
	out := map[string]bool{}

	rows, err := s.QueryContext(ctx, `SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("sqlite_master: %v", err)
	}
	type object struct{ typ, name string }
	var objects []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.typ, &o.name); err != nil {
			t.Fatalf("scan sqlite_master: %v", err)
		}
		objects = append(objects, o)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("sqlite_master rows: %v", err)
	}
	rows.Close()

	for _, o := range objects {
		out[fmt.Sprintf("object %s %s", o.typ, o.name)] = true
		switch o.typ {
		case "table":
			cols, err := s.QueryContext(ctx, `SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info(?)`, o.name)
			if err != nil {
				t.Fatalf("table_info %s: %v", o.name, err)
			}
			for cols.Next() {
				var name, typ string
				var notnull, pk int
				var dflt *string
				if err := cols.Scan(&name, &typ, &notnull, &dflt, &pk); err != nil {
					t.Fatalf("scan table_info %s: %v", o.name, err)
				}
				d := "<none>"
				if dflt != nil {
					d = *dflt
				}
				out[fmt.Sprintf("column %s.%s type=%s notnull=%d dflt=%s pk=%d", o.name, name, typ, notnull, d, pk)] = true
			}
			if err := cols.Err(); err != nil {
				t.Fatalf("table_info rows %s: %v", o.name, err)
			}
			cols.Close()
		case "index":
			cols, err := s.QueryContext(ctx, `SELECT name FROM pragma_index_info(?) ORDER BY seqno`, o.name)
			if err != nil {
				t.Fatalf("index_info %s: %v", o.name, err)
			}
			var names []string
			for cols.Next() {
				var n string
				if err := cols.Scan(&n); err != nil {
					t.Fatalf("scan index_info %s: %v", o.name, err)
				}
				names = append(names, n)
			}
			if err := cols.Err(); err != nil {
				t.Fatalf("index_info rows %s: %v", o.name, err)
			}
			cols.Close()
			out[fmt.Sprintf("index %s (%s)", o.name, strings.Join(names, ","))] = true
		}
	}
	return out
}

func TestUpgradedSchemaMatchesFresh(t *testing.T) {
	upgraded, _ := openReleaseFixture(t)
	fresh := openTestStore(t)
	defer fresh.Close()

	got := schemaSnapshot(t, upgraded)
	want := schemaSnapshot(t, fresh)

	var diffs []string
	for k := range want {
		if !got[k] {
			diffs = append(diffs, "missing in upgraded: "+k)
		}
	}
	for k := range got {
		if !want[k] {
			diffs = append(diffs, "only in upgraded: "+k)
		}
	}
	// Databases created before migration 15 keep the old column default; harmless because the only INSERT INTO uploads (uploads.go) always sets visibility.
	const (
		upgradedVisibility = "column uploads.visibility type=TEXT notnull=1 dflt='password' pk=0"
		freshVisibility    = "column uploads.visibility type=TEXT notnull=1 dflt='restricted' pk=0"
	)
	var unexpected []string
	for _, d := range diffs {
		if d == "only in upgraded: "+upgradedVisibility || d == "missing in upgraded: "+freshVisibility {
			continue
		}
		unexpected = append(unexpected, d)
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Fatalf("upgraded schema differs from a fresh database (uploads.visibility default is the only allowed difference):\n%s", strings.Join(unexpected, "\n"))
	}
	if len(diffs) != 2 {
		t.Fatalf("expected the uploads.visibility default difference to be present, got %d diffs: %v", len(diffs), diffs)
	}
}
