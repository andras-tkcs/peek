package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
)

func TestAddUploadGrantIsIdempotentAndLowercases(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "grant-a", 1)
	g1, _, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "Alice@Example.com", owner)
	if err != nil {
		t.Fatal(err)
	}
	g2, _, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, " alice@example.com ", owner)
	if err != nil {
		t.Fatal(err)
	}
	if g1.ID != g2.ID || g2.Email != "alice@example.com" || g2.CreatedByAccountID != owner {
		t.Fatalf("unexpected grants: %+v %+v", g1, g2)
	}
	list, _ := s.ListUploadGrants(ctx, id)
	if len(list) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(list))
	}
}

func TestRemoveUploadGrantMissingReturnsErrNoRows(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "grant-b", 1)
	if err := s.RemoveUploadGrant(ctx, id, models.UploadGrantUser, "nobody@example.com"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
	if _, _, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "a@example.com", owner); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveUploadGrant(ctx, id, models.UploadGrantUser, "A@example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestListUploadGrantsOrdersByKindThenEmail(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "grant-c", 1)
	for _, g := range []struct{ kind, email string }{
		{models.UploadGrantUser, "z@example.com"},
		{models.UploadGrantGroup, "team@example.com"},
		{models.UploadGrantUser, "b@example.com"},
	} {
		if _, _, err := s.AddUploadGrant(ctx, id, g.kind, g.email, owner); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListUploadGrants(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"group:team@example.com", "user:b@example.com", "user:z@example.com"}
	if len(list) != len(want) {
		t.Fatalf("got %d grants", len(list))
	}
	for i, g := range list {
		if g.Kind+":"+g.Email != want[i] {
			t.Fatalf("pos %d = %s:%s, want %s", i, g.Kind, g.Email, want[i])
		}
	}
}

func TestGrantsCascadeOnUploadDelete(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "grant-d", 1)
	if _, _, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "a@example.com", owner); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUpload(ctx, id); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListUploadGrants(ctx, id)
	if err != nil || len(list) != 0 {
		t.Fatalf("expected no grants after delete, got %v, %v", list, err)
	}
}

func TestGrantKindCheckConstraint(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	owner, id := seedVersionUpload(t, s, "o@example.test", "grant-e", 1)
	if _, _, err := s.AddUploadGrant(context.Background(), id, "team", "a@example.com", owner); err == nil {
		t.Fatal("expected error for kind team")
	}
}

func TestListUploadGrantsForUploads(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, id1 := seedVersionUpload(t, s, "o1@example.test", "grant-m1", 1)
	_, id2 := seedVersionUpload(t, s, "o2@example.test", "grant-m2", 1)
	for _, g := range []struct {
		id          int64
		kind, email string
	}{
		{id1, models.UploadGrantUser, "zed@example.com"},
		{id1, models.UploadGrantGroup, "team@example.com"},
		{id1, models.UploadGrantUser, "amy@example.com"},
		{id2, models.UploadGrantUser, "bob@example.com"},
	} {
		if _, _, err := s.AddUploadGrant(ctx, g.id, g.kind, g.email, 0); err != nil {
			t.Fatalf("add grant: %v", err)
		}
	}
	got, err := s.ListUploadGrantsForUploads(ctx, []int64{id1, id2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("keys = %d, want 2", len(got))
	}
	want := [][2]string{{"group", "team@example.com"}, {"user", "amy@example.com"}, {"user", "zed@example.com"}}
	if len(got[id1]) != len(want) {
		t.Fatalf("id1 grants = %+v", got[id1])
	}
	for i, w := range want {
		if got[id1][i].Kind != w[0] || got[id1][i].Email != w[1] {
			t.Fatalf("id1[%d] = %s %s, want %v", i, got[id1][i].Kind, got[id1][i].Email, w)
		}
	}
	if len(got[id2]) != 1 {
		t.Fatalf("id2 grants = %+v", got[id2])
	}
	empty, err := s.ListUploadGrantsForUploads(ctx, nil)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("nil ids = %v, %v; want non-nil empty map", empty, err)
	}
}

func TestGrantWritesAndScanErrors(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	accountID, uploadID := seedVersionUpload(t, s, "o@example.test", "g", 1)
	if g, _, err := s.AddUploadGrant(ctx, uploadID, "user", "a@example.test", accountID); err != nil || g.CreatedByAccountID != accountID {
		t.Fatalf("grant = %+v, %v", g, err)
	}
	if g, _, err := s.AddUploadGrant(ctx, uploadID, "group", "g@example.test", 0); err != nil || g.CreatedByAccountID != 0 {
		t.Fatalf("grant without creator = %+v, %v", g, err)
	}
	corruptInt(t, s, "upload_grants", "created_at")
	// The duplicate insert is a no-op, so the follow-up SELECT hits the bad row.
	_, _, err := s.AddUploadGrant(ctx, uploadID, "user", "a@example.test", accountID)
	wantErr(t, "AddUploadGrant select", err)
	_, err = s.ListUploadGrants(ctx, uploadID)
	wantErr(t, "ListUploadGrants", err)
	_, err = s.ListUploadGrantsForUploads(ctx, []int64{uploadID})
	wantErr(t, "ListUploadGrantsForUploads", err)

	failOn(t, s, "upload_grants", "INSERT")
	_, _, err = s.AddUploadGrant(ctx, uploadID, "user", "new@example.test", 0)
	wantErr(t, "AddUploadGrant insert", err)
	failOn(t, s, "upload_grants", "DELETE")
	wantErr(t, "RemoveUploadGrant", s.RemoveUploadGrant(ctx, uploadID, "user", "a@example.test"))
}

func TestListUploadsSharedWith(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, restricted := seedVersionUpload(t, s, "o@example.test", "shared-r", 1)
	_, signedIn := seedVersionUpload(t, s, "o2@example.test", "shared-s", 1)
	if err := s.SetUploadVisibility(ctx, restricted, models.UploadVisibilityRestricted); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUploadVisibility(ctx, signedIn, "signed-in"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{restricted, signedIn} {
		if _, _, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "Bob@Example.com", owner); err != nil {
			t.Fatal(err)
		}
	}
	slugs := func(list []models.Upload) []string {
		var out []string
		for _, u := range list {
			out = append(out, u.Slug)
		}
		return out
	}
	got, err := s.ListUploadsSharedWith(ctx, "BOB@example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if g := slugs(got); len(g) != 1 || g[0] != "shared-r" {
		t.Fatalf("user grant: got %v, want [shared-r]", g)
	}
	got, err = s.ListUploadsSharedWith(ctx, "bob@example.com", nil, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("owner's own page listed: %v", slugs(got))
	}
	if _, _, err := s.AddUploadGrant(ctx, restricted, models.UploadGrantGroup, "team@example.com", owner); err != nil {
		t.Fatal(err)
	}
	got, err = s.ListUploadsSharedWith(ctx, "carol@example.com", nil, 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("group grant without group: %v %v", slugs(got), err)
	}
	got, err = s.ListUploadsSharedWith(ctx, "carol@example.com", []string{"Team@example.com"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if g := slugs(got); len(g) != 1 || g[0] != "shared-r" {
		t.Fatalf("group grant: got %v, want [shared-r]", g)
	}
}

func TestListRestrictedGroupGrantEmails(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	ownerA, a := seedVersionUpload(t, s, "a@example.test", "grp-a", 1)
	ownerB, b := seedVersionUpload(t, s, "b@example.test", "grp-b", 1)
	ownerC, c := seedVersionUpload(t, s, "c@example.test", "grp-c", 1)
	for _, id := range []int64{a, b} {
		if err := s.SetUploadVisibility(ctx, id, models.UploadVisibilityRestricted); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []struct {
		id    int64
		owner int64
		kind  string
		email string
	}{
		{a, ownerA, models.UploadGrantGroup, "z-team@example.com"},
		{a, ownerA, models.UploadGrantGroup, "a-team@example.com"},
		{b, ownerB, models.UploadGrantGroup, "a-team@example.com"},
		{a, ownerA, models.UploadGrantUser, "user@example.com"},
		{c, ownerC, models.UploadGrantGroup, "public-team@example.com"},
	} {
		if _, _, err := s.AddUploadGrant(ctx, g.id, g.kind, g.email, g.owner); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListRestrictedGroupGrantEmails(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a-team@example.com", "z-team@example.com"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
	got, err = s.ListRestrictedGroupGrantEmails(ctx, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a-team@example.com"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("excluding owner: got %v, want %v", got, want)
	}
}

func TestAddUploadGrantReportsCreated(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "grant-created", 1)
	if _, created, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "a@example.com", owner); err != nil || !created {
		t.Fatalf("first call created=%v err=%v", created, err)
	}
	if _, created, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "A@example.com", owner); err != nil || created {
		t.Fatalf("second call created=%v err=%v", created, err)
	}
}
