package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
)

func TestAddUploadGrantIsIdempotentAndLowercases(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ctx := context.Background()
	owner, id := seedVersionUpload(t, s, "o@example.test", "grant-a", 1)
	g1, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "Alice@Example.com", owner)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, " alice@example.com ", owner)
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
	if _, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "a@example.com", owner); err != nil {
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
		if _, err := s.AddUploadGrant(ctx, id, g.kind, g.email, owner); err != nil {
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
	if _, err := s.AddUploadGrant(ctx, id, models.UploadGrantUser, "a@example.com", owner); err != nil {
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
	if _, err := s.AddUploadGrant(context.Background(), id, "team", "a@example.com", owner); err == nil {
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
		if _, err := s.AddUploadGrant(ctx, g.id, g.kind, g.email, 0); err != nil {
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
	if g, err := s.AddUploadGrant(ctx, uploadID, "user", "a@example.test", accountID); err != nil || g.CreatedByAccountID != accountID {
		t.Fatalf("grant = %+v, %v", g, err)
	}
	if g, err := s.AddUploadGrant(ctx, uploadID, "group", "g@example.test", 0); err != nil || g.CreatedByAccountID != 0 {
		t.Fatalf("grant without creator = %+v, %v", g, err)
	}
	corruptInt(t, s, "upload_grants", "created_at")
	// The duplicate insert is a no-op, so the follow-up SELECT hits the bad row.
	_, err := s.AddUploadGrant(ctx, uploadID, "user", "a@example.test", accountID)
	wantErr(t, "AddUploadGrant select", err)
	_, err = s.ListUploadGrants(ctx, uploadID)
	wantErr(t, "ListUploadGrants", err)
	_, err = s.ListUploadGrantsForUploads(ctx, []int64{uploadID})
	wantErr(t, "ListUploadGrantsForUploads", err)

	failOn(t, s, "upload_grants", "INSERT")
	_, err = s.AddUploadGrant(ctx, uploadID, "user", "new@example.test", 0)
	wantErr(t, "AddUploadGrant insert", err)
	failOn(t, s, "upload_grants", "DELETE")
	wantErr(t, "RemoveUploadGrant", s.RemoveUploadGrant(ctx, uploadID, "user", "a@example.test"))
}
