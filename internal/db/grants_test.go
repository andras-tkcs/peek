package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/puemos/peek/internal/models"
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
