package db

import (
	"context"
	"testing"
)

func TestCommentsAddAndList(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	accountID, uploadID := seedVersionUpload(t, s, "o@example.test", "commented", 10)
	anon, err := s.AddComment(ctx, uploadID, 1, "p", "text", "element", "Guest", "cookie", "hello", 0)
	if err != nil || anon.AccountID != 0 || anon.ID == 0 {
		t.Fatalf("anonymous comment = %+v, %v", anon, err)
	}
	signed, err := s.AddComment(ctx, uploadID, 2, "h1", "", "page", "Owner", "", "hi", accountID)
	if err != nil || signed.AccountID != accountID {
		t.Fatalf("account comment = %+v, %v", signed, err)
	}
	all, err := s.ListComments(ctx, uploadID, 0)
	if err != nil || len(all) != 2 {
		t.Fatalf("all comments = %+v, %v", all, err)
	}
	if all[0].AccountID != 0 || all[1].AccountID != accountID {
		t.Fatalf("account ids = %d, %d", all[0].AccountID, all[1].AccountID)
	}
	v2, err := s.ListComments(ctx, uploadID, 2)
	if err != nil || len(v2) != 1 || v2[0].Body != "hi" {
		t.Fatalf("version 2 comments = %+v, %v", v2, err)
	}
}

func TestCommentsFailures(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	_, uploadID := seedVersionUpload(t, s, "o@example.test", "commented", 10)
	if _, err := s.AddComment(ctx, uploadID, 1, "p", "", "element", "G", "c", "b", 0); err != nil {
		t.Fatal(err)
	}
	corruptInt(t, s, "comments", "created_at")
	_, err := s.ListComments(ctx, uploadID, 0)
	wantErr(t, "ListComments scan", err)
	failOn(t, s, "comments", "INSERT")
	_, err = s.AddComment(ctx, uploadID, 1, "p", "", "element", "G", "c", "b", 0)
	wantErr(t, "AddComment insert", err)
}
