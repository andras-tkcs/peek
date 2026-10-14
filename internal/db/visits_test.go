package db

import (
	"context"
	"testing"
	"time"
)

func TestVisitsRecordCountAndList(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	_, uploadID := seedVersionUpload(t, s, "o@example.test", "visited", 10)
	for _, c := range []string{"c1", "c1", "c2"} {
		if err := s.RecordVisit(ctx, uploadID, 1, c, "name-"+c, "203.0.113.1", "ua"); err != nil {
			t.Fatal(err)
		}
	}
	total, unique, err := s.CountVisits(ctx, uploadID)
	if err != nil || total != 3 || unique != 2 {
		t.Fatalf("CountVisits = %d, %d, %v", total, unique, err)
	}
	buckets, err := s.VisitBuckets(ctx, uploadID, time.Now().Add(-time.Hour), 3600)
	if err != nil || len(buckets) == 0 {
		t.Fatalf("VisitBuckets = %+v, %v", buckets, err)
	}
	var sum int
	for _, b := range buckets {
		sum += b.Count
	}
	if sum != 3 {
		t.Fatalf("bucket sum = %d", sum)
	}
	recent, err := s.RecentVisits(ctx, uploadID, 2)
	if err != nil || len(recent) != 2 || recent[0].IP != "203.0.113.1" || recent[0].UserAgent != "ua" {
		t.Fatalf("RecentVisits = %+v, %v", recent, err)
	}
}

func TestVisitorUpsertKeepsNameOnEmpty(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	if err := s.UpsertVisitor(ctx, "cookie", "Ann"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertVisitor(ctx, "cookie", ""); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetVisitor(ctx, "cookie")
	if err != nil || v.Name != "Ann" || v.Cookie != "cookie" {
		t.Fatalf("visitor = %+v, %v", v, err)
	}
	if err := s.UpsertVisitor(ctx, "cookie", "Bea"); err != nil {
		t.Fatal(err)
	}
	if v, err = s.GetVisitor(ctx, "cookie"); err != nil || v.Name != "Bea" {
		t.Fatalf("renamed visitor = %+v, %v", v, err)
	}
	if _, err := s.GetVisitor(ctx, "missing"); err == nil {
		t.Fatal("expected missing visitor error")
	}
}

func TestVisitScanErrors(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	_, uploadID := seedVersionUpload(t, s, "o@example.test", "visited", 10)
	if err := s.RecordVisit(ctx, uploadID, 1, "c", "n", "ip", "ua"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exec(`INSERT INTO visitors(cookie,name,created_at,last_seen) VALUES('bad','n','abc','abc')`); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetVisitor(ctx, "bad")
	wantErr(t, "GetVisitor", err)
	// A REAL timestamp makes the bucket expression a float, which cannot scan into int64.
	if _, err := s.Exec(`UPDATE visits SET visited_at=1e300`); err != nil {
		t.Fatal(err)
	}
	_, err = s.VisitBuckets(ctx, uploadID, time.Unix(0, 0), 60)
	wantErr(t, "VisitBuckets", err)
	corruptInt(t, s, "visits", "visited_at")
	_, err = s.RecentVisits(ctx, uploadID, 5)
	wantErr(t, "RecentVisits", err)
}
