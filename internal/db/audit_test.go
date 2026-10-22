package db

import (
	"context"
	"fmt"
	"testing"
)

func TestAuditLogAddAndList(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	for i := 0; i < 3; i++ {
		if err := s.AddAuditLog(ctx, "actor", fmt.Sprintf("act-%d", i), "detail", "203.0.113.9"); err != nil {
			t.Fatal(err)
		}
	}
	for _, limit := range []int{0, 1000, -1} {
		got, err := s.ListAuditLog(ctx, limit)
		if err != nil || len(got) != 3 || got[0].Actor != "actor" || got[0].IP != "203.0.113.9" {
			t.Fatalf("ListAuditLog(%d) = %+v, %v", limit, got, err)
		}
	}
	got, err := s.ListAuditLog(ctx, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("ListAuditLog(1) = %+v, %v", got, err)
	}
}

func TestAuditLogScanError(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	t.Cleanup(func() { s.Close() })
	if err := s.AddAuditLog(ctx, "a", "act", "d", "ip"); err != nil {
		t.Fatal(err)
	}
	corruptInt(t, s, "audit_log", "created_at")
	_, err := s.ListAuditLog(ctx, 10)
	wantErr(t, "ListAuditLog", err, errScan)
}
