package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
	"github.com/andras-tkcs/peek/internal/uploadquota"
)

func TestRecordVisitPersistsPrivacySafeAnalytics(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	upload, err := store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatal(err)
	}

	secret := strings.Repeat("a", 64)
	s := &Server{
		store:             store,
		secret:            secret,
		trustedProxy:      true,
		trustedProxyCIDRs: mustPrefixes(t, DefaultTrustedProxyCIDRs),
		visitQueue:        make(chan visitEvent, 4),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.startVisitWorker(ctx)
	}()

	req := httptest.NewRequest(http.MethodGet, "/p/page", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.10")
	req.Header.Set("User-Agent", strings.Repeat("u", 350))
	req.AddCookie(&http.Cookie{Name: nameCookie, Value: "Ada"})

	s.recordVisit(req, upload, "visitor-1", 1)
	flushCtx, flushCancel := context.WithTimeout(context.Background(), time.Second)
	defer flushCancel()
	if err := s.FlushVisits(flushCtx); err != nil {
		t.Fatalf("flush visits: %v", err)
	}

	total, unique, err := store.CountVisits(context.Background(), upload.ID)
	if err != nil {
		t.Fatalf("count visits: %v", err)
	}
	if total != 1 || unique != 1 {
		t.Fatalf("visits total=%d unique=%d", total, unique)
	}
	recent, err := store.RecentVisits(context.Background(), upload.ID, 1)
	if err != nil {
		t.Fatalf("recent visits: %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("recent visits = %+v", recent)
	}
	wantHash := sha256.Sum256([]byte(secret + "|203.0.113.10"))
	if recent[0].IP != hex.EncodeToString(wantHash[:])[:16] {
		t.Fatalf("ip hash = %q", recent[0].IP)
	}
	if strings.Contains(recent[0].IP, "203.0.113.10") {
		t.Fatalf("visit stored raw IP: %+v", recent[0])
	}
	if recent[0].UserAgent != strings.Repeat("u", 300) {
		t.Fatalf("user agent length = %d", len(recent[0].UserAgent))
	}
	visitor, err := store.GetVisitor(context.Background(), "visitor-1")
	if err != nil {
		t.Fatalf("get visitor: %v", err)
	}
	if visitor.Name != "Ada" {
		t.Fatalf("visitor name = %q", visitor.Name)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("visit worker did not stop")
	}
}

func pageCovAnalyticsServer(t *testing.T) (*Server, *db.Store, int64) {
	t.Helper()
	s, store, _, adminID := newFaultServer(t)
	s.visitQueue = make(chan visitEvent, 8)
	if err := store.CreateUploadChecked(context.Background(), "page", adminID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	return s, store, adminID
}

func TestPageCovVisitorIDFallsBackWhenRandomFails(t *testing.T) {
	s, _, _ := pageCovAnalyticsServer(t)
	stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand down") })
	rec := httptest.NewRecorder()
	if got := s.visitorID(rec, httptest.NewRequest(http.MethodGet, "/", nil)); got != "anon" {
		t.Fatalf("visitor id = %q, want anon", got)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("no cookie should be set when the id cannot be generated")
	}
}

func TestPageCovRecordVisitWithoutIPLeavesHashEmpty(t *testing.T) {
	s, store, _ := pageCovAnalyticsServer(t)
	u, err := store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ""
	s.recordVisit(req, u, "vid", 1)
	ev := <-s.visitQueue
	if ev.IPHash != "" {
		t.Fatalf("ip hash = %q, want empty", ev.IPHash)
	}
}

func TestPageCovVisitWorkerSurvivesVisitorUpsertFailure(t *testing.T) {
	s, store, _ := pageCovAnalyticsServer(t)
	u, err := store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatal(err)
	}
	dropTable(t, store, "visitors")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.startVisitWorker(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	s.visitQueue <- visitEvent{UploadID: u.ID, Version: 1, VID: "vid", Name: "Ada"}
	flushCtx, flushCancel := context.WithTimeout(ctx, 5*time.Second)
	defer flushCancel()
	if err := s.FlushVisits(flushCtx); err != nil {
		t.Fatal(err)
	}
	n, _, err := store.CountVisits(context.Background(), u.ID)
	if err != nil || n != 1 {
		t.Fatalf("visits = %d err = %v, want the visit recorded despite the visitor failure", n, err)
	}
}

func TestPageCovFlushVisitsHonoursContext(t *testing.T) {
	t.Run("queue full", func(t *testing.T) {
		s := &Server{visitQueue: make(chan visitEvent)}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if err := s.FlushVisits(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want deadline exceeded", err)
		}
	})
	t.Run("worker not draining", func(t *testing.T) {
		s := &Server{visitQueue: make(chan visitEvent, 1)}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if err := s.FlushVisits(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want deadline exceeded", err)
		}
	})
}
