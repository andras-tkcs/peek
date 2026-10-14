package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestLimiterAllowsUpToMax(t *testing.T) {
	l := newLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.allow("k") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.allow("k") {
		t.Fatalf("request beyond max should be rejected")
	}
}

func TestLimiterResetsAfterWindow(t *testing.T) {
	l, advance := newTestLimiter(2, time.Minute)
	if !l.allow("k") {
		t.Fatalf("first request should be allowed")
	}
	if !l.allow("k") {
		t.Fatalf("second request should be allowed")
	}
	if l.allow("k") {
		t.Fatalf("third request should be rejected before window reset")
	}
	advance(time.Minute + time.Nanosecond)
	if !l.allow("k") {
		t.Fatalf("request should be allowed after window reset")
	}
}

func TestLimiterPerKeyIsolation(t *testing.T) {
	l := newLimiter(1, time.Minute)
	if !l.allow("a") {
		t.Fatalf("key a first request should be allowed")
	}
	if !l.allow("b") {
		t.Fatalf("key b first request should be allowed")
	}
	if l.allow("a") {
		t.Fatalf("key a second request should be rejected")
	}
}

func TestLimiterCapacityCleanup(t *testing.T) {
	l, advance := newTestLimiter(1, time.Minute)
	l.maxKeys = 100
	for i := 0; i < 100; i++ {
		l.allow(fmt.Sprintf("k%d", i))
	}
	// After exceeding capacity, expired windows should be cleaned.
	advance(time.Minute + time.Nanosecond)
	if !l.allow("cleanup-key") {
		t.Fatalf("request should be allowed after cleanup of expired windows")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) != 1 {
		t.Fatalf("expired limiter windows were not cleaned up, entries=%d", len(l.hits))
	}
}

func TestRateLimitWrapperReturns429(t *testing.T) {
	s := &Server{globalLimiter: newLimiter(1, time.Minute)}
	called := 0
	handler := s.rateLimit(s.globalLimiter, func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK || called != 1 {
		t.Fatalf("first request should pass")
	}
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusTooManyRequests || called != 1 {
		t.Fatalf("second request should be 429 and not call handler")
	}
}

func TestRateLimitWrapperReturnsJSONForAPI(t *testing.T) {
	s := &Server{globalLimiter: newLimiter(1, time.Minute)}
	handler := s.rateLimit(s.globalLimiter, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)

	handler(httptest.NewRecorder(), req)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assertJSONRateLimit(t, rec)
}

func TestGlobalRateLimitReturnsJSONForAPI(t *testing.T) {
	s := &Server{globalLimiter: newLimiter(1, time.Minute)}
	handler := s.withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/uploads", nil)

	handler.ServeHTTP(httptest.NewRecorder(), req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertJSONRateLimit(t, rec)
}

func TestLimiterConcurrentAccess(t *testing.T) {
	l := newLimiter(10, time.Minute)
	const goroutines = 50
	const calls = 20
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < calls; j++ {
				_ = l.allow("concurrent-key")
			}
		}()
	}
	wg.Wait()
	w := l.hits["concurrent-key"]
	if w == nil || w.count > 10 {
		t.Fatalf("expected count <= max after concurrency, got %d", w.count)
	}
}

func assertJSONRateLimit(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q", got)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Error != "too many requests, try again shortly" {
		t.Fatalf("error = %q", body.Error)
	}
}

func newTestLimiter(max int, win time.Duration) (*limiter, func(time.Duration)) {
	now := time.Unix(1700000000, 0)
	l := newLimiter(max, win)
	l.now = func() time.Time {
		return now
	}
	return l, func(d time.Duration) {
		now = now.Add(d)
	}
}

func TestLimiterFailsClosedWhenFull(t *testing.T) {
	l, advance := newTestLimiter(5, time.Minute)
	l.maxKeys = 3
	for _, k := range []string{"a", "b", "c"} {
		if !l.allow(k) {
			t.Fatalf("key %s should be allowed", k)
		}
	}
	if l.allow("d") {
		t.Fatalf("new key on a full limiter should be denied")
	}
	if !l.allow("a") {
		t.Fatalf("existing key should keep working on a full limiter")
	}
	advance(time.Minute + time.Nanosecond)
	if !l.allow("d") {
		t.Fatalf("new key should be allowed after expired windows are pruned")
	}
}

func TestLimiterBlockedDoesNotCountHits(t *testing.T) {
	l, advance := newTestLimiter(2, time.Minute)
	if l.blocked("k") {
		t.Fatalf("unseen key should not be blocked")
	}
	if len(l.hits) != 0 {
		t.Fatalf("blocked must not create entries, got %d", len(l.hits))
	}
	l.recordFailure("k")
	l.recordFailure("k")
	if !l.blocked("k") {
		t.Fatalf("key should be blocked after max failures")
	}
	advance(time.Minute + time.Nanosecond)
	if l.blocked("k") {
		t.Fatalf("key should be unblocked after the window")
	}
}

func TestLimiterNilIsNoop(t *testing.T) {
	var l *limiter
	if l.blocked("k") {
		t.Fatalf("nil limiter should never block")
	}
	l.recordFailure("k")
}

func TestRateLimitWrapperGroupsIPv6By64(t *testing.T) {
	s := &Server{}
	l := newLimiter(1, time.Minute)
	handler := s.rateLimit(l, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	for i, tc := range []struct {
		addr string
		want int
	}{{"[2001:db8::1]:1", http.StatusOK}, {"[2001:db8::2]:1", http.StatusTooManyRequests}} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tc.addr
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("request %d from %s: code = %d, want %d", i+1, tc.addr, rec.Code, tc.want)
		}
	}
}
