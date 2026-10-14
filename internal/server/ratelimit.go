package server

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// limiterMaxKeys caps each limiter's map. When it is full and a new key
	// arrives, expired windows are pruned (at most once per limiterPruneInterval);
	// if it is still full the new key is denied. Failing closed keeps brute-force
	// limits intact under key flooding; existing keys keep working.
	limiterMaxKeys       = 50000
	limiterPruneInterval = time.Second

	accountLoginFailureMax    = 10
	accountLoginFailureWindow = 15 * time.Minute
	pagePasswordFailureMax    = 20
	pagePasswordFailureWindow = 10 * time.Minute
)

// limiter is a small fixed-window per-key rate limiter. It is intended for
// abuse mitigation (login brute force, comment spam) on a single-node,
// self-hosted deployment — not distributed quota enforcement.
type limiter struct {
	mu     sync.Mutex
	hits   map[string]*window
	max    int
	window time.Duration
	now    func() time.Time

	maxKeys   int
	nextPrune time.Time
}

type window struct {
	count int
	reset time.Time
}

func newLimiter(max int, win time.Duration) *limiter {
	return &limiter{hits: make(map[string]*window), max: max, window: win, now: time.Now, maxKeys: limiterMaxKeys}
}

func (l *limiter) allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.hasRoom(key, now) {
		return false
	}
	w := l.hits[key]
	if w == nil || now.After(w.reset) {
		l.hits[key] = &window{count: 1, reset: now.Add(l.window)}
		return true
	}
	if w.count >= l.max {
		return false
	}
	w.count++
	return true
}

// hasRoom reports whether key can be tracked, pruning expired windows when the
// map is full. The caller holds l.mu.
func (l *limiter) hasRoom(key string, now time.Time) bool {
	if _, ok := l.hits[key]; ok || len(l.hits) < l.maxKeys {
		return true
	}
	if !now.Before(l.nextPrune) {
		for k, w := range l.hits {
			if now.After(w.reset) {
				delete(l.hits, k)
			}
		}
		l.nextPrune = now.Add(limiterPruneInterval)
	}
	return len(l.hits) < l.maxKeys
}

// blocked reports whether key has used up its window, without counting a hit.
// A new key on a full map counts as blocked.
func (l *limiter) blocked(key string) bool {
	if l == nil {
		return false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.hasRoom(key, now) {
		return true
	}
	w := l.hits[key]
	return w != nil && !now.After(w.reset) && w.count >= l.max
}

// recordFailure counts one failed attempt for key.
func (l *limiter) recordFailure(key string) {
	if l == nil {
		return
	}
	_ = l.allow(key)
}

// rateLimit wraps a handler with a per-client-IP limit (HTML-style 429).
func (s *Server) rateLimit(l *limiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(s.rateLimitKey(r)) {
			rateLimitError(w, r)
			return
		}
		next(w, r)
	}
}

func rateLimitError(w http.ResponseWriter, r *http.Request) {
	if wantsJSONError(r) {
		jsonError(w, http.StatusTooManyRequests, "too many requests, try again shortly")
		return
	}
	http.Error(w, "Too many requests. Try again shortly.", http.StatusTooManyRequests)
}

func wantsJSONError(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.Header.Get("Accept"), "application/json")
}
