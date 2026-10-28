package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// pageEventHeartbeat is how often an idle stream re-checks access and the latest
// version, which also keeps proxies from closing it. Tests shorten it.
var pageEventHeartbeat = 20 * time.Second

const (
	// pageEventWriteTimeout replaces the server's WriteTimeout for each write on a
	// stream, so a long-lived stream is not cut off but a stuck client still is.
	pageEventWriteTimeout = 10 * time.Second
	// maxPageEventStreams caps open streams across all pages. Viewers over the cap
	// get a 503 and keep the page without live reload.
	maxPageEventStreams = 1000
)

// pageEventHub tells open viewer pages when a new version of their upload is
// created. It is in-process: Peek runs as a single process on one SQLite file.
// The zero value is ready to use.
type pageEventHub struct {
	mu     sync.Mutex
	subs   map[int64]map[chan int]struct{}
	count  int
	closed bool
	done   chan struct{}
}

// doneLocked returns the channel closed by close. Callers hold h.mu.
func (h *pageEventHub) doneLocked() chan struct{} {
	if h.done == nil {
		h.done = make(chan struct{})
	}
	return h.done
}

// subscribe registers a stream for uploadID. It returns false when the hub is
// closed or full.
func (h *pageEventHub) subscribe(uploadID int64) (chan int, <-chan struct{}, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.count >= maxPageEventStreams {
		return nil, nil, false
	}
	if h.subs == nil {
		h.subs = make(map[int64]map[chan int]struct{})
	}
	if h.subs[uploadID] == nil {
		h.subs[uploadID] = make(map[chan int]struct{})
	}
	ch := make(chan int, 1)
	h.subs[uploadID][ch] = struct{}{}
	h.count++
	return ch, h.doneLocked(), true
}

func (h *pageEventHub) unsubscribe(uploadID int64, ch chan int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[uploadID][ch]; !ok {
		return
	}
	delete(h.subs[uploadID], ch)
	if len(h.subs[uploadID]) == 0 {
		delete(h.subs, uploadID)
	}
	h.count--
}

// publish sends version to every stream of uploadID without blocking. A stream
// that has not read the previous value gets only the newest one.
func (h *pageEventHub) publish(uploadID int64, version int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[uploadID] {
		select {
		case <-ch:
		default:
		}
		ch <- version
	}
}

// close ends every open stream and refuses new ones, so a graceful shutdown does
// not wait for viewers to leave.
func (h *pageEventHub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	close(h.doneLocked())
}

// CloseEventStreams ends the viewer pages' live-reload streams. Register it with
// http.Server.RegisterOnShutdown.
func (s *Server) CloseEventStreams() {
	s.pageEvents.close()
}

// handlePageEvents streams the latest version number of an upload as
// Server-Sent Events. The viewer page reloads when it sees a newer version.
func (s *Server) handlePageEvents(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.viewerCanAccessUpload(r, u) {
		jsonError(w, s.uploadAccessStatus(r, u), uploadAccessRequiredMessage(u))
		return
	}
	ch, done, ok := s.pageEvents.subscribe(u.ID)
	if !ok {
		jsonError(w, http.StatusServiceUnavailable, "live reload unavailable")
		return
	}
	defer s.pageEvents.unsubscribe(u.ID, ch)

	rc := http.NewResponseController(w)
	send := func(format string, args ...any) bool {
		if err := rc.SetWriteDeadline(time.Now().Add(pageEventWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	sendVersion := func(v int) bool {
		return send("event: version\ndata: %s\n\n", strconv.Itoa(v))
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	// Ask nginx and similar proxies not to buffer the stream.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// Subscribing before this read means no version created since is missed.
	if !send("retry: 5000\n\n") || !sendVersion(u.LatestVersion) {
		return
	}

	ticker := time.NewTicker(pageEventHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case v := <-ch:
			if !sendVersion(v) {
				return
			}
		case <-ticker.C:
			// Re-check access so a visibility, grant or delete change ends the
			// stream, and resend the latest version in case an event was missed.
			cur, err := s.store.GetUpload(r.Context(), slug)
			if err != nil || cur.ID != u.ID || !s.viewerCanAccessUpload(r, cur) {
				return
			}
			if !sendVersion(cur.LatestVersion) {
				return
			}
		}
	}
}
