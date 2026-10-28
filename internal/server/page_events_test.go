package server

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/uploadquota"
)

// eventStream reads Server-Sent Events from a live test server.
type eventStream struct {
	resp *http.Response
	r    *bufio.Reader
}

func openEventStream(t *testing.T, ts *httptest.Server, slug string) *eventStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/uploads/"+slug+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type = %q", ct)
	}
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("missing X-Accel-Buffering: no")
	}
	return &eventStream{resp: resp, r: bufio.NewReader(resp.Body)}
}

// nextVersion returns the data of the next version event.
func (e *eventStream) nextVersion(t *testing.T) string {
	t.Helper()
	event := ""
	for {
		line, err := e.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read event: %v", err)
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: ") && event == "version":
			return strings.TrimPrefix(line, "data: ")
		}
	}
}

func (e *eventStream) expectClosed(t *testing.T) {
	t.Helper()
	if _, err := io.ReadAll(e.r); err != nil {
		t.Fatalf("stream did not end cleanly: %v", err)
	}
}

func TestPageEventsStreamsNewVersions(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	slug := seedVersionPage(t, s, admin)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	stream := openEventStream(t, ts, slug)
	if got := stream.nextVersion(t); got != "1" {
		t.Fatalf("initial version = %q, want 1", got)
	}
	if rec := uploadPage(t, s, admin, versionTestHTML2, map[string]string{"slug": slug}); rec.Code != http.StatusOK {
		t.Fatalf("version upload = %d: %s", rec.Code, rec.Body.String())
	}
	if got := stream.nextVersion(t); got != "2" {
		t.Fatalf("pushed version = %q, want 2", got)
	}
}

func TestPageEventsHeartbeatResendsVersionAndEndsOnDelete(t *testing.T) {
	old := pageEventHeartbeat
	pageEventHeartbeat = 20 * time.Millisecond
	t.Cleanup(func() { pageEventHeartbeat = old })

	s, admin := newHandlerTestServer(t)
	slug := seedVersionPage(t, s, admin)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	stream := openEventStream(t, ts, slug)
	for i := 0; i < 2; i++ {
		if got := stream.nextVersion(t); got != "1" {
			t.Fatalf("version %d = %q, want 1", i, got)
		}
	}
	if rec := doRequest(t, s, http.MethodDelete, "/api/uploads/"+slug, nil, asBearer(admin)); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	stream.expectClosed(t)
}

func TestPageEventsEndOnShutdown(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	slug := seedVersionPage(t, s, admin)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	stream := openEventStream(t, ts, slug)
	stream.nextVersion(t)
	s.CloseEventStreams()
	s.CloseEventStreams()
	stream.expectClosed(t)

	rec := doRequest(t, s, http.MethodGet, "/api/uploads/"+slug+"/events", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("events after shutdown = %d, want 503", rec.Code)
	}
}

func TestPageEventsRefusesUnknownAndPrivatePages(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	owner, err := s.store.CreateAccount(context.Background(), "owner@example.test", "Owner", false)
	if err != nil {
		t.Fatal(err)
	}
	for slug, vis := range map[string]string{"signed": "signed-in", "secret": "restricted"} {
		if err := s.store.CreateUploadChecked(context.Background(), slug, owner.ID, 0, slug+".html", 42, vis, uploadquota.Limits{}); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]int{"missing": http.StatusNotFound, "signed": http.StatusUnauthorized, "secret": http.StatusUnauthorized}
	for slug, want := range cases {
		if rec := doRequest(t, s, http.MethodGet, "/api/uploads/"+slug+"/events", nil); rec.Code != want {
			t.Errorf("%s: status = %d, want %d", slug, rec.Code, want)
		}
	}
}

func TestPageEventsRefusesOverCap(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	slug := seedVersionPage(t, s, admin)
	s.pageEvents.count = maxPageEventStreams
	rec := doRequest(t, s, http.MethodGet, "/api/uploads/"+slug+"/events", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPageEventHubKeepsNewestVersion(t *testing.T) {
	var h pageEventHub
	ch, _, ok := h.subscribe(7)
	if !ok {
		t.Fatal("subscribe refused")
	}
	h.publish(7, 2)
	h.publish(7, 3)
	h.publish(8, 9)
	if got := <-ch; got != 3 {
		t.Fatalf("got %d, want newest version 3", got)
	}
	h.unsubscribe(7, ch)
	h.unsubscribe(7, ch)
	if h.count != 0 || len(h.subs) != 0 {
		t.Fatalf("hub not empty after unsubscribe: count=%d subs=%d", h.count, len(h.subs))
	}
}

func TestPageMarksOnlyLatestLinkLive(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	slug := seedVersionPage(t, s, admin)
	if rec := doRequest(t, s, http.MethodGet, "/p/"+slug, nil); !strings.Contains(rec.Body.String(), `data-live="1"`) {
		t.Fatalf("latest link is not live: %d", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, "/p/"+slug+"/v/1", nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "data-live") {
		t.Fatalf("version link is live or failed: %d", rec.Code)
	}
}
