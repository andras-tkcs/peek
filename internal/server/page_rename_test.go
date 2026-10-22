package server

import (
	"context"
	"net/http"
	"testing"
)

func TestRenamedPageRedirects(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "old", "public")
	if err := s.store.RenameUpload(context.Background(), u.ID, "new", "New"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path, location string
		status         int
	}{
		{"/p/old?x=1", "/p/new?x=1", http.StatusFound},
		{"/p/old/v/2", "/p/new/v/2", http.StatusFound},
		{"/p/old/v/abc", "", http.StatusNotFound},
		{"/p/new", "", http.StatusOK},
		{"/p/missing", "", http.StatusNotFound},
	}
	for _, tc := range tests {
		rec := doRequest(t, s, http.MethodGet, tc.path, nil)
		if rec.Code != tc.status {
			t.Errorf("GET %s = %d, want %d", tc.path, rec.Code, tc.status)
		}
		if got := rec.Header().Get("Location"); tc.location != "" && got != tc.location {
			t.Errorf("GET %s Location = %q, want %q", tc.path, got, tc.location)
		}
	}
}
