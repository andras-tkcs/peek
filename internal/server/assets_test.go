package server

import (
	"net/http"
	"testing"
)

func TestStaticAssetRoutesServe(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	for _, path := range []string{
		"/bridge.js", "/app.js", "/dashboard-alpine.js", "/toast.js", "/alpine.min.js",
		"/pines.css", "/favicon.svg", "/favicon.png", "/favicon.ico", "/logo.svg", "/logo.png",
	} {
		t.Run(path, func(t *testing.T) {
			rec := doRequest(t, s, http.MethodGet, path, nil)
			if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
				t.Fatalf("GET %s = %d with %d bytes, want 200 with a body", path, rec.Code, rec.Body.Len())
			}
		})
	}
}
