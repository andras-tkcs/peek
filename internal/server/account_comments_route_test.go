package server_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestAccountCommentRouteRegistered(t *testing.T) {
	app := newTestApp(t)

	resp := app.requestString(t, http.MethodPost, "/api/uploads/x/account-comments", `{"body":"hi"}`)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(resp.Body), "missing token") {
		t.Fatalf("no token: status = %d, body = %s", resp.StatusCode, resp.Body)
	}

	resp = app.requestString(t, http.MethodPost, "/api/uploads/x/account-comments", `{"body":"hi"}`, withAuth(app.AdminToken))
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(resp.Body), "not found") {
		t.Fatalf("unknown slug: status = %d, body = %s", resp.StatusCode, resp.Body)
	}
}
