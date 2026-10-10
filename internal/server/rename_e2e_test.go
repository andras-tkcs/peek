package server_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestRenameE2E(t *testing.T) {
	app := newTestApp(t)
	app.client = noRedirectClient()

	up := uploadRawHTML(t, app, "first", "public")
	rename := func(slug, body string) testResponse {
		return app.requestString(t, http.MethodPost, "/api/uploads/"+slug+"/name", body, withAuth(app.AdminToken), withContentType("application/json"))
	}

	resp := rename(up.Slug, `{"name":"Second Report"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename status = %d: %s", resp.StatusCode, resp.Body)
	}
	for _, want := range []string{`"slug":"second-report"`, `"name":"Second Report"`} {
		if !strings.Contains(string(resp.Body), want) {
			t.Fatalf("rename body missing %q: %s", want, resp.Body)
		}
	}

	old := app.requestString(t, http.MethodGet, "/p/"+up.Slug, "")
	if old.StatusCode != http.StatusFound || old.Header.Get("Location") != "/p/second-report" {
		t.Fatalf("old link = %d %q", old.StatusCode, old.Header.Get("Location"))
	}
	if cur := app.requestString(t, http.MethodGet, "/p/second-report", ""); cur.StatusCode != http.StatusOK {
		t.Fatalf("new link status = %d", cur.StatusCode)
	}

	resp = rename("second-report", `{"name":"  "}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(resp.Body), "name is required") {
		t.Fatalf("empty name = %d: %s", resp.StatusCode, resp.Body)
	}

	again := uploadRawHTML(t, app, "first", "public")
	if again.Slug == up.Slug {
		t.Fatalf("old slug %q was reused", up.Slug)
	}
}
