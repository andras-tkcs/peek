package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
)

func grantPost(t *testing.T, s *Server, account int64, path, kind, email string, csrf bool) string {
	t.Helper()
	rec := dashboardPost(t, s, account, path, url.Values{"kind": {kind}, "email": {email}}, csrf)
	if rec.Code != 303 {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	return rec.Header().Get("Location")
}

func wantLocation(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func grantCount(t *testing.T, s *Server, id int64) []models.UploadGrant {
	t.Helper()
	grants, err := s.store.ListUploadGrants(context.Background(), id)
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	return grants
}

func TestDashboardGrantAddAndRemove(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page", "user", "Alice@Example.com", true)
	wantLocation(t, loc, "/dashboard?email=alice%40example.com&manage=page&ok=grant_added&slug=page")
	grants := grantCount(t, s, u.ID)
	if len(grants) != 1 || grants[0].Kind != "user" || grants[0].Email != "alice@example.com" {
		t.Fatalf("grants = %+v", grants)
	}
	if _, ok := auditActions(t, s)["upload.grant.add"]; !ok {
		t.Fatal("missing upload.grant.add audit")
	}
	loc = grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page/remove", "user", "alice@example.com", true)
	wantLocation(t, loc, "/dashboard?manage=page&ok=grant_removed&slug=page")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v, want none", g)
	}
	if _, ok := auditActions(t, s)["upload.grant.remove"]; !ok {
		t.Fatal("missing upload.grant.remove audit")
	}
}

func TestDashboardGrantRejectsInvalidEmail(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page", "user", "not-an-email", true)
	wantLocation(t, loc, "/dashboard?err=grant_email&manage=page&slug=page")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantRejectsGroupWithoutLookup(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page", "group", "team@example.com", true)
	wantLocation(t, loc, "/dashboard?err=grant_group_lookup&manage=page&slug=page")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantAcceptsGroupWithLookup(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	s.groups = fakeGroups{members: map[string]bool{}}
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page", "group", "team@example.com", true)
	wantLocation(t, loc, "/dashboard?email=team%40example.com&manage=page&ok=grant_added&slug=page")
	g := grantCount(t, s, u.ID)
	if len(g) != 1 || g[0].Kind != models.UploadGrantGroup {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantRemovesGroupWithoutLookup(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	grant(t, s, u, models.UploadGrantGroup, "team@example.com")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page/remove", "group", "team@example.com", true)
	wantLocation(t, loc, "/dashboard?manage=page&ok=grant_removed&slug=page")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantRemoveMissing(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page/remove", "user", "alice@example.com", true)
	wantLocation(t, loc, "/dashboard?err=grant_not_found&manage=page&slug=page")
}

func TestDashboardGrantRejectsNonOwner(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	other, err := s.store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	loc := grantPost(t, s, other.ID, "/dashboard/grants/page", "user", "alice@example.com", true)
	wantLocation(t, loc, "/dashboard?err=not_owner")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantRejectsMissingCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page", "user", "alice@example.com", false)
	wantLocation(t, loc, "/dashboard?err=invalid_session")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashCovGrantGuardsAndFailures(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)
	dashCovUpload(t, s, "page", adminID)

	for _, suffix := range []string{"", "/remove"} {
		if rec := doRequest(t, s, http.MethodPost, "/dashboard/grants/page"+suffix, nil); rec.Header().Get("Location") != "/login" {
			t.Fatalf("anonymous Location = %q", rec.Header().Get("Location"))
		}
		rec := dashboardPost(t, s, adminID, "/dashboard/grants/missing"+suffix, url.Values{"kind": {"user"}, "email": {"a@example.test"}}, true)
		assertDashboardRedirect(t, rec, "/dashboard?err="+flashNotFound)
	}

	rec := dashboardPost(t, s, adminID, "/dashboard/grants/page/remove", url.Values{"kind": {"bogus"}, "email": {"a@example.test"}}, true)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("remove with bad kind = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	if _, err := store.Exec(`INSERT INTO upload_grants(upload_id,kind,email,created_by_account_id,created_at) SELECT id,'user','b@example.test',?,0 FROM uploads WHERE slug='page'`, adminID); err != nil {
		t.Fatal(err)
	}
	addFailTrigger(t, store, "upload_grants", "INSERT")
	addFailTrigger(t, store, "upload_grants", "DELETE")
	rec = dashboardPost(t, s, adminID, "/dashboard/grants/page", url.Values{"kind": {"user"}, "email": {"a@example.test"}}, true)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err="+flashGrantFailed) {
		t.Fatalf("add failure Location = %q", loc)
	}
	rec = dashboardPost(t, s, adminID, "/dashboard/grants/page/remove", url.Values{"kind": {"user"}, "email": {"b@example.test"}}, true)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err="+flashGrantFailed) {
		t.Fatalf("remove failure Location = %q", loc)
	}
}
