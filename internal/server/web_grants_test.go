package server

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/puemos/peek/internal/models"
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
	wantLocation(t, loc, "/dashboard?manage=page&ok=Shared+%2Fp%2Fpage+with+alice%40example.com")
	grants := grantCount(t, s, u.ID)
	if len(grants) != 1 || grants[0].Kind != "user" || grants[0].Email != "alice@example.com" {
		t.Fatalf("grants = %+v", grants)
	}
	if _, ok := auditActions(t, s)["upload.grant.add"]; !ok {
		t.Fatal("missing upload.grant.add audit")
	}
	loc = grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page/remove", "user", "alice@example.com", true)
	wantLocation(t, loc, "/dashboard?manage=page&ok=Removed+alice%40example.com+from+%2Fp%2Fpage")
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
	wantLocation(t, loc, "/dashboard?err=invalid+email+address&manage=page")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantRejectsGroupWithoutLookup(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page", "group", "team@example.com", true)
	if !strings.HasPrefix(loc, "/dashboard?err=group+grants+need+Google+group+lookup") || !strings.Contains(loc, "&manage=page") {
		t.Fatalf("Location = %q", loc)
	}
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantAcceptsGroupWithLookup(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	s.groups = fakeGroups{members: map[string]bool{}}
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page", "group", "team@example.com", true)
	wantLocation(t, loc, "/dashboard?manage=page&ok=Shared+%2Fp%2Fpage+with+team%40example.com")
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
	wantLocation(t, loc, "/dashboard?manage=page&ok=Removed+team%40example.com+from+%2Fp%2Fpage")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantRemoveMissing(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page/remove", "user", "alice@example.com", true)
	wantLocation(t, loc, "/dashboard?err=grant+not+found&manage=page")
}

func TestDashboardGrantRejectsNonOwner(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	other, err := s.store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	loc := grantPost(t, s, other.ID, "/dashboard/grants/page", "user", "alice@example.com", true)
	wantLocation(t, loc, "/dashboard?err=not+owner")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}

func TestDashboardGrantRejectsMissingCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "page")
	loc := grantPost(t, s, u.OwnerAccountID, "/dashboard/grants/page", "user", "alice@example.com", false)
	wantLocation(t, loc, "/dashboard?err=invalid+session")
	if g := grantCount(t, s, u.ID); len(g) != 0 {
		t.Fatalf("grants = %+v", g)
	}
}
