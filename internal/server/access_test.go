package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
)

// fakeGroups is a GroupChecker keyed by "group|user".
type fakeGroups struct {
	members map[string]bool
	err     error
}

func (f fakeGroups) IsMember(_ context.Context, group, user string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.members[group+"|"+user], nil
}

func newViewer(t *testing.T, s *Server, email, name string, isAdmin bool) *models.Account {
	t.Helper()
	a, err := s.store.CreateAccount(context.Background(), email, name, isAdmin)
	if err != nil {
		t.Fatalf("create account %q: %v", email, err)
	}
	return a
}

func grant(t *testing.T, s *Server, u *models.Upload, kind, email string) {
	t.Helper()
	if _, _, err := s.store.AddUploadGrant(context.Background(), u.ID, kind, email, u.OwnerAccountID); err != nil {
		t.Fatalf("add grant: %v", err)
	}
}

func restrictedPage(t *testing.T, s *Server, slug string) *models.Upload {
	t.Helper()
	return newTwoVersionPage(t, s, slug, models.UploadVisibilityRestricted)
}

func auditActions(t *testing.T, s *Server) map[string]string {
	t.Helper()
	entries, err := s.store.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		out[e.Action] = e.Actor
	}
	return out
}

func TestRestrictedOwnerAndAdminCanView(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "r-owner")
	admin := newViewer(t, s, "admin@example.test", "Admin", true)
	for name, id := range map[string]int64{"owner": u.OwnerAccountID, "admin": admin.ID} {
		rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, id))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", name, rec.Code)
		}
	}
}

func TestRestrictedUserGrantAllowsView(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "r-user")
	bob := newViewer(t, s, "bob@example.com", "Bob", false)
	grant(t, s, u, models.UploadGrantUser, "Bob@Example.com")
	rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, bob.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestRestrictedWithoutGrantGets403Page(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "r-deny")
	eve := newViewer(t, s, "eve@example.com", "Eve", false)
	rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, eve.ID))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Access denied") || !strings.Contains(body, "eve@example.com") {
		t.Fatalf("unexpected body: %s", body)
	}
	if got := auditActions(t, s)["page.access.denied"]; got != "eve@example.com" {
		t.Fatalf("audit actor = %q, want eve@example.com", got)
	}
}

func TestRestrictedAnonymousRedirectsToLogin(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "r-anon")
	rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRestrictedGroupGrantUsesChecker(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	s.groups = fakeGroups{members: map[string]bool{"team@example.com|bob@example.com": true}}
	u := restrictedPage(t, s, "r-group")
	grant(t, s, u, models.UploadGrantGroup, "team@example.com")
	bob := newViewer(t, s, "bob@example.com", "Bob", false)
	eve := newViewer(t, s, "eve@example.com", "Eve", false)
	if rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, bob.ID)); rec.Code != http.StatusOK {
		t.Fatalf("member status = %d, want 200", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, eve.ID)); rec.Code != http.StatusForbidden {
		t.Fatalf("non-member status = %d, want 403", rec.Code)
	}
}

func TestRestrictedGroupCheckerErrorFailsClosed(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	s.groups = fakeGroups{members: map[string]bool{"team@example.com|bob@example.com": true}, err: errors.New("directory down")}
	u := restrictedPage(t, s, "r-group-err")
	grant(t, s, u, models.UploadGrantGroup, "team@example.com")
	bob := newViewer(t, s, "bob@example.com", "Bob", false)
	if rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, bob.ID)); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRestrictedGroupGrantIgnoredWhenNoChecker(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "r-group-none")
	grant(t, s, u, models.UploadGrantGroup, "team@example.com")
	bob := newViewer(t, s, "bob@example.com", "Bob", false)
	if rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, bob.ID)); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRestrictedCommentsAndViewsAPIReturn403ForSignedInNonGrantee(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "r-api")
	eve := newViewer(t, s, "eve@example.com", "Eve", false)
	base := "/api/uploads/" + u.Slug
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, base + "/comments", ""},
		{http.MethodPost, base + "/comments", `{"name":"Eve","body":"hi"}`},
		{http.MethodGet, base + "/views", ""},
	} {
		rec := doRequest(t, s, tc.method, tc.path, strings.NewReader(tc.body), asSession(s, eve.ID), withJSON())
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "access denied") {
			t.Fatalf("%s %s = %d %s, want 403 access denied", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		anon := doRequest(t, s, tc.method, tc.path, strings.NewReader(tc.body), withJSON())
		if anon.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s %s = %d, want 401", tc.method, tc.path, anon.Code)
		}
	}
}

func TestRestrictedAccountWithoutEmailDenied(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "r-noemail")
	grant(t, s, u, models.UploadGrantUser, "")
	acct := newViewer(t, s, "", "Token Only", false)
	rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, acct.ID))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := auditActions(t, s)["page.access.denied"]; got != "Token Only" {
		t.Fatalf("audit actor = %q, want account name", got)
	}
}

func TestGrantsNotEnforcedOnPrivate(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "p-private", models.UploadVisibilitySignedIn)
	grant(t, s, u, models.UploadGrantUser, "someone@example.com")
	eve := newViewer(t, s, "eve@example.com", "Eve", false)
	if rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug, nil, asSession(s, eve.ID)); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRestrictedVersionPageEnforced(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "r-version")
	eve := newViewer(t, s, "eve@example.com", "Eve", false)
	if rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug+"/v/1", nil, asSession(s, eve.ID)); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if rec := doRequest(t, s, http.MethodGet, "/p/"+u.Slug+"/v/1", nil, asSession(s, u.OwnerAccountID)); rec.Code != http.StatusOK {
		t.Fatalf("owner status = %d, want 200", rec.Code)
	}
}

func TestSetCovRestrictedGrantLookupFailureDenies(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := restrictedPage(t, s, "setcov-grants")
	viewer := newViewer(t, s, "setcov-viewer@example.test", "Viewer", false)
	dropTable(t, s.store, "upload_grants")
	if s.accountCanViewRestricted(context.Background(), viewer, u) {
		t.Fatal("grant lookup failure must deny access")
	}
}

func TestSetCovRestrictedUserGrantForOtherEmailSkippedInGroupLoopDenies(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	s.groups = fakeGroups{}
	u := restrictedPage(t, s, "setcov-skip")
	viewer := newViewer(t, s, "member@example.test", "Member", false)
	grant(t, s, u, models.UploadGrantUser, "someone-else@example.test")
	grant(t, s, u, models.UploadGrantGroup, "team@example.test")
	if s.accountCanViewRestricted(context.Background(), viewer, u) {
		t.Fatal("non-member must not view through a user grant for someone else")
	}
}
