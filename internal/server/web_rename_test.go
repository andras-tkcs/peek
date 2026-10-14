package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDashboardRenameChangesLinkAndAudits(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "page", "public", "")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/rename/page", url.Values{"name": {"Quarterly Report"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	newSlug := loc.Query().Get("manage")
	if !strings.HasPrefix(newSlug, "quarterly-report-") || len(newSlug) != len("quarterly-report-")+6 {
		t.Fatalf("new slug = %q", newSlug)
	}
	if ok := loc.Query().Get("ok"); ok != "renamed" || loc.Query().Get("slug") != newSlug {
		t.Fatalf("ok = %q slug = %q", ok, loc.Query().Get("slug"))
	}
	got, err := s.store.GetUpload(context.Background(), newSlug)
	if err != nil || got.Name != "Quarterly Report" {
		t.Fatalf("GetUpload = %+v, %v", got, err)
	}
	if _, ok := auditActions(t, s)["upload.rename"]; !ok {
		t.Fatal("missing upload.rename audit entry")
	}
}

func TestDashboardRenameRejectsEmptyName(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "page", "public", "")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/rename/page", url.Values{"name": {""}}, true)
	wantLocation(t, rec.Header().Get("Location"), "/dashboard?err=upload_name_required&manage=page&slug=page")
}

func TestDashboardRenameRejectsNonOwner(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "page", "public", "")
	other, err := s.store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	rec := dashboardPost(t, s, other.ID, "/dashboard/rename/page", url.Values{"name": {"X"}}, true)
	wantLocation(t, rec.Header().Get("Location"), "/dashboard?err=not_owner")
}

func TestDashboardRenameRejectsMissingCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "page", "public", "")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/rename/page", url.Values{"name": {"X"}}, false)
	wantLocation(t, rec.Header().Get("Location"), "/dashboard?err=invalid_session")
}

func TestUploadVersionToRenamedSlugExplains(t *testing.T) {
	s, admin := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "page", "public", "")
	if err := s.store.RenameUpload(context.Background(), u.ID, "renamed", "Renamed"); err != nil {
		t.Fatal(err)
	}
	rec := uploadPage(t, s, admin, "<html><body>v3</body></html>", map[string]string{"slug": "page"})
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "page was renamed; use slug renamed") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}
