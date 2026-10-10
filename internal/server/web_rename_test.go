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
	wantLocation(t, rec.Header().Get("Location"), "/dashboard?manage=quarterly-report&ok=Renamed+to+%2Fp%2Fquarterly-report")
	got, err := s.store.GetUpload(context.Background(), "quarterly-report")
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
	wantLocation(t, rec.Header().Get("Location"), "/dashboard?err=name+is+required&manage=page")
}

func TestDashboardRenameRejectsNonOwner(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "page", "public", "")
	other, err := s.store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	rec := dashboardPost(t, s, other.ID, "/dashboard/rename/page", url.Values{"name": {"X"}}, true)
	wantLocation(t, rec.Header().Get("Location"), "/dashboard?err=not+owner")
}

func TestDashboardRenameRejectsMissingCSRF(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "page", "public", "")
	rec := dashboardPost(t, s, u.OwnerAccountID, "/dashboard/rename/page", url.Values{"name": {"X"}}, false)
	wantLocation(t, rec.Header().Get("Location"), "/dashboard?err=invalid+session")
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
