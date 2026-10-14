package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/uploads"
)

func TestDashboardUploadedRedirectCarriesSlug(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/dashboard/upload", nil)
	rec := httptest.NewRecorder()

	dashboardUploaded(rec, req, "page")

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard?uploaded=page" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestFlashMessagesCoverAllCodes(t *testing.T) {
	codes := []string{
		flashInvalidSession, flashFormInvalid, flashNoHTML, flashNoFile, flashFileTooLarge,
		flashNotFound, flashNotOwner, flashDeleteFailed, flashVisibilityFailed, flashRenameFailed,
		flashGrantKind, flashGrantEmail, flashGrantGroupLookup, flashGrantFailed, flashGrantNotFound,
		flashInviteEmailRequired, flashInviteDomain, flashInviteFailed, flashBadInvite, flashInviteRevokeFailed,
		flashBadUser, flashLastAdminRemove, flashLastAdminDisable, flashUserUpdateFailed, flashSettingsFailed,
		flashAPIKeyName, flashAPIKeyCreateFailed, flashAPIKeyRegenerateFailed, flashAPIKeyRevokeFailed,
		flashUploadFailed, flashUploadPersistenceFailure,
		flashInviteCreated, flashInviteRevoked, flashUserUpdated, flashSettingsSaved, flashAPIKeyRevoked,
		flashPasswordUpdated, flashVisibilitySet, flashGrantAdded, flashGrantRemoved, flashRenamed,
		flashSessionsRevoked, flashSessionsRevokeFailed,
	}
	for _, code := range codes {
		if flashMessages[code] == "" {
			t.Errorf("flashMessages[%q] is missing or empty", code)
		}
	}
}

type noRenameRepo struct{}

func (noRenameRepo) UploadSlugExists(context.Context, string) (bool, error) { return false, nil }
func (noRenameRepo) ResolveSlugAlias(context.Context, string) (string, error) {
	return "", errors.New("unused")
}
func (noRenameRepo) RenameUpload(context.Context, int64, string, string) error { return nil }

func TestUploadFlashCodeMatchesUploadErrors(t *testing.T) {
	_, visErr1 := uploads.PrepareVisibility("bogus", "")
	_, visErr2 := uploads.PrepareVisibility("password", "")
	_, visErr3 := uploads.PrepareVisibility("public", "x")
	_, visErr4 := uploads.PrepareVisibility("password", strings.Repeat("a", 73))
	_, nameErr1 := uploads.Rename(context.Background(), noRenameRepo{}, "", uploads.RenameInput{Name: " "})
	_, nameErr2 := uploads.Rename(context.Background(), noRenameRepo{}, "", uploads.RenameInput{Name: strings.Repeat("a", 201)})
	cases := map[string]error{
		"bogus visibility":     visErr1,
		"password required":    visErr2,
		"password not allowed": visErr3,
		"password too long":    visErr4,
		"name required":        nameErr1,
		"name too long":        nameErr2,
		"empty file":           &uploads.Error{Kind: uploads.KindEmptyFile, Message: "empty file"},
		"invalid html":         &uploads.Error{Kind: uploads.KindInvalidHTML, Message: "file does not look like HTML"},
		"password hash":        &uploads.Error{Kind: uploads.KindPasswordHash, Message: "hash failed"},
		"slug generation":      &uploads.Error{Kind: uploads.KindSlugGeneration, Message: "slug generation failed"},
		"storage write":        &uploads.Error{Kind: uploads.KindStorageWrite, Message: "storage failed"},
		"total quota":          &uploads.Error{Kind: uploads.KindTotalQuotaExceeded, Message: "total storage quota exceeded"},
		"owner count":          &uploads.Error{Kind: uploads.KindOwnerCountExceeded, Message: "per-token upload count quota exceeded"},
		"owner storage":        &uploads.Error{Kind: uploads.KindOwnerStorageExceeded, Message: "per-token storage quota exceeded"},
		"persistence":          &uploads.Error{Kind: uploads.KindPersistenceFailure, Message: "db failed"},
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if err == nil {
				t.Fatal("expected an error")
			}
			code := uploadFlashCode(err)
			if code == flashUploadFailed {
				t.Fatalf("code = %q for %v", code, err)
			}
			if got := flashMessages[code]; got != err.Error() {
				t.Fatalf("flashMessages[%q] = %q, want %q", code, got, err.Error())
			}
		})
	}
	if got := uploadFlashCode(errors.New("x")); got != flashUploadFailed {
		t.Fatalf("code = %q", got)
	}
}

func TestGrantFlashCodeMatchesGrantErrors(t *testing.T) {
	s := &Server{}
	for _, c := range [][2]string{{"bogus", "a@b.c"}, {"user", "not-an-email"}, {"group", "g@example.com"}} {
		_, msg := s.normalizeGrantInput(c[0], c[1], true)
		code := grantFlashCode(msg)
		if code == flashGrantFailed {
			t.Fatalf("%v: no specific code for %q", c, msg)
		}
		if flashMessages[code] != msg {
			t.Fatalf("%v: flashMessages[%q] = %q, want %q", c, code, flashMessages[code], msg)
		}
	}
	if got := grantFlashCode("something else"); got != flashGrantFailed {
		t.Fatalf("code = %q", got)
	}
}

func TestResolveFlash(t *testing.T) {
	list := []dashUpload{{Slug: "page", Visibility: "public", Grants: []dashGrant{{Kind: "user", Email: "alice@example.com"}}}}
	tests := []struct {
		name  string
		query string
		want  dashboardFlashView
	}{
		{"not owner", "err=not_owner", dashboardFlashView{Error: "not owner"}},
		{"free text", "err=Call+IT+on+555-0100", dashboardFlashView{}},
		{"visibility", "ok=visibility_set&slug=page", dashboardFlashView{Success: "/p/page is now public"}},
		{"visibility other slug", "ok=visibility_set&slug=other", dashboardFlashView{}},
		{"password without slug", "ok=password_updated", dashboardFlashView{}},
		{"grant added", "ok=grant_added&slug=page&email=alice@example.com", dashboardFlashView{Success: "Shared /p/page with alice@example.com"}},
		{"grant added unknown email", "ok=grant_added&slug=page&email=mallory@evil.example", dashboardFlashView{}},
		{"grant removed", "ok=grant_removed&slug=page", dashboardFlashView{Success: "Removed access from /p/page"}},
		{"renamed", "ok=renamed&slug=page", dashboardFlashView{Success: "Renamed to /p/page"}},
		{"uploaded", "uploaded=page", dashboardFlashView{UploadedURL: "http://h/p/page"}},
		{"uploaded url", "uploaded=https://evil.example/x", dashboardFlashView{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if got := resolveFlash(q, list, "http://h"); got != tc.want {
				t.Fatalf("resolveFlash(%q) = %+v, want %+v", tc.query, got, tc.want)
			}
		})
	}
}

func TestSetCovParseDashboardFormReportsCSRFGenerationFailure(t *testing.T) {
	s, _, _, _ := newFaultServer(t)
	stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("rand down") })
	form := url.Values{"csrf": {"csrf-token"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	rec := httptest.NewRecorder()
	if s.parseDashboardForm(rec, req) {
		t.Fatal("parseDashboardForm succeeded without entropy")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
