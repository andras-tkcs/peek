package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
	webui "github.com/andras-tkcs/peek/internal/web"
)

func TestInviteLinkMissingTokenRendersWebError(t *testing.T) {
	s, _, _ := newAdminTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/invite/missing", nil)
	req.SetPathValue("token", "missing")
	rec := httptest.NewRecorder()

	s.handleInviteLink(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "Invite not found") {
		t.Fatalf("invite error did not render web page: %s", rec.Body.String())
	}
}

func TestDashboardRevokeInviteRejectsMissingInvite(t *testing.T) {
	s, _, accountID := newAdminTestServer(t)

	rec := httptest.NewRecorder()
	s.handleDashboardRevokeInvite(rec, dashboardInviteRequest(s, accountID, "999"))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := u.Query().Get("err"); got != "bad_invite" {
		t.Fatalf("err query = %q, location = %q", got, loc)
	}
}

func TestDashboardRevokeInviteReportsSuccessAfterUpdate(t *testing.T) {
	s, store, accountID := newAdminTestServer(t)
	inv, err := store.CreateInvite(context.Background(), "raw", "ciphertext", "user@example.test", accountID, time.Now().Add(inviteTTL))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.handleDashboardRevokeInvite(rec, dashboardInviteRequest(s, accountID, strconv.FormatInt(inv.ID, 10)))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Location") != "/admin?ok=invite_revoked" {
		t.Fatalf("location = %q", rec.Header().Get("Location"))
	}
}

func TestDashboardInviteRowsLogsDecryptFailure(t *testing.T) {
	s, store, accountID := newAdminTestServer(t)
	s.secret = "not-a-valid-secret"
	if _, err := store.CreateInvite(context.Background(), "raw", "ciphertext", "user@example.test", accountID, time.Now().Add(inviteTTL)); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	rows := s.dashboardInviteRows(context.Background())

	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Link != "" {
		t.Fatalf("link should be empty when decrypt fails: %+v", rows[0])
	}
	if !strings.Contains(logs.String(), "dashboard invite decrypt failed") {
		t.Fatalf("decrypt failure was not logged: %s", logs.String())
	}
}

func newAdminTestServer(t *testing.T) (*Server, *db.Store, int64) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	account, err := store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	return &Server{store: store, renderer: renderer, secret: strings.Repeat("0", 64)}, store, account.ID
}

func dashboardInviteRequest(s *Server, accountID int64, id string) *http.Request {
	form := url.Values{"csrf": {"csrf-token"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/invites/revoke/"+id, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", id)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(accountID, 10), sessionTTL)})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
	return req
}

func TestInviteLinkSetsCookieForPendingInvite(t *testing.T) {
	s, store, adminID, _ := admFaultAdmin(t)
	if _, err := store.CreateInvite(context.Background(), "raw-token", "cipher", "new@example.test", adminID, time.Now().Add(inviteTTL)); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodGet, "/invite/raw-token", nil)
	assertDashboardRedirect(t, rec, "/login")
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == inviteCookie && c.Value == "raw-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("invite cookie not set: %v", rec.Header()["Set-Cookie"])
	}
}

func admFaultAdmin(t *testing.T) (*Server, *db.Store, int64, *faultStorage) {
	t.Helper()
	s, store, storage, adminID := newFaultServer(t)
	return s, store, adminID, storage
}

func TestDashboardCreateInviteBranches(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, s *Server, store *db.Store)
		form  url.Values
		csrf  bool
		want  string
	}{
		{name: "bad csrf", form: url.Values{"email": {"a@example.test"}}, csrf: false, want: "/admin?err=invalid_session"},
		{name: "empty email", form: url.Values{"email": {""}}, csrf: true, want: "/admin?err=invite_email_required"},
		{name: "no at sign", form: url.Values{"email": {"nobody"}}, csrf: true, want: "/admin?err=invite_email_required"},
		{
			name: "domain rejected",
			setup: func(t *testing.T, s *Server, store *db.Store) {
				if err := store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.test"); err != nil {
					t.Fatal(err)
				}
			},
			form: url.Values{"email": {"a@other.test"}}, csrf: true, want: "/admin?err=invite_domain",
		},
		{
			name: "random failure",
			setup: func(t *testing.T, s *Server, store *db.Store) {
				stubSecureRandomRead(t, func(b []byte) (int, error) {
					if len(b) == 24 { // the invite token
						return 0, errors.New("rand down")
					}
					return rand.Read(b)
				})
			},
			form: url.Values{"email": {"a@example.test"}}, csrf: true, want: "/admin?err=invite_failed",
		},
		{
			name:  "encrypt failure",
			setup: func(t *testing.T, s *Server, store *db.Store) { s.secret = "zz" },
			form:  url.Values{"email": {"a@example.test"}}, csrf: true, want: "/admin?err=invite_failed",
		},
		{
			name:  "store failure",
			setup: func(t *testing.T, s *Server, store *db.Store) { addFailTrigger(t, store, "invites", "INSERT") },
			form:  url.Values{"email": {"a@example.test"}}, csrf: true, want: "/admin?err=invite_failed",
		},
		{name: "success", form: url.Values{"email": {" New@Example.test "}}, csrf: true, want: "/admin?ok=invite_created"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, store, _, adminID := newFaultServer(t)
			if tt.setup != nil {
				tt.setup(t, s, store)
			}
			rec := dashboardPost(t, s, adminID, "/dashboard/invites", tt.form, tt.csrf)
			assertDashboardRedirect(t, rec, tt.want)
		})
	}
}

func TestDashboardAdminActionsRejectNonAdmin(t *testing.T) {
	s, store, _, _ := newFaultServer(t)
	user, err := store.CreateAccount(context.Background(), "user@example.test", "User", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/dashboard/invites",
		"/dashboard/invites/revoke/1",
		"/dashboard/users/1/admin",
		"/dashboard/users/1/disabled",
	} {
		rec := dashboardPost(t, s, user.ID, path, url.Values{}, true)
		assertDashboardRedirect(t, rec, "/login")
	}
}

func TestDashboardAdminActionsRejectBadCSRF(t *testing.T) {
	s, _, _, adminID := newFaultServer(t)
	for _, path := range []string{
		"/dashboard/invites/revoke/1",
		"/dashboard/users/1/admin",
		"/dashboard/users/1/disabled",
	} {
		rec := dashboardPost(t, s, adminID, path, url.Values{}, false)
		assertDashboardRedirect(t, rec, "/admin?err=invalid_session")
	}
}

func TestDashboardRevokeInviteBadIDAndStoreFailure(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)
	rec := dashboardPost(t, s, adminID, "/dashboard/invites/revoke/abc", url.Values{}, true)
	assertDashboardRedirect(t, rec, "/admin?err=bad_invite")

	inv, err := store.CreateInvite(context.Background(), "raw", "cipher", "u@example.test", adminID, time.Now().Add(inviteTTL))
	if err != nil {
		t.Fatal(err)
	}
	addFailTrigger(t, store, "invites", "UPDATE")
	rec = dashboardPost(t, s, adminID, "/dashboard/invites/revoke/"+strconv.FormatInt(inv.ID, 10), url.Values{}, true)
	assertDashboardRedirect(t, rec, "/admin?err=invite_revoke_failed")
}

func TestDashboardUserToggles(t *testing.T) {
	for _, field := range []string{"admin", "disabled"} {
		t.Run(field, func(t *testing.T) {
			s, store, _, adminID := newFaultServer(t)
			other, err := store.CreateAccount(context.Background(), "other@example.test", "Other", false)
			if err != nil {
				t.Fatal(err)
			}
			base := "/dashboard/users/%s/" + field

			rec := dashboardPost(t, s, adminID, fmt.Sprintf(base, "abc"), url.Values{field: {"true"}}, true)
			assertDashboardRedirect(t, rec, "/admin?err=bad_user")

			// The only admin cannot lose admin rights or be disabled.
			wantLast := "/admin?err=last_admin_remove"
			if field == "disabled" {
				wantLast = "/admin?err=last_admin_disable"
			}
			lastVal := "true"
			if field == "admin" {
				lastVal = "false"
			}
			rec = dashboardPost(t, s, adminID, fmt.Sprintf(base, strconv.FormatInt(adminID, 10)), url.Values{field: {lastVal}}, true)
			assertDashboardRedirect(t, rec, wantLast)

			otherPath := fmt.Sprintf(base, strconv.FormatInt(other.ID, 10))
			rec = dashboardPost(t, s, adminID, otherPath, url.Values{field: {"true"}}, true)
			assertDashboardRedirect(t, rec, "/admin?ok=user_updated")

			addFailTrigger(t, store, "accounts", "UPDATE")
			rec = dashboardPost(t, s, adminID, otherPath, url.Values{field: {"false"}}, true)
			assertDashboardRedirect(t, rec, "/admin?err=user_update_failed")
		})
	}
}

func TestDashboardInviteRowsStatusesAndFailure(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)
	ctx := context.Background()
	mk := func(raw, email string, expires time.Time) int64 {
		cipher, err := encryptSecret(s.secret, raw)
		if err != nil {
			t.Fatal(err)
		}
		inv, err := store.CreateInvite(ctx, raw, cipher, email, adminID, expires)
		if err != nil {
			t.Fatal(err)
		}
		return inv.ID
	}
	mk("pending-raw", "pending@example.test", time.Now().Add(time.Hour))
	usedID := mk("used-raw", "used@example.test", time.Now().Add(time.Hour))
	revokedID := mk("revoked-raw", "revoked@example.test", time.Now().Add(time.Hour))
	mk("expired-raw", "expired@example.test", time.Now().Add(-time.Hour))
	if err := store.ConsumeInvite(ctx, usedID); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeInvite(ctx, revokedID); err != nil {
		t.Fatal(err)
	}

	got := map[string]inviteDashRow{}
	for _, row := range s.dashboardInviteRows(ctx) {
		got[row.Email] = row
	}
	for email, want := range map[string]string{
		"pending@example.test": "pending",
		"used@example.test":    "used",
		"revoked@example.test": "revoked",
		"expired@example.test": "expired",
	} {
		row, ok := got[email]
		if !ok || row.Status != want {
			t.Fatalf("%s row = %+v, want status %s", email, row, want)
		}
		if (want == "pending") != (row.Link != "" && row.CanRevoke) {
			t.Fatalf("%s link/revoke = %q/%v", email, row.Link, row.CanRevoke)
		}
	}

	dropTable(t, store, "invites")
	if rows := s.dashboardInviteRows(ctx); rows != nil {
		t.Fatalf("rows after drop = %+v, want nil", rows)
	}
}

func TestDashboardAccountRowsListFailure(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)
	rows := s.dashboardAccountRows(context.Background(), adminID)
	if len(rows) != 1 || !rows[0].IsSelf {
		t.Fatalf("rows = %+v", rows)
	}
	dropTable(t, store, "accounts")
	if rows := s.dashboardAccountRows(context.Background(), adminID); rows != nil {
		t.Fatalf("rows after drop = %+v, want nil", rows)
	}
}
