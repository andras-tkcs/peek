package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
	"github.com/andras-tkcs/peek/internal/uploadquota"
)

func TestAddCommentLogsVisitorUpsertFailure(t *testing.T) {
	s := newTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "owner@example.test", "Owner", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.Exec(`DROP TABLE visitors`); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	req := httptest.NewRequest(http.MethodPost, "/api/uploads/page/comments", strings.NewReader(`{"name":"Ada","body":"Looks good"}`))
	req.SetPathValue("slug", "page")
	rec := httptest.NewRecorder()

	s.handleAddComment(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"author":"Ada"`) {
		t.Fatalf("comment response did not include saved comment: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"anchor_kind":"page"`) {
		t.Fatalf("comment response did not infer page anchor kind: %s", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "comment visitor upsert failed") {
		t.Fatalf("visitor upsert failure was not logged: %s", logs.String())
	}
}

func TestAddCommentPersistsExplicitAnchorKind(t *testing.T) {
	s := newTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "owner@example.test", "Owner", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/uploads/page/comments", strings.NewReader(`{"name":"Ada","body":"Looks good","selector":"#hero","element_text":"Hero copy","anchor_kind":"element"}`))
	req.SetPathValue("slug", "page")
	rec := httptest.NewRecorder()

	s.handleAddComment(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"anchor_kind":"element"`) {
		t.Fatalf("comment response did not include explicit anchor kind: %s", rec.Body.String())
	}
}

func TestAddCommentRejectsInvalidAnchorKind(t *testing.T) {
	s := newTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "owner@example.test", "Owner", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/uploads/page/comments", strings.NewReader(`{"body":"Looks good","selector":"#hero","element_text":"Hero copy","anchor_kind":"sideways"}`))
	req.SetPathValue("slug", "page")
	rec := httptest.NewRecorder()

	s.handleAddComment(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestPrivateUploadCommentsRequireActiveAccount(t *testing.T) {
	s := newTestServer(t)
	owner, err := s.store.CreateAccount(context.Background(), "owner@example.test", "Owner", false)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := s.store.CreateAccount(context.Background(), "viewer@example.test", "Viewer", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUploadChecked(context.Background(), "private", owner.ID, 0, "private.html", 42, "private", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/uploads/private/comments", strings.NewReader(`{"name":"Ada","body":"Looks good"}`))
	req.SetPathValue("slug", "private")
	rec := httptest.NewRecorder()
	s.handleAddComment(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "login required") {
		t.Fatalf("anonymous private error = %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/uploads/private/comments", strings.NewReader(`{"name":"Ada","body":"Looks good"}`))
	req.SetPathValue("slug", "private")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: makeWebSession(s.secret, strconv.FormatInt(viewer.ID, 10), sessionTTL)})
	rec = httptest.NewRecorder()
	s.handleAddComment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("active viewer status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// accountCommentFixture creates an owner account with a public upload "page"
// and returns the server, the owner account and its token value.
func accountCommentFixture(t *testing.T) (*Server, *models.Account, string) {
	t.Helper()
	s := newTestServer(t)
	account, err := s.store.CreateAccount(context.Background(), "owner@example.test", "Owner", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUploadChecked(context.Background(), "page", account.ID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	return s, account, accountToken(t, s, account, "owner-token")
}

func accountToken(t *testing.T, s *Server, account *models.Account, value string) string {
	t.Helper()
	if err := s.store.CreateTokenForAccount(context.Background(), value, account.ID, "test token"); err != nil {
		t.Fatal(err)
	}
	return value
}

func postAccountComment(s *Server, slug, token, body string) *httptest.ResponseRecorder {
	return postAccountCommentAt(s, "/api/uploads/"+slug+"/account-comments", slug, token, body)
}

func postAccountCommentAt(s *Server, target, slug, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.SetPathValue("slug", slug)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.authToken(s.handleAddAccountComment)(rec, req)
	return rec
}

func TestAccountCommentRequiresToken(t *testing.T) {
	s, _, _ := accountCommentFixture(t)
	rec := postAccountComment(s, "page", "", `{"body":"hi"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountCommentRejectsNonOwner(t *testing.T) {
	s, _, _ := accountCommentFixture(t)
	other, err := s.store.CreateAccount(context.Background(), "other@example.test", "Other", false)
	if err != nil {
		t.Fatal(err)
	}
	rec := postAccountComment(s, "page", accountToken(t, s, other, "other-token"), `{"body":"hi"}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "not owner") {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountCommentAdminMayPostOnOthersUpload(t *testing.T) {
	s, _, _ := accountCommentFixture(t)
	admin, err := s.store.CreateAccount(context.Background(), "admin@example.test", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	rec := postAccountComment(s, "page", accountToken(t, s, admin, "admin-token"), `{"body":"hi"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountCommentUnknownSlug(t *testing.T) {
	s, _, token := accountCommentFixture(t)
	rec := postAccountComment(s, "missing", token, `{"body":"hi"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountCommentUsesAccountName(t *testing.T) {
	s, account, token := accountCommentFixture(t)
	rec := postAccountComment(s, "page", token, `{"name":"Mallory","body":"Looks good","selector":"#hero","element_text":"Hero copy","anchor_kind":"element"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "[") {
		t.Fatalf("response must be a single object: %s", rec.Body.String())
	}
	var out commentOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Author != "Owner" || out.Body != "Looks good" || out.Selector != "#hero" || out.Text != "Hero copy" || out.AnchorKind != "element" {
		t.Fatalf("unexpected comment: %+v", out)
	}
	if out.ID == 0 || out.CreatedAt == 0 {
		t.Fatalf("missing id or created_at: %+v", out)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("unexpected cookies: %v", cookies)
	}
	u, err := s.store.GetUpload(context.Background(), "page")
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.store.ListComments(context.Background(), u.ID, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %+v", err, list)
	}
	want := s.commentVisitorHash("account:" + strconv.FormatInt(account.ID, 10))
	if list[0].AuthorCookie != want || len(want) != 16 {
		t.Fatalf("author cookie = %q, want %q", list[0].AuthorCookie, want)
	}
}

func TestAccountCommentLandsOnRequestedOrLatestVersion(t *testing.T) {
	s, _, token := accountCommentFixture(t)
	ctx := context.Background()
	u, err := s.store.GetUpload(ctx, "page")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.CreateVersionChecked(ctx, u.ID, "page-v2.html", 10, u.OwnerAccountID, uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	base := "/api/uploads/page/account-comments"
	if rec := postAccountCommentAt(s, base, "page", token, `{"body":"latest"}`); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := postAccountCommentAt(s, base+"?v=1", "page", token, `{"body":"first"}`); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := postAccountCommentAt(s, base+"?v=9", "page", token, `{"body":"nope"}`); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "version not found") {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	for version, body := range map[int]string{2: "latest", 1: "first"} {
		list, err := s.store.ListComments(ctx, u.ID, version)
		if err != nil || len(list) != 1 || list[0].Body != body || list[0].Version != version {
			t.Fatalf("version %d comments: %v %+v", version, err, list)
		}
	}
}

func TestAccountCommentValidation(t *testing.T) {
	s, _, token := accountCommentFixture(t)
	tests := []struct {
		name string
		body string
		want int
	}{
		{"empty body", `{"body":""}`, http.StatusBadRequest},
		{"whitespace body", `{"body":"   "}`, http.StatusBadRequest},
		{"body too long", `{"body":"` + strings.Repeat("a", 4001) + `"}`, http.StatusRequestEntityTooLarge},
		{"selector too long", `{"body":"x","selector":"` + strings.Repeat("a", 501) + `"}`, http.StatusRequestEntityTooLarge},
		{"element_text too long", `{"body":"x","selector":"#a","element_text":"` + strings.Repeat("a", 201) + `"}`, http.StatusRequestEntityTooLarge},
		{"invalid anchor kind", `{"body":"x","anchor_kind":"sideways"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postAccountComment(s, "page", token, tt.body)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestAccountCommentAppearsInList(t *testing.T) {
	s, _, token := accountCommentFixture(t)
	if rec := postAccountComment(s, "page", token, `{"body":"Looks good"}`); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/api/uploads/page/comments", nil)
	req.SetPathValue("slug", "page")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.handleListComments(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var list []commentOut
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Author != "Owner" || list[0].Body != "Looks good" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func commentPageFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s, _ := newHandlerTestServer(t)
	owner := newViewer(t, s, "page-owner@example.test", "Page Owner", false)
	if err := s.store.CreateUploadChecked(context.Background(), "page", owner.ID, 0, "page.html", 42, "public", "", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	return s, "/api/uploads/page/comments"
}

func TestAddCommentSignedInViewerUsesAccountName(t *testing.T) {
	s, target := commentPageFixture(t)
	viewer := newViewer(t, s, "ada@example.com", "Ada Lovelace", false)
	rec := doRequest(t, s, http.MethodPost, target, strings.NewReader(`{"name":"Alice (owner)","body":"hi"}`), asSession(s, viewer.ID), withJSON())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"author":"Ada Lovelace"`) || !strings.Contains(body, `"verified":true`) || strings.Contains(body, "Alice (owner)") {
		t.Fatalf("body = %s", body)
	}
	u, _ := s.store.GetUpload(context.Background(), "page")
	list, err := s.store.ListComments(context.Background(), u.ID, 0)
	if err != nil || len(list) != 1 || list[0].AccountID != viewer.ID {
		t.Fatalf("list = %+v err = %v", list, err)
	}
}

func TestAddCommentAnonymousViewerIsUnverified(t *testing.T) {
	s, target := commentPageFixture(t)
	rec := doRequest(t, s, http.MethodPost, target, strings.NewReader(`{"name":"Alice (owner)","body":"hi"}`), withJSON())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"author":"Alice (owner)"`) || !strings.Contains(body, `"verified":false`) {
		t.Fatalf("body = %s", body)
	}
}

func TestAddCommentDisabledSessionIsUnverified(t *testing.T) {
	s, target := commentPageFixture(t)
	viewer := newViewer(t, s, "ada@example.com", "Ada Lovelace", false)
	if err := s.store.SetAccountDisabled(context.Background(), viewer.ID, true); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, s, http.MethodPost, target, strings.NewReader(`{"name":"Typed Name","body":"hi"}`), asSession(s, viewer.ID), withJSON())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"author":"Typed Name"`) || !strings.Contains(body, `"verified":false`) {
		t.Fatalf("body = %s", body)
	}
}

func TestAddCommentSignedInBlankNameUsesEmail(t *testing.T) {
	s, target := commentPageFixture(t)
	viewer := newViewer(t, s, "noname@example.com", "", false)
	rec := doRequest(t, s, http.MethodPost, target, strings.NewReader(`{"name":"Typed","body":"hi"}`), asSession(s, viewer.ID), withJSON())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"author":"noname@example.com"`) || !strings.Contains(body, `"verified":true`) {
		t.Fatalf("body = %s", body)
	}
}

func TestAccountCommentIsVerified(t *testing.T) {
	s, _, token := accountCommentFixture(t)
	rec := postAccountComment(s, "page", token, `{"body":"hi"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"verified":true`) {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/api/uploads/page/comments", nil)
	req.SetPathValue("slug", "page")
	list := httptest.NewRecorder()
	s.handleListComments(list, req)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"verified":true`) {
		t.Fatalf("list status = %d, body = %s", list.Code, list.Body.String())
	}
}
