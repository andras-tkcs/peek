package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
)

func postVersionComment(t *testing.T, s *Server, path, body string) *http.Response {
	t.Helper()
	rec := doRequest(t, s, http.MethodPost, path, strings.NewReader(`{"body":"`+body+`","name":"tester"}`), withJSON())
	return rec.Result()
}

func listVersionComments(t *testing.T, s *Server, path string) []commentOut {
	t.Helper()
	rec := doRequest(t, s, http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	var out []commentOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func TestCommentsArePerVersion(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "cmtpage", models.UploadVisibilityPublic, "")
	base := "/api/uploads/cmtpage/comments"

	if got := postVersionComment(t, s, base+"?v=1", "on-one").StatusCode; got != http.StatusOK {
		t.Fatalf("post v1 = %d", got)
	}
	if got := postVersionComment(t, s, base+"?v=2", "on-two").StatusCode; got != http.StatusOK {
		t.Fatalf("post v2 = %d", got)
	}

	v1 := listVersionComments(t, s, base+"?v=1")
	if len(v1) != 1 || v1[0].Body != "on-one" || v1[0].Version != 1 {
		t.Fatalf("v1 comments = %+v", v1)
	}
	v2 := listVersionComments(t, s, base+"?v=2")
	if len(v2) != 1 || v2[0].Body != "on-two" || v2[0].Version != 2 {
		t.Fatalf("v2 comments = %+v", v2)
	}
	latest := listVersionComments(t, s, base)
	if len(latest) != 1 || latest[0].Body != "on-two" {
		t.Fatalf("latest comments = %+v", latest)
	}
}

func TestCommentsUnknownVersion404(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "cmt404", models.UploadVisibilityPublic, "")
	base := "/api/uploads/cmt404/comments"
	for _, v := range []string{"3", "0", "-1", "abc"} {
		rec := doRequest(t, s, http.MethodGet, base+"?v="+v, nil)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "version not found") {
			t.Fatalf("GET v=%s = %d %s", v, rec.Code, rec.Body.String())
		}
		if got := postVersionComment(t, s, base+"?v="+v, "x").StatusCode; got != http.StatusNotFound {
			t.Fatalf("POST v=%s = %d", v, got)
		}
	}
}

func TestListVersionsAPI(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	u := newTwoVersionPage(t, s, "verlist", models.UploadVisibilityPublic, "")
	ctx := context.Background()
	if err := s.store.CreateTokenForAccount(ctx, "ver-owner-token", u.OwnerAccountID, "owner"); err != nil {
		t.Fatalf("owner token: %v", err)
	}
	newAccountWithToken(t, s, "other@example.test", "ver-other-token", false)

	rec := doRequest(t, s, http.MethodGet, "/api/uploads/verlist/versions", nil, asBearer("ver-owner-token"))
	if rec.Code != http.StatusOK {
		t.Fatalf("owner = %d: %s", rec.Code, rec.Body.String())
	}
	var list []struct {
		Version int    `json:"version"`
		Size    int64  `json:"size"`
		URL     string `json:"url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 2 || list[0].Version != 1 || list[1].Version != 2 {
		t.Fatalf("list = %+v", list)
	}
	if list[1].URL != "http://localhost:7700/p/verlist/v/2" {
		t.Fatalf("url = %q", list[1].URL)
	}

	rec = doRequest(t, s, http.MethodGet, "/api/uploads/verlist/versions", nil, asBearer("ver-other-token"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-owner = %d", rec.Code)
	}
}

func TestExportIncludesVersions(t *testing.T) {
	s, adminToken := newHandlerTestServer(t)
	newTwoVersionPage(t, s, "verexp", models.UploadVisibilityPublic, "")
	if got := postVersionComment(t, s, "/api/uploads/verexp/comments?v=1", "old").StatusCode; got != http.StatusOK {
		t.Fatalf("post = %d", got)
	}

	rec := doRequest(t, s, http.MethodGet, "/api/uploads/verexp/export", nil, asBearer(adminToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body.String())
	}
	var exp struct {
		LatestVersion int `json:"latest_version"`
		Versions      []struct {
			Version int `json:"version"`
		} `json:"versions"`
		Comments []struct {
			Body    string `json:"body"`
			Version int    `json:"version"`
		} `json:"comments"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if exp.LatestVersion != 2 || len(exp.Versions) != 2 {
		t.Fatalf("export = %+v", exp)
	}
	if len(exp.Comments) != 1 || exp.Comments[0].Version != 1 {
		t.Fatalf("comments = %+v", exp.Comments)
	}
}
