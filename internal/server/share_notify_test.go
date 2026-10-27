package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/privacyfence/peek/internal/models"
)

func shareFixture(t *testing.T) (*Server, *fakeMailer) {
	t.Helper()
	s, _ := newHandlerTestServer(t)
	fake := &fakeMailer{}
	s.mailer = fake
	configureSMTP(t, s)
	return s, fake
}

func TestShareMessageUserGrant(t *testing.T) {
	s, _ := shareFixture(t)
	u := &models.Upload{Slug: "abc", Name: "Q3 plan"}
	m := s.shareMessage("Ann", "ann@example.com", u, models.UploadGrant{Kind: models.UploadGrantUser, Email: "bob@example.com"})
	wantBody := "Ann (ann@example.com) shared a page with you on Peek:\n\n  Q3 plan\n  " + s.baseURL + "/p/abc\n\nOpen the link and sign in as bob@example.com to view it.\n"
	if m.Subject != `Ann shared "Q3 plan" with you on Peek` || m.Body != wantBody || m.To != "bob@example.com" || m.ReplyTo != "ann@example.com" {
		t.Fatalf("message = %+v", m)
	}
}

func TestShareMessageGroupGrant(t *testing.T) {
	s, _ := shareFixture(t)
	u := &models.Upload{Slug: "abc", Name: "Q3 plan"}
	m := s.shareMessage("Ann", "ann@example.com", u, models.UploadGrant{Kind: models.UploadGrantGroup, Email: "team@example.com"})
	if !strings.HasSuffix(m.Body, "\n\nOpen the link and sign in with an account in the group team@example.com to view it.\n") || m.ReplyTo != "ann@example.com" {
		t.Fatalf("message = %+v", m)
	}
}

func TestShareMessageSanitizesName(t *testing.T) {
	s, _ := shareFixture(t)
	name := "a\nb\rc" + strings.Repeat("x", 200)
	m := s.shareMessage("An\nn", "ann@example.com", &models.Upload{Slug: "abc", Name: name}, models.UploadGrant{Kind: models.UploadGrantUser, Email: "b@example.com"})
	if strings.ContainsAny(m.Subject, "\r\n") {
		t.Fatalf("subject has control characters: %q", m.Subject)
	}
	prefix := `An n shared "`
	inner := strings.TrimSuffix(strings.TrimPrefix(m.Subject, prefix), `" with you on Peek`)
	if !strings.HasSuffix(inner, "…") || utf8.RuneCountInString(inner) != 81 || !strings.HasPrefix(inner, "a b cxx") {
		t.Fatalf("subject name = %q", inner)
	}
}

func TestShareMessageEmptySharerName(t *testing.T) {
	s, _ := shareFixture(t)
	u := &models.Upload{Slug: "abc", Name: "P"}
	g := models.UploadGrant{Kind: models.UploadGrantUser, Email: "b@example.com"}
	if m := s.shareMessage("", "ann@example.com", u, g); !strings.HasPrefix(m.Subject, `ann@example.com shared "P"`) {
		t.Fatalf("subject = %q", m.Subject)
	}
	if m := s.shareMessage("", "", u, g); !strings.HasPrefix(m.Subject, `Someone shared "P"`) {
		t.Fatalf("subject = %q", m.Subject)
	}
}

func TestNotifyShareSkipsSharerAndWhenOff(t *testing.T) {
	s, fake := shareFixture(t)
	u := &models.Upload{Slug: "abc", Name: "P"}
	r := httptest.NewRequest("POST", "/", nil)
	grants := []models.UploadGrant{
		{Kind: models.UploadGrantUser, Email: "ann@example.com"},
		{Kind: models.UploadGrantUser, Email: "b@example.com"},
		{Kind: models.UploadGrantGroup, Email: "b@example.com"},
	}
	sent, err := s.notifyShare(r, "Ann", "Ann@Example.com", u, grants)
	if err != nil || !sent || fake.sends() != 1 || len(fake.msgs[0]) != 1 || fake.msgs[0][0].To != "b@example.com" {
		t.Fatalf("sent=%v err=%v msgs=%+v", sent, err, fake.msgs)
	}
	if sent, err = s.notifyShare(r, "Ann", "ann@example.com", u, grants[:1]); sent || err != nil || fake.sends() != 1 {
		t.Fatalf("only sharer: sent=%v err=%v", sent, err)
	}
	if err := s.store.SetSetting(context.Background(), "smtp_host", ""); err != nil {
		t.Fatal(err)
	}
	if sent, err = s.notifyShare(r, "Ann", "ann@example.com", u, grants); sent || err != nil || fake.sends() != 1 {
		t.Fatalf("email off: sent=%v err=%v", sent, err)
	}
}

func TestNotifyShareSkipsOutsideAllowedDomain(t *testing.T) {
	s, fake := shareFixture(t)
	if err := s.store.SetSetting(context.Background(), authAllowedEmailDomainSetting, "example.com"); err != nil {
		t.Fatal(err)
	}
	u := &models.Upload{Slug: "abc", Name: "P"}
	r := httptest.NewRequest("POST", "/", nil)
	grants := []models.UploadGrant{
		{Kind: models.UploadGrantUser, Email: "a@example.com"},
		{Kind: models.UploadGrantUser, Email: "b@other.org"},
	}
	if sent, err := s.notifyShare(r, "Ann", "", u, grants); err != nil || !sent {
		t.Fatalf("sent=%v err=%v", sent, err)
	}
	if len(fake.msgs[0]) != 1 || fake.msgs[0][0].To != "a@example.com" {
		t.Fatalf("msgs = %+v", fake.msgs)
	}
	entries, err := s.store.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "upload.share.notify" && strings.Contains(e.Detail, "skipped=1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no notify audit with skipped=1: %+v", entries)
	}
}
