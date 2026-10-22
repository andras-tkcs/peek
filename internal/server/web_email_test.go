package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/andras-tkcs/peek/internal/mail"
)

// fakeMailer records what it is asked to send and returns err.
type fakeMailer struct {
	mu   sync.Mutex
	cfgs []mail.Config
	msgs [][]mail.Message
	err  error
}

func (f *fakeMailer) Send(_ context.Context, cfg mail.Config, msgs []mail.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfgs = append(f.cfgs, cfg)
	f.msgs = append(f.msgs, msgs)
	return f.err
}

func (f *fakeMailer) sends() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

// postEmailTest posts the Send test email form as the account.
func postEmailTest(t *testing.T, s *Server, accountID int64) *http.Response {
	t.Helper()
	form := url.Values{"csrf": {"csrf-token"}}
	rec := doRequest(t, s, http.MethodPost, "/dashboard/email/test", strings.NewReader(form.Encode()),
		asSession(s, accountID),
		func(r *http.Request) {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "csrf-token"})
		})
	return rec.Result()
}

func configureSMTP(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	for k, v := range map[string]string{"smtp_host": "smtp.example.test", "smtp_port": "2525", "smtp_from": "peek@example.test", "smtp_username": "user"} {
		if err := s.store.SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.encryptedSetSetting(ctx, "smtp_password", "pw"); err != nil {
		t.Fatal(err)
	}
}

func TestEmailTestSendsToAdmin(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	fake := &fakeMailer{}
	s.mailer = fake
	configureSMTP(t, s)
	admin := newAccountWithToken(t, s, "admin@example.test", "admin-token", true)

	resp := postEmailTest(t, s, admin.ID)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin?ok="+flashEmailTestSent {
		t.Fatalf("response = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if fake.sends() != 1 || len(fake.msgs[0]) != 1 {
		t.Fatalf("sends = %v", fake.msgs)
	}
	msg := fake.msgs[0][0]
	if msg.To != "admin@example.test" || msg.Subject != "Peek test email" || !strings.Contains(msg.Body, "Email notifications are working.") {
		t.Fatalf("message = %+v", msg)
	}
	cfg := fake.cfgs[0]
	if cfg.Host != "smtp.example.test" || cfg.Port != 2525 || cfg.From != "peek@example.test" || cfg.Username != "user" || cfg.Password != "pw" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestEmailTestNotConfigured(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	fake := &fakeMailer{}
	s.mailer = fake
	admin := newAccountWithToken(t, s, "admin@example.test", "admin-token", true)

	resp := postEmailTest(t, s, admin.ID)
	if resp.Header.Get("Location") != "/admin?err="+flashEmailNotConfigured {
		t.Fatalf("Location = %q", resp.Header.Get("Location"))
	}
	if fake.sends() != 0 {
		t.Fatal("nothing should be sent")
	}
}

func TestEmailTestSendFailure(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	fake := &fakeMailer{err: errors.New("relay down")}
	s.mailer = fake
	configureSMTP(t, s)
	admin := newAccountWithToken(t, s, "admin@example.test", "admin-token", true)

	resp := postEmailTest(t, s, admin.ID)
	if resp.Header.Get("Location") != "/admin?err="+flashEmailTestFailed {
		t.Fatalf("Location = %q", resp.Header.Get("Location"))
	}
	if fake.sends() != 1 {
		t.Fatalf("sends = %d", fake.sends())
	}
}

func TestEmailTestRequiresAdmin(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	fake := &fakeMailer{}
	s.mailer = fake
	configureSMTP(t, s)
	user := newAccountWithToken(t, s, "user@example.test", "user-token", false)

	resp := postEmailTest(t, s, user.ID)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("response = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if fake.sends() != 0 {
		t.Fatal("nothing should be sent")
	}
}
