package server

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/andras-tkcs/peek/internal/mail"
)

// emailTestTimeout bounds one test email send.
const emailTestTimeout = 15 * time.Second

// smtpConfig builds the relay config from the saved settings. It reports false
// when email is off, which is when the host or the From address is blank.
func (s *Server) smtpConfig(ctx context.Context) (mail.Config, bool) {
	cfg := mail.Config{
		Host:     s.settingString(ctx, "smtp_host"),
		Username: s.settingString(ctx, "smtp_username"),
		Password: s.settingString(ctx, "smtp_password"),
		From:     s.settingString(ctx, "smtp_from"),
		TLS:      s.settingString(ctx, "smtp_tls"),
	}
	if port := strings.TrimSpace(s.settingString(ctx, "smtp_port")); port != "" {
		cfg.Port, _ = strconv.Atoi(port)
	}
	if cfg.Host == "" || cfg.From == "" {
		return mail.Config{}, false
	}
	return cfg, true
}

func (s *Server) handleDashboardEmailTest(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	owner, ok := s.webAuth(r)
	if !ok || !owner.IsAdmin {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseAdminForm(w, r) {
		return
	}
	cfg, ok := s.smtpConfig(r.Context())
	if !ok {
		adminError(w, r, flashEmailNotConfigured)
		return
	}
	if owner.Email == "" {
		adminError(w, r, flashEmailNoAddress)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), emailTestTimeout)
	defer cancel()
	err := s.mailSender().Send(ctx, cfg, []mail.Message{{
		To:      owner.Email,
		Subject: "Peek test email",
		Body:    "This is a test email from Peek at " + s.baseURL + ".\nEmail notifications are working.\n",
	}})
	if err != nil {
		slog.Error("test email failed", "err", err)
		s.auditRequest(r, owner.Name, "email.test", auditDetail("result", "failed"))
		adminError(w, r, flashEmailTestFailed)
		return
	}
	s.auditRequest(r, owner.Name, "email.test", auditDetail("result", "sent"))
	adminOK(w, r, flashEmailTestSent)
}
