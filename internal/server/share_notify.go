package server

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/privacyfence/peek/internal/mail"
	"github.com/privacyfence/peek/internal/models"
)

// shareNotifyTimeout bounds one notification send.
const shareNotifyTimeout = 15 * time.Second

// shareSubjectNameRunes caps the page name in the subject.
const shareSubjectNameRunes = 80

// notifyShare emails each grant's address that sharer gave it access to u.
// It returns sent=false with a nil error when email is off or there is no
// recipient left after skipping the sharer's own address.
// The send runs under context.WithTimeout(r.Context(), shareNotifyTimeout) and is
// audited with s.auditRequest(r, sharerName, "upload.share.notify", …).
func (s *Server) notifyShare(r *http.Request, sharerName, sharerEmail string, u *models.Upload, grants []models.UploadGrant) (sent bool, err error) {
	cfg, ok := s.smtpConfig(r.Context())
	if !ok {
		return false, nil
	}
	self := strings.ToLower(strings.TrimSpace(sharerEmail))
	domain := strings.ToLower(s.allowedEmailDomain(r.Context()))
	seen := map[string]bool{}
	var msgs []mail.Message
	skipped := 0
	for _, g := range grants {
		addr := strings.ToLower(strings.TrimSpace(g.Email))
		if addr == "" || addr == self || seen[addr] {
			continue
		}
		seen[addr] = true
		if domain != "" {
			at := strings.LastIndex(addr, "@")
			if at < 0 || addr[at+1:] != domain {
				skipped++
				continue
			}
		}
		msgs = append(msgs, s.shareMessage(sharerName, sharerEmail, u, g))
	}
	if len(msgs) == 0 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), shareNotifyTimeout)
	defer cancel()
	err = s.mailSender().Send(ctx, cfg, msgs)
	result := "sent"
	if err != nil {
		result = "failed"
		slog.Error("share notification failed", "slug", u.Slug, "err", err)
	}
	s.auditRequest(r, sharerName, "upload.share.notify", auditDetail("slug", u.Slug, "recipients", strconv.Itoa(len(msgs)), "skipped", strconv.Itoa(skipped), "result", result))
	if err != nil {
		return false, err
	}
	return true, nil
}

// shareMessage builds the email for one grant.
func (s *Server) shareMessage(sharerName, sharerEmail string, u *models.Upload, g models.UploadGrant) mail.Message {
	name := stripControl(u.Name)
	sharerName = stripControl(sharerName)
	if sharerName == "" {
		sharerName = stripControl(sharerEmail)
	}
	if sharerName == "" {
		sharerName = "Someone"
	}
	subjectName := name
	if rs := []rune(name); len(rs) > shareSubjectNameRunes {
		subjectName = string(rs[:shareSubjectNameRunes]) + "…"
	}
	sharer := sharerName
	if sharerEmail != "" {
		sharer += " (" + sharerEmail + ")"
	}
	last := "Open the link and sign in as " + g.Email + " to view it.\n"
	if g.Kind == models.UploadGrantGroup {
		last = "Open the link and sign in with an account in the group " + g.Email + " to view it.\n"
	}
	body := sharer + " shared a page with you on Peek:\n\n  " + name + "\n  " + s.baseURL + "/p/" + u.Slug + "\n\n" + last
	return mail.Message{
		To:      g.Email,
		ReplyTo: sharerEmail,
		Subject: sharerName + ` shared "` + subjectName + `" with you on Peek`,
		Body:    body,
	}
}

// stripControl replaces every rune below 0x20 and 0x7f with a space.
func stripControl(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, v)
}
