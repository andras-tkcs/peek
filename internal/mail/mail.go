// Package mail sends Peek's plain-text notification emails through an SMTP relay.
package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// TLS modes for Config.TLS.
const (
	TLSStartTLS = "starttls" // plain connect, then STARTTLS; required, never downgraded
	TLSImplicit = "tls"      // TLS from the first byte (port 465)
	TLSNone     = "none"     // no TLS; for a local relay only
)

const defaultTimeout = 30 * time.Second

// Config is one SMTP relay. Port 0 means 587 for starttls and none, 465 for tls.
type Config struct {
	Host     string
	Port     int
	Username string // empty: no AUTH
	Password string
	From     string // bare address
	TLS      string // one of the TLS* constants; empty means TLSStartTLS
}

// Message is one plain-text email to one recipient.
type Message struct {
	To      string // bare address
	ReplyTo string // optional bare address
	Subject string
	Body    string // plain text, "\n" line endings
}

// Sender delivers messages through an SMTP relay.
type Sender interface {
	Send(ctx context.Context, cfg Config, msgs []Message) error
}

// SMTPSender is the net/smtp Sender. Dial is nil in production (net.Dialer).
type SMTPSender struct {
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Send delivers msgs over a single SMTP connection.
func (d SMTPSender) Send(ctx context.Context, cfg Config, msgs []Message) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	mode := cfg.TLS
	if mode == "" {
		mode = TLSStartTLS
	}
	switch mode {
	case TLSStartTLS, TLSImplicit, TLSNone:
	default:
		return fmt.Errorf("unknown smtp tls mode %q", cfg.TLS)
	}
	port := cfg.Port
	if port == 0 {
		port = 587
		if mode == TLSImplicit {
			port = 465
		}
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))

	dial := d.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp connect %s: %w", addr, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("smtp connect %s: %w", addr, err)
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	var c *smtp.Client
	if mode == TLSImplicit {
		c, err = smtp.NewClient(tls.Client(conn, tlsConfig), cfg.Host)
	} else {
		c, err = smtp.NewClient(conn, cfg.Host)
	}
	if err != nil {
		return fmt.Errorf("smtp greeting from %s: %w", addr, err)
	}
	defer c.Close()

	if mode == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp server %s does not offer STARTTLS", cfg.Host)
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("smtp starttls %s: %w", cfg.Host, err)
		}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}

	domain := addressDomain(cfg.From)
	for _, msg := range msgs {
		if err := sendOne(c, cfg.From, msg, domain); err != nil {
			return fmt.Errorf("smtp send to %s: %w", msg.To, err)
		}
	}
	if err := c.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}
	return nil
}

func sendOne(c *smtp.Client, from string, msg Message, domain string) error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	raw, err := BuildMessage(from, msg, time.Now(), "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	if err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(msg.To); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func addressDomain(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return addr[i+1:]
	}
	return "localhost"
}

// BuildMessage renders the RFC 5322 bytes of msg sent from from. It rejects CR or
// LF in any header value and any address net/mail cannot parse as a bare address.
func BuildMessage(from string, msg Message, now time.Time, messageID string) ([]byte, error) {
	for name, v := range map[string]string{"from": from, "to": msg.To, "reply-to": msg.ReplyTo, "subject": msg.Subject, "message-id": messageID} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%s header contains a line break", name)
		}
	}
	if err := checkAddress("from", from); err != nil {
		return nil, err
	}
	if err := checkAddress("to", msg.To); err != nil {
		return nil, err
	}
	if msg.ReplyTo != "" {
		if err := checkAddress("reply-to", msg.ReplyTo); err != nil {
			return nil, err
		}
	}

	var b strings.Builder
	header := func(name, value string) { b.WriteString(name + ": " + value + "\r\n") }
	header("From", `"Peek" <`+from+`>`)
	header("To", msg.To)
	if msg.ReplyTo != "" {
		header("Reply-To", msg.ReplyTo)
	}
	header("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", messageID)
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(msg.Body)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func checkAddress(field, addr string) error {
	parsed, err := netmail.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("%s address %q: %w", field, addr, err)
	}
	if parsed.Address != addr {
		return fmt.Errorf("%s address %q: %w", field, addr, errNotBare)
	}
	return nil
}

var errNotBare = errors.New("not a bare email address")
