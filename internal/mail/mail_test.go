package mail

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorded struct {
	from string
	rcpt []string
	data string
}

type fakeSMTP struct {
	addr      net.Addr
	mu        sync.Mutex
	conns     int
	mails     []recorded
	authLine  string
	offerAuth bool
	silent    bool
}

func startFake(t *testing.T, offerAuth, silent bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{addr: ln.Addr(), offerAuth: offerAuth, silent: silent}
	var wg sync.WaitGroup
	var cmu sync.Mutex
	var open []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			cmu.Lock()
			open = append(open, conn)
			cmu.Unlock()
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				f.serve(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		cmu.Lock()
		for _, c := range open {
			c.Close()
		}
		cmu.Unlock()
		wg.Wait()
	})
	return f
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	if f.silent {
		buf := make([]byte, 1)
		conn.Read(buf) // blocks until the test closes the conn
		return
	}
	r := bufio.NewReader(conn)
	say := func(s string) { conn.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	var cur recorded
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			if f.offerAuth {
				say("250-fake")
				say("250 AUTH PLAIN")
			} else {
				say("250 fake")
			}
		case strings.HasPrefix(up, "AUTH"):
			f.mu.Lock()
			f.authLine = line
			f.mu.Unlock()
			say("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			cur = recorded{from: line[len("MAIL FROM:"):]}
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			cur.rcpt = append(cur.rcpt, line[len("RCPT TO:"):])
			say("250 ok")
		case up == "DATA":
			say("354 go")
			var sb strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				sb.WriteString(l)
			}
			cur.data = sb.String()
			f.mu.Lock()
			f.mails = append(f.mails, cur)
			f.mu.Unlock()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

func (f *fakeSMTP) config() Config {
	a := f.addr.(*net.TCPAddr)
	return Config{Host: "127.0.0.1", Port: a.Port, From: "peek@example.com", TLS: TLSNone}
}

func TestSendNoneDeliversAllMessagesOnOneConnection(t *testing.T) {
	f := startFake(t, false, false)
	msgs := []Message{
		{To: "a@example.com", Subject: "one", Body: "first\n"},
		{To: "b@example.com", Subject: "two", Body: "second\n"},
	}
	if err := (SMTPSender{}).Send(context.Background(), f.config(), msgs); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conns != 1 {
		t.Fatalf("connections = %d, want 1", f.conns)
	}
	if len(f.mails) != 2 {
		t.Fatalf("mails = %d, want 2", len(f.mails))
	}
	for i, want := range []string{"<a@example.com>", "<b@example.com>"} {
		if len(f.mails[i].rcpt) != 1 || f.mails[i].rcpt[0] != want {
			t.Errorf("mail %d rcpt = %v, want %s", i, f.mails[i].rcpt, want)
		}
	}
	if !strings.Contains(f.mails[0].data, "first") || !strings.Contains(f.mails[1].data, "second") {
		t.Errorf("bodies not recorded: %q / %q", f.mails[0].data, f.mails[1].data)
	}
}

func TestSendStartTLSRequiresExtension(t *testing.T) {
	f := startFake(t, false, false)
	cfg := f.config()
	cfg.TLS = TLSStartTLS
	err := (SMTPSender{}).Send(context.Background(), cfg, []Message{{To: "a@example.com", Subject: "s", Body: "b\n"}})
	if err == nil || err.Error() != "smtp server 127.0.0.1 does not offer STARTTLS" {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildMessageHeaders(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	raw, err := BuildMessage("peek@example.com", Message{
		To: "a@example.com", ReplyTo: "r@example.com", Subject: "Héllo", Body: "line é\nsecond\n",
	}, now, "<id@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	want := "From: \"Peek\" <peek@example.com>\r\n" +
		"To: a@example.com\r\n" +
		"Reply-To: r@example.com\r\n" +
		"Subject: =?utf-8?q?H=C3=A9llo?=\r\n" +
		"Date: Wed, 04 Mar 2026 05:06:07 +0000\r\n" +
		"Message-ID: <id@example.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"Auto-Submitted: auto-generated\r\n" +
		"\r\n" +
		"line =C3=A9\r\nsecond\r\n"
	if string(raw) != want {
		t.Fatalf("got:\n%q\nwant:\n%q", raw, want)
	}

	raw, err = BuildMessage("peek@example.com", Message{To: "a@example.com", Subject: "x", Body: "y\n"}, now, "<id@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Reply-To") {
		t.Error("Reply-To present without ReplyTo")
	}
}

func TestBuildMessageRejectsHeaderInjection(t *testing.T) {
	ok := Message{To: "a@example.com", ReplyTo: "r@example.com", Subject: "s", Body: "b"}
	tests := []struct {
		name string
		from string
		mut  func(*Message)
	}{
		{"LF in from", "peek@example.com\nBcc: x@example.com", func(*Message) {}},
		{"CR in to", "peek@example.com", func(m *Message) { m.To = "a@example.com\rBcc: x@example.com" }},
		{"LF in reply-to", "peek@example.com", func(m *Message) { m.ReplyTo = "r@example.com\nBcc: x" }},
		{"CRLF in subject", "peek@example.com", func(m *Message) { m.Subject = "s\r\nBcc: x@example.com" }},
		{"LF in subject", "peek@example.com", func(m *Message) { m.Subject = "s\nBcc: x@example.com" }},
		{"bad from", "not an address", func(*Message) {}},
		{"bad to", "peek@example.com", func(m *Message) { m.To = "nope" }},
		{"display name in to", "peek@example.com", func(m *Message) { m.To = "Bob <a@example.com>" }},
		{"display name in reply-to", "peek@example.com", func(m *Message) { m.ReplyTo = "Bob <r@example.com>" }},
		{"bad reply-to", "peek@example.com", func(m *Message) { m.ReplyTo = "nope" }},
		{"empty to", "peek@example.com", func(m *Message) { m.To = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := ok
			tt.mut(&m)
			if _, err := BuildMessage(tt.from, m, time.Now(), "<id@example.com>"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSendPlainAuthOverLocalhost(t *testing.T) {
	f := startFake(t, true, false)
	cfg := f.config()
	cfg.Username = "user"
	cfg.Password = "secret"
	if err := (SMTPSender{}).Send(context.Background(), cfg, []Message{{To: "a@example.com", Subject: "s", Body: "b\n"}}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fields := strings.Fields(f.authLine)
	if len(fields) != 3 || !strings.EqualFold(fields[0], "AUTH") || fields[1] != "PLAIN" {
		t.Fatalf("auth line = %q", f.authLine)
	}
	dec, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(string(dec), "\x00"); len(got) != 3 || got[1] != "user" || got[2] != "secret" {
		t.Fatalf("decoded auth = %q", dec)
	}
}

func TestSendImplicitTLSFailsAgainstPlainServer(t *testing.T) {
	f := startFake(t, false, false)
	cfg := f.config()
	cfg.TLS = TLSImplicit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := (SMTPSender{}).Send(ctx, cfg, []Message{{To: "a@example.com", Subject: "s", Body: "b\n"}}); err == nil {
		t.Fatal("expected error")
	}
}

func TestSendTimesOut(t *testing.T) {
	f := startFake(t, false, true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := (SMTPSender{}).Send(ctx, f.config(), []Message{{To: "a@example.com", Subject: "s", Body: "b\n"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestSendRejectsUnknownTLSMode(t *testing.T) {
	cfg := Config{Host: "127.0.0.1", From: "peek@example.com", TLS: "bogus"}
	if err := (SMTPSender{}).Send(context.Background(), cfg, nil); err == nil {
		t.Fatal("expected error")
	}
}
