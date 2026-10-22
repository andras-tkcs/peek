// Command contact-form is an example Peek page backend: it receives contact
// form submissions relayed by peek.fetch, emails them and keeps a copy.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const maxMessageBytes = 5000

type submission struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

type server struct {
	token   string
	dataDir string
	send    func(s submission) error

	mu sync.Mutex
}

func main() {
	srv := &server{
		token:   os.Getenv("PEEK_BACKEND_TOKEN"),
		dataDir: envOr("DATA_DIR", "/data"),
		send:    sendMail,
	}
	addr := ":" + envOr("PORT", "8080")
	log.Printf("contact-form listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, srv.routes()))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /api/contact", s.handleContact)
	mux.HandleFunc("GET /api/submissions", s.handleSubmissions)
	return s.requireToken(mux)
}

// requireToken rejects requests that did not come through Peek: every Peek
// relay request carries the per-container token.
func (s *server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Peek-Backend-Token")
		if s.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleContact(w http.ResponseWriter, r *http.Request) {
	var in submission
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Email = strings.TrimSpace(in.Email)
	in.Message = strings.TrimSpace(in.Message)
	switch {
	case in.Name == "" || in.Email == "" || in.Message == "":
		writeError(w, http.StatusBadRequest, "name, email and message are required")
		return
	case len(in.Message) > maxMessageBytes:
		writeError(w, http.StatusBadRequest, "message is too long (max 5000 bytes)")
		return
	case strings.ContainsAny(in.Name, "\r\n") || strings.ContainsAny(in.Email, "\r\n"):
		writeError(w, http.StatusBadRequest, "name and email must be single lines")
		return
	}
	if _, err := mail.ParseAddress(in.Email); err != nil {
		writeError(w, http.StatusBadRequest, "email is not a valid address")
		return
	}
	if err := s.send(in); err != nil {
		log.Printf("send mail: %v", err)
		writeError(w, http.StatusBadGateway, "could not send the message")
		return
	}
	if err := s.store(in); err != nil {
		// The email went out; losing the local copy must not fail the request.
		log.Printf("store submission: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *server) store(in submission) error {
	line, err := json.Marshal(in)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.submissionsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (s *server) submissionsPath() string {
	return filepath.Join(s.dataDir, "submissions.jsonl")
}

// handleSubmissions lists stored submissions for signed-in viewers only:
// Peek sets X-Peek-User-Email only on signed-in and restricted pages.
func (s *server) handleSubmissions(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Peek-User-Email") == "" {
		writeError(w, http.StatusForbidden, "sign in to view submissions")
		return
	}
	s.mu.Lock()
	data, err := os.ReadFile(s.submissionsPath())
	s.mu.Unlock()
	if err != nil && !os.IsNotExist(err) {
		log.Printf("read submissions: %v", err)
		writeError(w, http.StatusInternalServerError, "could not read submissions")
		return
	}
	out := []json.RawMessage{}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, json.RawMessage(line))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func sendMail(in submission) error {
	host, port := os.Getenv("SMTP_HOST"), envOr("SMTP_PORT", "25")
	to, from := os.Getenv("MAIL_TO"), os.Getenv("MAIL_FROM")
	if host == "" || to == "" || from == "" {
		return fmt.Errorf("SMTP_HOST, MAIL_TO and MAIL_FROM must be set")
	}
	var auth smtp.Auth
	if user := os.Getenv("SMTP_USERNAME"); user != "" {
		auth = smtp.PlainAuth("", user, os.Getenv("SMTP_PASSWORD"), host)
	}
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Reply-To: " + in.Email + "\r\n" +
		"Subject: Contact form: " + in.Name + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		in.Message + "\r\n\r\nFrom: " + in.Name + " <" + in.Email + ">\r\n"
	return smtp.SendMail(host+":"+port, auth, from, []string{to}, []byte(msg))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
