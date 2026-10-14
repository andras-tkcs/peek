package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	webui "github.com/andras-tkcs/peek/internal/web"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	if s.setupRequired(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if r.Method == "GET" {
		s.renderLoginForm(w, http.StatusOK, "", r)
		return
	}
	// POST
	if err := r.ParseForm(); err != nil {
		s.renderLoginForm(w, http.StatusOK, "Invalid session.", r)
		return
	}
	validCSRF, csrfErr := s.validateCSRF(r, w, r.FormValue("csrf"))
	if csrfErr != nil {
		s.renderCSRFError(w, csrfErr)
		return
	}
	if !validCSRF {
		s.renderLoginForm(w, http.StatusOK, "Invalid session.", r)
		return
	}

	var (
		accountID int64
		actorName string
		err       error
	)
	switch r.FormValue("method") {
	case "password":
		accountID, actorName, err = s.loginWithPassword(r)
	case "token":
		accountID, actorName, err = s.loginWithToken(r)
	default:
		err = fmt.Errorf("unsupported login method")
	}
	if errors.Is(err, errLoginThrottled) {
		rateLimitError(w, r)
		return
	}
	if err != nil {
		s.renderLoginForm(w, http.StatusOK, "Invalid credentials.", r)
		return
	}
	s.setWebSession(w, accountID)
	s.auditRequest(r, actorName, "login.success", "")
	http.Redirect(w, r, s.consumeNextPath(w, r), http.StatusSeeOther)
}

// passwordCompare is bcrypt.CompareHashAndPassword; tests swap it to count calls.
var passwordCompare = bcrypt.CompareHashAndPassword

// dummyPasswordHash is a bcrypt hash of a constant at bcrypt.DefaultCost, made
// once on first use. Failed logins compare against it so they take as long as a
// real comparison.
var dummyPasswordHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("peek-dummy-password-for-timing"), bcrypt.DefaultCost)
	if err != nil {
		panic("generate dummy password hash: " + err.Error())
	}
	return h
})

// checkPassword runs exactly one bcrypt comparison: against hash when it is
// set, otherwise against dummyPasswordHash (and then always fails).
func checkPassword(hash, password string) bool {
	if hash == "" {
		_ = passwordCompare(dummyPasswordHash(), []byte(password))
		return false
	}
	return passwordCompare([]byte(hash), []byte(password)) == nil
}

var errLoginThrottled = errors.New("too many failed sign-in attempts")

func loginFailureKey(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// loginWithPassword counts failures per email address, whether or not the
// account exists, so the limiter does not reveal which accounts are real.
func (s *Server) loginWithPassword(r *http.Request) (int64, string, error) {
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	if email == "" || password == "" {
		return 0, "", fmt.Errorf("missing credentials")
	}
	key := loginFailureKey(email)
	if s.accountLoginLimiter.blocked(key) {
		return 0, "", errLoginThrottled
	}
	id, name, err := s.checkPasswordLogin(r.Context(), email, password)
	if err != nil {
		s.accountLoginLimiter.recordFailure(key)
	}
	return id, name, err
}

func (s *Server) checkPasswordLogin(ctx context.Context, email, password string) (int64, string, error) {
	owner, err := s.store.GetAccountByEmail(ctx, email)
	hash := ""
	if err == nil {
		hash = owner.PasswordHash
	}
	// Exactly one bcrypt comparison on every path, so response time does not
	// reveal which accounts exist. Policy errors are only reachable with the
	// correct password.
	if !checkPassword(hash, password) {
		return 0, "", fmt.Errorf("invalid credentials")
	}
	if owner.Disabled {
		return 0, "", fmt.Errorf("account disabled")
	}
	if !s.accountAllowedByEmailDomain(ctx, owner.Email) {
		return 0, "", errAccountNotEligible
	}
	if s.oauthLoginRequired(ctx) && !owner.IsAdmin {
		return 0, "", fmt.Errorf("oauth required")
	}
	return owner.ID, owner.Name, nil
}

func (s *Server) loginWithToken(r *http.Request) (int64, string, error) {
	tok := strings.TrimSpace(r.FormValue("token"))
	if tok == "" {
		return 0, "", fmt.Errorf("missing token")
	}
	owner, err := s.store.GetToken(r.Context(), tok)
	if err != nil {
		return 0, "", err
	}
	if owner.Disabled {
		return 0, "", fmt.Errorf("account disabled")
	}
	if !s.accountAllowedByEmailDomain(r.Context(), owner.Email) {
		return 0, "", errAccountNotEligible
	}
	if (!s.tokenLoginEnabled(r.Context()) || s.oauthLoginRequired(r.Context())) && !owner.IsAdmin {
		return 0, "", fmt.Errorf("token login disabled")
	}
	return owner.AccountID, owner.Name, nil
}

func (s *Server) oauthLoginRequired(ctx context.Context) bool {
	return len(s.enabledOAuthProviders(ctx)) > 0
}

func (s *Server) tokenLoginEnabled(ctx context.Context) bool {
	return s.settingBool(ctx, "auth_token_login_enabled")
}

func (s *Server) loginData(csrf, errMsg string, r *http.Request) loginData {
	_, inviteErr := r.Cookie(inviteCookie)
	providers := s.enabledOAuthProviders(r.Context())
	oauthEnabled := len(providers) > 0
	return loginData{
		CSRF:          csrf,
		Error:         errMsg,
		Invite:        inviteErr == nil,
		Providers:     providers,
		PasswordLogin: true,
		TokenLogin:    s.tokenLoginEnabled(r.Context()) && !oauthEnabled,
		OAuthEnabled:  oauthEnabled,
	}
}

func (s *Server) renderLoginForm(w http.ResponseWriter, status int, errMsg string, r *http.Request) {
	csrf, ok := s.csrfToken(w)
	if !ok {
		return
	}
	s.renderHTML(w, status, webui.TemplateLogin, s.loginData(csrf, errMsg, r))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderWebError(w, http.StatusBadRequest, "Invalid session", "Your logout request could not be verified.")
		return
	}
	validCSRF, err := s.validateCSRF(r, w, r.FormValue("csrf"))
	if err != nil {
		s.renderCSRFError(w, err)
		return
	}
	if !validCSRF {
		s.renderWebError(w, http.StatusBadRequest, "Invalid session", "Your logout request could not be verified.")
		return
	}
	s.setCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
