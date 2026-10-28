package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/privacyfence/peek/internal/models"
	webui "github.com/privacyfence/peek/internal/web"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	if s.setupRequired(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if r.Method == "GET" {
		if _, ok := s.webAuth(r); ok {
			http.Redirect(w, r, s.consumeNextPath(w, r), http.StatusSeeOther)
			return
		}
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
		account *models.Account
		err     error
	)
	switch r.FormValue("method") {
	case "password":
		account, err = s.loginWithPassword(r)
	case "token":
		account, err = s.loginWithToken(r)
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
	s.setWebSession(w, account)
	s.auditRequest(r, account.Name, "login.success", "")
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

// RFC 5321 path limit; longer input cannot be an account email.
const maxLoginEmailLen = 254

func loginFailureKey(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// loginWithPassword counts failures per email address, whether or not the
// account exists, so the limiter does not reveal which accounts are real.
func (s *Server) loginWithPassword(r *http.Request) (*models.Account, error) {
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	if email == "" || password == "" {
		return nil, fmt.Errorf("missing credentials")
	}
	if len(email) > maxLoginEmailLen {
		checkPassword("", password) // one bcrypt compare, like every other failure
		return nil, fmt.Errorf("invalid credentials")
	}
	key := loginFailureKey(email)
	if s.accountLoginLimiter.blocked(key) {
		return nil, errLoginThrottled
	}
	account, err := s.checkPasswordLogin(r.Context(), email, password)
	if err != nil {
		s.accountLoginLimiter.recordFailure(key)
	}
	return account, err
}

func (s *Server) checkPasswordLogin(ctx context.Context, email, password string) (*models.Account, error) {
	owner, err := s.store.GetAccountByEmail(ctx, email)
	hash := ""
	if err == nil {
		hash = owner.PasswordHash
	}
	// Exactly one bcrypt comparison on every path, so response time does not
	// reveal which accounts exist. Policy errors are only reachable with the
	// correct password.
	if !checkPassword(hash, password) {
		return nil, fmt.Errorf("invalid credentials")
	}
	if owner.Disabled {
		return nil, fmt.Errorf("account disabled")
	}
	if !s.accountAllowedByEmailDomain(ctx, owner.Email) {
		return nil, errAccountNotEligible
	}
	if s.oauthLoginRequired(ctx) && !owner.IsAdmin {
		return nil, fmt.Errorf("oauth required")
	}
	return owner, nil
}

func (s *Server) loginWithToken(r *http.Request) (*models.Account, error) {
	tok := strings.TrimSpace(r.FormValue("token"))
	if tok == "" {
		return nil, fmt.Errorf("missing token")
	}
	owner, err := s.store.GetToken(r.Context(), tok)
	if err != nil {
		return nil, err
	}
	provisioned, err := s.store.IsProvisionedToken(r.Context(), owner.ID)
	if err != nil {
		return nil, err
	}
	if provisioned {
		return nil, fmt.Errorf("token login disabled")
	}
	if owner.Disabled {
		return nil, fmt.Errorf("account disabled")
	}
	if !s.accountAllowedByEmailDomain(r.Context(), owner.Email) {
		return nil, errAccountNotEligible
	}
	if (!s.tokenLoginEnabled(r.Context()) || s.oauthLoginRequired(r.Context())) && !owner.IsAdmin {
		return nil, fmt.Errorf("token login disabled")
	}
	account, err := s.store.GetAccountByID(r.Context(), owner.AccountID)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func (s *Server) oauthLoginRequired(ctx context.Context) bool {
	return s.googleOrgSignupEnabled(ctx) || len(s.enabledOAuthProviders(ctx)) > 0
}

func (s *Server) tokenLoginEnabled(ctx context.Context) bool {
	return s.settingBool(ctx, "auth_token_login_enabled")
}

func (s *Server) loginData(csrf, errMsg string, r *http.Request) loginData {
	_, inviteErr := r.Cookie(inviteCookie)
	providers := s.enabledOAuthProviders(r.Context())
	oauthRequired := s.oauthLoginRequired(r.Context())
	return loginData{
		CSRF:          csrf,
		Error:         errMsg,
		Invite:        inviteErr == nil && !s.googleOrgSignupEnabled(r.Context()),
		Providers:     providers,
		PasswordLogin: true,
		TokenLogin:    s.tokenLoginEnabled(r.Context()) && !oauthRequired,
		OAuthEnabled:  oauthRequired,
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
