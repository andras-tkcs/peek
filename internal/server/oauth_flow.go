package server

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/privacyfence/peek/internal/models"
	webui "github.com/privacyfence/peek/internal/web"
)

func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	p, err := s.oauthProviderConfig(r.Context(), r.PathValue("provider"))
	if err != nil {
		s.renderOAuthError(w, r, http.StatusNotFound, "OAuth provider is not configured.")
		return
	}
	state, err := randID(24)
	if err != nil {
		slog.Error("oauth state generation failed", "provider", p.Key, "err", err)
		s.renderOAuthError(w, r, http.StatusInternalServerError, "OAuth login could not start.")
		return
	}
	verifier := oauth2.GenerateVerifier()
	nonce, err := randID(24)
	if err != nil {
		slog.Error("oauth nonce generation failed", "provider", p.Key, "err", err)
		s.renderOAuthError(w, r, http.StatusInternalServerError, "OAuth login could not start.")
		return
	}
	s.setCookie(w, &http.Cookie{
		Name:     oauthCookieName(p.Key),
		Value:    s.makeOAuthFlowCookie(p.Key, state, verifier, nonce),
		Path:     "/oauth/" + p.Key,
		MaxAge:   10 * 60,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if oauthProviderUsesIDToken(p.Key) {
		opts = append(opts, oidc.Nonce(nonce))
	}
	if p.Key == "google" && s.googleOrgSignupEnabled(r.Context()) {
		if domain := s.allowedEmailDomain(r.Context()); domain != "" {
			opts = append(opts, oauth2.SetAuthURLParam("hd", domain))
		}
	}
	url := s.oauth2Config(p).AuthCodeURL(state, opts...)
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	p, err := s.oauthProviderConfig(r.Context(), r.PathValue("provider"))
	if err != nil {
		s.renderOAuthError(w, r, http.StatusNotFound, "OAuth provider is not configured.")
		return
	}
	state, verifier, nonce, ok := s.parseOAuthFlowCookie(r, p.Key)
	if !ok || state == "" || state != r.URL.Query().Get("state") {
		s.clearCookie(w, oauthCookieName(p.Key), "/oauth/"+p.Key)
		s.renderOAuthError(w, r, http.StatusBadRequest, "OAuth session expired. Try signing in again.")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.clearCookie(w, oauthCookieName(p.Key), "/oauth/"+p.Key)
		s.renderOAuthError(w, r, http.StatusUnauthorized, "OAuth sign-in was denied.")
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		s.clearCookie(w, oauthCookieName(p.Key), "/oauth/"+p.Key)
		s.renderOAuthError(w, r, http.StatusBadRequest, "OAuth callback was missing a code.")
		return
	}
	ctx := r.Context()
	tok, err := s.oauth2Config(p).Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		slog.Warn("oauth token exchange failed", "provider", p.Key, "err", err)
		s.clearCookie(w, oauthCookieName(p.Key), "/oauth/"+p.Key)
		s.renderOAuthError(w, r, http.StatusBadGateway, "OAuth token exchange failed.")
		return
	}
	profile, err := s.fetchOAuthProfile(ctx, p, tok, nonce)
	if err != nil {
		slog.Warn("oauth profile lookup failed", "provider", p.Key, "err", err)
		s.clearCookie(w, oauthCookieName(p.Key), "/oauth/"+p.Key)
		s.renderOAuthError(w, r, http.StatusBadGateway, "OAuth profile lookup failed.")
		return
	}
	account, created, err := s.resolveOAuthAccountCreated(r, profile)
	if err != nil {
		slog.Warn("oauth account resolution failed", "provider", p.Key, "err", err)
		s.clearCookie(w, oauthCookieName(p.Key), "/oauth/"+p.Key)
		s.renderOAuthError(w, r, http.StatusForbidden, oauthAccountErrorMessage(err))
		return
	}
	if err := s.store.UpsertOAuthIdentity(ctx, account.ID, profile.Provider, profile.ProviderUserID, profile.Email, profile.Name); err != nil {
		slog.Error("oauth account link failed", "provider", p.Key, "account_id", account.ID, "err", err)
		s.clearCookie(w, oauthCookieName(p.Key), "/oauth/"+p.Key)
		s.renderOAuthError(w, r, http.StatusInternalServerError, "OAuth account link failed.")
		return
	}
	s.clearCookie(w, oauthCookieName(p.Key), "/oauth/"+p.Key)
	s.clearCookie(w, inviteCookie, "/")
	s.setWebSession(w, account)
	s.audit("oauth login provider=%s account=%d email=%q created=%t", p.Key, account.ID, account.Email, created)
	s.renderSignedIn(w, r, account, created)
}

// renderSignedIn answers a successful OAuth callback with a same-origin page
// instead of a redirect: the callback is reached from the provider's site, and
// browsers do not send the SameSite=Strict session cookie on a redirect in that
// chain, so a 303 to the dashboard would arrive signed out.
func (s *Server) renderSignedIn(w http.ResponseWriter, r *http.Request, account *models.Account, created bool) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	s.renderHTML(w, http.StatusOK, webui.TemplateSignedIn, webui.SignedInData{
		Next:    s.consumeNextPath(w, r),
		Email:   account.Email,
		Created: created,
	})
}

func (s *Server) renderOAuthError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	s.renderLoginForm(w, status, msg, r)
}

func oauthAccountErrorMessage(err error) string {
	if err == nil {
		return "OAuth account could not be linked."
	}
	switch err.Error() {
	case "OAuth account must have a verified email":
		return "OAuth account must have a verified email."
	case "account disabled":
		return "This account is disabled."
	case "account not eligible":
		return "This email address is not allowed to sign in."
	case "google workspace account required":
		return "Sign in with your Google Workspace account."
	case "invite required":
		return "An invite is required for this account."
	case "invite not found", "invite does not match this account":
		return "This invite is invalid or expired."
	default:
		return "OAuth account could not be linked."
	}
}
