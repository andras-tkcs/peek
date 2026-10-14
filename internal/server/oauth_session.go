package server

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	inviteCookie = "hn_invite"
	nextCookie   = "hn_next"
)

func oauthCookieName(provider string) string {
	return "hn_oauth_" + provider
}

func (s *Server) makeOAuthFlowCookie(provider, state, verifier, nonce string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(provider + "|" + state + "|" + verifier + "|" + nonce))
	return makeWebSession(s.secret, payload, 10*time.Minute)
}

func (s *Server) parseOAuthFlowCookie(r *http.Request, provider string) (state, verifier, nonce string, ok bool) {
	c, err := r.Cookie(oauthCookieName(provider))
	if err != nil || c.Value == "" {
		return "", "", "", false
	}
	payload, ok := parseSignedSubject(s.secret, c.Value)
	if !ok {
		return "", "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", "", false
	}
	parts := strings.SplitN(string(raw), "|", 4)
	if len(parts) != 4 || parts[0] != provider || parts[3] == "" {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[3], true
}

func (s *Server) setWebSession(w http.ResponseWriter, accountID int64) {
	s.setCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    makeWebSession(s.secret, strconv.FormatInt(accountID, 10), sessionTTL),
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	})
}

func (s *Server) setNextPath(w http.ResponseWriter, next string) {
	if !safeNextPath(next) {
		return
	}
	s.setCookie(w, &http.Cookie{
		Name:     nextCookie,
		Value:    next,
		Path:     "/",
		MaxAge:   10 * 60,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})
}

func (s *Server) consumeNextPath(w http.ResponseWriter, r *http.Request) string {
	next := "/dashboard"
	if c, err := r.Cookie(nextCookie); err == nil && safeNextPath(c.Value) {
		next = c.Value
	}
	s.clearCookie(w, nextCookie, "/")
	return next
}

func safeNextPath(next string) bool {
	return strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") &&
		!strings.ContainsAny(next, "\r\n")
}

func (s *Server) clearCookie(w http.ResponseWriter, name, path string) {
	s.setCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})
}
