package server

import (
	"net/http"

	"github.com/privacyfence/peek/internal/models"
)

// webAuth validates the signed session cookie and returns the account.
// The cookie holds a signed reference to the account id, so it is revocable via
// account disablement, the allowed email domain and the OAuth-required setting,
// and never carries an API credential.
func (s *Server) webAuth(r *http.Request) (*models.Account, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, false
	}
	sub, ok := parseSignedSubject(s.secret, c.Value)
	if !ok {
		return nil, false
	}
	id, epoch, ok := parseSessionSubject(sub)
	if !ok {
		return nil, false
	}
	a, err := s.store.GetAccountByID(r.Context(), id)
	if err != nil {
		return nil, false
	}
	if a.SessionEpoch != epoch {
		return nil, false
	}
	if s.accountActive(r.Context(), a) != nil {
		return nil, false
	}
	return a, true
}
