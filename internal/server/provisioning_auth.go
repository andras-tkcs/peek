package server

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/privacyfence/peek/internal/db"
	"github.com/privacyfence/peek/internal/models"
)

const provisioningKeyPrefix = "peekprov_"

type provisionerContextKeyType struct{}

var provisionerContextKey = provisionerContextKeyType{}

// newProvisioningKey returns a new provisioning key. It is shown once and never again.
func newProvisioningKey() (string, error) {
	id, err := randID(32)
	if err != nil {
		return "", err
	}
	return provisioningKeyPrefix + id, nil
}

func withProvisioner(r *http.Request, p *models.Provisioner) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), provisionerContextKey, p))
}

func provisionerFrom(r *http.Request) (*models.Provisioner, bool) {
	p, ok := r.Context().Value(provisionerContextKey).(*models.Provisioner)
	return p, ok && p != nil
}

func requireProvisioner(w http.ResponseWriter, r *http.Request) (*models.Provisioner, bool) {
	p, ok := provisionerFrom(r)
	if !ok {
		jsonError(w, http.StatusInternalServerError, "auth context missing")
		return nil, false
	}
	return p, true
}

// authProvisioner gates an endpoint behind a provisioning key. Ordinary tokens
// are refused without a lookup, and provisioning keys are not in the tokens
// table, so neither kind works on the other's endpoints.
func (s *Server) authProvisioner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := bearerToken(r)
		if key == "" {
			jsonError(w, http.StatusUnauthorized, "missing token")
			return
		}
		if !strings.HasPrefix(key, provisioningKeyPrefix) {
			jsonError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		p, err := s.store.GetProvisionerByKey(r.Context(), key)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		now := time.Now()
		if p.LastUsedAt == 0 || now.Unix()-p.LastUsedAt >= db.TokenLastUsedInterval {
			if err := s.store.TouchProvisionerLastUsed(r.Context(), p.ID, now); err != nil {
				slog.Warn("provisioner last-used update failed", "provisioner_id", p.ID, "err", err)
			}
		}
		next(w, withProvisioner(r, p))
	}
}
