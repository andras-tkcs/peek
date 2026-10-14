package server

import (
	"net/http"
	"testing"
)

func TestAPICovRenameErrors(t *testing.T) {
	s, _, ownerTok := apiCovFixture(t, "cov-rename")
	newAccountWithToken(t, s, "stranger@example.test", "stranger-token", false)
	apiCovStatus(t, s, http.MethodPost, "/api/uploads/missing/name", ownerTok, `{"name":"x"}`, http.StatusNotFound)
	apiCovStatus(t, s, http.MethodPost, "/api/uploads/cov-rename/name", "stranger-token", `{"name":"x"}`, http.StatusForbidden)
	apiCovStatus(t, s, http.MethodPost, "/api/uploads/cov-rename/name", ownerTok, `{`, http.StatusBadRequest)
	apiCovStatus(t, s, http.MethodPost, "/api/uploads/cov-rename/name", ownerTok, `{"name":"  "}`, http.StatusBadRequest)
	addFailTrigger(t, s.store, "uploads", "UPDATE")
	apiCovStatus(t, s, http.MethodPost, "/api/uploads/cov-rename/name", ownerTok, `{"name":"New Name"}`, http.StatusInternalServerError)
}
