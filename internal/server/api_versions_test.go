package server

import (
	"net/http"
	"testing"
)

func TestAPICovListVersions(t *testing.T) {
	s, _, ownerTok := apiCovFixture(t, "cov-versions")
	newAccountWithToken(t, s, "stranger@example.test", "stranger-token", false)
	apiCovStatus(t, s, http.MethodGet, "/api/uploads/missing/versions", ownerTok, "", http.StatusNotFound)
	apiCovStatus(t, s, http.MethodGet, "/api/uploads/cov-versions/versions", "stranger-token", "", http.StatusForbidden)
	apiCovStatus(t, s, http.MethodGet, "/api/uploads/cov-versions/versions", ownerTok, "", http.StatusOK)
	apiCovBreakVersionKey(t, s)
	apiCovStatus(t, s, http.MethodGet, "/api/uploads/cov-versions/versions", ownerTok, "", http.StatusInternalServerError)
}
