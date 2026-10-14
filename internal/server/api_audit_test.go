package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAPICovAuditLimitAndFailure(t *testing.T) {
	s, adminTok := newHandlerTestServer(t)
	for _, name := range []string{"a", "b", "c"} {
		apiCovStatus(t, s, http.MethodPost, "/api/tokens", adminTok, `{"name":"`+name+`"}`, http.StatusOK)
	}
	var rows []map[string]any
	body := apiCovStatus(t, s, http.MethodGet, "/api/audit?limit=2", adminTok, "", http.StatusOK)
	if err := json.Unmarshal([]byte(body), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("limit=2 rows = %d err = %v", len(rows), err)
	}
	// Non-numeric and non-positive limits fall back to the default.
	for _, q := range []string{"limit=abc", "limit=0"} {
		body = apiCovStatus(t, s, http.MethodGet, "/api/audit?"+q, adminTok, "", http.StatusOK)
		if err := json.Unmarshal([]byte(body), &rows); err != nil || len(rows) != 3 {
			t.Fatalf("%s rows = %d err = %v", q, len(rows), err)
		}
	}
	dropTable(t, s.store, "audit_log")
	apiCovStatus(t, s, http.MethodGet, "/api/audit", adminTok, "", http.StatusInternalServerError)
}
