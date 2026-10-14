package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/andras-tkcs/peek/internal/models"
)

func TestAPICovCreateTokenValidation(t *testing.T) {
	s, adminTok := newHandlerTestServer(t)
	for _, body := range []string{`{`, `{"name":"  "}`} {
		apiCovStatus(t, s, http.MethodPost, "/api/tokens", adminTok, body, http.StatusBadRequest)
	}
}

func TestAPICovCreateTokenFailures(t *testing.T) {
	t.Run("rand failure", func(t *testing.T) {
		s, adminTok := newHandlerTestServer(t)
		stubSecureRandomRead(t, func([]byte) (int, error) { return 0, errors.New("no entropy") })
		apiCovStatus(t, s, http.MethodPost, "/api/tokens", adminTok, `{"name":"x"}`, http.StatusInternalServerError)
	})
	t.Run("store failure", func(t *testing.T) {
		s, adminTok := newHandlerTestServer(t)
		addFailTrigger(t, s.store, "tokens", "INSERT")
		apiCovStatus(t, s, http.MethodPost, "/api/tokens", adminTok, `{"name":"x"}`, http.StatusInternalServerError)
	})
}

func TestAPICovListTokensFailure(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	dropTable(t, s.store, "tokens")
	rec := httptest.NewRecorder()
	s.handleListTokens(rec, httptest.NewRequest(http.MethodGet, "/api/tokens", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAPICovDeleteToken(t *testing.T) {
	s, adminTok := newHandlerTestServer(t)
	apiCovStatus(t, s, http.MethodDelete, "/api/tokens/abc", adminTok, "", http.StatusBadRequest)
	apiCovStatus(t, s, http.MethodDelete, "/api/tokens/99999", adminTok, "", http.StatusNotFound)

	tokens, err := s.store.ListTokens(t.Context())
	if err != nil || len(tokens) != 1 {
		t.Fatalf("tokens = %v err = %v", tokens, err)
	}
	apiCovStatus(t, s, http.MethodDelete, "/api/tokens/"+strconv.FormatInt(tokens[0].ID, 10), adminTok, "", http.StatusBadRequest)

	body := apiCovStatus(t, s, http.MethodPost, "/api/tokens", adminTok, `{"name":"temp"}`, http.StatusOK)
	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	tokens, err = s.store.ListTokens(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var tempID int64
	for _, tk := range tokens {
		if tk.Name == "temp" {
			tempID = tk.ID
		}
	}
	if tempID == 0 {
		t.Fatal("temp token not listed")
	}

	addFailTrigger(t, s.store, "tokens", "DELETE")
	apiCovStatus(t, s, http.MethodDelete, "/api/tokens/"+strconv.FormatInt(tempID, 10), adminTok, "", http.StatusInternalServerError)
	if _, err := s.store.Exec(`DROP TRIGGER cov_fail_tokens_delete`); err != nil {
		t.Fatal(err)
	}
	apiCovStatus(t, s, http.MethodDelete, "/api/tokens/"+strconv.FormatInt(tempID, 10), adminTok, "", http.StatusOK)
}

func TestAPICovActorName(t *testing.T) {
	if got := actorName(nil); got != "unknown" {
		t.Fatalf("actorName(nil) = %q", got)
	}
	if got := actorName(&models.Token{Name: "ci"}); got != "ci" {
		t.Fatalf("actorName = %q", got)
	}
}
