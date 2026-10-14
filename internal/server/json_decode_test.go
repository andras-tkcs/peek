package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	var body struct {
		Name string `json:"name"`
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"token","extra":true}`))
	rec := httptest.NewRecorder()

	err := decodeJSON(rec, req, &body, smallJSONBodyLimit)

	if err == nil {
		t.Fatal("expected unknown field error")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown field", err)
	}
}

func TestDecodeJSONRejectsTrailingValues(t *testing.T) {
	var body struct {
		Name string `json:"name"`
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"token"} {"name":"other"}`))
	rec := httptest.NewRecorder()

	err := decodeJSON(rec, req, &body, smallJSONBodyLimit)

	if err == nil || !strings.Contains(err.Error(), "single JSON value") {
		t.Fatalf("error = %v, want trailing value rejection", err)
	}
}

func TestDecodeJSONEnforcesBodyLimit(t *testing.T) {
	var body struct {
		Name string `json:"name"`
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"too-long"}`))
	rec := httptest.NewRecorder()

	err := decodeJSON(rec, req, &body, 4)

	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error = %v, want body limit error", err)
	}
}

func TestDecodeJSONNonPositiveLimitUsesDefault(t *testing.T) {
	var body struct {
		Name string `json:"name"`
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"`+strings.Repeat("a", smallJSONBodyLimit*2)+`"}`))
	if err := decodeJSON(httptest.NewRecorder(), req, &body, 0); err != nil {
		t.Fatalf("a body under the default limit failed: %v", err)
	}
	if len(body.Name) != smallJSONBodyLimit*2 {
		t.Fatalf("name length = %d", len(body.Name))
	}
}
