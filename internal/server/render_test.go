package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	webui "github.com/privacyfence/peek/internal/web"
)

func TestRenderHTMLUninitializedRendererReturns500(t *testing.T) {
	s := &Server{renderer: &webui.Renderer{}}
	rec := httptest.NewRecorder()
	s.renderHTML(rec, http.StatusOK, webui.TemplateError, webui.ErrorData{Title: "t"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestRenderHTMLWriteFailureIsLogged(t *testing.T) {
	s, _, _, _ := newFaultServer(t)
	w := &failingWriter{ResponseRecorder: *httptest.NewRecorder()}
	s.renderHTML(w, http.StatusTeapot, webui.TemplateError, webui.ErrorData{Title: "t"})
	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", w.Code)
	}
}
