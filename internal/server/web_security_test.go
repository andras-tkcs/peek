package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	webui "github.com/privacyfence/peek/internal/web"
)

func TestDashboardTemplateHasNoInlineScriptExecution(t *testing.T) {
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(webui.TemplateDashboard, dashData{
		CSRF:             "csrf",
		User:             "admin",
		UploadSuccessURL: `");alert(1);//`,
		Uploads: []dashUpload{{
			Slug:         "abc123",
			Name:         `x" onmouseover="alert(1)`,
			SizeHuman:    "1 KB",
			CreatedHuman: "2026-06-21 10:00",
		}},
	})
	if err != nil {
		t.Fatalf("execute dashboard template: %v", err)
	}
	html := string(body)
	if strings.Contains(html, "onclick=") || strings.Contains(html, "onchange=") || strings.Contains(html, "onsubmit=") {
		t.Fatalf("dashboard template contains inline event handler: %s", html)
	}
	if strings.Contains(html, "<script>") {
		t.Fatalf("dashboard template contains inline script block: %s", html)
	}
	if strings.Contains(html, `onmouseover="alert(1)"`) {
		t.Fatalf("dashboard template rendered executable injected attribute: %s", html)
	}
	if !strings.Contains(html, `<script src="/alpine.min.js?v=`) {
		t.Fatalf("dashboard template did not include alpine.min.js: %s", html)
	}
	if !strings.Contains(html, `<script src="/dashboard-alpine.js?v=`) {
		t.Fatalf("dashboard template did not include dashboard-alpine.js: %s", html)
	}
}

func TestAdminTemplateHasNoInlineScriptExecution(t *testing.T) {
	renderer, err := webui.NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	const payload = `<script>alert(1)</script>`
	body, err := renderer.Execute(webui.TemplateAdmin, adminData{
		CSRF:     "csrf",
		User:     "admin",
		Invites:  []inviteDashRow{{ID: 1, Email: payload, Status: "pending", Link: payload, CanRevoke: true}},
		Accounts: []accountDashRow{{ID: 2, Name: payload, Email: "x@example.test"}},
	})
	if err != nil {
		t.Fatalf("execute admin template: %v", err)
	}
	html := string(body)
	if strings.Contains(html, payload) {
		t.Fatalf("admin template rendered a raw script tag: %s", html)
	}
	if strings.Contains(html, "onclick=") || strings.Contains(html, "onchange=") || strings.Contains(html, "onsubmit=") {
		t.Fatalf("admin template contains inline event handler: %s", html)
	}
	if !strings.Contains(html, `<script src="/dashboard-alpine.js?v=`) {
		t.Fatalf("admin template did not include dashboard-alpine.js: %s", html)
	}
}

func TestDashboardCSPRestrictsScriptsToSelf(t *testing.T) {
	if !strings.Contains(webui.DashboardCSP, "script-src 'self'") {
		t.Fatalf("dashboard CSP does not pin scripts to self: %s", webui.DashboardCSP)
	}
	if !strings.Contains(webui.DashboardCSP, "'unsafe-eval'") {
		t.Fatalf("dashboard CSP must allow unsafe-eval for Alpine.js expression evaluation: %s", webui.DashboardCSP)
	}
	if !strings.Contains(webui.DashboardCSP, "style-src 'self' 'unsafe-inline'") {
		t.Fatalf("dashboard CSP must allow unsafe-inline for styles (Alpine.js transitions): %s", webui.DashboardCSP)
	}
}

func urlencodedForm(r *http.Request) {
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
}

func TestRequestBodyCapRejectsDeclaredOversizedForm(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/login", strings.NewReader("token="+strings.Repeat("a", maxRequestBodyBytes)), urlencodedForm)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "Request body too large.\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestRequestBodyCapCutsChunkedForm(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/login", strings.NewReader("token="+strings.Repeat("a", 100<<10)), urlencodedForm, func(r *http.Request) { r.ContentLength = -1 })
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Invalid session.") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestRequestBodyCapJSONAPI(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/api/uploads/anything/comments", strings.NewReader(strings.Repeat("a", maxRequestBodyBytes+1)), withJSON())
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v: %s", err, rec.Body.String())
	}
	if out.Error != "request body too large" {
		t.Fatalf("error = %q", out.Error)
	}
}

func TestRequestBodyCapExemptsUploads(t *testing.T) {
	s, adminToken := newHandlerTestServer(t)
	body := "<!doctype html><html><body>" + strings.Repeat("x", 100<<10) + "</body></html>"
	rec := doRequest(t, s, http.MethodPost, "/api/upload?filename=big.html&visibility=public", strings.NewReader(body), asBearer(adminToken), func(r *http.Request) { r.Header.Set("Content-Type", "text/html; charset=utf-8") })
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestRequestBodyCapAllowsSmallForms(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	if rec := doRequest(t, s, http.MethodGet, "/healthz", nil); rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	rec := doRequest(t, s, http.MethodPost, "/login", strings.NewReader("token=small"), urlencodedForm)
	if rec.Code == http.StatusRequestEntityTooLarge || rec.Code >= http.StatusInternalServerError {
		t.Fatalf("status = %d, want the form to be read: %s", rec.Code, rec.Body.String())
	}
}
