package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/privacyfence/peek/internal/models"
	webui "github.com/privacyfence/peek/internal/web"
)

const (
	cliLoginTTL      = 15 * time.Minute
	cliLoginInterval = 2
	// cliTokenTTL is how long a token issued through `peek login` stays valid.
	cliTokenTTL = 90 * 24 * time.Hour
	// cliLoginUserAgentMax caps the stored User-Agent of a login request, in bytes.
	cliLoginUserAgentMax = 200
	userCodeAlphabet     = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	cliLoginCodeError    = "That code is invalid or expired. Check the code in your terminal."
	cliLoginSessionError = "Invalid session. Enter the code again."
)

// formatUserCode renders a stored 8-character code as ABCD-EFGH.
func formatUserCode(code string) string {
	if len(code) == 8 {
		return code[:4] + "-" + code[4:]
	}
	return code
}

// normalizeUserCode turns typed input into the stored form: upper-case, with
// spaces, tabs and dashes removed. ok is false unless the result is exactly 8
// characters from userCodeAlphabet.
func normalizeUserCode(raw string) (code string, ok bool) {
	code = strings.ToUpper(strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '-':
			return -1
		}
		return r
	}, raw))
	if len(code) != 8 {
		return "", false
	}
	for i := 0; i < len(code); i++ {
		if strings.IndexByte(userCodeAlphabet, code[i]) < 0 {
			return "", false
		}
	}
	return code, true
}

// cliLoginUserAgent returns the request's User-Agent cut to cliLoginUserAgentMax
// bytes, with any partial UTF-8 sequence dropped.
func cliLoginUserAgent(r *http.Request) string {
	ua := strings.TrimSpace(r.UserAgent())
	if len(ua) > cliLoginUserAgentMax {
		ua = ua[:cliLoginUserAgentMax]
	}
	return strings.ToValidUTF8(ua, "")
}

func (s *Server) handleCLILoginStart(w http.ResponseWriter, r *http.Request) {
	if s.setupRequired(r.Context()) {
		jsonError(w, http.StatusBadRequest, "server setup is not complete")
		return
	}
	deviceCode, err := randID(32)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "device code failed")
		return
	}
	var userCode string
	for range 5 {
		userCode, err = randomUserCode()
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "user code failed")
			return
		}
		err = s.store.CreateCLILoginDeviceWithContext(r.Context(), deviceCode, userCode, time.Now().Add(cliLoginTTL), s.clientIP(r), cliLoginUserAgent(r))
		if err == nil {
			break
		}
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "login start failed")
		return
	}
	jsonOK(w, map[string]any{
		"device_code":      deviceCode,
		"user_code":        formatUserCode(userCode),
		"verification_url": s.baseURL + "/cli-login",
		"interval":         cliLoginInterval,
		"expires_in":       int(cliLoginTTL.Seconds()),
	})
}

func (s *Server) handleCLILoginPoll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if err := decodeJSON(w, r, &body, smallJSONBodyLimit); err != nil {
		jsonError(w, http.StatusBadRequest, "bad json")
		return
	}
	body.DeviceCode = strings.TrimSpace(body.DeviceCode)
	if body.DeviceCode == "" {
		jsonError(w, http.StatusBadRequest, "device_code required")
		return
	}
	d, err := s.store.GetCLILoginByDevice(r.Context(), body.DeviceCode)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid device code")
		return
	}
	if time.Now().After(d.ExpiresAt) {
		if d.Status == "pending" {
			if err := s.store.ExpireCLILogin(r.Context(), d.ID); err != nil {
				slog.Warn("cli login expire failed", "device_id", d.ID, "err", err)
			}
		}
		jsonOK(w, map[string]any{"status": "expired"})
		return
	}
	switch d.Status {
	case "pending":
		jsonOK(w, map[string]any{"status": "pending", "interval": cliLoginInterval})
	case "denied", "expired":
		jsonOK(w, map[string]any{"status": d.Status})
	case "approved":
		if !d.ConsumedAt.IsZero() {
			jsonOK(w, map[string]any{"status": "consumed"})
			return
		}
		if err := s.store.ConsumeCLILogin(r.Context(), d.ID); err != nil {
			jsonOK(w, map[string]any{"status": "consumed"})
			return
		}
		account, err := s.store.GetAccountByID(r.Context(), d.AccountID)
		if err != nil || s.accountActive(r.Context(), account) != nil {
			jsonOK(w, map[string]any{"status": "denied"})
			return
		}
		token, err := randID(24)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "token generation failed")
			return
		}
		expiresAt := time.Now().Add(cliTokenTTL).Unix()
		if _, err := s.store.CreateAccountTokenExpiring(r.Context(), account.ID, token, "CLI login", expiresAt); err != nil {
			jsonError(w, http.StatusInternalServerError, "token creation failed")
			return
		}
		s.audit("cli token issued account=%d email=%q expires_at=%d", account.ID, account.Email, expiresAt)
		jsonOK(w, map[string]any{"status": "approved", "token": token})
	default:
		jsonOK(w, map[string]any{"status": "expired"})
	}
}

// handleCLILoginEntry renders the form where a signed-in user types the code
// that `peek login` printed in their own terminal.
func (s *Server) handleCLILoginEntry(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	owner, ok := s.webAuth(r)
	if !ok {
		s.setNextPath(w, "/cli-login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderCLILoginEntry(w, http.StatusOK, webui.CLILoginEntryData{User: owner.Name})
}

// handleCLILoginLookup checks a typed code and shows the approval page for it.
func (s *Server) handleCLILoginLookup(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	owner, ok := s.webAuth(r)
	if !ok {
		s.setNextPath(w, "/cli-login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	entryError := func(msg string) {
		s.renderCLILoginEntry(w, http.StatusOK, webui.CLILoginEntryData{User: owner.Name, Error: msg})
	}
	if err := r.ParseForm(); err != nil {
		entryError(cliLoginSessionError)
		return
	}
	validCSRF, err := s.validateCSRF(r, w, r.FormValue("csrf"))
	if err != nil {
		s.renderCSRFError(w, err)
		return
	}
	if !validCSRF {
		entryError(cliLoginSessionError)
		return
	}
	code, ok := normalizeUserCode(r.FormValue("code"))
	if !ok {
		entryError(cliLoginCodeError)
		return
	}
	d, err := s.store.GetCLILoginByUserCode(r.Context(), code)
	if err != nil || d.Status != "pending" || time.Now().After(d.ExpiresAt) {
		entryError(cliLoginCodeError)
		return
	}
	s.renderCLILoginForm(w, http.StatusOK, s.cliLoginApprovalData(r, owner, d, ""))
}

// handleCLILoginLegacyLink sends old /cli-login/<code> links to the empty code form.
func (s *Server) handleCLILoginLegacyLink(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	http.Redirect(w, r, "/cli-login", http.StatusSeeOther)
}

// cliLoginApprovalData builds the approval page for device d.
func (s *Server) cliLoginApprovalData(r *http.Request, owner *models.Account, d *models.CLILoginDevice, errMsg string) webui.CLILoginData {
	return webui.CLILoginData{
		Code:        formatUserCode(d.UserCode),
		User:        owner.Name,
		Error:       errMsg,
		RequestIP:   orUnknown(d.RequestIP),
		UserAgent:   orUnknown(d.UserAgent),
		RequestedAt: d.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		CurrentIP:   s.clientIP(r),
	}
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func (s *Server) handleCLILoginApprove(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	code, codeOK := normalizeUserCode(r.PathValue("code"))
	owner, ok := s.webAuth(r)
	if !ok {
		s.setNextPath(w, "/cli-login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderCLILoginEntry(w, http.StatusOK, webui.CLILoginEntryData{User: owner.Name, Error: cliLoginSessionError})
		return
	}
	validCSRF, err := s.validateCSRF(r, w, r.FormValue("csrf"))
	if err != nil {
		s.renderCSRFError(w, err)
		return
	}
	if !validCSRF {
		s.renderCLILoginEntry(w, http.StatusOK, webui.CLILoginEntryData{User: owner.Name, Error: cliLoginSessionError})
		return
	}
	expired := func() {
		s.renderHTML(w, http.StatusOK, webui.TemplateCLILoginDone, webui.CLILoginDoneData{Title: "CLI login expired", Message: "Start a new login from the CLI."})
	}
	if !codeOK {
		expired()
		return
	}
	d, err := s.store.GetCLILoginByUserCode(r.Context(), code)
	if err != nil || d.Status != "pending" || time.Now().After(d.ExpiresAt) {
		expired()
		return
	}
	if r.FormValue("decision") == "deny" {
		if err := s.store.DenyCLILogin(r.Context(), d.ID); err != nil {
			slog.Warn("cli login deny failed", "device_id", d.ID, "err", err)
			s.renderCLILoginForm(w, http.StatusOK, s.cliLoginApprovalData(r, owner, d, "Denial failed."))
			return
		}
		s.audit("cli login denied account=%d code=%s request_ip=%q", owner.ID, code, d.RequestIP)
		s.renderHTML(w, http.StatusOK, webui.TemplateCLILoginDone, webui.CLILoginDoneData{Title: "CLI login denied", Message: "Return to your terminal to continue."})
		return
	}
	if err := s.store.ApproveCLILogin(r.Context(), d.ID, owner.ID); err != nil {
		slog.Warn("cli login approve failed", "device_id", d.ID, "account_id", owner.ID, "err", err)
		s.renderCLILoginForm(w, http.StatusOK, s.cliLoginApprovalData(r, owner, d, "Approval failed."))
		return
	}
	s.audit("cli login approved account=%d code=%s request_ip=%q", owner.ID, code, d.RequestIP)
	s.renderHTML(w, http.StatusOK, webui.TemplateCLILoginDone, webui.CLILoginDoneData{Title: "CLI login approved", Message: "Return to your terminal to continue."})
}

func (s *Server) renderCLILoginForm(w http.ResponseWriter, status int, data webui.CLILoginData) {
	csrf, ok := s.csrfToken(w)
	if !ok {
		return
	}
	data.CSRF = csrf
	s.renderHTML(w, status, webui.TemplateCLILogin, data)
}

func (s *Server) renderCLILoginEntry(w http.ResponseWriter, status int, data webui.CLILoginEntryData) {
	csrf, ok := s.csrfToken(w)
	if !ok {
		return
	}
	data.CSRF = csrf
	s.renderHTML(w, status, webui.TemplateCLILoginEntry, data)
}

func randomUserCode() (string, error) {
	b := make([]byte, 8)
	if _, err := secureRandomRead(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = userCodeAlphabet[int(b[i])%len(userCodeAlphabet)]
	}
	return string(b), nil
}
