package server

import (
	"net/http"
	"net/url"
	"strings"
)

const sessionCookie = "hn_session"
const dashboardPath = "/dashboard"
const adminPath = "/admin"

func noCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
}

// Flash codes. Redirects to the dashboard carry only these codes (and slugs or
// emails that are checked against the viewer's own uploads); the text shown is
// looked up in flashMessages.
const (
	flashInvalidSession           = "invalid_session"
	flashFormInvalid              = "form_invalid"
	flashNoHTML                   = "no_html"
	flashNoFile                   = "no_file"
	flashFileTooLarge             = "file_too_large"
	flashNotFound                 = "not_found"
	flashNotOwner                 = "not_owner"
	flashDeleteFailed             = "delete_failed"
	flashVisibilityFailed         = "visibility_failed"
	flashRenameFailed             = "rename_failed"
	flashGrantKind                = "grant_kind"
	flashGrantEmail               = "grant_email"
	flashGrantGroupLookup         = "grant_group_lookup"
	flashGrantFailed              = "grant_failed"
	flashGrantNotFound            = "grant_not_found"
	flashInviteEmailRequired      = "invite_email_required"
	flashInviteDomain             = "invite_domain"
	flashInviteFailed             = "invite_failed"
	flashInviteNotUsed            = "invite_not_used"
	flashBadInvite                = "bad_invite"
	flashInviteRevokeFailed       = "invite_revoke_failed"
	flashBadUser                  = "bad_user"
	flashLastAdminRemove          = "last_admin_remove"
	flashLastAdminDisable         = "last_admin_disable"
	flashUserUpdateFailed         = "user_update_failed"
	flashSettingsFailed           = "settings_failed"
	flashAPIKeyName               = "api_key_name"
	flashAPIKeyCreateFailed       = "api_key_create_failed"
	flashAPIKeyRegenerateFailed   = "api_key_regenerate_failed"
	flashAPIKeyRevokeFailed       = "api_key_revoke_failed"
	flashUploadFailed             = "upload_failed"
	flashUploadPersistenceFailure = "upload_persistence_failure"
	flashEmailNotConfigured       = "email_not_configured"
	flashEmailNoAddress           = "email_no_address"
	flashEmailTestFailed          = "email_test_failed"
	flashShareNotifyFailed        = "share_notify_failed"

	flashInviteCreated = "invite_created"
	flashInviteRevoked = "invite_revoked"
	flashUserUpdated   = "user_updated"
	flashSettingsSaved = "settings_saved"
	flashAPIKeyRevoked = "api_key_revoked"
	flashVisibilitySet = "visibility_set"
	flashGrantAdded    = "grant_added"
	flashGrantRemoved  = "grant_removed"
	flashRenamed       = "renamed"
	flashEmailTestSent = "email_test_sent"
)

// flashMessages is the only source of flash text. {slug}, {visibility} and
// {email} are filled from the viewer's own uploads by flashText.
var flashMessages = map[string]string{
	flashInvalidSession:           flashInvalidSession,
	flashFormInvalid:              "file too large or invalid form",
	flashNoHTML:                   "no html pasted",
	flashNoFile:                   "no file selected",
	flashFileTooLarge:             "file too large",
	flashNotFound:                 "not found",
	flashNotOwner:                 "not owner",
	flashDeleteFailed:             "delete failed",
	flashVisibilityFailed:         "visibility update failed",
	flashRenameFailed:             "rename failed",
	flashGrantKind:                "kind must be user or group",
	flashGrantEmail:               "invalid email address",
	flashGrantGroupLookup:         "group grants need Google group lookup; set PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL on the server",
	flashGrantFailed:              "grant update failed",
	flashGrantNotFound:            "grant not found",
	flashInviteEmailRequired:      "email required",
	flashInviteDomain:             "email must match allowed domain",
	flashInviteFailed:             "invite failed",
	flashInviteNotUsed:            "invites are not used while Google org sign-in is on",
	flashBadInvite:                "bad invite",
	flashInviteRevokeFailed:       "invite revoke failed",
	flashBadUser:                  "bad user",
	flashLastAdminRemove:          "cannot remove last admin",
	flashLastAdminDisable:         "cannot disable last admin",
	flashUserUpdateFailed:         "user update failed",
	flashSettingsFailed:           "settings update failed",
	flashAPIKeyName:               apiKeyNameError,
	flashAPIKeyCreateFailed:       "API key could not be created",
	flashAPIKeyRegenerateFailed:   "API key could not be regenerated",
	flashAPIKeyRevokeFailed:       "API key could not be revoked",
	flashUploadFailed:             "upload failed",
	flashUploadPersistenceFailure: "db failed",
	flashEmailNotConfigured:       "email is not configured: set an SMTP host and From address",
	flashEmailNoAddress:           "your account has no email address",
	flashEmailTestFailed:          "test email failed; see the server log",
	flashShareNotifyFailed:        "saved, but the notification email could not be sent",
	flashSessionsRevoked:          "other sessions signed out",
	flashSessionsRevokeFailed:     "sign out failed",

	"upload_empty_file":             "empty file",
	"upload_invalid_html":           "file does not look like HTML",
	"upload_invalid_visibility":     "visibility must be public, signed-in, or restricted",
	"upload_slug_generation":        "slug generation failed",
	"upload_storage_write":          "storage failed",
	"upload_total_quota_exceeded":   "total storage quota exceeded",
	"upload_owner_count_exceeded":   "per-token upload count quota exceeded",
	"upload_owner_storage_exceeded": "per-token storage quota exceeded",
	"upload_name_required":          "name is required",
	"upload_name_too_long":          "name must be 200 characters or fewer",

	flashInviteCreated: "invite created",
	flashInviteRevoked: "invite revoked",
	flashUserUpdated:   "user updated",
	flashSettingsSaved: "settings saved",
	flashAPIKeyRevoked: "API key revoked",
	flashVisibilitySet: "/p/{slug} is now {visibility}",
	flashGrantAdded:    "Shared /p/{slug} with {email}",
	flashGrantRemoved:  "Removed access from /p/{slug}",
	flashRenamed:       "Renamed to /p/{slug}",
	flashEmailTestSent: "test email sent",
}

func dashboardError(w http.ResponseWriter, r *http.Request, code string) {
	dashboardFlash(w, r, url.Values{"err": {code}})
}

func adminError(w http.ResponseWriter, r *http.Request, code string) {
	adminFlash(w, r, url.Values{"err": {code}})
}

func adminOK(w http.ResponseWriter, r *http.Request, code string) {
	adminFlash(w, r, url.Values{"ok": {code}})
}

// adminFlash redirects to the admin page with flash codes. Only codes from
// flashMessages are ever rendered.
func adminFlash(w http.ResponseWriter, r *http.Request, q url.Values) {
	http.Redirect(w, r, adminPath+"?"+q.Encode(), http.StatusSeeOther)
}

func dashboardOK(w http.ResponseWriter, r *http.Request, code string) {
	dashboardFlash(w, r, url.Values{"ok": {code}})
}

// dashboardOKSlug flashes a success code whose message names /p/<slug>.
func dashboardOKSlug(w http.ResponseWriter, r *http.Request, code, slug string) {
	dashboardFlash(w, r, url.Values{"ok": {code}, "slug": {slug}})
}

// dashboardUploaded flashes the share link of the upload with this slug.
func dashboardUploaded(w http.ResponseWriter, r *http.Request, slug string) {
	dashboardFlash(w, r, url.Values{"uploaded": {slug}})
}

func dashboardHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, dashboardPath, http.StatusSeeOther)
}

// dashboardFlash redirects to the dashboard with flash codes and parameters.
// Only codes from flashMessages are ever rendered.
func dashboardFlash(w http.ResponseWriter, r *http.Request, q url.Values) {
	http.Redirect(w, r, dashboardPath+"?"+q.Encode(), http.StatusSeeOther)
}

// dashboardFlashManage redirects to the dashboard with a flash code about slug
// and reopens its access dialog.
func dashboardFlashManage(w http.ResponseWriter, r *http.Request, key, code, slug string) {
	dashboardFlash(w, r, url.Values{key: {code}, "manage": {slug}, "slug": {slug}})
}

// dashboardFlashView is the resolved toast text for one dashboard render.
type dashboardFlashView struct {
	Error       string
	Success     string
	UploadedURL string
}

// resolveFlash turns the flash codes in q into text. Placeholders are filled
// only from uploads the viewer can see on this dashboard; a code that is unknown,
// or that names an upload or grant the viewer cannot see, renders nothing.
func resolveFlash(q url.Values, list []dashUpload, baseURL string) dashboardFlashView {
	var out dashboardFlashView
	if code := q.Get("err"); code != "" {
		out.Error = flashText(code, q, list)
	}
	if code := q.Get("ok"); code != "" {
		out.Success = flashText(code, q, list)
	}
	if slug := q.Get("uploaded"); slug != "" {
		if u := findDashUpload(list, slug); u != nil {
			out.UploadedURL = baseURL + "/p/" + u.Slug
		}
	}
	return out
}

func flashText(code string, q url.Values, list []dashUpload) string {
	text, ok := flashMessages[code]
	if !ok {
		return ""
	}
	if !strings.Contains(text, "{") {
		return text
	}
	u := findDashUpload(list, q.Get("slug"))
	if u == nil {
		return ""
	}
	email := ""
	if strings.Contains(text, "{email}") {
		email = q.Get("email")
		if !dashUploadHasGrant(u, email) {
			return ""
		}
	}
	return strings.NewReplacer("{slug}", u.Slug, "{visibility}", u.Visibility, "{email}", email).Replace(text)
}

func findDashUpload(list []dashUpload, slug string) *dashUpload {
	if slug == "" {
		return nil
	}
	for i := range list {
		if list[i].Slug == slug {
			return &list[i]
		}
	}
	return nil
}

func dashUploadHasGrant(u *dashUpload, email string) bool {
	for _, g := range u.Grants {
		if email != "" && g.Email == email {
			return true
		}
	}
	return false
}

// grantFlashCode maps a normalizeGrantInput message to its flash code.
func grantFlashCode(msg string) string {
	switch msg {
	case "kind must be user or group":
		return flashGrantKind
	case "invalid email address":
		return flashGrantEmail
	case "group grants need Google group lookup; set PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL on the server":
		return flashGrantGroupLookup
	default:
		return flashGrantFailed
	}
}

func (s *Server) parseDashboardForm(w http.ResponseWriter, r *http.Request) bool {
	return s.parseForm(w, r, dashboardError)
}

func (s *Server) parseAdminForm(w http.ResponseWriter, r *http.Request) bool {
	return s.parseForm(w, r, adminError)
}

// parseForm parses r's form and checks its CSRF token, calling fail with the
// invalid-session flash code when either is bad.
func (s *Server) parseForm(w http.ResponseWriter, r *http.Request, fail func(http.ResponseWriter, *http.Request, string)) bool {
	if err := r.ParseForm(); err != nil {
		fail(w, r, flashInvalidSession)
		return false
	}
	validCSRF, err := s.validateCSRF(r, w, r.FormValue("csrf"))
	if err != nil {
		s.renderCSRFError(w, err)
		return false
	}
	if !validCSRF {
		fail(w, r, flashInvalidSession)
		return false
	}
	return true
}
