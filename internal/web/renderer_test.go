package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRendererExecutesAllTemplates(t *testing.T) {
	renderer, err := newRenderer(func(name string) string {
		return "/" + name + "?v=test"
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}

	cases := []struct {
		name string
		data any
		want string
	}{
		{
			name: TemplateSetup,
			data: SetupData{CSRF: "csrf", Code: "code"},
			want: "Create admin",
		},
		{
			name: TemplateLogin,
			data: LoginData{CSRF: "csrf", Providers: []AuthProvider{{Key: "github", Name: "GitHub"}}, PasswordLogin: true, OAuthEnabled: true},
			want: "Continue with GitHub",
		},
		{
			name: TemplateAPIKeyShown,
			data: APIKeyShownData{Title: "API key created", Name: "QA runner", Key: "peek_x"},
			want: "Copy it now. Peek stores only a hash and cannot show it again.",
		},
		{
			name: TemplateDashboard,
			data: DashboardData{
				CSRF:    "csrf",
				User:    "Admin",
				IsAdmin: true,
				Uploads: []DashboardUpload{{Slug: "abc123", Name: "page.html", SizeHuman: "1 KB", CreatedHuman: "2026-06-21 10:00"}},
			},
			want: "Upload HTML",
		},
		{
			name: TemplateAdmin,
			data: AdminData{
				CSRF:     "csrf",
				User:     "Admin",
				Invites:  []InviteDashboardRow{{ID: 1, Email: "person@example.com", Status: "pending", Expires: "2026-06-28 10:00", Link: "http://example.test/invite/token", CanRevoke: true}},
				Accounts: []AccountDashboardRow{{ID: 1, Name: "Admin", Email: "admin@example.com", Admin: true, IsSelf: true}},
			},
			want: "Settings",
		},
		{
			name: TemplateStats,
			data: StatsData{Slug: "abc123", Name: "page.html", TotalVisits: 2, UniqueVisitors: 1, Recent: []StatsVisit{{Name: "Ada", IP: "hash", UA: "test", WhenHuman: "2026-06-21 10:00"}}},
			want: "Recent visits",
		},
		{
			name: TemplatePage,
			data: PageData{Name: "page.html", Slug: "abc123", RawURL: "/raw/abc123?t=t&v=v", FrameURL: "/raw/abc123?t=t&v=v"},
			want: "sandbox=",
		},
		{
			name: TemplateIndex,
			data: IndexData{BaseURL: "http://localhost:7700"},
			want: "CLI quick start",
		},
		{
			name: TemplateError,
			data: ErrorData{Title: "Page not found", Message: "This shared page does not exist."},
			want: "Page not found",
		},
		{
			name: TemplateCLILogin,
			data: CLILoginData{Code: "ABCD-EFGH", CSRF: "csrf", User: "Admin", RequestIP: "203.0.113.7", UserAgent: "peek-cli/dev", RequestedAt: "2026-10-11 10:00:00 UTC", CurrentIP: "198.51.100.2"},
			want: "Only approve if you just ran",
		},
		{
			name: TemplateCLILoginEntry,
			data: CLILoginEntryData{CSRF: "csrf", User: "Admin"},
			want: `name="code"`,
		},
		{
			name: TemplateCLILoginDone,
			data: CLILoginDoneData{Title: "CLI login approved", Message: "Return to your terminal to continue."},
			want: "CLI login approved",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := renderer.Execute(tc.name, tc.data)
			if err != nil {
				t.Fatalf("execute %s: %v", tc.name, err)
			}
			if !strings.Contains(string(body), tc.want) {
				t.Fatalf("rendered %s without %q: %s", tc.name, tc.want, body)
			}
		})
	}
}

func TestStatsTemplateRendersSparkline(t *testing.T) {
	renderer, err := newRenderer(func(name string) string {
		return "/" + name + "?v=test"
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateStats, StatsData{
		Slug:           "abc123",
		Name:           "page.html",
		TotalVisits:    3,
		UniqueVisitors: 2,
		Sparkline: StatsSparkline{
			Summary:  "3 visits last 7 days",
			LinePath: "M 2.0 54.0 L 166.0 2.0",
			AreaPath: "M 2.0 54.0 L 166.0 2.0 L 166.0 54.0 L 2.0 54.0 Z",
			LastX:    "166.0",
			LastY:    "2.0",
		},
	})
	if err != nil {
		t.Fatalf("execute stats: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		"3 visits last 7 days",
		`aria-label="Visit trend for the last 7 days"`,
		`d="M 2.0 54.0 L 166.0 2.0"`,
		`cx="166.0"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("stats template missing %q: %s", want, html)
		}
	}
}

func TestPageTemplateUsesDatasetForViewerConfig(t *testing.T) {
	renderer, err := newRenderer(func(name string) string {
		return "/" + name + "?v=test"
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplatePage, PageData{Name: "page.html", Slug: "abc123", RawURL: "/raw/abc123/v/1?t=t&v=v", FrameURL: "/raw/abc123/v/1?t=t&v=v", Visibility: "password", Version: 1, LatestVersion: 3})
	if err != nil {
		t.Fatalf("execute page: %v", err)
	}
	html := string(body)
	if strings.Contains(html, `x-init="init(`) {
		t.Fatalf("page template should not call Alpine init with positional args: %s", html)
	}
	for _, want := range []string{
		`x-data="pageApp"`,
		`data-slug="abc123"`,
		`data-visibility="password"`,
		`data-version="1"`,
		`id="hn-version-banner"`,
		`Version 1 of 3`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("page template missing %q: %s", want, html)
		}
	}
}

func TestPageTemplateOmitsBannerOnLatestVersion(t *testing.T) {
	renderer, err := newRenderer(func(name string) string { return "/" + name })
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplatePage, PageData{Name: "p", Slug: "abc123", RawURL: "/raw/abc123/v/3", FrameURL: "/raw/abc123/v/3", Visibility: "public", Version: 3, LatestVersion: 3})
	if err != nil {
		t.Fatalf("execute page: %v", err)
	}
	if strings.Contains(string(body), "hn-version-banner") {
		t.Fatalf("latest version should not render the banner")
	}
}

func TestPageTemplateNameModalCanBeShownByAlpine(t *testing.T) {
	renderer, err := newRenderer(func(name string) string {
		return "/" + name + "?v=test"
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplatePage, PageData{Name: "page.html", Slug: "abc123", RawURL: "/raw/abc123?t=t&v=v", FrameURL: "/raw/abc123?t=t&v=v", Visibility: "public"})
	if err != nil {
		t.Fatalf("execute page: %v", err)
	}
	html := string(body)
	start := strings.Index(html, `<div id="hn-name-modal"`)
	if start < 0 {
		t.Fatalf("page template missing name modal: %s", html)
	}
	end := strings.Index(html[start:], ">")
	if end < 0 {
		t.Fatalf("name modal tag was not closed: %s", html[start:])
	}
	tag := html[start : start+end+1]
	if strings.Contains(tag, " hidden") {
		t.Fatalf("name modal must not use the hidden attribute because Alpine x-show cannot override it: %s", tag)
	}
	for _, want := range []string{`x-show="nameModalOpen"`, `x-cloak`} {
		if !strings.Contains(tag, want) {
			t.Fatalf("name modal tag missing %q: %s", want, tag)
		}
	}
}

func TestAdminInviteLinkRendersAsCopyAction(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateAdmin, AdminData{
		CSRF: "csrf",
		User: "Admin",
		Invites: []InviteDashboardRow{{
			ID:        1,
			Email:     "person@example.com",
			Status:    "pending",
			Expires:   "2026-06-28 10:00",
			Link:      "http://example.test/invite/token",
			CanRevoke: true,
		}},
	})
	if err != nil {
		t.Fatalf("execute admin: %v", err)
	}
	html := string(body)
	if !strings.Contains(html, `title="Copy invite link"`) || !strings.Contains(html, `data-url="http://example.test/invite/token"`) {
		t.Fatalf("admin invite did not render a copy action: %s", html)
	}
	if !strings.Contains(html, `<span class="peek-link-copy-text">http://example.test/invite/token</span>`) {
		t.Fatalf("admin invite did not render the link value in the copy control: %s", html)
	}
	if strings.Contains(html, `>Copy link</span>`) {
		t.Fatalf("admin invite should show the link value, not generic copy text: %s", html)
	}
	if strings.Contains(html, `<code`) {
		t.Fatalf("admin invite should not render the link in an unconstrained code element: %s", html)
	}
	if strings.Contains(html, `window.location.origin + url`) {
		t.Fatalf("admin invite copy should not concatenate origin onto absolute URLs: %s", html)
	}
}

func TestAdminGoogleOrgSwitchAndInvitations(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	render := func(googleOrg bool) string {
		body, err := renderer.Execute(TemplateAdmin, AdminData{
			CSRF:            "csrf",
			User:            "Admin",
			GoogleOrgSignup: googleOrg,
			Invites:         []InviteDashboardRow{{ID: 1, Email: "person@example.com", Status: "pending"}},
			SettingsPanel: DashboardSettings{Auth: AuthSettings{
				GoogleOrg: SettingRow{Key: "auth_google_org_signup", Label: "Google org sign-in"},
			}},
		})
		if err != nil {
			t.Fatalf("execute admin: %v", err)
		}
		return string(body)
	}
	off := render(false)
	if !strings.Contains(off, "Invitations") || !strings.Contains(off, `name="auth_google_org_signup"`) {
		t.Fatalf("mode off should show invitations and the switch: %s", off)
	}
	on := render(true)
	if !strings.Contains(on, `name="auth_google_org_signup"`) {
		t.Fatalf("mode on should still show the switch: %s", on)
	}
	if strings.Contains(on, "Invitations") || strings.Contains(on, "Create invite") {
		t.Fatalf("mode on should hide the invitations card: %s", on)
	}
}

func TestDashboardUploadFormShowsSelectedFileAndDisablesEmptySubmit(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateDashboard, DashboardData{
		CSRF: "csrf",
		User: "Admin",
	})
	if err != nil {
		t.Fatalf("execute dashboard: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		`x-on:submit="guardUploadSubmit($event)"`,
		`x-on:change="setSelectedFile($event.target.files && $event.target.files[0])"`,
		`x-text="fileName || 'Click to choose an HTML file'"`,
		`x-text="fileSizeLabel ? fileSizeLabel + ' selected' : 'File selected'"`,
		`x-model="html"`,
		`:disabled="!canUpload()"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard upload form missing %q: %s", want, html)
		}
	}
}

func TestDashboardRendersAccessDialogPerUpload(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateDashboard, DashboardData{
		CSRF:    "csrf",
		User:    "Admin",
		Uploads: []DashboardUpload{{Slug: "page", Name: "page.html", Visibility: "restricted"}},
	})
	if err != nil {
		t.Fatalf("execute dashboard: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		`action="/dashboard/visibility/page"`,
		`x-data="{ vis: 'restricted' }"`,
		`x-ref="visibilityDialog"`,
		`value="restricted" x-model="vis"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard access dialog missing %q: %s", want, html)
		}
	}
	if strings.Contains(html, `value="password"`) {
		t.Fatalf("dashboard offers a password option: %s", html)
	}
}

func TestLoginRendersTabsWithMultipleMethods(t *testing.T) {
	renderer, err := newRenderer(func(name string) string {
		return "/" + name + "?v=test"
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}

	body, err := renderer.Execute(TemplateLogin, LoginData{
		CSRF:          "csrf",
		PasswordLogin: true,
		TokenLogin:    true,
	})
	if err != nil {
		t.Fatalf("execute login: %v", err)
	}
	if got := strings.Count(string(body), `alt="Peek"`); got != 1 {
		t.Fatalf("login rendered %d logos, want 1: %s", got, body)
	}
	if !strings.Contains(string(body), `class="peek-login-tabs"`) {
		t.Fatalf("login did not render method tabs: %s", body)
	}
	if strings.Contains(string(body), `<span>token</span>`) {
		t.Fatalf("login rendered old stacked token separator: %s", body)
	}
}

func TestLoginRendersBrandedOAuthButtons(t *testing.T) {
	renderer, err := newRenderer(func(name string) string {
		return "/" + name + "?v=test"
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}

	body, err := renderer.Execute(TemplateLogin, LoginData{
		CSRF: "csrf",
		Providers: []AuthProvider{
			{Key: "google", Name: "Google"},
			{Key: "github", Name: "GitHub"},
			{Key: "oidc", Name: "SSO"},
		},
		PasswordLogin: true,
		OAuthEnabled:  true,
	})
	if err != nil {
		t.Fatalf("execute login: %v", err)
	}

	html := string(body)
	for _, want := range []string{
		`href="/oauth/google/start"`,
		`class="peek-oauth-button peek-oauth-button-google"`,
		`Continue with Google`,
		`href="/oauth/github/start"`,
		`class="peek-oauth-button peek-oauth-button-github"`,
		`Continue with GitHub`,
		`href="/oauth/oidc/start"`,
		`class="peek-oauth-button peek-oauth-button-oidc"`,
		`Continue with SSO`,
		`class="peek-oauth-logo" viewBox="0 0 18 18" aria-hidden="true"`,
		`class="peek-oauth-logo" viewBox="0 0 98 96" aria-hidden="true"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("login oauth button missing %q: %s", want, html)
		}
	}
	if got := strings.Count(html, `alt="Peek"`); got != 1 {
		t.Fatalf("login rendered %d Peek logos, want 1: %s", got, html)
	}
	oidcStart := strings.Index(html, `href="/oauth/oidc/start"`)
	if oidcStart < 0 {
		t.Fatalf("OIDC button missing: %s", html)
	}
	oidcEnd := strings.Index(html[oidcStart:], `</a>`)
	if oidcEnd < 0 {
		t.Fatalf("OIDC button not closed: %s", html[oidcStart:])
	}
	oidcButton := html[oidcStart : oidcStart+oidcEnd]
	if strings.Contains(oidcButton, `peek-oauth-logo`) {
		t.Fatalf("OIDC button should not render a provider logo: %s", oidcButton)
	}
}

func TestLoginInviteCopyIsClear(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateLogin, LoginData{
		CSRF:      "csrf",
		Invite:    true,
		Providers: []AuthProvider{{Key: "google", Name: "Google"}},
	})
	if err != nil {
		t.Fatalf("execute login: %v", err)
	}
	html := string(body)
	if !strings.Contains(html, "Accept your invite by signing in.") {
		t.Fatalf("login invite copy missing: %s", html)
	}
	if strings.Contains(html, "Choose a provider to accept your invite.") {
		t.Fatalf("login rendered confusing invite copy: %s", html)
	}
}

func TestAdminRendersSettingsTabsAndControls(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	google := OAuthProviderSettings{
		Key:          "google",
		Name:         "Google",
		Enabled:      SettingRow{Key: "oauth_google_enabled", Value: "true", Label: "Google login", Description: "Enable Google OAuth login"},
		ClientID:     SettingRow{Key: "oauth_google_client_id", Label: "Google client ID", Description: "OAuth web client ID"},
		ClientSecret: SettingRow{Key: "oauth_google_client_secret", Label: "Google client secret", Description: "OAuth web client secret", IsSecret: true},
		EnabledValue: true,
	}
	google.Fields = []SettingRow{google.ClientID, google.ClientSecret}
	github := OAuthProviderSettings{
		Key:          "github",
		Name:         "GitHub",
		Enabled:      SettingRow{Key: "oauth_github_enabled", Label: "GitHub login", Description: "Enable GitHub OAuth login"},
		ClientID:     SettingRow{Key: "oauth_github_client_id", Label: "GitHub client ID", Description: "OAuth app client ID"},
		ClientSecret: SettingRow{Key: "oauth_github_client_secret", Label: "GitHub client secret", Description: "OAuth app client secret", IsSecret: true},
	}
	github.Fields = []SettingRow{github.ClientID, github.ClientSecret}
	oidc := OAuthProviderSettings{
		Key:          "oidc",
		Name:         "SSO",
		Enabled:      SettingRow{Key: "oauth_oidc_enabled", Label: "SSO login", Description: "Enable generic OpenID Connect login"},
		ClientID:     SettingRow{Key: "oauth_oidc_client_id", Label: "SSO client ID", Description: "OpenID Connect client ID"},
		ClientSecret: SettingRow{Key: "oauth_oidc_client_secret", Label: "SSO client secret", Description: "OpenID Connect client secret", IsSecret: true},
	}
	oidc.Fields = []SettingRow{
		{Key: "oauth_oidc_issuer_url", Label: "SSO issuer URL", Description: "OpenID Connect issuer URL"},
		oidc.ClientID,
		oidc.ClientSecret,
	}
	body, err := renderer.Execute(TemplateAdmin, AdminData{
		CSRF: "csrf",
		User: "Admin",
		SettingsPanel: DashboardSettings{
			Auth: AuthSettings{
				Token:     SettingRow{Key: "auth_token_login_enabled", Value: "true", Label: "Access token login", Description: "Allow token login"},
				Domain:    SettingRow{Key: "auth_allowed_email_domain", Value: "example.com", Label: "Allowed email domain", Description: "Restrict login by domain"},
				Google:    google,
				GitHub:    github,
				OIDC:      oidc,
				Providers: []OAuthProviderSettings{google, github, oidc},
			},
			Storage: StorageSettings{
				Backend:    SettingRow{Key: "storage", Value: "s3", Label: "Storage backend", Description: "file or s3", IsStartup: true},
				Value:      "s3",
				S3Selected: true,
				S3Settings: []SettingRow{{Key: "s3_endpoint", Label: "S3 endpoint URL", Description: "S3-compatible endpoint"}},
			},
			Limits: []LimitSetting{{
				Key: "max_upload", FormKey: "max_upload_mb", JSKey: "maxUpload",
				Label: "Max upload size", Description: "Maximum size per HTML file upload",
				Unit: "MB", Value: 2, Min: 1, Max: 1024, Step: 1,
			}},
		},
	})
	if err != nil {
		t.Fatalf("execute admin: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		`settingsTab === 'auth'`,
		`settingsTab === 'storage'`,
		`settingsTab === 'limits'`,
		`name="auth_allowed_email_domain"`,
		`value="example.com"`,
		`name="oauth_google_enabled"`,
		`name="oauth_github_enabled"`,
		`name="oauth_oidc_enabled"`,
		`name="oauth_oidc_issuer_url"`,
		`x-show="oauth.google"`,
		`:disabled="!oauth.github"`,
		`:disabled="!oauth.oidc"`,
		`name="storage" value="file"`,
		`name="storage" value="s3"`,
		`type="number" name="max_upload_mb"`,
		`>MB</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("admin settings controls missing %q: %s", want, html)
		}
	}
	if strings.Contains(html, `type="range"`) || strings.Contains(html, `peek-range-input`) {
		t.Fatalf("admin limits should render compact number inputs, not sliders: %s", html)
	}
	if !strings.Contains(html, `name="storage" value="s3" x-model="storageBackend" checked`) {
		t.Fatalf("s3 storage radio was not checked: %s", html)
	}
}

func TestDashboardRendersGenericAndUploadFlashesSeparately(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateDashboard, DashboardData{
		CSRF:             "csrf",
		User:             "Admin",
		FlashSuccess:     "settings saved",
		UploadSuccessURL: "http://example.test/p/page",
	})
	if err != nil {
		t.Fatalf("execute dashboard: %v", err)
	}
	html := string(body)
	if !strings.Contains(html, "settings saved") {
		t.Fatalf("dashboard did not render generic success: %s", html)
	}
	if !strings.Contains(html, "Uploaded! Share link:") || !strings.Contains(html, "http://example.test/p/page") {
		t.Fatalf("dashboard did not render upload success: %s", html)
	}
	for _, want := range []string{
		`data-peek-toast data-toast-type="success" data-toast-message="settings saved"`,
		`data-peek-toast data-toast-type="success" data-toast-message="Uploaded! Share link:" data-toast-description="http://example.test/p/page"`,
		`x-data="peekToasts"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard flash did not render toast marker %q: %s", want, html)
		}
	}
	if strings.Contains(html, `data-url="settings saved"`) {
		t.Fatalf("generic success rendered as copyable upload URL: %s", html)
	}
	if strings.Contains(html, `Uploaded! Share link:</span>`) {
		t.Fatalf("dashboard rendered old inline upload flash instead of toast marker: %s", html)
	}
}

func TestPageTemplateToolbarCanBeHidden(t *testing.T) {
	renderer, err := newRenderer(func(name string) string {
		return "/" + name + "?v=test"
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplatePage, PageData{Name: "page.html", Slug: "abc123", RawURL: "/raw/abc123?t=t&v=v", FrameURL: "/raw/abc123?t=t&v=v", Visibility: "public"})
	if err != nil {
		t.Fatalf("execute page: %v", err)
	}
	html := string(body)
	start := strings.Index(html, `<div id="hn-bar"`)
	if start < 0 {
		t.Fatalf("page template missing toolbar: %s", html)
	}
	end := strings.Index(html[start:], ">")
	if end < 0 {
		t.Fatalf("toolbar tag was not closed: %s", html[start:])
	}
	tag := html[start : start+end+1]
	if !strings.Contains(tag, `x-show="!barHidden"`) {
		t.Fatalf("toolbar must be hideable with Alpine x-show: %s", tag)
	}
	if strings.Contains(tag, "x-cloak") {
		t.Fatalf("toolbar must render visible before Alpine boots: %s", tag)
	}
	for _, want := range []string{`id="hn-hide-btn"`, `@click="hideBar"`, `title="Hide toolbar (Shift+H)"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("page template missing %q", want)
		}
	}
}

func TestDashboardAccessDialogShowsGrantHintWhenNotRestricted(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateDashboard, DashboardData{
		CSRF:    "csrf",
		User:    "Admin",
		Uploads: []DashboardUpload{{Slug: "page", Visibility: "public"}},
	})
	if err != nil {
		t.Fatalf("execute dashboard: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		"Grants apply once you save Restricted above.",
		"Only you and admins can open this page until you share it.",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}
}

func TestDashboardRendersRenameFormAndSafeDeleteConfirm(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateDashboard, DashboardData{
		CSRF:    "csrf",
		User:    "Admin",
		Uploads: []DashboardUpload{{Slug: "page", Name: "it's <b>", Visibility: "public"}},
	})
	if err != nil {
		t.Fatalf("execute dashboard: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		`action="/dashboard/rename/page"`,
		`name="name" value="it&#39;s &lt;b&gt;"`,
		`data-confirm="Delete it&#39;s &lt;b&gt;? This cannot be undone."`,
		`x-on:submit="confirm($event, $el.dataset.confirm)"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard missing %q: %s", want, html)
		}
	}
	if strings.Contains(html, `'Delete it`) {
		t.Fatalf("dashboard embeds the name in an Alpine string: %s", html)
	}
}

func TestDashboardTemplateRendersAPIKeys(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateDashboard, DashboardData{
		CSRF: "csrf",
		User: "u",
		APIKeys: []DashboardAPIKey{{
			ID: 7, Name: "QA runner", Hint: "…a1b2", Created: "2026-10-01 10:00", LastUsed: "Never", Expires: "Never",
		}},
	})
	if err != nil {
		t.Fatalf("execute dashboard: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		`action="/dashboard/api-keys/7/regenerate"`,
		`action="/dashboard/api-keys/7/revoke"`,
		"…a1b2",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}
	body, err = renderer.Execute(TemplateDashboard, DashboardData{CSRF: "csrf", User: "u"})
	if err != nil {
		t.Fatalf("execute empty dashboard: %v", err)
	}
	if !strings.Contains(string(body), "No API keys yet.") {
		t.Fatal("empty dashboard missing placeholder")
	}
}

func TestPageTemplateShowsVerifiedCommentMarker(t *testing.T) {
	renderer, err := newRenderer(func(name string) string {
		return "/" + name + "?v=test"
	})
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplatePage, PageData{Name: "page.html", Slug: "abc123", RawURL: "/raw/abc123/v/1", FrameURL: "/raw/abc123/v/1", Visibility: "public", Version: 1, LatestVersion: 1})
	if err != nil {
		t.Fatalf("execute page: %v", err)
	}
	html := string(body)
	for _, want := range []string{`hn-comment-verified`, `x-show="c.verified"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("page template missing %q", want)
		}
	}
}

func TestNewRendererNilAssetPathUsesDefault(t *testing.T) {
	r, err := newRenderer(nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := r.Execute(TemplateIndex, IndexData{BaseURL: "http://h"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "http://h") {
		t.Fatalf("body missing base url")
	}
}

func TestExecuteUninitializedAndUnknown(t *testing.T) {
	for _, r := range []*Renderer{nil, {}} {
		if _, err := r.Execute(TemplateIndex, nil); err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Fatalf("err = %v", err)
		}
	}
	r, err := NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Execute("no-such-template", nil); err == nil || !strings.Contains(err.Error(), "render no-such-template") {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderHTML(t *testing.T) {
	r, err := NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := r.RenderHTML(rec, 418, TemplateError, ErrorData{Title: "T", Message: "M"}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 418 || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(rec.Body.String(), "M") {
		t.Fatalf("code=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = httptest.NewRecorder()
	if err := r.RenderHTML(rec, 200, "no-such-template", nil); err == nil {
		t.Fatal("expected error")
	}
	if rec.Body.Len() != 0 {
		t.Fatal("nothing should be written on render error")
	}
}

func TestAdminRendersBackendsTab(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	render := func(b BackendSettings) string {
		body, err := renderer.Execute(TemplateAdmin, AdminData{CSRF: "csrf", User: "Admin", SettingsPanel: DashboardSettings{Backends: b}})
		if err != nil {
			t.Fatalf("execute admin: %v", err)
		}
		return string(body)
	}
	empty := render(BackendSettings{})
	if !strings.Contains(empty, "settingsTab === 'backends'") || !strings.Contains(empty, "Backends are off. Start peekd with --backends docker") {
		t.Fatalf("empty backends tab wrong: %s", empty)
	}
	on := render(BackendSettings{Enabled: true, Fields: []SettingRow{{Key: "backend_registry_password", Label: "Registry password", IsSecret: true}}})
	if strings.Contains(on, "Backends are off") || !strings.Contains(on, `type="password" name="backend_registry_password"`) {
		t.Fatalf("enabled backends tab wrong: %s", on)
	}
}

func TestAdminProvisionersCardRenders(t *testing.T) {
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	body, err := renderer.Execute(TemplateAdmin, AdminData{
		CSRF: "csrf",
		User: "Admin",
		Accounts: []AccountDashboardRow{
			{ID: 1, Name: "Alice", Email: "a@x.test", ManagedBy: "PrivacyFence"},
			{ID: 2, Name: "Bob", Email: "b@x.test"},
		},
		Provisioners: []ProvisionerDashboardRow{{ID: 4, Name: "PrivacyFence", Hint: "abcd", Created: "2026-01-02T03:04:05Z", LastUsed: "never", Accounts: 3}},
	})
	if err != nil {
		t.Fatalf("execute admin: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		"PrivacyFence", "…abcd", "2026-01-02T03:04:05Z", "never",
		`action="/dashboard/provisioners/4/revoke"`, `name="csrf" value="csrf"`,
		"Managed by PrivacyFence",
		"Create a provisioning key with peek provisioner create --name &lt;name&gt;. Revoking a key signs every account it manages out of that system; the accounts and their pages stay.",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("admin page missing %q: %s", want, html)
		}
	}
	if strings.Contains(html, "No provisioning keys.") || strings.Count(html, "Managed by") != 1 {
		t.Fatalf("unexpected empty text or badge count: %s", html)
	}

	empty, err := renderer.Execute(TemplateAdmin, AdminData{CSRF: "csrf", User: "Admin"})
	if err != nil || !strings.Contains(string(empty), "No provisioning keys.") {
		t.Fatalf("empty state missing: %v", err)
	}
}
