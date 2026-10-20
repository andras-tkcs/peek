# Google-only org sign-in without invites

## Goal

Add one admin setting, `auth_google_org_signup`, that turns Peek into a "Google sign-in for the whole organization" server. With it on, anyone who signs in with a Google Workspace account whose verified email is in the allowed email domain (`auth_allowed_email_domain`) gets a Peek account created on their first sign-in. No invite link is needed and nothing is emailed. Google is the only identity provider while the mode is on: the GitHub and generic OIDC providers are inactive, and non-admin password and token login stay disabled, exactly as they are today whenever any OAuth provider is enabled. Admins keep their local password form as the recovery path. The mode cannot be saved unless Google login is configured and an allowed domain is set.

This replaces the invite-link workflow for companies that only use Google Workspace. Peek has no SMTP and no email sending, so the old invite flow needed an admin to copy a link and send it by hand.

## Current state

- OAuth signup is invite-only. `resolveOAuthAccount` in `internal/server/oauth_accounts.go:13` links an existing identity or an existing account with the same verified email, and otherwise requires a pending invite from the `hn_invite` cookie (`internal/server/oauth_accounts.go:48-69`); without it the error is `invite required`.
- Invites are created by `handleDashboardCreateInvite` (`internal/server/admin.go:36`), opened through `handleInviteLink` (`internal/server/admin.go:18`, route `GET /invite/{token}` in `internal/server/routes.go:70`) and listed by `dashboardInviteRows` (`internal/server/admin.go:152`). The dashboard shows them in the "Invitations" card of `internal/web/templates/dashboard.gohtml` (starts near line 241).
- Providers are Google, GitHub and OIDC. `enabledOAuthProviders` (`internal/server/oauth_config.go:48`) lists the configured ones through `oauthProviderMetadata` (`internal/server/oauth_config.go:59`); `oauthProviderConfig` (`internal/server/oauth_config.go:82`) builds the real config for the start and callback handlers (`internal/server/oauth_flow.go:14` and `:49`). `oauthLoginRequired` (`internal/server/web_login.go:164`) is true when at least one provider is enabled, and it is what disables non-admin password login (`internal/server/web_login.go:133`), token login (`internal/server/web_login.go:154`) and, through `accountActive` (`internal/server/account_policy.go:30`), dashboard sessions and API tokens of accounts that never linked an OAuth identity. `accountActive` accepts a linked identity of any provider.
- The allowed email domain is checked by `accountAllowedByEmailDomain` (`internal/server/auth_domain.go:58`) and is already applied to OAuth login, so a Google profile with an email outside the domain is refused with `errAccountNotEligible` before any account is created. `validateAllowedEmailDomainUpdate` (`internal/server/auth_domain.go:62`) refuses a domain no active admin matches.
- The Google profile comes from the ID token in `fetchGoogleProfile` (`internal/server/oauth_profile.go:59`); it reads `sub`, `email`, `email_verified` and `name` but not `hd`, the claim Google sets for Workspace-managed accounts.
- Settings are declared in `settingsMeta` (`internal/server/settings.go:20`), validated by `normalizeSettingValue` (`internal/server/settings.go:106`) and saved by two handlers that both call `validateAllowedEmailDomainUpdate` before writing: the API handler `handleUpdateSettings` (`internal/server/settings.go:72`) and the dashboard form handler `handleDashboardSettings` (`internal/server/settings.go:213`). The dashboard handler submits every boolean setting on each save (an unchecked box is saved as empty). The dashboard Auth tab is rendered from `dashboardSettingsPanel` (`internal/server/settings.go:325`) and the row order list in `dashboardSettingsRows` (`internal/server/settings.go:472`) into `internal/web/templates/dashboard.gohtml`.
- There is no email-sending code anywhere (`grep -rn smtp --include=*.go` is empty).

## Design

### Setting

- Key: `auth_google_org_signup`. Constant `authGoogleOrgSignupSetting` in a new file `internal/server/auth_google_org.go`. Boolean, stored as `"true"` or `""`, read with `s.settingBool`. Off by default; no entry in `initDefaultSettings`.
- `settingsMeta` entry: Label `Google org sign-in`, Description `Only Google sign-in for everyone in the allowed email domain. The first sign-in creates the account; no invite needed. Requires Google login and an allowed email domain.`, `IsBool: true`.
- `func (s *Server) googleOrgSignupEnabled(ctx context.Context) bool` returns `s.settingBool(ctx, authGoogleOrgSignupSetting)`.

### Validation

`func (s *Server) validateGoogleOrgSignupUpdate(ctx context.Context, updates map[string]string) error` in `internal/server/auth_google_org.go`.

1. If `updates` contains none of these keys, return nil: `auth_google_org_signup`, `auth_allowed_email_domain`, `oauth_google_enabled`, `oauth_google_client_id`, `oauth_google_client_secret`.
2. Build the effective value of each of those keys: the value in `updates` when present, otherwise the stored value from `s.encryptedGetAllSettings(ctx)` (secrets come back decrypted). A lookup error returns `errors.New("settings lookup failed")`.
3. If the effective `auth_google_org_signup` is not true (use `settingValueBool`, already in `internal/server`), return nil.
4. Otherwise check, in this order, and return the first failure:
   - effective domain is empty: `auth_google_org_signup requires auth_allowed_email_domain`
   - effective domain is `gmail.com` or `googlemail.com`: `auth_google_org_signup cannot be used with a consumer Google domain`
   - effective `oauth_google_enabled` is not true, or client id or client secret is empty after trimming: `auth_google_org_signup requires Google login with client credentials`

Both settings handlers call it right after `validateAllowedEmailDomainUpdate`, with the same error handling (API: `jsonError(w, http.StatusBadRequest, err.Error())`; dashboard: `s.renderDashboard(w, r, owner, http.StatusBadRequest, nil, err.Error())`). Because it also runs when only the domain or the Google credentials change, an admin cannot clear the domain, disable Google or blank the Google client ID while the mode is on.

### Google-only providers

While `googleOrgSignupEnabled` is true, `oauthProviderMetadata` and `oauthProviderConfig` return the error `fmt.Errorf("%s oauth is disabled while Google org sign-in is on", key)` for any key other than `google`, before looking at that provider's settings. That one change hides the GitHub and SSO buttons, closes `/oauth/github/*` and `/oauth/oidc/*`, and drops them from `/api/auth/providers` (`enabledOAuthProviders` skips providers whose metadata errors). Their stored settings are kept so turning the mode off restores them. `oauthLoginRequired` (`internal/server/web_login.go:164`) additionally returns true whenever `googleOrgSignupEnabled` is true, even if the Google provider cannot be loaded (for example its stored secret no longer decrypts), so non-admin password login, token login and password-only accounts stay refused and never silently come back. The admin password form stays on the login page. `loginData` (`internal/server/web_login.go`) sets `Invite` only when the `hn_invite` cookie exists and the mode is off, so a stale invite cookie shows no invite banner.

Accounts that already linked a GitHub or SSO identity keep working while the mode is on (`accountActive` accepts any linked identity); this plan does not change that, and the docs say so. Likewise deleting someone in Google Workspace does not disable their Peek account or API keys; an admin disables the account in Peek.

### Auto-provisioning

`resolveOAuthAccount` (`internal/server/oauth_accounts.go`) gets a new guard directly after its existing domain check (the `accountAllowedByEmailDomain` test at the top, `internal/server/oauth_accounts.go:17-19`) and before the linked-identity lookup, so it covers all later branches including an existing account that is matched by email:

```go
if s.googleOrgSignupEnabled(r.Context()) {
	if err := s.checkGoogleOrgProfile(r.Context(), profile); err != nil {
		return nil, err
	}
}
```

`func (s *Server) checkGoogleOrgProfile(ctx context.Context, profile *oauthProfile) error` in `internal/server/oauth_accounts.go`:

1. `profile.Provider != "google"` returns `errAccountNotEligible`.
2. `s.allowedEmailDomain(ctx) == ""` returns `errAccountNotEligible` (fail closed; the domain check above passes everything when no domain is set).
3. `profile.HostedDomain == ""` returns `errGoogleWorkspaceRequired`. The new variable is `errGoogleWorkspaceRequired = errors.New("google workspace account required")`. This rejects personal Google accounts that merely carry a work email address, including ones that would otherwise match an existing Peek account (an ex-employee's personal account that kept the address). The `hd` value itself is not compared with the allowed domain, because a Workspace with secondary domains reports its primary domain as `hd`; the email-domain check already pins the address to the allowed domain.
4. Otherwise nil.

The existing branches (linked identity, existing account by email) then run unchanged. Immediately before the `inviteToken := ""` line a final block replaces the invite lookup when the mode is on:

```go
if s.googleOrgSignupEnabled(r.Context()) {
	return s.provisionGoogleOrgAccount(r.Context(), profile)
}
```

`func (s *Server) provisionGoogleOrgAccount(ctx context.Context, profile *oauthProfile) (*models.Account, error)`:

1. `s.store.CreateAccount(ctx, profile.Email, profile.Name, false)`. If it fails, look the account up again with `s.store.GetAccountByEmail`; when that finds one that is not disabled, return it (two first sign-ins racing on the unique email); otherwise return `errors.New("account creation failed")`.
2. `s.audit("account provisioned %s", auditDetail("provider", "google", "email", account.Email))`, then return the account. New accounts are never admins.

`oauthProfile` gains `HostedDomain string`. `fetchGoogleProfile` reads the `hd` claim (`HD string \`json:"hd"\``) and sets `HostedDomain: strings.ToLower(strings.TrimSpace(claims.HD))`. The other providers leave it empty.

`oauthAccountErrorMessage` (`internal/server/oauth_flow.go:113`) gains two cases, which apply in every mode, not only Google org mode (a deliberate change: the user should learn why a domain refusal happened; it is not an internal failure): `"account not eligible"` returns `This email address is not allowed to sign in.` and `"google workspace account required"` returns `Sign in with your Google Workspace account.`

`handleOAuthStart` (`internal/server/oauth_flow.go:14`): when `p.Key == "google"`, the mode is on and the allowed domain is non-empty, append `oauth2.SetAuthURLParam("hd", domain)` to `opts` so Google's account chooser prefers that domain. It is a hint only; the server-side checks above are the enforcement.

### Invites while the mode is on

- `handleDashboardCreateInvite` (`internal/server/admin.go`): when the mode is on, `dashboardError(w, r, flashInviteNotUsed)` after the admin check and form parse and before the email checks. New flash code `flashInviteNotUsed = "invite_not_used"` with message `invites are not used while Google org sign-in is on` in `internal/server/web_helpers.go` (the error map near line 82).
- `handleInviteLink` (`internal/server/admin.go`): when the mode is on, `http.Redirect(w, r, "/login", http.StatusSeeOther)` without setting the invite cookie.
- Existing invites and the `invites` table are untouched, so turning the mode off brings them back.

### Dashboard

- `internal/web/renderer.go`: `AuthSettings` gains `GoogleOrg SettingRow`; `DashboardData` gains `GoogleOrgSignup bool`.
- `dashboardSettingsPanel` (`internal/server/settings.go`) sets `GoogleOrg: dashboardSettingRow(raw, authGoogleOrgSignupSetting)`. `renderDashboard` (`internal/server/web_dashboard.go`) sets `GoogleOrgSignup: s.googleOrgSignupEnabled(r.Context())`.
- `dashboard.gohtml`: in the Auth tab, directly after the "Allowed email domain" label and before the provider list, a switch built exactly like the "Access token login" switch (`peek-setting-switch`), bound to `.SettingsPanel.Auth.GoogleOrg`. The whole "Invitations" card (`<div>` that starts with `<h2 ...>Invitations`) is wrapped in `{{if not .GoogleOrgSignup}}...{{end}}`.
- The login page template needs no change: it already shows only the enabled providers plus the "Admin sign in" password form when OAuth is on.

### Rejected alternatives

- A new `auth_mode` enum setting: a boolean on top of the existing Google settings is enough and keeps the existing provider settings meaningful.
- Rejecting `gmail.com` and `googlemail.com` is defence in depth only: the `hd` requirement already excludes consumer accounts, so nobody should rely on the domain rule alone.
- Comparing `hd` with the allowed domain: breaks Workspaces that use a secondary domain for email addresses.
- Requiring only a verified email in the domain, without `hd`: lets a personal Google account that registered an existing work address sign in; Workspace membership is the stronger statement for "everyone from the org".
- Sending invite emails over SMTP: a new dependency and a new secret for something the domain rule already makes unnecessary.

## ADRs

The repository has no ADR directory (`docs.adr_dir` is not set in `.claude/toolkit.yaml`), so there are none.

## Manual steps

There are no steps before implementation: every phase tests against a fake Google issuer. After implementation, two checks need a real Google Workspace and a real Google Cloud OAuth client: creating that client, and signing in with an org account and with a personal account. They are listed in the step-by-step page, https://claude.ai/artifact/GuDBtWBvhLR4DnAGgy4gfg (source `docs/plans/google-org-signup-plan-manual-steps.html`), and go unchecked into the PR body.

## Risks and open questions

- `settingValueBool` is used by `dashboardOAuthProviderSettings` in `internal/server/settings.go`. If it does not treat `"true"` as true, stop with `status=blocked` and report its actual behaviour; do not write a second helper.
- The dashboard handler submits every boolean on each save, so enabling `auth_google_org_signup` and `oauth_google_enabled` in one form post must validate against the merged values (the plan's `updates` overlay). A test covers this; if the merged check rejects a valid combination, stop.
- `internal/web/renderer_test.go` and `internal/server/web_dashboard_test.go` may assert exact dashboard HTML. If an existing test fails only because the Invitations card or a new switch appears or disappears, update that assertion; if it fails for any other reason, stop.
- `oauthAccountErrorMessage` currently maps `account not eligible` to the generic message. If an existing test pins that, update it to the new message (the plan intends the change).
- Operators who set the mode with an allowed domain that is not their Workspace primary or secondary domain simply lock everyone out. The allowed domain must match an active admin email (`validateAllowedEmailDomainUpdate`) and admins outside the domain are refused even with a password, so the last phase documents the order: make sure an active admin has an email in the domain, then set the domain, then turn the mode on.

## Implementation manifest

```yaml
plan_slug: google-org-signup
feature_branch: feat/google-org-signup
max_parallel: 2
manual_steps_artifact: https://claude.ai/artifact/GuDBtWBvhLR4DnAGgy4gfg
manual_steps_source: docs/plans/google-org-signup-plan-manual-steps.html
manual_before: []
manual_after:
  - id: ma1-google-oauth-client
    title: Create the Google OAuth client and enable Google org sign-in
    why: CI uses a fake Google issuer; only a real client proves the redirect URI, consent screen and the hd claim work against Google.
  - id: ma2-real-sign-in
    title: Sign in with an org account and a personal account
    why: Confirms auto-provisioning without an invite, rejection of accounts outside the org, and that the admin password form still works.
verify_after_merge:
  - go build ./...
  - go test -count=1 ./internal/server/... ./internal/web/... -run 'GoogleOrg|OAuth|Invite|Dashboard|Settings|Login'
final_checks:
  - docs/plans/google-org-signup-plan.md and docs/plans/google-org-signup-plan-manual-steps.html are deleted and nothing links to them
  - grep -rn auth_google_org_signup docs/src/content/docs/auth-access.md docs/src/content/docs/reference.md docs/operations.md README.md skills/peek-server/SKILL.md matches in every file
phases:
  - id: p1-setting-and-validation
    title: Add the auth_google_org_signup setting, its validation and Google-only providers
    depends_on: []
    complexity: S
    touches:
      - internal/server/auth_google_org.go
      - internal/server/auth_google_org_test.go
      - internal/server/settings.go
      - internal/server/oauth_config.go
      - internal/server/web_login.go
    brief: |
      Read the Design sections "Setting", "Validation", "Google-only providers" of docs/plans/google-org-signup-plan.md first.
      1. Create internal/server/auth_google_org.go (package server). Add `const authGoogleOrgSignupSetting = "auth_google_org_signup"`, `func (s *Server) googleOrgSignupEnabled(ctx context.Context) bool` (returns s.settingBool(ctx, authGoogleOrgSignupSetting)) and `func (s *Server) validateGoogleOrgSignupUpdate(ctx context.Context, updates map[string]string) error` exactly as specified in "Validation", with the three exact error strings. Use the unexported var `googleOrgRelatedSettings = []string{authGoogleOrgSignupSetting, authAllowedEmailDomainSetting, "oauth_google_enabled", "oauth_google_client_id", "oauth_google_client_secret"}` for step 1 of the validation. Use `settingValueBool` (internal/server/settings.go) for boolean values.
      2. In internal/server/settings.go add the settingsMeta entry for authGoogleOrgSignupSetting with the exact Label and Description from the Design and `IsBool: true`, and add `authGoogleOrgSignupSetting` to the `order` slice in dashboardSettingsRows directly after `authAllowedEmailDomainSetting`.
      3. In internal/server/settings.go call `s.validateGoogleOrgSignupUpdate(r.Context(), updates)` directly after each of the two existing `s.validateAllowedEmailDomainUpdate(...)` calls (handleUpdateSettings and handleDashboardSettings), copying that call's error handling.
      4. In internal/server/oauth_config.go add the guard from "Google-only providers" as the first statement after `key = strings.ToLower(strings.TrimSpace(key))` in both oauthProviderMetadata and oauthProviderConfig: `if key != "google" && s.googleOrgSignupEnabled(ctx) { return ..., fmt.Errorf("%s oauth is disabled while Google org sign-in is on", key) }` (return `authProvider{}` and `nil` respectively).
      5. In internal/server/web_login.go change oauthLoginRequired to `return s.googleOrgSignupEnabled(ctx) || len(s.enabledOAuthProviders(ctx)) > 0` and in loginData set `Invite: inviteErr == nil && !s.googleOrgSignupEnabled(r.Context())`.
      6. Create internal/server/auth_google_org_test.go. Use newTestServer (internal/server/oauth_test.go:30). Prepare settings with `s.store.SetSetting` for plain keys but with `s.encryptedSetSetting(ctx, key, value)` for `oauth_google_client_secret` and the other client secrets (a plaintext secret written with SetSetting decrypts to an empty string; see internal/server/settings_test.go:306 for the pattern). Use `https://8.8.8.8/oidc` as the OIDC issuer so normalizeOIDCIssuerURL does no DNS lookup. Tests: TestGoogleOrgValidateUpdate (table: mode off returns nil whatever else is set; mode on with no domain; with gmail.com; with googlemail.com; with domain but Google disabled; with Google enabled but empty client secret; fully valid; an update that clears the domain while the stored mode is on; an update that sets only auth_google_org_signup=true while the stored domain and Google settings are valid), TestGoogleOrgOnlyGoogleProviderWhileEnabled (enable google, github and oidc with client id and secret and the oidc issuer; with the mode off enabledOAuthProviders returns three providers; with it on it returns exactly google, and oauthProviderConfig(ctx, "github") returns an error), TestGoogleOrgLoginStillRequiredWhenGoogleUnloadable (mode on, Google client secret blank: oauthLoginRequired is true and enabledOAuthProviders is empty; with the mode off it is false), TestGoogleOrgLoginIgnoresStaleInviteCookie (loginData with an hn_invite cookie has Invite true with the mode off and false with it on), TestGoogleOrgSettingsAPIRejectsInvalid (copy the request building of TestUpdateSettingsRejectsInvalidValuesBeforeWriting in internal/server/settings_test.go: setting auth_google_org_signup=true with no domain returns 400 and does not write the key), TestGoogleOrgDashboardSettingsRejectsInvalid (the same through handleDashboardSettings, copying TestDashboardSettingsRejectsInvalidValuesBeforeWriting) and TestGoogleOrgDashboardSettingsAcceptsCombinedEnable (one dashboard form post that sets auth_google_org_signup, oauth_google_enabled, oauth_google_client_id, an empty oauth_google_client_secret while a secret is already stored, and the domain; expects 303 and the stored value "true").
      7. Run `gofmt -l internal/server` (must print nothing), `go test ./internal/server -run '^TestGoogleOrg' -count=1`, then `mise run check-full` (settings and auth code changed).
      Stop with status=blocked if settingValueBool does not exist or if the two settings handlers no longer call validateAllowedEmailDomainUpdate at the places named in "Current state".
    acceptance:
      - go test ./internal/server -run '^TestGoogleOrgValidateUpdate$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgOnlyGoogleProviderWhileEnabled$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgLoginStillRequiredWhenGoogleUnloadable$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgLoginIgnoresStaleInviteCookie$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgSettingsAPIRejectsInvalid$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgDashboardSettingsRejectsInvalid$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgDashboardSettingsAcceptsCombinedEnable$' -count=1 passes
      - grep -c 'validateGoogleOrgSignupUpdate' internal/server/settings.go prints 2
      - mise run check-full passes
  - id: p2-provisioning-and-invites
    title: Auto-provision Google org accounts and retire invites while the mode is on
    depends_on: [p1-setting-and-validation]
    complexity: M
    touches:
      - internal/server/oauth_profile.go
      - internal/server/oauth_accounts.go
      - internal/server/oauth_flow.go
      - internal/server/oauth_flow_test.go
      - internal/server/oauth_test.go
      - internal/server/admin.go
      - internal/server/web_helpers.go
      - internal/server/auth_google_org_signup_test.go
    brief: |
      Read the Design sections "Auto-provisioning" and "Invites while the mode is on" of docs/plans/google-org-signup-plan.md first. p1 already added googleOrgSignupEnabled in internal/server/auth_google_org.go.
      1. internal/server/oauth_profile.go: add `HostedDomain string` to oauthProfile; in fetchGoogleProfile add `HD string \`json:"hd"\`` to the claims struct and set `HostedDomain: strings.ToLower(strings.TrimSpace(claims.HD))` in the returned profile.
      2. internal/server/oauth_accounts.go: add `var errGoogleWorkspaceRequired = errors.New("google workspace account required")`, add checkGoogleOrgProfile and provisionGoogleOrgAccount exactly as specified, insert the checkGoogleOrgProfile guard directly after the existing accountAllowedByEmailDomain check at the top of resolveOAuthAccount, and insert the provisionGoogleOrgAccount block immediately before `inviteToken := ""`. Keep every other branch unchanged. Use `s.audit(...)` and `auditDetail(...)` the way internal/server/admin.go does for "invite created".
      3. internal/server/oauth_flow.go: in oauthAccountErrorMessage add the two cases from the Design (`account not eligible`, `google workspace account required`) with the exact message strings; in handleOAuthStart append the `hd` auth URL option as specified (use `s.allowedEmailDomain(r.Context())`).
      4. internal/server/web_helpers.go: add `flashInviteNotUsed = "invite_not_used"` next to flashInviteFailed and its message `invites are not used while Google org sign-in is on` in the error message map next to flashInviteFailed.
      5. internal/server/admin.go: in handleDashboardCreateInvite, directly after the form parse and before the email checks, `dashboardError(w, r, flashInviteNotUsed); return` when s.googleOrgSignupEnabled is true; at the top of handleInviteLink redirect to /login with http.StatusSeeOther when it is true.
      6. Update existing tests for the intentional message change: internal/server/oauth_test.go TestOAuthAccountErrorMessageHidesInternalFailures (line ~185): the `errAccountNotEligible` case now wants "This email address is not allowed to sign in."; and extend TestOAuthCovAccountErrorMessages in internal/server/oauth_flow_test.go with both new messages.
      7. Tests in the new file internal/server/auth_google_org_signup_test.go. Use newTestServer; for settings use s.store.SetSetting except `s.encryptedSetSetting` for client secrets; for admin request helpers use newAdminTestServer (internal/server/admin_test.go:103), dashboardPost and assertDashboardRedirect (internal/server/web_dashboard_test.go:459 and :474). Tests: TestGoogleOrgFetchGoogleProfileReadsHostedDomain (token with and without "hd", copying TestFetchGoogleProfileRequiresMatchingNonce and restoreGoogleIssuerURL), TestGoogleOrgResolveProvisionsAccount (mode on, domain example.com, google profile with HostedDomain "example.com": a non-admin enabled account with that email and name exists afterwards and no invite cookie was needed), TestGoogleOrgResolveRejections (table: email outside the domain -> errAccountNotEligible; empty HostedDomain -> errGoogleWorkspaceRequired; provider github -> errAccountNotEligible; mode on but domain empty -> errAccountNotEligible; unverified email -> error; and the same empty-HostedDomain profile for an email that already has an account, including an admin account, -> errGoogleWorkspaceRequired and the account is not returned), TestGoogleOrgResolveLinksExistingAccountAndKeepsDisabled (an existing account with a Workspace profile is reused; a disabled one returns "account disabled"), TestGoogleOrgModeOffStillRequiresInvite (mode off returns "invite required"), TestGoogleOrgCallbackProvisionsAndSignsIn, TestGoogleOrgStartAddsHostedDomainHint (the redirect Location query contains hd=example.com when the mode is on and not when it is off, copying TestOAuthStartSendsNonceAndStoresItInFlowCookie), TestGoogleOrgInviteCreateRefused (redirect with the invite_not_used flash, no invite row created) and TestGoogleOrgInviteLinkRedirects (a pending invite link redirects to /login and sets no hn_invite cookie).
         TestGoogleOrgCallbackProvisionsAndSignsIn builds its own fake Google; do not reuse newFakeOIDCServer (it only serves /oidc/* and cannot add hd). Build it like this: generate an RSA key; `oidctest.Server{PublicKeys: ...}` as in TestFetchGoogleProfileRequiresMatchingNonce serves discovery and keys, and wrap it in an `http.NewServeMux` on an httptest.Server that also serves `POST /token` returning JSON `{"access_token":"a","token_type":"Bearer","expires_in":3600,"id_token":<oidctest.SignIDToken(priv, "test-key", oidc.RS256, claims)>}` with claims containing iss (the server URL), aud "client-id", sub "g-1", exp, email "new@example.com", email_verified true, hd "example.com" and nonce "nonce-123". Call `restoreGoogleIssuerURL(t, ts.URL)`. Google's token endpoint is google.Endpoint.TokenURL (https://oauth2.googleapis.com/token), so give the request context an http client that rewrites that host to the test server: `oidc.ClientContext`-style via `context.WithValue(ctx, oauth2.HTTPClient, client)` using the existing rewriteHostTransport in internal/server/oauth_test.go:531 (read how fakeOIDCServer.client() builds it). Build the callback cookie with `s.makeOAuthFlowCookie("google", "state-1", "verifier", "nonce-123")` named by `oauthCookieName("google")`, enable google with client id "client-id" and a secret through encryptedSetSetting, and call handleOAuthCallback through the helper oauthCovCallback in internal/server/oauth_flow_test.go:48 (check how it passes cookies and context; extend by wrapping the request context rather than editing the helper). Assert status 303, a session cookie, and an account for new@example.com.
      8. Run gofmt -l, `go test ./internal/server -run 'GoogleOrg|OAuth|Invite' -count=1`, then `mise run check-full` (auth code changed).
      Stop with status=blocked if the callback fake cannot be built from the pieces named above (report which piece is missing), if CreateAccount fails in a way the lookup fallback cannot explain, or if an existing OAuth test fails for a reason other than the intentional message change.
    acceptance:
      - go test ./internal/server -run '^TestGoogleOrgFetchGoogleProfileReadsHostedDomain$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgResolveProvisionsAccount$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgResolveRejections$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgResolveLinksExistingAccountAndKeepsDisabled$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgModeOffStillRequiresInvite$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgCallbackProvisionsAndSignsIn$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgStartAddsHostedDomainHint$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgInviteCreateRefused$|^TestGoogleOrgInviteLinkRedirects$' -count=1 passes
      - go test ./internal/server -run '^TestOAuthCovAccountErrorMessages$|^TestOAuthAccountErrorMessageHidesInternalFailures$' -count=1 passes
      - grep -n 'HostedDomain' internal/server/oauth_profile.go internal/server/oauth_accounts.go matches in both files
      - mise run check-full passes
  - id: p3-dashboard-ui
    title: Show the Google org sign-in switch and hide invitations while it is on
    depends_on: [p1-setting-and-validation]
    complexity: S
    touches:
      - internal/server/settings.go
      - internal/server/web_dashboard.go
      - internal/server/web_dashboard_test.go
      - internal/server/auth_google_org_dashboard_test.go
      - internal/web/renderer.go
      - internal/web/renderer_test.go
      - internal/web/templates/dashboard.gohtml
    brief: |
      Read the Design section "Dashboard" of docs/plans/google-org-signup-plan.md first. p1 already added the setting, settingsMeta entry, row order and googleOrgSignupEnabled.
      1. internal/web/renderer.go: add `GoogleOrg SettingRow` to AuthSettings and `GoogleOrgSignup bool` to DashboardData.
      2. internal/server/settings.go: in dashboardSettingsPanel add `GoogleOrg: dashboardSettingRow(raw, authGoogleOrgSignupSetting),` to the AuthSettings literal, after `Domain`.
      3. internal/server/web_dashboard.go: in the dashData literal in renderDashboard add `GoogleOrgSignup: s.googleOrgSignupEnabled(r.Context()),`.
      4. internal/web/templates/dashboard.gohtml: after the closing </label> of the "Allowed email domain" block and before `{{range .SettingsPanel.Auth.Providers}}`, add a switch that copies the "Access token login" `<label class="peek-setting-switch">` block verbatim but uses `.SettingsPanel.Auth.GoogleOrg` in place of `.SettingsPanel.Auth.Token` (key, checked state, label, description). Wrap the whole Invitations card, from the `<div class="rounded-xl border border-border bg-card p-5 shadow-sm">` that contains `<h2 ...>Invitations` to its closing `</div>` (one card, lines ~242-282, followed by the separate Users card), in `{{if not .GoogleOrgSignup}}` ... `{{end}}`, inside the existing `{{if .IsAdmin}}` block. Keep the Users card outside the new conditional.
      5. internal/web/renderer_test.go: add TestDashboardGoogleOrgSwitchAndInvitations: render the dashboard template (copy the setup of TestDashboardInviteLinkRendersAsCopyAction) twice with IsAdmin true, an invite row and `SettingsPanel.Auth.GoogleOrg` set to a SettingRow with Key `auth_google_org_signup`; with GoogleOrgSignup false the output contains `Invitations` and `name="auth_google_org_signup"`; with GoogleOrgSignup true it contains `name="auth_google_org_signup"` and does not contain `Invitations` or `Create invite`.
      6. Create internal/server/auth_google_org_dashboard_test.go: TestGoogleOrgDashboardReflectsSetting uses `newHandlerTestServer`, `doRequest` and `asSession(s, adminID)` (internal/server/handler_helpers_test.go:19, :47, :64) to GET /dashboard as an admin, once with the setting off (body contains `Create invite`) and once with `auth_google_org_signup` stored as `true` together with a valid domain and Google settings (use s.encryptedSetSetting for the client secret): the body contains the exact substring `name="auth_google_org_signup" value="true" checked` and does not contain `Create invite`.
      7. If an existing test in internal/server/web_dashboard_test.go or internal/web/renderer_test.go fails only because of the new switch or the hidden card, update its assertion; any other failure means stop.
      8. Run gofmt -l, `go test ./internal/web/... ./internal/server -run 'GoogleOrg|Dashboard' -count=1`, `mise run check-full`.
      Stop with status=blocked if the Invitations card in dashboard.gohtml does not have the single-<div> structure described, rather than guessing which closing tag to wrap.
    acceptance:
      - go test ./internal/web -run '^TestDashboardGoogleOrgSwitchAndInvitations$' -count=1 passes
      - go test ./internal/server -run '^TestGoogleOrgDashboardReflectsSetting$' -count=1 passes
      - grep -n 'GoogleOrgSignup' internal/web/renderer.go internal/server/web_dashboard.go internal/web/templates/dashboard.gohtml matches in all three files
      - mise run check-full passes
  - id: p4-docs-and-retire-plan
    title: Document the mode and delete the plan
    depends_on: [p2-provisioning-and-invites, p3-dashboard-ui]
    complexity: S
    touches:
      - docs/src/content/docs/auth-access.md
      - docs/src/content/docs/reference.md
      - docs/src/content/docs/manual.md
      - docs/operations.md
      - README.md
      - skills/peek-server/SKILL.md
      - docs/plans/google-org-signup-plan.md
      - docs/plans/google-org-signup-plan-manual-steps.html
    brief: |
      Read the whole Design section of docs/plans/google-org-signup-plan.md first. Write new prose as natural flowing lines; do not manually wrap Markdown lines (AGENTS.md "Editing rule").
      1. docs/src/content/docs/auth-access.md: after the "Invites And Users" section add a section `## Google Org Sign-In` that explains: what the `auth_google_org_signup` setting does, that it needs Google login with client credentials and an allowed email domain (and refuses gmail.com and googlemail.com), that only Google Workspace accounts (Google's `hd` claim) with a verified email in the allowed domain are provisioned on first sign-in as non-admin users, that GitHub and SSO providers and invites are inactive while it is on (their settings are kept), that existing accounts with the same email are linked as before, that non-admin password and token login stay disabled and admins keep the password form as recovery, and that a wrong allowed domain locks out everyone except admins. Also state: accounts that already linked a GitHub or SSO identity keep working while the mode is on; deleting a user in Google Workspace does not disable their Peek account or API keys, so an admin disables it in Peek; and the order to enable it safely (make sure an active admin has an email in the allowed domain, set the allowed domain, configure Google login, then turn the mode on). Add `auth_google_org_signup` to the runtime-settings table at the end of the file (row after `auth_allowed_email_domain`). In the "Invites And Users" section add one sentence pointing to the new section.
      2. docs/src/content/docs/reference.md: add a row for `auth_google_org_signup` (type boolean) after the `auth_allowed_email_domain` row of the settings table.
      3. docs/src/content/docs/manual.md: after the sentence about inviting users by email (the line that starts `For company sign-in`), add one sentence saying a Google-only organization can turn on Google org sign-in instead and skip invites.
      4. docs/operations.md: in the "For company usage, prefer OAuth/SSO with invite-only signup." paragraph add a sentence that Google Workspace organizations can use `auth_google_org_signup` instead of invites.
      5. README.md: in the "Access controls for internal teams" bullet add `Google org sign-in (no invites)` after `invite-only Google/GitHub/OIDC OAuth`; in the dashboard paragraph that says `OAuth signups are invite-only` add `unless Google org sign-in is on`.
      6. skills/peek-server/SKILL.md: after the paragraph that starts `OAuth signups are invite-only.` add a paragraph describing the setting (what it does, its requirements, and that invites are inactive while it is on).
      7. Delete docs/plans/google-org-signup-plan.md and docs/plans/google-org-signup-plan-manual-steps.html with `git rm`, and make sure nothing else in the repository links to them.
      8. After pushing the phase branch, dispatch the pages.yml workflow against it (ci.dispatchable) and wait for the build to pass.
      Stop with status=blocked if a sentence quoted above no longer exists in its file; report which one.
    acceptance:
      - grep -c 'auth_google_org_signup' docs/src/content/docs/auth-access.md docs/src/content/docs/reference.md docs/operations.md README.md skills/peek-server/SKILL.md prints a count of at least 1 for every file
      - grep -n '^## Google Org Sign-In' docs/src/content/docs/auth-access.md matches
      - test ! -e docs/plans/google-org-signup-plan.md && test ! -e docs/plans/google-org-signup-plan-manual-steps.html
      - grep -rn 'google-org-signup-plan' . --include=*.md --include=*.html --include=*.yml --include=*.yaml prints nothing
      - the pages.yml workflow dispatched against the phase branch finishes with conclusion success
```
