# Start Peek fully configured from the environment

## Goal

A new Peek server can start already set up: no first-run `/setup` code from the log, no clicks on the Admin page. The `privacyfence-suite` Docker stack needs this, and it is useful to any container deployment. In the suite, Peek's SSO is PrivacyFence itself, an OpenID Connect provider at `<privacyfence>/oidc`.

- **Sign-in from the environment.** Google sign-in, Google org sign-in, generic OIDC (SSO) sign-in, a new SSO sign-up, and the allowed email domain can be set by variables. They are then locked on the Admin page.
- **A provisioning key from a file.** `PEEK_PROVISIONING_KEY_FILE` registers PrivacyFence's provisioning key at start, so nobody runs `peek provisioner create`. Replacing the file rotates the key in place.
- **Admins by email, and no first-run code.** `PEEK_ADMIN_EMAILS` names the admins, as `PRIVACYFENCE_ADMIN_EMAILS` does in PrivacyFence. They become admins at their Google or SSO sign-in. `/setup` is skipped when admin emails are set, or when sign-in comes from the environment and accounts can come from sign-up or provisioning.

## Current state

- **First admin.** The first admin can only be created through `/setup`.
  - `bootstrapSetup` (`internal/server/bootstrap.go:97-132`) writes `<data>/setup.key` and prints the URL when the database has no account. It returns early, and deletes the file, when accounts exist (`:102-105`).
  - `setupRequired` (`:134-137`) makes `/login` redirect to `/setup` (`internal/server/web_login.go:20-22`), and `/api/cli/login/start` answers 400 (`internal/server/cli_login.go:66-69`).
  - `bootstrap_test.go` calls `bootstrapSetup` five times (`:217`, `:228`, `:241`, `:248`, `:258`).
- **Start order.** `server.New` calls `bootstrapSetup` (`server.go:144`) before `initDefaultSettings` (`:152`). The `Server` struct is built at `:213`, and its error paths call `cancel()` (`:254-279`) before `backends.Start` (`:276`).
- **Runtime settings.** Every sign-in setting is a runtime setting in the SQLite `settings` table (`settingsMeta`, `internal/server/settings.go:22-62`).
  - Secrets are encrypted with the server secret (`runtime_settings.go:97-106`).
  - `normalizeSettingValue` is a method (`settings.go:128`); its issuer case calls the method `s.normalizeOIDCIssuerURL(value)` (`settings.go:146-150` → `oauth_config.go:144-146`), which uses `s.oidcAllowPrivateIssuer`.
  - `validateGoogleOrgSignupUpdate` is a method reading `s.encryptedGetAllSettings` (`auth_google_org.go:26-63`).
- **Two writers.**
  - `handleUpdateSettings` is `PUT /api/settings` (`settings.go:90-123`).
  - The dashboard handler (`settings.go:272-327`) normalises `r.FormValue(k)` for every bool key whether posted or not, so an unchecked or missing box stores `""`. A new bool setting must therefore exist in the template, or every save resets it.
- **The dashboard view.**
  - `renderAdmin` (`internal/server/web_admin.go:36-50`) calls the free function `dashboardSettingsPanel(raw)` (`settings.go:388`).
  - `webui.SettingRow`, `AuthSettings` and `OAuthProviderSettings` are in `internal/web/renderer.go:154-204`; `webui.AdminData` is at `renderer.go:257`.
  - The template is `internal/web/templates/admin.gohtml:141-205`. Provider fields carry Alpine `:disabled="!oauth.{{$providerKey}}"` (`:199`), and the enabled switch uses `x-model` (`:187`).
- **Google org sign-in.**
  - Validation is `validateGoogleOrgSignupUpdate`; the account is created by `provisionGoogleOrgAccount` (`oauth_accounts.go:20-44`).
  - With org sign-in on, every non-Google login is refused: `checkGoogleOrgProfile` (`oauth_accounts.go:19-21`, called at `:59-63`) and `oauthProviderConfig` (`oauth_config.go:61-63`, `:87-89`).
- **OAuth account resolution.** `resolveOAuthAccountCreated` (`oauth_accounts.go:52-118`) has four successful returns:
  - identity-linked (`:75`);
  - email-adopted (`:87`), which is how provisioned accounts sign in;
  - org-provisioned (`:93`);
  - invite-created (`:117`).

  GitHub's `EmailVerified` is hard-coded true (`oauth_profile.go:138`).
- **OIDC.** The provider key is `"oidc"` (`oauth_config.go:75-79`); discovery happens at each login (`oauth_config.go:121`). PKCE S256 and the nonce are already in place (`oauth_flow.go:27`, `:42`). Plain-http or private issuers need `PEEK_OIDC_ALLOW_PRIVATE_ISSUER` (`oauth_config.go:158-160`).
- **Flags and env.**
  - `parseServeConfig` (`internal/peekd/run.go:104-243`) fills `serveConfig` (`run.go:27-57`), which is copied into `server.Config` (`run.go:332` onwards).
  - Each flag also reads `PEEK_<FLAG>`. `getenvSecret` supports `_FILE` (`env.go:57-76`), and `secretFlagWarnings` warns about secret flags (`env.go:78-92`). The usage text lists the `_FILE` variables (`run.go:95-97`).
- **Provisioning keys.**
  - Keys are created only through `POST /api/provisioners` (`api_provisioners.go:12-39`) and stored as `HashToken(key)` plus a hint (`internal/db/provisioners.go:23-39`). `created_by_account_id` is NULL for 0, and keys must start with `peekprov_` (`provisioning_auth.go:50-74`).
  - `DeleteProvisioner` (`provisioners.go:73-114`) deletes every token the provisioner minted, detaches their uploads, and drops the links.
  - The Admin page lists and revokes provisioners (`admin.go:228`, `admin.gohtml:137`).
- **Admins and provisioned accounts.** A provisioned account that becomes an admin loses its provisioned token at once (403 `account is a Peek admin; connect it by hand`, `account_policy.go:76-78`), and upsert then answers 409 (`provisioned_accounts.go:74-76`).
- **Allowed domain.** The pure check is `emailMatchesAllowedDomain(email, domain)` (`auth_domain.go:41`). `accountActive` applies it to every admin too (`account_policy.go:29`).

## Design

### Variables and flags

They are read in `parseServeConfig` as flags with a `PEEK_` environment default, like the existing ones, stored on `serveConfig`, and copied into `server.Config`.

| Flag | Env | Locks (setting) | Phase |
|---|---|---|---|
| `--google-client-id` | `PEEK_GOOGLE_CLIENT_ID` | `oauth_google_client_id`, and `oauth_google_enabled=true` | p2 |
| `--google-client-secret` | `PEEK_GOOGLE_CLIENT_SECRET` (`_FILE`) | `oauth_google_client_secret` | p2 |
| `--oidc-issuer-url` | `PEEK_OIDC_ISSUER_URL` | `oauth_oidc_issuer_url`, and `oauth_oidc_enabled=true` | p2 |
| `--oidc-client-id` | `PEEK_OIDC_CLIENT_ID` | `oauth_oidc_client_id` | p2 |
| `--oidc-client-secret` | `PEEK_OIDC_CLIENT_SECRET` (`_FILE`) | `oauth_oidc_client_secret` | p2 |
| `--allowed-email-domain` | `PEEK_ALLOWED_EMAIL_DOMAIN` | `auth_allowed_email_domain` | p2 |
| `--google-org-signup` | `PEEK_GOOGLE_ORG_SIGNUP` | `auth_google_org_signup` (only when true) | p2 |
| `--oidc-signup` | `PEEK_OIDC_SIGNUP` | `auth_oidc_signup` (only when true) | p2 |
| `--provisioning-key-file` | `PEEK_PROVISIONING_KEY_FILE` | none | p3 |
| `--provisioning-key-name` | `PEEK_PROVISIONING_KEY_NAME` (default `PrivacyFence`) | none | p3 |
| `--admin-emails` | `PEEK_ADMIN_EMAILS` | none | p4 |

- **Empty and false.** An empty value means "not set by the environment", and the setting belongs to the Admin page. A bool locks only when true.
- **Which name is shown.** `LockedBy` always names the plain variable (such as `PEEK_GOOGLE_CLIENT_SECRET`), even when the value came from the flag or from `_FILE`. That is intended: it is the name the docs use.
- **Secret flags.** `secretFlagWarnings` gains `google-client-secret` → `PEEK_GOOGLE_CLIENT_SECRET_FILE` and `oidc-client-secret` → `PEEK_OIDC_CLIENT_SECRET_FILE`. The usage text (`run.go:95-97`) lists both `_FILE` forms.
- **Exact pair errors from `parseServeConfig`:**
  - `set PEEK_GOOGLE_CLIENT_ID and PEEK_GOOGLE_CLIENT_SECRET (or PEEK_GOOGLE_CLIENT_SECRET_FILE) together`
  - `set PEEK_OIDC_ISSUER_URL, PEEK_OIDC_CLIENT_ID and PEEK_OIDC_CLIENT_SECRET (or PEEK_OIDC_CLIENT_SECRET_FILE) together`
- **Removing a variable** leaves its last value in the database, now editable on the Admin page. For example, `oauth_google_enabled` stays true. The docs say so.

### SSO sign-up (phase p1, an Admin-page setting first)

- **The setting.** `auth_oidc_signup` (const `authOIDCSignupSetting`, new file `internal/server/auth_oidc_signup.go`) is a bool runtime setting.
  - `settingsMeta` label: `SSO sign-up`.
  - Description: `The first SSO sign-in of anyone in the allowed email domain creates the account. Requires SSO login and an allowed email domain, and cannot be combined with Google org sign-in.`
- **Validation.** `func (s *Server) validateOIDCSignupUpdate(ctx context.Context, updates map[string]string) error` mirrors `validateGoogleOrgSignupUpdate`: it reads the effective values (updates over stored), applies only when the effective `auth_oidc_signup` is true, and fails with:
  - `auth_oidc_signup requires auth_allowed_email_domain`
  - `auth_oidc_signup requires SSO login with an issuer and client credentials` (unless `oauth_oidc_enabled` is true and the issuer, client id and secret are non-empty)
  - `auth_oidc_signup cannot be used with auth_google_org_signup` (both true)

  Both writers call it right after `validateGoogleOrgSignupUpdate`.
- **Account creation.** In `resolveOAuthAccountCreated`, after the existing-email lookup and the Google-org branch: when `profile.Provider == "oidc"` and the setting is on, call `provisionOIDCSignupAccount(ctx, profile)`. It is modelled on `provisionGoogleOrgAccount`: a non-admin account, audit `account provisioned` with `provider` `oidc`, and no `hd` check (the domain check already ran at the top).
- **Dashboard row.** `webui.AuthSettings` gains `OIDCSignup SettingRow` next to `GoogleOrg`, filled in `dashboardSettingsPanel`. The template renders its switch next to the Google-org switch, with the same markup, so the dashboard writer always posts it.

### Locked settings (phase p2)

- **The type.** `server.Config` gains `LockedSettings map[string]LockedSetting`, with `type LockedSetting struct { Value string; Env string }` in the new `internal/server/locked_settings.go`. `Env` is the variable from the table. For `oauth_google_enabled` it is `PEEK_GOOGLE_CLIENT_ID`; for `oauth_oidc_enabled` it is `PEEK_OIDC_ISSUER_URL`. `peekd` builds the map in `run.go` when it copies `serveConfig` into `server.Config`.
- **Applying them.** `func (s *Server) applyLockedSettings(ctx context.Context) error` runs in `server.New` right after `srv := &Server{...}` (`server.go:213`) and before the backends block; on error it calls `cancel()` and returns the error. `s.locked` holds the map. In order, it does three things:
  1. Normalise each value with `s.normalizeSettingValue(key, value)`, which uses `s.oidcAllowPrivateIssuer` for the issuer.
  2. Run `s.validateGoogleOrgSignupUpdate(ctx, locked)` and `s.validateOIDCSignupUpdate(ctx, locked)`, with the locked values as the updates.
  3. Write every value with `s.encryptedSetSetting`, on every start, so the environment always wins.
- **Error format.** An error is wrapped as `fmt.Errorf("%s: %w", env, err)`, for example `PEEK_GOOGLE_ORG_SIGNUP: auth_google_org_signup requires auth_allowed_email_domain`. For a validator error, which is not tied to one key, the env is the variable of the bool that triggered it.
- **Domain lockout warning.** `applyLockedSettings` does not run `validateAllowedEmailDomainUpdate`, whose "an active admin must match" rule guards Admin-page edits. Instead, when `auth_allowed_email_domain` is locked, accounts exist and no active admin's email matches it, it logs `slog.Warn("no active admin is in PEEK_ALLOWED_EMAIL_DOMAIN; admins outside it cannot sign in", "domain", d)`.
- **The writers.**
  - `handleUpdateSettings` refuses a body containing a locked key with 400 `<key> is set by <ENV> on the server`.
  - The dashboard handler drops locked keys from `updates` before validating, without an error (its form always posts the bools).
- **Showing them.**
  - `webui.SettingRow` gains `LockedBy string` with `json:"locked_by,omitempty"`.
  - `handleGetSettings` fills it. `dashboardSettingsPanel` gains a second parameter `locked map[string]string` (setting key → env name), passed from `renderAdmin` (`web_admin.go:40`) as `s.lockedEnvNames()`; the existing call in `settings_test.go:673` passes `nil`.
  - The rows that can be locked are domain, Google org, SSO sign-up, and each provider's enabled, client-id, client-secret and issuer rows. The token row cannot be locked.
- **Template.** For a row with `LockedBy`, `admin.gohtml` renders the input with a static `disabled`, leaves out the Alpine `:disabled` binding, and adds `Set by {{.LockedBy}} on the server` under it.

### Provisioning key from a file (phase p3)

- **Reading the file.**
  - The trimmed content must start with `peekprov_` and be at least 40 bytes, else `PEEK_PROVISIONING_KEY_FILE must hold a key that starts with peekprov_ and is at least 40 characters`.
  - An unreadable file gives `PEEK_PROVISIONING_KEY_FILE cannot be read: <os error>`.
  - The name is trimmed and must be 1 to 100 characters, else `PEEK_PROVISIONING_KEY_NAME must be 1 to 100 characters`.
- **Config.** `server.Config` gains `ProvisioningKey string` and `ProvisioningKeyName string`.
- **New `db.Store` method.** `RotateProvisionerKey(ctx context.Context, id int64, key string) error` runs `UPDATE provisioners SET key_hash=?, hint=? WHERE id=?`. Links, tokens and accounts are kept.
- **What `server.New` does at start.** Right after `applyLockedSettings`, it calls `seedProvisioner(ctx, store, name, key)`:
  - If `GetProvisionerByKey(key)` finds it, nothing changes.
  - Otherwise it lists provisioners with that name:
    - none: `CreateProvisioner(name, key, 0)`, then audit `provisioner registered` with actor `PEEK_PROVISIONING_KEY_FILE`;
    - one: `RotateProvisionerKey(id, key)`, then audit `provisioner rotated` with the same actor;
    - more than one: fail the start with `PEEK_PROVISIONING_KEY_NAME matches more than one provisioner; revoke the extra ones on the Admin page`.
  - It logs `provisioning key "<name>" registered from PEEK_PROVISIONING_KEY_FILE` (or `rotated`) with `slog.Info`, never the key.
  - It works with no admin account.
- **Admin page.**
  - `webui.AdminData` gains `ProvisioningKeyFromFile string` (the name, empty when unset), filled in `renderAdmin` (`web_admin.go:42-50`).
  - In the provisioners list, the row whose name equals it shows no Revoke button, and shows instead `Registered from PEEK_PROVISIONING_KEY_FILE: replace the file and restart to rotate it.`
  - `dashboardProvisionerRows` (`admin.go:228`) gains a `FromFile bool` on each row.
  - The revoke handler (`admin.go:252-276`) refuses that provisioner with `This provisioning key is registered from PEEK_PROVISIONING_KEY_FILE; replace the file and restart instead.`

### Admins by email, and skipping setup (phase p4)

- **Parsing.** `PEEK_ADMIN_EMAILS` reaches `server.Config.AdminEmailsRaw string` unparsed. `parseAdminEmails(raw string) ([]string, error)` in the new `internal/server/env_admins.go` splits on commas, trims, lower-cases and drops empty parts. Each entry must satisfy `mail.ParseAddress(entry)` with `addr.Address == entry`, else `PEEK_ADMIN_EMAILS has an invalid email: <entry>`. `server.New` calls it first and keeps the result as `s.adminEmails`.
- **Domain check.** With a locked `auth_allowed_email_domain`, every admin email must pass `emailMatchesAllowedDomain`, else the start fails with `PEEK_ADMIN_EMAILS has <email>, outside PEEK_ALLOWED_EMAIL_DOMAIN`.
- **A sign-in for admins.** With admin emails set, the start fails with `PEEK_ADMIN_EMAILS needs a sign-in for the admins: set Google or SSO sign-in in the environment` unless locked Google sign-in is on, or locked OIDC is on and `auth_google_org_signup` is not locked true.
- **When setup is skipped.** `setupSkipReason(cfg Config) (string, error)` reads only `cfg`, never the database:
  - `PEEK_ADMIN_EMAILS names the admins` when admin emails are set.
  - Otherwise, `sign-in and accounts come from the environment` when Google or OIDC is locked on and at least one of `auth_google_org_signup` or `auth_oidc_signup` is locked true, or `cfg.ProvisioningKey` is set.
  - Otherwise, when Google or OIDC is locked on, an error: `with sign-in from the environment, set PEEK_ADMIN_EMAILS, a sign-up (PEEK_GOOGLE_ORG_SIGNUP or PEEK_OIDC_SIGNUP) or PEEK_PROVISIONING_KEY_FILE, or nobody can get in`.
  - Otherwise, an empty string and no error (today's `/setup`).
- **Using the reason.**
  - `bootstrapSetup(ctx, store, dataDir, baseURL, skipReason)` keeps today's early return when accounts exist.
  - With no accounts and a non-empty reason, it removes `setup.key`, writes no code and prints `Peek first-run setup is skipped: <reason>.`.
  - `Server.setupSkipped` is set from a non-empty reason, and `setupRequired` returns false when it is true.
  - Update the five existing `bootstrapSetup` calls in `bootstrap_test.go` to pass `""`.
- **Promotion at sign-in.** In `resolveOAuthAccountCreated`, at every successful return (identity-linked, email-adopted, org-provisioned, SSO-provisioned and invite-created), a new `promoteListedAdmin(ctx, account, profile)` makes the account an admin, with audit `account promoted` and `reason` `PEEK_ADMIN_EMAILS`. It does so only when all of these hold:
  - `profile.Provider` is `"google"` or `"oidc"`;
  - `profile.EmailVerified` is true;
  - `normalizeOAuthEmail(profile.Email) == account.Email`;
  - that email is in `s.adminEmails`;
  - the account is not an admin yet.

  Before the invite branch, a listed email with no account (and no sign-up branch that applies) is created with `CreateAccount(email, name, true)`.
- **Every sign-in counts.** Promotion runs at every sign-in, like PrivacyFence's admins by email. To demote someone for good, remove them from the list first.
- **Side effect, documented.** A provisioned account promoted this way loses PrivacyFence's token at once, and later provisioning answers 409.
- **Trust.** Promotion trusts the identity provider's `email_verified`. PrivacyFence sets it only for verified addresses. With a plain-http issuer, the token exchange is unencrypted, which is acceptable only on `localhost`; the docs say so.

### Rejected

- **Seeding the settings once, like `initDefaultSettings`.** A compose file is re-run with the same environment. A one-time seed diverges silently after the first Admin-page edit, and a secret rotation in the file would never reach the database.
- **Rotating the key by deleting and re-creating the provisioner.** It deletes every token PrivacyFence minted and drops the links. An in-place hash update keeps them.
- **An admin password from a file.** It would be a second sign-in path to maintain. Every suite configuration signs in through SSO, and `/setup` remains for servers configured on the Admin page.
- **Creating the first admin through a token in the environment.** An admin token outlives its use and grants API access, whereas an email list grants nothing until the person signs in.
- **Letting a provisioning key reach admin accounts.** The suite's localhost stack simply has no Peek admin; its accounts come from provisioning.

## Manual steps

None. The suite plan's `manual_after` signs in to a real Peek through PrivacyFence.

## Risks and open questions

- **Discovery must reach the issuer.** `oidc.NewProvider` fetches `<issuer>/.well-known/openid-configuration` from inside Peek's container at each login, and `iss` must equal the issuer exactly. An issuer of `http://localhost:…/oidc` works only when Peek shares the issuer's network namespace, as the suite's localhost stack does. This fails at login, not at start. It is a deployment fact for the docs, not a code change.
- **Existing fixtures may assume the settings live only in the database.** That covers `auth_google_org_signup_test.go` and `auth_google_org_dashboard_test.go`. Adjust the fixtures; do not change `validateGoogleOrgSignupUpdate`'s behaviour.
- **The provider range in the template.** If a locked provider field cannot drop its `:disabled` binding without restructuring the range, stop with `status=blocked`.
- **Markdown in this repository is not hard-wrapped** (AGENTS.md). Docs phases write flowing lines.

## Implementation manifest

```yaml
plan_slug: env-bootstrap
feature_branch: feat/env-bootstrap
max_parallel: 1
verify_after_merge:
  - go test ./internal/server/... ./internal/peekd/... ./internal/db/... ./internal/web/...
final_checks:
  - docs/plans/env-bootstrap-plan.md is deleted and nothing links to it
  - CHANGELOG.md has entries under "## [Unreleased]" for SSO sign-up, locked sign-in settings, PEEK_PROVISIONING_KEY_FILE, PEEK_ADMIN_EMAILS and the skipped setup, and no new version heading
phases:
  - id: p1-oidc-signup
    title: SSO sign-up as an Admin-page setting
    depends_on: []
    complexity: S
    touches:
      - internal/server/auth_oidc_signup.go
      - internal/server/auth_oidc_signup_test.go
      - internal/server/oauth_accounts.go
      - internal/server/oauth_accounts_test.go
      - internal/server/settings.go
      - internal/server/settings_test.go
      - internal/web/renderer.go
      - internal/web/renderer_test.go
      - internal/web/templates/admin.gohtml
      - CHANGELOG.md
    brief: |
      Read docs/plans/env-bootstrap-plan.md, section "SSO sign-up". Every string is quoted from there.
      1. New internal/server/auth_oidc_signup.go: authOIDCSignupSetting, (s *Server) oidcSignupEnabled(ctx) bool, (s *Server) validateOIDCSignupUpdate(ctx, updates) error with the three messages, and (s *Server) provisionOIDCSignupAccount(ctx, profile) modelled on provisionGoogleOrgAccount.
      2. settings.go: add the settingsMeta row; call validateOIDCSignupUpdate in both writers right after validateGoogleOrgSignupUpdate; fill AuthSettings.OIDCSignup in dashboardSettingsPanel.
      3. oauth_accounts.go, resolveOAuthAccountCreated: the OIDC sign-up branch after the Google-org branch.
      4. internal/web/renderer.go: OIDCSignup SettingRow on AuthSettings. admin.gohtml: its switch next to the Google-org switch, with the same markup.
      5. Tests:
         - auth_oidc_signup_test.go: TestOIDCSignupNeedsDomain, TestOIDCSignupNeedsSSO, TestOIDCSignupConflictsWithGoogleOrg, TestOIDCSignupCreatesNonAdmin, TestOIDCSignupRefusesOutsideDomain.
         - settings_test.go: TestDashboardSavesOIDCSignup and TestAPIRejectsInvalidOIDCSignup.
         - renderer_test.go: the switch renders.
      6. CHANGELOG.md, "## [Unreleased]", "### Added": "- SSO sign-up: the first SSO sign-in of anyone in the allowed email domain creates the account, like Google org sign-in."
      7. Run `mise run fmt-check`, `mise run vet`, `mise run test`, then `mise run check-full`.
    acceptance:
      - go test ./internal/server/... ./internal/web/... passes, including every named test
      - mise run check-full passes
      - grep -n "auth_oidc_signup cannot be used with auth_google_org_signup" internal/server/auth_oidc_signup.go finds the message

  - id: p2-locked-settings
    title: Sign-in settings from the environment, locked on the Admin page
    depends_on: [p1-oidc-signup]
    complexity: M
    touches:
      - internal/peekd/run.go
      - internal/peekd/env.go
      - internal/peekd/run_test.go
      - internal/peekd/env_test.go
      - internal/server/server.go
      - internal/server/locked_settings.go
      - internal/server/locked_settings_test.go
      - internal/server/settings.go
      - internal/server/settings_test.go
      - internal/server/web_admin.go
      - internal/web/renderer.go
      - internal/web/renderer_test.go
      - internal/web/templates/admin.gohtml
      - CHANGELOG.md
    brief: |
      Read docs/plans/env-bootstrap-plan.md: "Variables and flags" (the p2 rows) and "Locked settings".
      1. internal/peekd/run.go: the p2 flags with PEEK_ env defaults (secrets via getenvSecret, bools via getenvBool), new fields on serveConfig, the two pair errors, the usage text, and building server.Config.LockedSettings where serveConfig is copied into server.Config. env.go: the two secretFlagWarnings entries.
      2. New internal/server/locked_settings.go: LockedSetting, (s *Server) applyLockedSettings(ctx) error, (s *Server) lockedEnvNames() map[string]string, and the domain lockout warning. server.go: keep the map on Server, and call applyLockedSettings right after `srv := &Server{...}` with cancel() on error.
      3. settings.go: the API refusal and the dashboard skip. Fill LockedBy in handleGetSettings, and give dashboardSettingsPanel the locked parameter. web_admin.go:40: pass s.lockedEnvNames(). Update the call in settings_test.go:673 to pass nil.
      4. renderer.go: LockedBy on SettingRow. admin.gohtml: the static disabled, no :disabled binding, and the "Set by … on the server" line for locked rows. Stop condition: see Risks (provider range).
      5. Tests:
         - run_test.go: each flag and env, both pair errors, the usage text lists both _FILE forms.
         - env_test.go: the two warnings.
         - locked_settings_test.go: TestLockedValuesWrittenEncryptedEveryStart, TestLockedWinsOverDatabase, TestLockedInvalidIssuerFailsWithEnvPrefix, TestLockedOrgSignupWithoutDomainFails, TestLockedDomainWarnsWhenNoAdminMatches.
         - settings_test.go: TestAPIRejectsLockedKey, TestDashboardKeepsLockedBool, TestGetSettingsShowsLockedBy.
         - renderer_test.go: TestLockedRowRendersDisabledWithoutAlpineBinding.
      6. CHANGELOG.md "### Added": "- Sign-in from the environment: `PEEK_GOOGLE_CLIENT_ID`/`_SECRET`, `PEEK_OIDC_ISSUER_URL`/`_CLIENT_ID`/`_SECRET`, `PEEK_ALLOWED_EMAIL_DOMAIN`, `PEEK_GOOGLE_ORG_SIGNUP` and `PEEK_OIDC_SIGNUP` set the sign-in settings at every start and lock them on the Admin page."
      7. Run `mise run check-full`.
    acceptance:
      - go test ./internal/peekd/... ./internal/server/... ./internal/web/... passes, including every named test
      - mise run check-full passes
      - grep -n "func (s \*Server) applyLockedSettings" internal/server/locked_settings.go finds it

  - id: p3-provisioning-key-file
    title: PEEK_PROVISIONING_KEY_FILE registers or rotates a provisioning key at every start
    depends_on: [p2-locked-settings]
    complexity: M
    touches:
      - internal/peekd/run.go
      - internal/peekd/run_test.go
      - internal/server/server.go
      - internal/server/provisioning_seed.go
      - internal/server/provisioning_seed_test.go
      - internal/server/admin.go
      - internal/server/admin_test.go
      - internal/server/web_admin.go
      - internal/server/web_admin_test.go
      - internal/db/provisioners.go
      - internal/db/provisioners_test.go
      - internal/web/renderer.go
      - internal/web/templates/admin.gohtml
      - CHANGELOG.md
    brief: |
      Read docs/plans/env-bootstrap-plan.md, section "Provisioning key from a file".
      1. run.go: --provisioning-key-file and --provisioning-key-name with the three errors; new serveConfig fields copied to server.Config.
      2. internal/db/provisioners.go: RotateProvisionerKey, with a test in provisioners_test.go that links and tokens survive.
      3. New internal/server/provisioning_seed.go: seedProvisioner as designed, with audit entries and log lines. Call it from server.New right after applyLockedSettings, with cancel() on error.
      4. Admin page: ProvisioningKeyFromFile on webui.AdminData (renderer.go:257), filled in web_admin.go; FromFile on the provisioner rows (admin.go:228); the template shows the sentence instead of Revoke for that row; the revoke handler (admin.go:252-276) refuses it with the message.
      5. Tests:
         - provisioning_seed_test.go: TestSeedRegistersFirstStart, TestSeedSameKeyNoop, TestSeedRotatesInPlaceKeepingLinks, TestSeedTwoSameNameFails, TestSeedWorksWithoutAccounts, TestSeededKeyAnswersProvisioningSelf.
         - run_test.go: the errors and the default name.
         - admin_test.go or web_admin_test.go: TestFileProvisionerHasNoRevoke and TestRevokeFileProvisionerRefused.
      6. CHANGELOG.md "### Added": "- `PEEK_PROVISIONING_KEY_FILE` registers a provisioning key at every start, and replacing the file rotates it in place, so PrivacyFence can provision accounts without `peek provisioner create`."
      7. Run `mise run check-full`.
    acceptance:
      - go test ./internal/server/... ./internal/peekd/... ./internal/db/... passes, including every named test
      - mise run check-full passes
      - grep -n "func (s \*Store) RotateProvisionerKey" internal/db/provisioners.go finds it

  - id: p4-admin-emails
    title: PEEK_ADMIN_EMAILS, and /setup skipped when admins or sign-in come from the environment
    depends_on: [p3-provisioning-key-file]
    complexity: M
    touches:
      - internal/peekd/run.go
      - internal/peekd/run_test.go
      - internal/server/server.go
      - internal/server/bootstrap.go
      - internal/server/bootstrap_test.go
      - internal/server/env_admins.go
      - internal/server/env_admins_test.go
      - internal/server/oauth_accounts.go
      - internal/server/oauth_accounts_test.go
      - CHANGELOG.md
    brief: |
      Read docs/plans/env-bootstrap-plan.md, section "Admins by email, and skipping setup".
      1. run.go: --admin-emails (PEEK_ADMIN_EMAILS), passed raw as server.Config.AdminEmailsRaw.
      2. New internal/server/env_admins.go: parseAdminEmails, checkAdminEmails(cfg, emails) (the domain and "needs a sign-in" errors), setupSkipReason(cfg), and (s *Server) promoteListedAdmin(ctx, account, profile).
      3. server.go: parse the emails and compute the skip reason before bootstrapSetup (server.go:144); return the errors from both. Keep adminEmails and setupSkipped on Server.
      4. bootstrap.go: the new skipReason parameter and log line; setupRequired returns false when s.setupSkipped. Update the five calls in bootstrap_test.go to pass "".
      5. oauth_accounts.go, resolveOAuthAccountCreated: call promoteListedAdmin at the five successful returns, and create a listed email as admin before the invite branch.
      6. Tests:
         - run_test.go: the flag.
         - env_admins_test.go: TestParseAdminEmailsRejectsInvalid, TestAdminEmailOutsideDomainFails, TestAdminEmailsNeedSignIn, TestSkipReasonAdminEmails, TestSkipReasonSignupOrKey, TestSkipLockedSignInWithoutAccountsSourceFails, TestNoSkipWithoutEnv.
         - bootstrap_test.go: TestSetupSkippedPrintsReason, TestSkippedSetupLoginDoesNotRedirect, TestSkippedSetupCLILoginAllowed.
         - oauth_accounts_test.go: TestListedSSOSignInPromoted, TestListedGitHubSignInNotPromoted, TestListedEmailWithoutAccountCreatedAsAdmin, TestUnlistedStillNeedsInvite, TestPromotionNeedsMatchingEmail.
      7. CHANGELOG.md "### Added": "- `PEEK_ADMIN_EMAILS` names the admins by email, who become admins at their Google or SSO sign-in. First-run `/setup` is skipped when admin emails are set, or when sign-in and accounts come from the environment."
      8. Run `mise run check-full`.
    acceptance:
      - go test ./internal/server/... ./internal/peekd/... passes, including every named test
      - mise run check-full passes
      - grep -n "first-run setup is skipped" internal/server/bootstrap.go finds the line
      - grep -n "func setupSkipReason" internal/server/env_admins.go finds it

  - id: p5-docs-retire
    title: Reference and operations docs, delete the plan
    depends_on: [p4-admin-emails]
    complexity: S
    touches:
      - docs/src/content/docs/reference.md
      - docs/src/content/docs/auth-access.md
      - docs/src/content/docs/server-setup.md
      - docs/operations.md
      - README.md
      - docs/plans/env-bootstrap-plan.md
    brief: |
      Write flowing Markdown lines; do not hard-wrap (AGENTS.md).
      1. docs/src/content/docs/reference.md:
         - the flags table (lines 7-41): every flag from the plan's table with its env name and a one-line meaning;
         - the Runtime Settings table (near line 61): auth_oidc_signup.
      2. docs/src/content/docs/auth-access.md: a section "Configure sign-in from the environment" covering:
         - locked settings: what the Admin page shows, that the API refuses them, and that removing a variable leaves the last value editable;
         - SSO sign-up, and its conflict with Google org sign-in;
         - PEEK_ADMIN_EMAILS: every sign-in promotes, and to demote someone for good remove them from the list first; a promoted provisioned account loses its provisioned token, and later provisioning answers 409; the trust in email_verified, and plain http only on localhost;
         - when /setup is skipped, and the start error;
         - in the provisioning part, PEEK_PROVISIONING_KEY_FILE: in-place rotation, no Revoke for it, and replacing the file instead;
         - that an issuer at http://localhost works only when Peek shares its network namespace.

         Add auth_oidc_signup near auth-access.md:196.
      3. docs/src/content/docs/server-setup.md and docs/operations.md ("First run"): a minimal environment-only example (PEEK_BASE_URL, PEEK_OIDC_ISSUER_URL, PEEK_OIDC_CLIENT_ID, PEEK_OIDC_CLIENT_SECRET_FILE, PEEK_ALLOWED_EMAIL_DOMAIN, PEEK_OIDC_SIGNUP=true, PEEK_ADMIN_EMAILS, PEEK_PROVISIONING_KEY_FILE). README.md: one sentence and a link where first run is described.
      4. Dispatch pages.yml on the branch (it is in ci.dispatchable) and read its result.
      5. Delete docs/plans/env-bootstrap-plan.md; `grep -rn "env-bootstrap-plan" .` finds nothing.
    acceptance:
      - test ! -e docs/plans/env-bootstrap-plan.md
      - grep -rn "PEEK_ADMIN_EMAILS" docs/src/content/docs/reference.md docs/src/content/docs/auth-access.md docs/operations.md finds each file
      - the pages.yml run on the branch is green
```
