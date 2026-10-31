# Start Peek fully configured from the environment

## Goal

A new Peek server can start already set up, with no first-run `/setup` code from the log and no
clicks on the Admin page. This is what the `privacyfence-suite` Docker stack needs, and it is
useful to any container deployment:

- **Admins by email, no first-run code.** `PEEK_ADMIN_EMAILS` names the admins, as
  `PRIVACYFENCE_ADMIN_EMAILS` does in PrivacyFence. They become admins when they first sign in with
  Google or SSO. `/setup` is skipped when admin emails are set, or when Google or SSO sign-in comes
  from the environment. In the suite, SSO is PrivacyFence itself (its OIDC provider at
  `<privacyfence>/oidc`).
- **Sign-in from the environment.** Google sign-in, Google org sign-in (automatic accounts for the
  allowed domain), generic OIDC (SSO) sign-in with a new matching OIDC sign-up, and the allowed email
  domain can be set by variables. They are then locked on the Admin page.
- **A provisioning key from a file.** `PEEK_PROVISIONING_KEY_FILE` registers a PrivacyFence
  provisioning key at start, so nobody has to run `peek provisioner create`.

## Current state

- **First admin.** The first admin can only be created through `/setup`. `bootstrapSetup`
  (`internal/server/bootstrap.go:95-132`) writes `<data>/setup.key` and prints the URL when the
  database has no account. `setupRequired` (`bootstrap.go:134-137`) makes `/login` redirect to
  `/setup` (`internal/server/web_login.go:20-22`), and `/api/cli/login/start` answers 400 while setup
  is pending (`internal/server/cli_login.go:66-69`).
- **Sign-in settings.** Every sign-in setting is a runtime setting in the SQLite `settings` table
  (`settingsMeta`, `internal/server/settings.go:22-52`):
  - `oauth_{google,oidc}_{enabled,client_id,client_secret}`, `oauth_oidc_issuer_url`,
    `auth_allowed_email_domain`, `auth_google_org_signup`.
  - Secrets are encrypted with the server secret (`internal/server/runtime_settings.go:97-106`).
  - `initDefaultSettings` (`runtime_settings.go:10-44`) seeds only keys that are absent.
  - Two writers exist: `handleUpdateSettings` (`settings.go:90-123`, `PUT /api/settings`) and the
    dashboard form handler (`settings.go:280-325`). The dashboard form posts every bool setting, so
    an unchecked box writes `false`.
  - The dashboard view is built by `dashboardSettingsMap` and the `webui.AuthSettings` literal
    (`settings.go:375-420`). `webui.SettingRow` and `webui.AuthSettings` are in
    `internal/web/renderer.go:154-204`, and the template is `internal/web/templates/admin.gohtml:141-205`.
- **Google org sign-in.** Validation is `validateGoogleOrgSignupUpdate`
  (`internal/server/auth_google_org.go:26-63`), and the account is created by
  `provisionGoogleOrgAccount` (`internal/server/oauth_accounts.go:20-44`). OAuth account resolution is
  in `resolveOAuthAccountCreated` (`oauth_accounts.go:52-118`). An existing account with the same email
  is adopted (`:80-87`), which is how provisioned accounts sign in. The OIDC provider key is `"oidc"`
  (`internal/server/oauth_config.go:75-79`).
- **Issuer validation.** `normalizeOIDCIssuerURL(value, allowPrivateIssuer)` is at
  `oauth_config.go:148-185`.
- **Flags and env.** Both are parsed in `parseServeConfig` (`internal/peekd/run.go:100-200`). Each
  flag also reads `PEEK_<FLAG>`. `getenvSecret` supports `_FILE` (`internal/peekd/env.go:57-76`).
  `secretFlagWarnings` (`env.go:78-92`) warns about secrets passed as flags. `server.Config` is at
  `internal/server/server.go:33-65`, and `server.New` runs `bootstrapSetup` and then
  `initDefaultSettings` (`server.go:140-158`).
- **Provisioning keys.** Keys are created only through `POST /api/provisioners` with an admin token
  (`internal/server/api_provisioners.go:12-39`). They are stored as `HashToken(key)`
  (`internal/db/provisioners.go:23-39`). `created_by_account_id` may be NULL (`CreateProvisioner`
  passes NULL for 0). Keys must start with `peekprov_` (`internal/server/provisioning_auth.go:50-74`).
- **Accounts.** `CreateAccount`, `CreateAccountWithPassword`, `GetAccountByEmail` and
  `SetAccountAdmin` are in `internal/db/accounts.go`. There is no password setter. `/setup` hashes the
  password with bcrypt (`internal/server/web_setup.go:54-67`; rules: not empty, at most 72 bytes).

## Design

### Variables and flags

All are read in `parseServeConfig` as flags with a `PEEK_` environment default, as the existing
ones are. Secrets also accept `_FILE` through `getenvSecret`.

| Flag | Env | Setting it locks | Notes |
|---|---|---|---|
| `--google-client-id` | `PEEK_GOOGLE_CLIENT_ID` | `oauth_google_client_id`, and `oauth_google_enabled=true` | with the secret |
| `--google-client-secret` | `PEEK_GOOGLE_CLIENT_SECRET` (`_FILE`) | `oauth_google_client_secret` | with the id |
| `--oidc-issuer-url` | `PEEK_OIDC_ISSUER_URL` | `oauth_oidc_issuer_url`, and `oauth_oidc_enabled=true` | with id and secret |
| `--oidc-client-id` | `PEEK_OIDC_CLIENT_ID` | `oauth_oidc_client_id` | |
| `--oidc-client-secret` | `PEEK_OIDC_CLIENT_SECRET` (`_FILE`) | `oauth_oidc_client_secret` | |
| `--allowed-email-domain` | `PEEK_ALLOWED_EMAIL_DOMAIN` | `auth_allowed_email_domain` | |
| `--google-org-signup` | `PEEK_GOOGLE_ORG_SIGNUP` | `auth_google_org_signup` (only when true) | bool |
| `--oidc-signup` | `PEEK_OIDC_SIGNUP` | `auth_oidc_signup` (only when true; new setting) | bool |
| `--admin-emails` | `PEEK_ADMIN_EMAILS` | (no setting) | comma list |
| `--provisioning-key-file` | `PEEK_PROVISIONING_KEY_FILE` | (no setting) | a path |

- **Empty means not set.** An empty value means "not set by the environment". The setting then
  belongs to the Admin page as today.
- **Bools lock only when true.** A bool locks the setting only when it is true. Unset or false
  leaves the Admin page in charge.
- **Secret flags warn.** `secretFlagWarnings` gains `google-client-secret` →
  `PEEK_GOOGLE_CLIENT_SECRET_FILE` and `oidc-client-secret` → `PEEK_OIDC_CLIENT_SECRET_FILE`.
- **Pairs are checked in `parseServeConfig`.** The exact errors, returned as is:
  - `set PEEK_GOOGLE_CLIENT_ID and PEEK_GOOGLE_CLIENT_SECRET (or PEEK_GOOGLE_CLIENT_SECRET_FILE) together`
  - `set PEEK_OIDC_ISSUER_URL, PEEK_OIDC_CLIENT_ID and PEEK_OIDC_CLIENT_SECRET (or PEEK_OIDC_CLIENT_SECRET_FILE) together`

### Locked settings (phase p1)

- `server.Config` gains `LockedSettings map[string]LockedSetting`, where
  `type LockedSetting struct { Value string; Env string }` is in the new
  `internal/server/locked_settings.go`. `Env` names the variable, such as `PEEK_GOOGLE_CLIENT_ID`; for
  `oauth_google_enabled` it is `PEEK_GOOGLE_CLIENT_ID`, and for `oauth_oidc_enabled` it is
  `PEEK_OIDC_ISSUER_URL`. `peekd` builds the map from the table above.
- `server.New`, after `initDefaultSettings`, calls `applyLockedSettings(ctx, store, secret, cfg)`.
  It does the following in order:
  1. Normalises each value with `normalizeSettingValue`. For `oauth_oidc_issuer_url` it uses
     `normalizeOIDCIssuerURL(value, cfg.OIDCAllowPrivateIssuer)`.
  2. Runs `validateGoogleOrgSignupUpdate` and `validateOIDCSignupUpdate` with the locked values as
     the updates.
  3. Writes every value with the same encryption `encryptedSetSetting` uses, on every start, so the
     environment always wins.

  It does **not** run `validateAllowedEmailDomainUpdate`, whose "an active admin must match" rule
  guards Admin-page lockouts; p2 checks the admin emails against the domain instead.
- **Start-up errors.** A start-up error is returned wrapped as `fmt.Errorf("%s: %w", env, err)`, for
  example `PEEK_GOOGLE_ORG_SIGNUP: auth_google_org_signup requires auth_allowed_email_domain`.
- **The API refuses locked keys.** `handleUpdateSettings` refuses a body that contains a locked key
  with 400 `<key> is set by <ENV> on the server`.
- **The dashboard skips locked keys.** The dashboard handler drops locked keys from `updates` before
  validating, without an error (its form always posts the bools).
- **The rows say who set them.** `webui.SettingRow` gains `LockedBy string` with
  `json:"locked_by,omitempty"`. `handleGetSettings` and the dashboard view fill it.
- **The template disables locked inputs.** `admin.gohtml` renders a locked input with `disabled` and,
  under it, `Set by {{.LockedBy}} on the server`. This covers the token, domain, Google-org and
  OIDC-sign-up rows, and each provider's enabled, client-id and client-secret rows.

### OIDC sign-up (phase p1)

- **New setting.** `auth_oidc_signup` (const `authOIDCSignupSetting`, in the new
  `internal/server/auth_oidc_signup.go`) is a bool runtime setting with
  `settingsMeta` label `SSO sign-up` and description
  `The first SSO sign-in of anyone in the allowed email domain creates the account. Requires SSO login and an allowed email domain.`
- **Validation.** `validateOIDCSignupUpdate(ctx, updates)` mirrors `validateGoogleOrgSignupUpdate`.
  It applies only when the effective `auth_oidc_signup` is true, and fails with:
  - `auth_oidc_signup requires auth_allowed_email_domain`, when the domain is empty.
  - `auth_oidc_signup requires SSO login with an issuer and client credentials`, unless
    `oauth_oidc_enabled` is true and the issuer, client id and secret are non-empty.

  Both settings writers call it next to `validateGoogleOrgSignupUpdate`.
- **Account creation.** In `resolveOAuthAccountCreated`, after the existing-email lookup and the
  Google-org branch, `profile.Provider == "oidc"` with the setting on calls
  `provisionOIDCSignupAccount`. It is modelled on `provisionGoogleOrgAccount`: a non-admin account,
  with the audit line `account provisioned` and `provider` `oidc`. There is no `hd` check, since the
  domain check already ran at the top.

### Admins by email (phase p2)

- **Parsing.** `PEEK_ADMIN_EMAILS` is split on commas, trimmed and lower-cased; empty parts are
  dropped. Each entry must pass `validProvisioningEmail`, else
  `PEEK_ADMIN_EMAILS has an invalid email: <entry>`. The result goes to
  `server.Config.AdminEmails []string`.
- **Domain check.** With a locked `auth_allowed_email_domain`, every admin email must be in that
  domain (same rule as `accountAllowedByEmailDomain`), else the start fails with
  `PEEK_ADMIN_EMAILS has <email>, outside PEEK_ALLOWED_EMAIL_DOMAIN`.
- **A sign-in for the admins.** With `AdminEmails` set, the start fails with
  `PEEK_ADMIN_EMAILS needs a sign-in for the admins: set Google or SSO sign-in in the environment`
  unless Google or OIDC is locked on.
- **Setup is skipped.** `bootstrapSetup` gains a `skipReason string` parameter:
  - `PEEK_ADMIN_EMAILS names the admins` when `AdminEmails` is non-empty;
  - otherwise `sign-in comes from the environment` when Google or OIDC is locked on;
  - otherwise empty.

  When it is non-empty, `bootstrapSetup` removes `setup.key`, writes no code, and prints
  `Peek first-run setup is skipped: <skipReason>.` instead of the URL. `Server` keeps `setupSkipped bool`,
  and `setupRequired` returns false when it is true. A server skipped for the second reason, with no
  admin emails, has no admin until one is promoted on the Admin page by another admin. That is
  intended for single-person installs (the suite's localhost stack), where every setting comes from
  the environment.
- **Admins are made at OAuth sign-in.** In `resolveOAuthAccountCreated`, once the account is
  resolved or created, a verified email in `s.adminEmails` gets `SetAccountAdmin(id, true)` if the
  account is not an admin yet. A listed email with no account and no other way in (no invite, no
  org sign-up) is created as an admin with `CreateAccount(email, name, true)`. The audit line is
  `account promoted` with `reason` `PEEK_ADMIN_EMAILS`. Removing an email from the list does not
  demote anyone; the Admin page does that (documented).
- **A provisioned account becomes an admin too.** An account Peek made through provisioning, which
  is later named in `PEEK_ADMIN_EMAILS`, becomes an admin at its first OAuth sign-in. From then on
  provisioning answers 409 for it, as for any admin; PrivacyFence documents this.

### Provisioning key from a file (phase p3)

- **File rules.** `PEEK_PROVISIONING_KEY_FILE` names a file whose trimmed content must start with
  `peekprov_` and be at least 40 bytes long, else
  `PEEK_PROVISIONING_KEY_FILE must hold a key that starts with peekprov_ and is at least 40 characters`.
  Unreadable gives `PEEK_PROVISIONING_KEY_FILE cannot be read: <os error>`.
- **Name.** `--provisioning-key-name` / `PEEK_PROVISIONING_KEY_NAME` (default `PrivacyFence`, 1 to
  100 characters after trimming) is the name it is stored under.
- **What the start does.** `server.New` calls `seedProvisioner(ctx, store, name, key)`:
  - If `GetProvisionerByKey(key)` finds it, it does nothing.
  - Otherwise it deletes every provisioner with the same name (`DeleteProvisioner`, which already
    drops its links and tokens, never accounts) and calls `CreateProvisioner(name, key, 0)`.
  - It logs `provisioning key "<name>" registered from PEEK_PROVISIONING_KEY_FILE` with `slog.Info`,
    never the key.

  Replacing the file therefore rotates the key at the next start.
- **Order.** It runs after `checkAdminEmails`. It works with no admin account, so a server can be
  provisioned before any admin signs in.
- **Locked on the Admin page.** A provisioner registered this way can still be revoked on the Admin
  page. It comes back at the next start, which the Admin page says under the provisioners list when
  the server has a key file: `The key named <name> is registered from PEEK_PROVISIONING_KEY_FILE at every start.`
  `server.Config` gains `ProvisioningKey string` and `ProvisioningKeyName string`, and the dashboard
  data gains `ProvisioningKeyFromFile string` (the name, empty when unset).

### Rejected

- **Seeding the settings once, like `initDefaultSettings`.** A compose file is re-run with the same
  environment. A one-time seed diverges silently after the first Admin-page edit, and a client-secret
  rotation in the secret file would never reach the database.
- **An admin password from a file.** It would be a second sign-in path to maintain. Every suite
  configuration signs in through SSO (PrivacyFence), and `/setup` remains for servers configured on
  the Admin page.
- **Creating the first admin through a token in the environment.** An admin token outlives its use
  and grants API access; an email list grants nothing until the person signs in.
- **Letting a provisioning key reach admin accounts.** The suite's localhost stack simply has no
  Peek admin instead.

## Manual steps

None. The suite plan's `manual_after` signs in to a real Google-configured Peek.

## Risks and open questions

- **`server.New`'s order matters.** `bootstrapSetup` runs before `initDefaultSettings`
  (`server.go:140-158`). p2 must compute the skip reason from the config (`AdminEmails` and
  `LockedSettings`, not the database), so `bootstrapSetup` can stay first. If `server.New` is structured differently from these line numbers, stop
  with `status=blocked`.
- **The template's provider rows are a range over `Providers`.** If a locked provider row cannot be
  rendered disabled without restructuring that range, stop with `status=blocked`.
- **A Google-org-signup test fixture may assume the setting is only in the DB.** Adjust fixtures; do
  not change `validateGoogleOrgSignupUpdate`'s behaviour.

## Implementation manifest

```yaml
plan_slug: env-bootstrap
feature_branch: feat/env-bootstrap
max_parallel: 1
verify_after_merge:
  - go test ./internal/server/... ./internal/peekd/... ./internal/db/...
final_checks:
  - docs/plans/env-bootstrap-plan.md is deleted and nothing links to it
  - CHANGELOG.md has entries under "## [Unreleased]" for locked sign-in settings, SSO sign-up, PEEK_ADMIN_EMAILS and the skipped setup, and PEEK_PROVISIONING_KEY_FILE, and no new version heading
phases:
  - id: p1-locked-settings
    title: Sign-in settings from the environment, locked on the Admin page, and SSO sign-up
    depends_on: []
    complexity: M
    touches:
      - internal/peekd/run.go
      - internal/peekd/env.go
      - internal/peekd/run_test.go
      - internal/peekd/env_test.go
      - internal/server/server.go
      - internal/server/locked_settings.go
      - internal/server/locked_settings_test.go
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
      Read docs/plans/env-bootstrap-plan.md, sections "Variables and flags" (only the rows that lock a
      setting), "Locked settings" and "OIDC sign-up". Every string is quoted from there.
      1. internal/peekd/run.go, parseServeConfig: add the flags --google-client-id,
         --google-client-secret, --oidc-issuer-url, --oidc-client-id, --oidc-client-secret,
         --allowed-email-domain, --google-org-signup, --oidc-signup with PEEK_ env defaults like the
         existing ones (secrets via getenvSecret, bools via getenvBool). Add the two pair errors.
         Add google-client-secret and oidc-client-secret to secretFlagWarnings in env.go.
         Build server.Config.LockedSettings from the non-empty values (and the true bools), with the
         Env names in the Design.
      2. New internal/server/locked_settings.go: LockedSetting, applyLockedSettings (normalise,
         validate, write encrypted, wrap errors as "<ENV>: <err>"), and a Server method
         lockedBy(key) string. Call applyLockedSettings from server.New right after
         initDefaultSettings, and keep the map on Server.
      3. New internal/server/auth_oidc_signup.go: authOIDCSignupSetting, oidcSignupEnabled,
         validateOIDCSignupUpdate, provisionOIDCSignupAccount. Add the settingsMeta row in
         settings.go. In oauth_accounts.go, resolveOAuthAccountCreated: add the OIDC sign-up branch
         after the Google-org branch.
      4. settings.go: call validateOIDCSignupUpdate in both writers. In handleUpdateSettings refuse
         locked keys with 400 "<key> is set by <ENV> on the server"; in the dashboard handler drop
         locked keys from updates before validating. Fill LockedBy in handleGetSettings and in the
         dashboard rows (settings.go:375-420), including an OIDC sign-up row: add
         OIDCSignup SettingRow to webui.AuthSettings next to GoogleOrg.
      5. internal/web/renderer.go: add LockedBy to SettingRow. admin.gohtml: render the OIDC sign-up
         switch next to the Google-org one, and for every row with LockedBy, add disabled and the line
         "Set by {{.LockedBy}} on the server". Stop condition: see Risks (the provider range).
      6. Tests (Go table tests in the existing style):
         - run_test.go: each flag and env; both pair errors; the secret-flag warnings.
         - locked_settings_test.go: values written encrypted on every start and win over a DB value;
           the invalid issuer, org-sign-up-without-domain and OIDC-sign-up-without-SSO start errors
           carry the env prefix.
         - settings_test.go: PUT /api/settings with a locked key → 400 with the message; the dashboard
           POST leaves a locked bool unchanged; GET shows locked_by.
         - auth_oidc_signup_test.go and oauth_accounts_test.go: OIDC sign-up creates a non-admin
           account in the domain, refuses outside it, and does nothing for Google.
         - renderer_test.go: the locked line renders.
      7. CHANGELOG.md, "## [Unreleased]", "### Added":
         "- Sign-in from the environment: `PEEK_GOOGLE_CLIENT_ID`/`_SECRET`, `PEEK_OIDC_ISSUER_URL`/`_CLIENT_ID`/`_SECRET`, `PEEK_ALLOWED_EMAIL_DOMAIN`, `PEEK_GOOGLE_ORG_SIGNUP` and `PEEK_OIDC_SIGNUP` set the sign-in settings at every start and lock them on the Admin page."
         "- SSO sign-up: the first SSO sign-in of anyone in the allowed email domain creates the account, like Google org sign-in."
      8. Run `mise run fmt-check`, `mise run vet`, `mise run test`, then `mise run check-full`.
    acceptance:
      - go test ./internal/peekd/... ./internal/server/... ./internal/web/... passes
      - mise run check-full passes
      - grep -n "is set by %s on the server\|is set by .* on the server" internal/server/settings.go finds the refusal
      - grep -n "auth_oidc_signup requires auth_allowed_email_domain" internal/server/auth_oidc_signup.go finds the message

  - id: p2-admin-emails
    title: PEEK_ADMIN_EMAILS, and /setup skipped when admins or sign-in come from the environment
    depends_on: [p1-locked-settings]
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
      Read docs/plans/env-bootstrap-plan.md, section "Admins by email".
      1. run.go: add --admin-emails (PEEK_ADMIN_EMAILS). Parse and validate the list (the
         invalid-email error) and put AdminEmails []string on server.Config.
      2. New internal/server/env_admins.go: checkAdminEmails(cfg) for the domain and "needs a sign-in"
         start errors (it reads cfg.LockedSettings, not the database), setupSkipReason(cfg) string
         returning the two reasons from the Design, and promoteListedAdmin(ctx, account) used by OAuth
         resolution.
      3. bootstrap.go: bootstrapSetup(ctx, store, dataDir, baseURL, skipReason) skips the code with
         the exact log line when skipReason is non-empty. setupRequired returns false when
         s.setupSkipped. server.go: compute the reason with setupSkipReason(cfg) before bootstrapSetup,
         keep setupSkipped and adminEmails on Server, and call checkAdminEmails before
         applyLockedSettings. Stop condition: see Risks (server.New's order).
      4. oauth_accounts.go, resolveOAuthAccountCreated: promote a listed verified email, and create a
         listed email as admin when no other path applies, before the invite branch. The audit line is
         "account promoted" with reason PEEK_ADMIN_EMAILS.
      5. Tests:
         - run_test.go: parsing and errors.
         - bootstrap_test.go: no setup.key and the log line for each reason; /login does not redirect
           to /setup; /api/cli/login/start is not refused.
         - env_admins_test.go: both start errors; each skip reason; empty without either.
         - oauth_accounts_test.go: a listed SSO sign-in becomes admin; a listed email with no account
           is created as admin; an unlisted one still needs an invite or sign-up.
      6. CHANGELOG.md "### Added":
         "- `PEEK_ADMIN_EMAILS` names the admins by email, who become admins at their first Google or SSO sign-in. First-run `/setup` is skipped when admin emails are set, or when Google or SSO sign-in comes from the environment."
      7. Run `mise run check-full`.
    acceptance:
      - go test ./internal/server/... ./internal/peekd/... passes
      - mise run check-full passes
      - grep -n "first-run setup is skipped" internal/server/bootstrap.go finds the line
      - grep -n "func setupSkipReason" internal/server/env_admins.go finds it

  - id: p3-provisioning-key-file
    title: PEEK_PROVISIONING_KEY_FILE registers a provisioning key at every start
    depends_on: [p2-admin-emails]
    complexity: S
    touches:
      - internal/peekd/run.go
      - internal/peekd/run_test.go
      - internal/server/server.go
      - internal/server/provisioning_seed.go
      - internal/server/provisioning_seed_test.go
      - internal/server/admin.go
      - internal/web/renderer.go
      - internal/web/templates/admin.gohtml
      - CHANGELOG.md
    brief: |
      Read docs/plans/env-bootstrap-plan.md, section "Provisioning key from a file".
      1. run.go: add --provisioning-key-file (PEEK_PROVISIONING_KEY_FILE) and
         --provisioning-key-name (PEEK_PROVISIONING_KEY_NAME, default "PrivacyFence"); read and
         validate as designed (both errors, and the name length 1 to 100:
         "PEEK_PROVISIONING_KEY_NAME must be 1 to 100 characters"). Put ProvisioningKey and
         ProvisioningKeyName on server.Config.
      2. New internal/server/provisioning_seed.go: seedProvisioner(ctx, store, name, key) as designed,
         using GetProvisionerByKey, ListProvisioners, DeleteProvisioner and CreateProvisioner(name, key, 0).
         Call it from server.New after applyLockedSettings when cfg.ProvisioningKey is set.
      3. Admin page: add ProvisioningKeyFromFile string to the admin page data in
         internal/web/renderer.go, fill it in admin.go where the provisioners list is built, and render
         the sentence from the Design under the provisioners list in admin.gohtml
         (near line 137).
      4. Tests: provisioning_seed_test.go (first start registers; same key is a no-op; a new key
         replaces the same-name one and its links; works with zero accounts; a seeded key answers
         GET /api/provisioning/self with 200); run_test.go (errors and default name).
      5. CHANGELOG.md "### Added":
         "- `PEEK_PROVISIONING_KEY_FILE` registers a provisioning key at every start, so PrivacyFence can provision accounts without `peek provisioner create`."
      6. Run `mise run check-full`.
    acceptance:
      - go test ./internal/server/... ./internal/peekd/... passes
      - mise run check-full passes
      - grep -n "registered from PEEK_PROVISIONING_KEY_FILE" internal/server/provisioning_seed.go finds the log line

  - id: p4-docs-retire
    title: Reference and operations docs, delete the plan
    depends_on: [p3-provisioning-key-file]
    complexity: S
    touches:
      - docs/src/content/docs/reference.md
      - docs/src/content/docs/auth-access.md
      - docs/src/content/docs/server-setup.md
      - docs/operations.md
      - README.md
      - docs/plans/env-bootstrap-plan.md
    brief: |
      1. docs/src/content/docs/reference.md, flags table (lines 7-41): add every flag from the plan's
         "Variables and flags" table with its env name and one-line meaning.
      2. docs/src/content/docs/auth-access.md: a section "Configure sign-in from the environment"
         covering locked settings (what the Admin page shows, that the API refuses them), SSO sign-up,
         PEEK_ADMIN_EMAILS (no demotion on removal, provisioned accounts become admins and are then
         refused by provisioning), and when /setup is skipped; and in the provisioning part,
         PEEK_PROVISIONING_KEY_FILE (rotation by replacing the file, revocation comes back at restart).
      3. docs/src/content/docs/server-setup.md and docs/operations.md "First run": say that
         PEEK_ADMIN_EMAILS skips /setup, with a minimal example (PEEK_BASE_URL, PEEK_GOOGLE_CLIENT_ID,
         PEEK_GOOGLE_CLIENT_SECRET_FILE, PEEK_ALLOWED_EMAIL_DOMAIN, PEEK_GOOGLE_ORG_SIGNUP=true,
         PEEK_ADMIN_EMAILS). README.md: one sentence and a link to that section where first run is described.
      4. Dispatch pages.yml on the branch to check the docs site builds (it is in ci.dispatchable),
         and read its result.
      5. Delete docs/plans/env-bootstrap-plan.md; `grep -rn "env-bootstrap-plan" .` finds nothing.
    acceptance:
      - test ! -e docs/plans/env-bootstrap-plan.md
      - grep -rn "PEEK_ADMIN_EMAILS" docs/src/content/docs/reference.md docs/src/content/docs/auth-access.md docs/operations.md finds each file
      - the pages.yml run on the branch is green
```
