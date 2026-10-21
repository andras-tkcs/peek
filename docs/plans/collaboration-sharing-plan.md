# Plan: collaboration sharing (dashboard "shared with me", share emails, no page passwords)

## Goal

Make Peek feel like a collaboration tool for one organization rather than a link drop:

- The dashboard lists a page by its **title only**. The copy-link icon and the `/p/<slug>` text are gone, because the row was too dense.
- The dashboard also lists the pages **shared with me**: restricted pages that have a grant for my email address or for a Google group I belong to. An icon on each row says whether I **own** the page (I can edit it), whether I can edit it **as an admin**, or whether it is only **shared with me** (view only).
- Sharing a restricted page **sends a notification email** with the link to each new grantee. Switching a page to restricted emails everyone who already has a grant. Email is sent over SMTP, which admins configure on a new **Email** tab of the Admin page. That tab has a **Send test email** button.
- The dashboard upload card gets a third mode, **Empty page**: type a name and click **Create page** to get a new page that holds a minimal HTML document titled with that name. You can then upload versions to it.
- The **password** visibility goes away everywhere (dashboard, API, CLI, page gate). A migration turns existing password pages into restricted pages. The new default visibility is **restricted**.
- With **Google org sign-in** on, the Admin page no longer mentions invites anywhere. The Invitations card is already hidden today (`internal/web/templates/admin.gohtml:30`, since 7bdcb18); what is left is setting help text that still talks about invites.

There is no tracking issue. The request came from the user in the planning session.

Decisions the user made while planning: existing password pages become **restricted**; the default visibility becomes **restricted**; email is **SMTP configured on the Admin page**; an email is sent **when a grant is added to a restricted page and when a page switches to restricted**, from both the dashboard and the API/CLI.

## Current state

Line references are to `main` at 3ff1f89.

### Dashboard list
- `internal/server/web_dashboard.go:36-97` `renderDashboard`: admins get `ListAllUploads`; everyone else gets `ListUploadsByOwner`. Grants are loaded for every listed upload (`ListUploadGrantsForUploads`) and put on the row. Nothing lists pages owned by someone else that were shared with the viewer.
- `internal/web/renderer.go:103-115` `DashboardUpload{Slug, Name, SizeHuman, Visibility, CreatedHuman, Grants}`.
- `internal/web/templates/dashboard.gohtml:87-97`: the first cell holds a `/p/<slug>` link, a copy button (`peek-copy-button`, two SVGs) and the name as muted text. Header: "Your uploads". Row actions: Access dialog (rename, visibility with a Password option and password input, grants), Stats, Delete.
- `internal/web/assets/dashboard-alpine.js:37-39,63`: `visibility: "password"` default and a `canUpload` password check. `internal/web/assets/app.js:134,168`: `pageApp.visibility` defaults to `"password"`.
- `internal/server/web_helpers.go:178-235` `resolveFlash`: placeholders are filled only from rows in the dashboard list, and `{email}` only when that row's `Grants` include the email.

### Page passwords
- Model: `internal/models/models.go:7` `UploadVisibilityPassword`, `:112` `Upload.PasswordHash`.
- Domain: `internal/uploads/visibility.go:21-50` `PrepareVisibility(visibility, password) (VisibilityChange, error)` bcrypt-hashes the password. `internal/uploads/service.go:114-118` sets the default visibility to `password`. Error kinds `KindPasswordRequired/NotAllowed/TooLong/Hash` (`service.go:68-71`). `ValidatePasswordLength` (`validate.go:32`) is also used for **account** passwords in `internal/server/web_setup.go:58` and must stay.
- DB: `internal/db/uploads.go:17-19` defaults an empty visibility to `password`. `CreateUploadChecked(..., visibility, passwordHash string, limits)` (46 test call sites), `SetUploadVisibility(ctx, id, visibility, hash)`, `uploadSelect`/`scanUpload` read `password_hash`. `internal/db/schema.go:35`: `visibility TEXT NOT NULL DEFAULT 'password'`. The last migration is 14 (`internal/db/migrations.go:52`).
- Viewing: `internal/server/pages.go:88-90` renders the gate, `:125-127` sets the unlock cookie, `:168-218` `handlePagePassword` and `setPageAuthCookie`. `internal/server/comments.go:291-296` is the password case of `viewerCanAccessUpload`, `:307-316` `uploadAccessRequiredMessage`, `:329` `authCookieName`. `internal/server/security.go:100-115` holds the page-auth cookie helpers. `internal/server/routes.go:39,41` define the `POST /p/{slug}` and `POST /p/{slug}/v/{n}` routes behind `passwordLimiter`. `internal/server/server.go:74,79,212,216` define `passwordLimiter` and `pagePasswordFailLimiter`, and `ratelimit.go:20-21` their constants. `internal/web/renderer.go:18,271-275` `TemplateGate`/`GateData`, and `internal/web/templates/gate.gohtml`.
- API: `internal/server/api_uploads.go:50-120` (multipart `password`, the raw-body `password` refusal, version uploads refusing `password`), `:232-274` `handleSetVisibility` and `visibilityAuditDetail`.
- Dashboard handlers: `web_dashboard.go:125,160,220-237`. Flash codes: `web_helpers.go:59,106-110,124`. Error kinds mapping: `internal/server/upload_service.go:31`.
- CLI: `internal/cli/upload_command.go:18-106,154-194` (`--password`, `--password-stdin`, default `password`, `validVisibility`), `internal/cli/uploads_command.go:113-185` (`peek visibility`), `internal/cli/commands.go:77-88` (help), `internal/cli/hostcheck.go:78` (warning text mentions page passwords).
- Docs: README.md (14 mentions), `docs/operations.md` (Page Access, the gate lock), docs site pages `auth-access.md`, `using-peek.md`, `manual.md`, `index.md`, `reference.md`, `skills/peek/SKILL.md`, `skills/peek-server/SKILL.md`, `scripts/gen-screenshots.sh:114-115`.

### Grants and access
- `internal/db/grants.go`: `AddUploadGrant` is idempotent (`ON CONFLICT DO NOTHING`) and returns the row; it does not say whether it inserted one.
- `internal/server/access.go:18-52` `accountCanViewRestricted`: owner, admin, user grant on the lowercased email, then group grants through `GroupChecker.IsMember` (cached in `internal/groups`, 5 s timeout per lookup).
- `internal/server/web_grants.go` (dashboard add/remove) and `internal/server/api_grants.go` (API add/remove/list).

### Email
There is no mail code anywhere (`grep -rn smtp internal` is empty). Runtime settings live in `internal/server/settings.go:20-46` (`settingsMeta`), are normalized by `normalizeSettingValue` (`:110-154`), saved by `handleDashboardSettings` (`:218-266`) and rendered through `dashboardSettingsPanel` (`:334-353`). Secret keys are encrypted at rest through `secretSettingKeys` (`internal/server/security.go:207-213`). The Admin settings form has three Alpine tabs (`admin.gohtml:112-116`).

### Invites under Google org sign-in
`admin.gohtml:30` already hides the Invitations card when `GoogleOrgSignup` is on. `handleInviteLink` and `handleDashboardCreateInvite` already refuse invites (`internal/server/admin.go:19,49`), and the login page hides its invite note (`web_login.go:179`). Still visible: the help text of "Allowed email domain" ("…CLI approval, and invites…", `settings.go:22`) and of "Google org sign-in" ("…no invite needed…", `settings.go:23`).

### Tooling
`mise run check` = fmt-check, vet, test, build. `mise run build` runs `mise run tailwind`, which regenerates the committed `internal/web/assets/pines.css` from the templates and `internal/web/tailwind-input.css`; it downloads a pinned Tailwind binary (verified to work in the container). `scripts/coverage-gate.sh` (in `check-full`) requires total statement coverage of at least 90%. `internal/architecture_test.go` enforces package import rules.

## Design

### 3.1 Removing password visibility

- Visibilities are `public`, `signed-in`, `restricted`. The legacy input `private` keeps mapping to `signed-in`.
- **Migration 15** `drop_password_visibility`: `UPDATE uploads SET visibility='restricted', password_hash='' WHERE visibility='password'`. It is a plain SQL entry in the `migrations` slice. The `password_hash` column **stays** in the schema; SQLite column drops are not worth a table rebuild, and older binaries can still read the column. No Go code reads or writes it after phase p2, except `SetUploadVisibility`, which clears it to `''`.
- `internal/db/schema.go`: the `uploads.visibility` default becomes `'restricted'`. This only affects new databases; existing ones keep `DEFAULT 'password'` from `CREATE TABLE IF NOT EXISTS` and migration 6, which is harmless because Go always passes a visibility.
- Viewing: no gate, no `POST /p/{slug}` or `POST /p/{slug}/v/{n}` routes (the mux answers them with 405), no unlock cookie, no page-password limiters. `viewerCanAccessUpload` drops the password case, so a stray `password` row falls through to `default: false` and `servePage`'s fail-closed branch answers 403 "This page is not available." `uploadAccessRequiredMessage` returns `"access denied"` for every visibility except `signed-in`, which keeps `"login required"`.
- Domain API, all exact:
  ```go
  // PrepareVisibility validates and normalizes a visibility. The legacy "private"
  // maps to signed-in. An empty visibility is invalid here; Create applies its own
  // default before calling this.
  func PrepareVisibility(visibility string) (string, error)
  ```
  The only error is `newError(KindInvalidVisibility, "visibility must be public, signed-in, or restricted")`. Remove the `VisibilityChange` type and `KindPasswordRequired`, `KindPasswordNotAllowed`, `KindPasswordTooLong`, `KindPasswordHash`. `CreateInput.Password` is removed. `Create`'s default is `models.UploadVisibilityRestricted`.
- DB API: `CreateUploadChecked(ctx, slug string, ownerAccountID, ownerTokenID int64, name string, size int64, visibility string, limits uploadquota.Limits) error`, with `password_hash` left out of the INSERT so it takes the column default `''`, and an empty visibility defaulting to `models.UploadVisibilityRestricted`. `SetUploadVisibility(ctx, id int64, visibility string) error` runs `UPDATE uploads SET visibility=?, password_hash='' WHERE id=?`. `uploadSelect` and `scanUpload` no longer read `password_hash`. `models.Upload.PasswordHash` and `models.UploadVisibilityPassword` are removed (`models.Account.PasswordHash` stays: it is the account login password).
- HTTP API: `const passwordRemovedMessage = "password-protected pages were removed; use restricted visibility and grants"` in `api_uploads.go`. A multipart upload with a non-empty `password` field, or a `POST /api/uploads/{slug}/visibility` body with a non-empty `password`, gets 400 with that message. `visibility=password` gets the normal invalid-visibility 400. `handleUploadVersion` loses its `password` parameter, and its message becomes `"visibility cannot be set when uploading a new version; use the visibility endpoint"`. `visibilityAuditDetail` is deleted; callers use `auditDetail("slug", slug, "visibility", v)`.
- Dashboard handlers ignore any `password` form field. Flash code `flashPasswordUpdated` and the `upload_password_*` messages are removed. `upload_invalid_visibility` reads `"visibility must be public, signed-in, or restricted"`.
- CLI: `--password` and `--password-stdin` on `peek upload` and `peek visibility` fail with `passwordFlagRemoved(flag)`, a new helper in `internal/cli/upload_command.go`: `func passwordFlagRemoved(flag string) error { return fmt.Errorf("%s is no longer supported: password-protected pages were removed; use --visibility restricted and 'peek grant'", flag) }`. The `--slug` refusal text (`upload_command.go:74-76`) is unchanged, apart from its condition no longer mentioning password. The default visibility for a new upload is `restricted`. `validVisibility` accepts `public`, `signed-in`, `private`, `restricted`. Usage strings: `usage: peek upload <file.html> [--visibility public|signed-in|restricted] [--name <name>] [--slug <slug>]` and `usage: peek visibility <slug> public|signed-in|restricted`. The invalid message is `visibility must be public, signed-in, or restricted`. The http warning in `hostcheck.go:78` becomes `warning: %s uses plain http://; your token is sent unencrypted. Use https:// unless this host is only reachable on a trusted network.`

Rejected: keeping existing password pages working as legacy (it keeps the gate, limiters and cookie code for a feature that is gone); migrating them to `signed-in` (it widens who can see them).

### 3.2 Dashboard: title only, shared with me, role icons

- One card titled **Pages** (it was "Your uploads"), with the row count next to it as today.
- `DashboardUpload` gains `Role string` and `OwnerName string`. The roles are the strings `"owner"` (I own it), `"admin"` (someone else owns it and I am an admin), and `"viewer"` (shared with me, view only). In `internal/server/web_dashboard.go`: `const (dashRoleOwner = "owner"; dashRoleAdmin = "admin"; dashRoleViewer = "viewer")`.
- Rows:
  - Admin: `ListAllUploads`, as today. Role `owner` when `OwnerAccountID == me`, else `admin`.
  - Everyone else: `ListUploadsByOwner(me)` (role `owner`) plus `sharedWithAccount(ctx, me)` (role `viewer`). The two lists are merged and sorted newest first by `CreatedAt` (`sort.SliceStable`). An upload is never in both lists, because the shared query excludes my own pages.
  - Grants are loaded **only for `owner` and `admin` rows**. A viewer row has no `Grants`, so other grantees' emails never reach a viewer and `resolveFlash` never fills `{email}` for a viewer row.
- DB (`internal/db/grants.go`):
  ```go
  // ListRestrictedGroupGrantEmails returns the distinct group emails granted on
  // restricted uploads not owned by excludeOwnerID, sorted.
  func (s *Store) ListRestrictedGroupGrantEmails(ctx context.Context, excludeOwnerID int64) ([]string, error)

  // ListUploadsSharedWith returns restricted uploads not owned by excludeOwnerID
  // that have a user grant for userEmail or a group grant for one of groupEmails,
  // newest first. userEmail and groupEmails are compared lowercased.
  func (s *Store) ListUploadsSharedWith(ctx context.Context, userEmail string, groupEmails []string, excludeOwnerID int64) ([]models.Upload, error)
  ```
  `ListUploadsSharedWith` is `uploadSelect + ` WHERE u.visibility='restricted' AND u.owner_account_id<>? AND EXISTS (SELECT 1 FROM upload_grants g WHERE g.upload_id=u.id AND ((g.kind='user' AND g.email=?) OR (g.kind='group' AND g.email IN (…)))) ORDER BY u.created_at DESC``. With no groups, the `IN` part is left out.
- Server (`internal/server/access.go`):
  ```go
  // maxSharedGroupChecks bounds the group lookups one dashboard render makes.
  const maxSharedGroupChecks = 25

  // sharedWithAccount returns the restricted uploads owned by someone else that a
  // may view through a user grant or a group grant.
  func (s *Server) sharedWithAccount(ctx context.Context, a *models.Account) ([]models.Upload, error)
  ```
  An empty email (automation account) returns `nil, nil`. When `s.groups != nil`, it lists the group emails, checks at most the first 25 with `IsMember` (`slog.Warn("shared-with-me group check limit reached", "groups", n)` when there are more; a lookup error is `slog.Warn("group membership check failed", "group", g, "err", err)` and is skipped), and passes the member groups to `ListUploadsSharedWith`. An error from it is logged as `slog.Error("dashboard shared list failed", "account_id", a.ID, "err", err)` and the dashboard shows the owned rows only.
- Icon paths (heroicons v2 outline, `fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"`, each `<path stroke-linecap="round" stroke-linejoin="round" d="…"/>`):
  - pencil-square: `m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10`
  - shield-check: `M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z`
  - eye: two paths, `M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z` and `M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z`
- Template branch order: `{{if eq .Role "viewer"}}…eye…{{else if eq .Role "admin"}}…shield…{{else}}…pencil…{{end}}`, so a row with an empty Role (older renderer tests) shows the owner icon.
- Template, first cell (heroicons outline, 24×24 viewBox, `class="h-4 w-4 shrink-0 text-muted-foreground"` on the `<svg>`, wrapped in a `<span>` with `title` and `aria-label` and `role="img"`):
  - owner: pencil-square icon, `title="You own this page and can edit it"`, `aria-label="Owned by you"`.
  - admin: shield-check icon, `title="Owned by {{.OwnerName}}. You can edit it as an admin"`, `aria-label="Owned by {{.OwnerName}}, editable as admin"`.
  - viewer: eye icon, `title="Shared with you by {{.OwnerName}}. View only"`, `aria-label="Shared with you, view only"`.
  - Then `<a href="/p/{{.Slug}}" target="_blank" title="{{.Name}}" class="min-w-0 truncate font-medium text-primary no-underline hover:underline">{{.Name}}</a>`. There is no copy button and no slug text. The column header is `Page` (was `Link`).
- Viewer rows have an empty actions cell: no Access, Stats or Delete. The handlers already refuse non-owners.
- The upload form's visibility picker is, in order, **Restricted** (default), **Signed-in users**, **Public**. The Access dialog's picker is the same, with no password radio, input or hint. The Access dialog heading becomes `Access for {{.Name}}`.
- Empty state: `No pages yet.` / `Upload an HTML file or paste HTML above. Pages people share with you show up here too.`
- `dashboard-alpine.js`: `visibility: "restricted"`; the `password` state and the password clause of `canUpload` are removed. Keep `clipboardState()` spread into `dashboard()`: `admin()` and `TestDashboardAlpineClipboardUsesSharedFailureFeedback` still use it.
- `internal/web/tailwind-input.css`: delete the `.peek-copy-button`, `.peek-copy-button-copied` and `.peek-copy-icon` rules; only the removed dashboard copy button used them (check with grep that `admin.gohtml` uses `peek-link-copy-button` and `peek-copy-icon`; if `peek-copy-icon` is still used anywhere, keep that rule). `app.js`: both `"password"` defaults become `"restricted"`.

Rejected: a separate "Shared with me" card (two near-identical tables; the icon carries the distinction); listing `signed-in` pages as shared (that would be every page in the org).

### 3.3 Mail package

New package `internal/mail` (one file `mail.go`, tests in `mail_test.go`). It knows nothing about uploads or HTTP. Only `internal/server` imports it.

```go
package mail

// TLS modes for Config.TLS.
const (
	TLSStartTLS = "starttls" // plain connect, then STARTTLS; required, never downgraded
	TLSImplicit = "tls"      // TLS from the first byte (port 465)
	TLSNone     = "none"     // no TLS; for a local relay only
)

// Config is one SMTP relay. Port 0 means 587 for starttls and none, 465 for tls.
type Config struct {
	Host     string
	Port     int
	Username string // empty: no AUTH
	Password string
	From     string // bare address
	TLS      string // one of the TLS* constants; empty means TLSStartTLS
}

// Message is one plain-text email to one recipient.
type Message struct {
	To      string // bare address
	ReplyTo string // optional bare address
	Subject string
	Body    string // plain text, "\n" line endings
}

// Sender delivers messages through an SMTP relay.
type Sender interface {
	Send(ctx context.Context, cfg Config, msgs []Message) error
}

// SMTPSender is the net/smtp Sender. Dial is nil in production (net.Dialer).
type SMTPSender struct {
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d SMTPSender) Send(ctx context.Context, cfg Config, msgs []Message) error

// BuildMessage renders the RFC 5322 bytes of msg sent from from. It rejects CR or
// LF in any header value and any address net/mail cannot parse as a bare address.
func BuildMessage(from string, msg Message, now time.Time, messageID string) ([]byte, error)
```

- `Send` opens **one** connection for all messages. Without a context deadline it applies 30 s (`context.WithTimeout`) and sets the deadline on the conn. `TLSImplicit` wraps the conn in `tls.Client(conn, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})`. `TLSStartTLS` requires the `STARTTLS` extension (`fmt.Errorf("smtp server %s does not offer STARTTLS", cfg.Host)` when it is missing) and calls `StartTLS` with the same TLS config. A non-empty `Username` runs `smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)`. net/smtp itself refuses PLAIN auth without TLS unless the host is localhost, and that error is returned as is. Then for each message it runs `Mail(cfg.From)`, `Rcpt(msg.To)`, `Data`, writes `BuildMessage(...)`, and closes; finally `Quit`. Errors are wrapped: `fmt.Errorf("smtp send to %s: %w", msg.To, err)`. Message-ID: `<` + 16 random bytes in hex + `@` + domain of `From` + `>`.
- Headers, in this order: `From: "Peek" <from>`, `To: <to>`, `Reply-To:` (only when set), `Subject:` (`mime.QEncoding.Encode("utf-8", subject)`), `Date:` (`now.Format(time.RFC1123Z)`), `Message-ID:`, `MIME-Version: 1.0`, `Content-Type: text/plain; charset=utf-8`, `Content-Transfer-Encoding: quoted-printable`, `Auto-Submitted: auto-generated`. CRLF line endings. The body goes through `mime/quotedprintable`.
- `internal/architecture_test.go`: a rule for `internal/mail` forbidding `net/http` and every other `github.com/andras-tkcs/peek/internal/...` package.

Rejected: Gmail API through the Workspace service account (Google-only, needs another domain-wide scope); sending asynchronously (needs goroutine ownership and gives the sharer no feedback; a send is bounded by its timeout instead).

### 3.4 SMTP settings, test email, invite wording

- Runtime settings (in `settingsMeta`; none are bool):
  | key | Label | Description | normalize |
  |---|---|---|---|
  | `smtp_host` | `SMTP host` | `Mail relay host name, such as smtp-relay.gmail.com (blank = email off)` | trimmed; error `smtp_host must be a host name without scheme or port` if it contains any of ` /:@` |
  | `smtp_port` | `SMTP port` | `Blank = 587, or 465 for implicit TLS` | `""` or an integer 1–65535, else `smtp_port must be between 1 and 65535` |
  | `smtp_tls` | `SMTP TLS` | `starttls (default), tls (implicit, port 465) or none (local relay only)` | lowercased; `""`, `starttls`, `tls` or `none`, else `smtp_tls must be starttls, tls or none` |
  | `smtp_username` | `SMTP username` | `Blank = no authentication` | trimmed |
  | `smtp_password` | `SMTP password` | `Password or app password for the SMTP username` | trimmed; `IsSecret: true`; added to `secretSettingKeys` |
  | `smtp_from` | `From address` | `Sender address of Peek emails, such as peek@example.com (blank = email off)` | `""` or `mail.ParseAddress` whose `.Address` equals the value, else `smtp_from must be an email address` |
- A file in `internal/server` that needs both packages imports `netmail "net/mail"`; `internal/mail` is always imported unaliased as `mail`. Note that `normalizeSettingValue` trims every value, so an SMTP password cannot start or end with a space; this is documented, not changed.
- Email is **on** when `smtp_host` and `smtp_from` are both non-empty. `func (s *Server) smtpConfig(ctx context.Context) (mail.Config, bool)` builds the config from settings (port parsed; 0 when blank).
- `Server` gets a field `mailer mail.Sender`. `New` sets it to `mail.SMTPSender{}`. `func (s *Server) mailSender() mail.Sender` returns `s.mailer`, or `mail.SMTPSender{}` when it is nil (internal tests build `Server` literals). Tests set `s.mailer` to a fake that records messages.
- `webui.DashboardSettings` gains `Email EmailSettings`, with `type EmailSettings struct { Host, Port, TLS, Username, Password, From SettingRow; TLSValue string }` (`TLSValue` is `starttls` when blank). The Admin settings form gets a fourth tab, **Email** (`settingsTab === 'email'`), with text inputs for host, port, username and From, a password input for the password (blank keeps it, as with S3), and a `<select name="smtp_tls">` with the options `starttls`, `tls`, `none`. Under the fields: `<button type="submit" form="hn-email-test" class="peek-row-button">Send test email</button>` and the hint `Sends a test email to your own address using the saved settings. Save first.` The `<form id="hn-email-test" method="POST" action="/dashboard/email/test">` with its hidden csrf input sits **after** the settings `</form>`, because forms cannot nest.
- Route `POST /dashboard/email/test` → `handleDashboardEmailTest` in the new `internal/server/web_email.go`. Order, as in `handleDashboardSettings`: `owner, ok := s.webAuth(r); if !ok || !owner.IsAdmin { http.Redirect(w, r, "/login", http.StatusSeeOther); return }`, then `if !s.parseAdminForm(w, r) { return }` (CSRF), then the checks below. Results go out through `adminError` / `adminOK` (redirect to /admin).
- Test fake, in `internal/server/web_email_test.go`, reused by p7: `type fakeMailer struct { mu sync.Mutex; cfgs []mail.Config; msgs [][]mail.Message; err error }` with `Send` appending under the lock and returning `err`. Flash codes:
  - `email_not_configured`: `email is not configured: set an SMTP host and From address`
  - `email_no_address`: `your account has no email address`
  - `email_test_failed`: `test email failed; see the server log` (and `slog.Error("test email failed", "err", err)`)
  - `email_test_sent` (ok): `test email sent`
  It sends `Subject: Peek test email` and `Body: "This is a test email from Peek at " + s.baseURL + ".\nEmail notifications are working.\n"` to the admin's own email, with a 15 s timeout. Audit: `s.auditRequest(r, owner.Name, "email.test", auditDetail("result", "sent"|"failed"))`.
- Invite wording: `settingsMeta` descriptions become `Restrict human sign-in, CLI approval, and invites to this email domain (blank = any domain)` (unchanged) for the default, and `dashboardSettingsPanel` replaces the Domain description with `Restrict human sign-in and CLI approval to this email domain (blank = any domain)` when `settingValueBool(raw[authGoogleOrgSignupSetting])`. The Google org description becomes `Only Google sign-in for everyone in the allowed email domain. The first sign-in creates the account. Requires Google login and an allowed email domain.` With org sign-in on, `GET /admin` contains no `invite` (case-insensitive).

### 3.5 Share notifications

- `AddUploadGrant` becomes `func (s *Store) AddUploadGrant(ctx context.Context, uploadID int64, kind, email string, createdBy int64) (*models.UploadGrant, bool, error)`. The bool is true when this call inserted the row (`RowsAffected() == 1` of the INSERT).
- New file `internal/server/share_notify.go`:
  ```go
  // shareNotifyTimeout bounds one notification send.
  const shareNotifyTimeout = 15 * time.Second

  // notifyShare emails each grant's address that sharer gave it access to u.
  // It returns sent=false with a nil error when email is off or there is no
  // recipient left after skipping the sharer's own address.
  // The send runs under context.WithTimeout(r.Context(), shareNotifyTimeout) and is
  // audited with s.auditRequest(r, sharerName, "upload.share.notify", …).
  func (s *Server) notifyShare(r *http.Request, sharerName, sharerEmail string, u *models.Upload, grants []models.UploadGrant) (sent bool, err error)

  // shareMessage builds the email for one grant.
  func (s *Server) shareMessage(sharerName, sharerEmail string, u *models.Upload, g models.UploadGrant) mail.Message
  ```
  Recipients are the grant emails, deduplicated, skipping one equal to the lowercased `sharerEmail`. When the `auth_allowed_email_domain` setting is non-empty, a recipient whose domain (the part after the last `@`, lowercased) differs is skipped too, so Peek cannot be used to mail arbitrary outside addresses; skipped recipients are counted in the audit detail as `"skipped", strconv.Itoa(k)`. Group grants email the group address. One `Send` call carries all messages. Audit: `auditDetail("slug", u.Slug, "recipients", strconv.Itoa(n), "result", "sent"|"failed")` under action `upload.share.notify`. On failure: `slog.Error("share notification failed", "slug", u.Slug, "err", err)`.
- Before building, `shareMessage` replaces every rune below 0x20 and 0x7f in `u.Name` and `sharerName` with a space, and cuts `u.Name` to 80 runes in the Subject only (adding `…` when cut), so a page name cannot make `BuildMessage` refuse the message or produce an over-long header. An empty `sharerName` falls back to `sharerEmail`, then to `Someone`.
- The message, exactly (`{sharer}` is `sharerName`, followed by ` (sharerEmail)` when `sharerEmail` is non-empty; `{url}` is `s.baseURL + "/p/" + u.Slug`; ReplyTo is `sharerEmail`):
  - Subject: `{sharerName} shared "{u.Name}" with you on Peek`
  - Body for a user grant:
    ```
    {sharer} shared a page with you on Peek:

      {u.Name}
      {url}

    Open the link and sign in as {g.Email} to view it.
    ```
  - Body for a group grant: the same, except that the last line is `Open the link and sign in with an account in the group {g.Email} to view it.`
- When an email goes out (both the dashboard and the API):
  - **Grant added**: after a successful `AddUploadGrant` with `created == true` and `u.Visibility == restricted`, call `notifyShare` with that one grant.
  - **Switched to restricted**: after a successful `SetUploadVisibility` where the old visibility was not restricted and the new one is, call `notifyShare` with `ListUploadGrants(u.ID)`. A list error is logged and skips the email.
  - No email on grant removal, on adding an existing grant again, on adding grants to a non-restricted page, or on the migration.
- Dashboard feedback: on a send error the redirect carries both the success code and `err=share_notify_failed`, with the message `saved, but the notification email could not be sent`. On success, or when email is off, it is unchanged. `resolveFlash` already shows both `Error` and `Success`.
- API: `POST /api/uploads/{slug}/grants` answers `grantAddOut{grantOut; Notified bool `json:"notified"`}` (the embedded struct flattens into the JSON). `POST /api/uploads/{slug}/visibility` answers `{"visibility": v, "notified": bool}`. A send error never changes the status code (still 200).

### 3.6 New empty page from the dashboard

- The mode toggle of the upload card (`dashboard.gohtml`, radios `name="mode"`) gets a third option after **Paste HTML**: `<input type="radio" name="mode" value="empty" x-model="mode" class="sr-only"> Empty page`, styled like the other two.
- In empty mode the file picker and textarea are hidden (they are already `x-show` on `mode`). The name input gets `x-model="name"`, its placeholder is `page name` (instead of `name (optional)`) and it is `:required="mode === 'empty'"`. The submit button's text is `Create page` in empty mode and `Upload &amp; get link` otherwise (`x-text`).
- `dashboard-alpine.js`: the state gains `name: ""`, and `canUpload()` returns `this.name.trim() !== ""` when `this.mode === "empty"`.
- `handleDashboardUpload`: `mode == "empty"` → if `name == ""`, `dashboardError(w, r, "upload_name_required")` (that flash code already exists). Otherwise `data = []byte(emptyPageHTML(name))`, and the request goes through the same `uploadService().Create` path with the selected visibility (default restricted), the same audit (`upload.create`) and the same `dashboardUploaded` redirect.
  ```go
  // emptyPageHTML is the starter document of a page created empty from the dashboard.
  func emptyPageHTML(name string) string {
  	return "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>" + html.EscapeString(name) + "</title>\n</head>\n<body>\n</body>\n</html>\n"
  }
  ```
  (`html` is the standard library `html` package.) This passes `looksLikeHTML` (`internal/uploads/validate.go`), so no domain change is needed.

Rejected: a separate "New page" button and dialog (it repeats the visibility picker; a third mode reuses the form).

### 3.7 Non-goals

No change to `GET /api/uploads` or `peek list` (they still list owned pages only). No email on invites. No HTML email. No per-user opt-out.

## Manual steps

There is nothing to do before implementation: every phase builds and tests against fakes (a fake SMTP server, a fake `mail.Sender`, the existing fake `GroupChecker`).

After the last merge, before the PR merges, the user verifies four things on a staging server ([step-by-step page](https://claude.ai/artifact/2gLXKAMWX7EbnUEwHD56TF)):

- `ma1-smtp-live`: real SMTP settings, **Send test email**, share a restricted page, and the email arrives with a working link.
- `ma2-dashboard-look`: the dashboard rows and icons as an owner, a grantee and an admin.
- `ma3-upgrade-copy`: the new binary on a copy of real data turns password pages into restricted ones.
- `ma4-google-org-admin`: on a Google org sign-in server, the Admin page mentions no invites.

## Risks and open questions

- **Interim states between phases**: after p1b, a page still stored as `password` (one created between p1b and p2 in a test, or a row the migration missed) is served to nobody, by the fail-closed branch. After p2, the dashboard template still shows a Password radio until p5, and choosing it gets the invalid-visibility flash. Both states are expected; workers must not "fix" them early.
- **p1b stop condition**: `servePage` must not end up admitting a `password` row. If removing the gate makes any test expect a password page to render its iframe, the test is wrong for the new behaviour; change it to expect 403. If `servePage` has no fail-closed `default` branch any more, stop with `status=blocked`.
- **p2 compile fan-out**: removing `Upload.PasswordHash` and the `CreateUploadChecked` parameter breaks every test call site. `go build ./... && go vet ./...` lists them all. If a non-test caller outside the `touches` list appears, stop with `status=blocked`.
- **Shared-with-me cost**: group checks run one after another, so a slow Directory API can make a dashboard render take up to 25 × 5 s. That is bounded by `maxSharedGroupChecks` and documented in `docs/operations.md`. The results are cached for the group cache TTL.
- **net/smtp PLAIN auth over `none`**: refused by the standard library unless the host is localhost. That is intended and documented, not a bug to work around.
- **Tailwind regeneration**: phases that add utility classes must run `mise run tailwind` and commit `internal/web/assets/pines.css`. If the Tailwind download fails, stop with `status=blocked`; do not hand-edit `pines.css`. Phases that do not list `pines.css` in `touches` restore it with `git checkout -- internal/web/assets/pines.css` and stop with `status=blocked` if their build changed it.
- **Coverage gate (90% total)**: `internal/mail` is new code. If `scripts/coverage-gate.sh` drops below 90% after p4, add tests for `BuildMessage` and `Send` error paths, not exclusions.

## Implementation manifest

```yaml
plan_slug: collaboration-sharing
feature_branch: feat/collaboration-sharing
max_parallel: 2
manual_steps_artifact: https://claude.ai/artifact/2gLXKAMWX7EbnUEwHD56TF
manual_steps_source: docs/plans/collaboration-sharing-plan-manual-steps.html
manual_before: []
manual_after:
  - id: ma1-smtp-live
    title: Configure real SMTP on a staging server, send a test email and a share notification
    why: CI only talks to a fake SMTP server; TLS, AUTH and real delivery (spam filtering, link rendering) need a real relay.
  - id: ma2-dashboard-look
    title: Check the dashboard rows and role icons as owner, grantee and admin
    why: Template tests check markup, not whether the row reads clearly and the icons and tooltips make sense.
  - id: ma3-upgrade-copy
    title: Run the new binary against a copy of real data that has password pages
    why: Migration 15 is tested on a synthetic database; this confirms real password pages become restricted and their owners can still open them.
  - id: ma4-google-org-admin
    title: On a Google org sign-in server, confirm the Admin page mentions no invites
    why: Confirms the wording change on a real configuration the user cares about.
verify_after_merge:
  - go build ./...
  - go test -race -count=1 ./internal/server/... ./internal/db/... ./internal/uploads/... ./internal/mail/... ./internal/cli/...
final_checks:
  - docs/plans/collaboration-sharing-plan.md and docs/plans/collaboration-sharing-plan-manual-steps.html are deleted and nothing links to them
  - "grep -rniIE 'password-protected|page password|password visibility|visibility[= ]password|--password' README.md docs/src/content/docs skills scripts/demo-report.html | grep -v 'were removed' prints nothing"
  - grep -rnw 'UploadVisibilityPassword\|handlePagePassword\|TemplateGate' internal cmd prints nothing
  - mise run check-full passes
phases:
  - id: p1a-migrate-password-pages
    title: Migration 15 turns password pages into restricted pages
    depends_on: []
    complexity: S
    touches:
      - internal/db/migrations.go
      - internal/db/schema.go
      - internal/db/migrations_test.go
    brief: |
      Read AGENTS.md, CONTRIBUTING.md, docs/architecture.md, docs/operations.md and Design 3.1 of docs/plans/collaboration-sharing-plan.md.
      1. internal/db/migrations.go: append `{15, "drop_password_visibility", `UPDATE uploads SET visibility='restricted', password_hash='' WHERE visibility='password'`}` to `migrations`.
      2. internal/db/schema.go: change the uploads table's `visibility TEXT NOT NULL DEFAULT 'password'` to `DEFAULT 'restricted'` (only that column; the accounts password_hash column is unrelated).
      3. internal/db/migrations_test.go: add `TestMigration15PasswordPagesBecomeRestricted`, modelled on `TestMigrationRenamesPrivateVisibilityToSignedIn` and using `migCovPrepare(t, 15, …)`: insert an upload with visibility 'password' and a non-empty password_hash, and a 'public' one; run migrations; assert the first is visibility='restricted' with password_hash='' and the second is unchanged.
      4. Run `mise run check`. If the build changes internal/web/assets/pines.css, run `git checkout -- internal/web/assets/pines.css` and stop with status=blocked.
    acceptance:
      - go test ./internal/db -run '^TestMigration15PasswordPagesBecomeRestricted$' -count=1 passes
      - grep -n "DEFAULT 'restricted'" internal/db/schema.go matches
      - mise run check-full passes

  - id: p1b-remove-password-gate
    title: Remove the page-password gate, unlock route, cookies and limiters
    depends_on: [p1a-migrate-password-pages]
    complexity: M
    touches:
      - internal/server/pages.go
      - internal/server/comments.go
      - internal/server/security.go
      - internal/server/routes.go
      - internal/server/server.go
      - internal/server/ratelimit.go
      - internal/server/*_test.go
      - internal/web/renderer.go
      - internal/web/renderer_test.go
      - internal/web/templates/gate.gohtml
      - internal/web/assets/pines.css
    brief: |
      Read Design 3.1 of docs/plans/collaboration-sharing-plan.md. This phase removes how password pages are *viewed*; it does NOT touch creation (models.UploadVisibilityPassword, uploads.PrepareVisibility and the dashboard/API inputs stay until p2).
      1. internal/server/comments.go: remove the `case models.UploadVisibilityPassword` branch of `viewerCanAccessUpload` and the `authCookieName` function. `uploadAccessRequiredMessage` returns "login required" for signed-in and "access denied" for everything else. In the comment at the top of `handleListComments`, replace "…go through the public / password-cookie gate instead." with "…go through the page access check instead."
      2. internal/server/pages.go: in `servePage`, delete the password gate branch (`TemplateGate`) and the `setPageAuthCookie` call. Delete `handlePagePassword`, `setPageAuthCookie` and `querysuffix` (only handlePagePassword uses it). Keep the fail-closed `if !s.viewerCanAccessUpload(r, u)` branch exactly as it is; stop with status=blocked if it is gone.
      3. internal/server/routes.go: delete the `POST /p/{slug}` and `POST /p/{slug}/v/{n}` routes. internal/server/server.go: delete the `passwordLimiter` and `pagePasswordFailLimiter` fields and initializers. internal/server/ratelimit.go: delete `pagePasswordFailureMax` and `pagePasswordFailureWindow`. internal/server/security.go: delete `pageAuthSubject`, `makePageAuthCookieValue`, `verifyPageAuthCookie` and their comment.
      4. internal/web/renderer.go: delete `TemplateGate` and `GateData`; delete internal/web/templates/gate.gohtml; fix internal/web/renderer_test.go if it renders the gate.
      5. Tests: `go build ./... && go vet ./...` lists every broken test file. Delete tests that only exercised unlocking (TestPasswordPageAccessMatrix, wrong-password and lockout tests, the unlock-cookie helper). In `TestPageAccessMatrix` the `models.UploadVisibilityPassword` row becomes `{deny, noauth}` for all five actors (page 403, API 401, since `uploadAccessStatus` returns 403 only for restricted), and its `wantFrame` stays false. `TestRawAccessMatrix` drops its password case. `TestOwnerOnlyAPIMatrix` keeps its password case unchanged. Do not loosen any other assertion.
      6. Add to pages_test.go: `TestPagePasswordRoutesRemoved` (`POST /p/<slug>` and `POST /p/<slug>/v/1` answer 405) and `TestStrayPasswordVisibilityFailsClosed` (create a row with the literal string "password" as visibility through `s.store.CreateUploadChecked`; as owner, admin and anonymous: `/p/<slug>` is 403, `GET /api/uploads/<slug>/comments` without a token is 401, and the `/raw/<slug>/v/1` route is 403 or 404, never 200). Use the literal "password", not the model constant, so p2 can remove the constant without touching this test.
      7. Run `mise run check` (it regenerates pines.css because gate.gohtml is gone; commit the change) and `mise run race`.
    acceptance:
      - go test ./internal/server -run '^(TestPagePasswordRoutesRemoved|TestStrayPasswordVisibilityFailsClosed)$' -count=1 passes
      - grep -rnw 'handlePagePassword\|TemplateGate\|GateData\|pagePasswordFailLimiter\|passwordLimiter\|authCookieName\|verifyPageAuthCookie' internal prints nothing
      - test -e internal/web/templates/gate.gohtml fails (file is deleted)
      - mise run check-full passes

  - id: p2-remove-password-input
    title: Drop password visibility from the model, domain, DB API and HTTP handlers; default to restricted
    depends_on: [p1b-remove-password-gate]
    complexity: M
    touches:
      - internal/models/models.go
      - internal/uploads/visibility.go
      - internal/uploads/service.go
      - internal/uploads/*_test.go
      - internal/db/uploads.go
      - internal/db/*_test.go
      - internal/server/api_uploads.go
      - internal/server/web_dashboard.go
      - internal/server/web_helpers.go
      - internal/server/upload_service.go
      - internal/server/*_test.go
      - internal/peekd/*_test.go
    brief: |
      Read Design 3.1 of docs/plans/collaboration-sharing-plan.md; it has every signature and string used here. Templates and JS are NOT changed here (p5 does that). Until then the dashboard's Password radio gets the invalid-visibility flash, which is expected.
      1. internal/models/models.go: delete `UploadVisibilityPassword` and `Upload.PasswordHash`. Keep `Account.PasswordHash`.
      2. internal/uploads/visibility.go: replace the file body with `PrepareVisibility(visibility string) (string, error)` exactly as in Design 3.1 (trim; "private" → signed-in; public/signed-in/restricted ok; else KindInvalidVisibility "visibility must be public, signed-in, or restricted"). Delete `VisibilityChange` and the bcrypt import. internal/uploads/service.go: delete `CreateInput.Password` and the `KindPasswordRequired`, `KindPasswordNotAllowed`, `KindPasswordTooLong`, `KindPasswordHash` kinds; set the empty-visibility default to `models.UploadVisibilityRestricted`; change the `Repository.CreateUploadChecked` signature to drop `passwordHash`. Keep `ValidatePasswordLength` in validate.go (web_setup.go uses it for account passwords).
      3. internal/db/uploads.go: `CreateUploadChecked` drops the `passwordHash` parameter, leaves `password_hash` out of the INSERT, and defaults an empty visibility to `models.UploadVisibilityRestricted`. `SetUploadVisibility(ctx, id, visibility)` runs `UPDATE uploads SET visibility=?, password_hash='' WHERE id=?`. Remove `u.password_hash` from `uploadSelect` and `&u.PasswordHash` from `scanUpload`.
      4. internal/server/api_uploads.go: add `const passwordRemovedMessage = "password-protected pages were removed; use restricted visibility and grants"`. Multipart: a non-empty trimmed `password` field → `jsonError(w, http.StatusBadRequest, passwordRemovedMessage)` before any other work. Delete the raw-body `visibility == password` refusal. `handleUploadVersion` drops its `password` parameter, and its refusal text becomes "visibility cannot be set when uploading a new version; use the visibility endpoint". In `handleSetVisibility`, keep the `Password` body field only to refuse a non-empty one with passwordRemovedMessage, then call `uploads.PrepareVisibility(body.Visibility)` and `SetUploadVisibility(ctx, u.ID, v)`. Delete `visibilityAuditDetail` and inline `auditDetail("slug", slug, "visibility", v)` at both callers.
      5. internal/server/web_dashboard.go: the upload handler no longer reads `password`; the visibility handler calls `uploads.PrepareVisibility(r.FormValue("visibility"))`; delete the `flashPasswordUpdated` branch (restricted keeps `dashboardFlashManage`, others `dashboardOKSlug`). internal/server/web_helpers.go: delete `flashPasswordUpdated` and the four `upload_password_*` messages; set `upload_invalid_visibility` to "visibility must be public, signed-in, or restricted". internal/server/upload_service.go: drop the removed kinds from the 400 mapping.
      6. Fix every caller: `go build ./... && go vet ./...` lists them (about 46 `CreateUploadChecked` test calls: drop the hash argument; tests that used "password" visibility switch to "restricted" or are deleted when they only tested passwords; internal/uploads/visibility_test.go and service_test.go are rewritten for the new signature). If a non-test caller outside `touches` breaks, stop with status=blocked.
      7. Add tests: internal/uploads/visibility_test.go `TestPrepareVisibilityRejectsPassword` ("password" → KindInvalidVisibility) and `TestCreateDefaultsToRestricted` in service_test.go; internal/server/api_uploads_test.go `TestAPIUploadRejectsPasswordField` (multipart with password=x → 400 whose body contains passwordRemovedMessage) and `TestAPISetVisibilityRejectsPassword` (visibility "password" → 400; body with password → 400 with passwordRemovedMessage).
      8. `TestStrayPasswordVisibilityFailsClosed` (from p1b) must keep passing unchanged. Run `mise run check-full`. If the build changes internal/web/assets/pines.css, run `git checkout -- internal/web/assets/pines.css` and stop with status=blocked.
    acceptance:
      - go test ./internal/uploads -run '^(TestPrepareVisibilityRejectsPassword|TestCreateDefaultsToRestricted)$' -count=1 passes
      - go test ./internal/server -run '^(TestAPIUploadRejectsPasswordField|TestAPISetVisibilityRejectsPassword)$' -count=1 passes
      - grep -rn 'UploadVisibilityPassword' internal prints nothing
      - grep -c 'PasswordHash' internal/models/models.go prints 1 (Account.PasswordHash)
      - grep -rn 'u\.PasswordHash\|&u\.PasswordHash' internal/db internal/server internal/uploads --include=*.go prints nothing
      - grep -rn 'KindPassword' internal prints nothing
      - go test ./internal/server -run '^TestStrayPasswordVisibilityFailsClosed$' -count=1 passes
      - mise run check-full passes

  - id: p3-cli-drop-password
    title: Remove --password from the CLI and default uploads to restricted
    depends_on: []
    complexity: S
    touches:
      - internal/cli/upload_command.go
      - internal/cli/uploads_command.go
      - internal/cli/commands.go
      - internal/cli/hostcheck.go
      - internal/cli/*_test.go
    brief: |
      Read the CLI bullet of Design 3.1 in docs/plans/collaboration-sharing-plan.md; it has the exact strings.
      1. internal/cli/upload_command.go: add `passwordFlagRemoved` from Design 3.1; `--password` and `--password-stdin` return `passwordFlagRemoved(a)` as soon as they are parsed. Delete the password variables, stdin reading, the shell-history warning and the `password` multipart field (`streamMultipartUpload` and `writeMultipartUpload` lose the `password` parameter). The default visibility for a new upload (no --slug) is "restricted". `validVisibility` accepts public, signed-in, private and restricted. Update the usage and invalid-visibility strings to the Design text.
      2. internal/cli/uploads_command.go (`peek visibility`): the same flag errors through `passwordFlagRemoved`; the body is `{"visibility": visibility}`; the usage and invalid strings come from the Design.
      3. internal/cli/commands.go: delete the help lines `peek upload <file.html> --password <pw> …`, `peek upload <file.html> --password-stdin`, `peek visibility <slug> password --password <pw>` and `… --password-stdin`; anywhere the help lists visibilities, list public|signed-in|restricted.
      4. internal/cli/hostcheck.go:78: use the Design warning text.
      5. Tests: update upload_command_test.go, uploads_command_test.go, uploads_command_requests_test.go, hostcheck_test.go and commands_test.go to the new behaviour. Add `TestUploadPasswordFlagRemoved` and `TestVisibilityPasswordFlagRemoved` (each flag → the exact error, no request sent) and `TestUploadDefaultsToRestricted` (multipart field visibility=restricted when no --visibility is given).
      6. Run `mise run check`. If the build changes internal/web/assets/pines.css, run `git checkout -- internal/web/assets/pines.css` and stop with status=blocked.
    acceptance:
      - go test ./internal/cli -run '^(TestUploadPasswordFlagRemoved|TestVisibilityPasswordFlagRemoved|TestUploadDefaultsToRestricted)$' -count=1 passes
      - grep -rn '"password"' internal/cli --include=*.go | grep -v _test.go prints nothing
      - grep -c -- '"--password-stdin"' internal/cli/upload_command.go internal/cli/uploads_command.go prints 1 for each file
      - mise run check passes

  - id: p4-mail-package
    title: Add internal/mail, a small net/smtp sender with header-safe message building
    depends_on: []
    complexity: M
    touches:
      - internal/mail/mail.go
      - internal/mail/mail_test.go
      - internal/architecture_test.go
    brief: |
      Read Design 3.3 of docs/plans/collaboration-sharing-plan.md; it fixes every exported name, header, default and error text. Standard library only (net/smtp, crypto/tls, mime, mime/quotedprintable, net/mail, crypto/rand); no new dependency.
      1. Create internal/mail/mail.go with the package doc comment "Package mail sends Peek's plain-text notification emails through an SMTP relay." and the constants, Config, Message, Sender, SMTPSender, Send and BuildMessage from Design 3.3. A port of 0 picks 587 (starttls, none) or 465 (tls). The context deadline (30 s default) is applied to the conn with SetDeadline.
      2. BuildMessage rejects with an error: any CR or LF in From, To, ReplyTo or Subject; any From, To or non-empty ReplyTo for which `net/mail.ParseAddress(x)` fails or whose `.Address != x`.
      3. internal/mail/mail_test.go: a fake SMTP server in the test file (net.Listen("tcp", "127.0.0.1:0"), one goroutine per connection owned by the test through a sync.WaitGroup and closed in t.Cleanup). It speaks 220/EHLO (advertising `250-AUTH PLAIN` only when the test asks for it)/MAIL/RCPT/DATA/QUIT and records each envelope and DATA. Tests: `TestSendNoneDeliversAllMessagesOnOneConnection` (two messages, one connection, both RCPTs and bodies recorded); `TestSendStartTLSRequiresExtension` (the server offers no STARTTLS → the Design error text); `TestBuildMessageHeaders` (header order and values, Q-encoded non-ASCII subject, quoted-printable body, CRLF line endings); `TestBuildMessageRejectsHeaderInjection` (table: CR or LF in each field, plus bad addresses); `TestSendPlainAuthOverLocalhost` (TLSNone with Username set against the fake on 127.0.0.1 advertising `AUTH PLAIN`; the fake records the AUTH line and decodes user and password; net/smtp allows PLAIN to localhost); `TestSendImplicitTLSFailsAgainstPlainServer` (TLSImplicit against the plain fake returns an error); `TestSendTimesOut` (a fake that never answers the greeting, ctx with a 200 ms deadline → error within 2 s). Inject the dialer through `SMTPSender.Dial` only where needed; the fake listens on 127.0.0.1, so a nil Dial works too.
      4. internal/architecture_test.go: add a rule for "github.com/andras-tkcs/peek/internal/mail" forbidding "net/http" and the cli, db, groups, models, objectstore, peekd, server, uploads, uploadquota, version and web internal packages, in the same style as the existing rules.
      5. Run `mise run check` and `go test -race -count=1 ./internal/mail/...`. If the build changes internal/web/assets/pines.css, run `git checkout -- internal/web/assets/pines.css` and stop with status=blocked.
    acceptance:
      - go test -race ./internal/mail -run '^(TestSendNoneDeliversAllMessagesOnOneConnection|TestSendStartTLSRequiresExtension|TestBuildMessageHeaders|TestBuildMessageRejectsHeaderInjection|TestSendPlainAuthOverLocalhost|TestSendImplicitTLSFailsAgainstPlainServer|TestSendTimesOut)$' -count=1 passes
      - go test ./internal -run '^TestInternalPackageDependencyDirection$' -count=1 passes
      - grep -n 'internal/mail' internal/architecture_test.go matches
      - p=$(mktemp) && go test ./internal/mail -coverprofile=$p && go tool cover -func=$p | tail -1 reports >= 80%
      - mise run check passes

  - id: p5-dashboard-pages
    title: "Dashboard: title-only rows, pages shared with me, role icons, no password UI"
    depends_on: [p2-remove-password-input]
    complexity: M
    touches:
      - internal/db/grants.go
      - internal/db/grants_test.go
      - internal/server/access.go
      - internal/server/web_dashboard.go
      - internal/server/web_dashboard_test.go
      - internal/web/renderer.go
      - internal/web/renderer_test.go
      - internal/web/assets_test.go
      - internal/web/templates/dashboard.gohtml
      - internal/web/assets/dashboard-alpine.js
      - internal/web/assets/app.js
      - internal/web/assets/pines.css
      - internal/web/tailwind-input.css
    brief: |
      Read Design 3.2 of docs/plans/collaboration-sharing-plan.md; it fixes every name, query, string and icon.
      1. internal/db/grants.go: add `ListRestrictedGroupGrantEmails` and `ListUploadsSharedWith` exactly as specified (reuse `uploadSelect` and `scanUploads` from uploads.go; lowercase the emails with `normalizeGrantEmail`). Tests in grants_test.go: `TestListUploadsSharedWith` (user grant on a restricted page → listed; the same grant on a signed-in page → not listed; the owner's own restricted page → not listed; a group grant listed only when the group is passed) and `TestListRestrictedGroupGrantEmails` (distinct, sorted, excludes the owner's pages and non-restricted pages).
      2. internal/server/access.go: add `maxSharedGroupChecks` and `sharedWithAccount` as specified.
      3. internal/web/renderer.go: add `Role string` and `OwnerName string` to `DashboardUpload`, with a comment listing the three roles.
      4. internal/server/web_dashboard.go `renderDashboard`: add the role constants. Admin: ListAllUploads with role owner or admin. Others: ListUploadsByOwner (owner) + sharedWithAccount (viewer), merged newest first with sort.SliceStable on CreatedAt. Fill OwnerName from `models.Upload.OwnerName`. Load grants only for the IDs of owner and admin rows.
      5. internal/web/templates/dashboard.gohtml: the card title becomes "Pages"; the header "Link" becomes "Page"; the first cell is the role icon span plus the title link exactly as in Design 3.2 (delete the copy button and the slug text); viewer rows get an empty actions cell (`{{if ne .Role "viewer"}}…existing actions…{{end}}`). Upload picker: Restricted, Signed-in users, Public, with no password input. Access dialog: no Password radio, password input or hint; the heading is "Access for {{.Name}}". Empty-state text from the Design. Take the pencil-square, shield-check and eye outline paths from heroicons v2 (24×24, stroke-width 1.5).
      6. internal/web/assets/dashboard-alpine.js: `visibility: "restricted"`; remove `password` and its `canUpload` clause; keep `clipboardState()` (Design 3.2). internal/web/assets/app.js: both "password" defaults become "restricted". Follow the JS rules in CONTRIBUTING.md (no HTML string insertion). internal/web/tailwind-input.css: delete the dead copy-button rules as Design 3.2 says. Update internal/web/assets_test.go `TestParentAppReadsViewerConfigFromDataset` to expect `this.visibility = dataset.visibility || "restricted"`. Update internal/web/renderer_test.go `TestDashboardRendersAccessDialogPerUpload`: use `Visibility: "restricted"`, drop the `autocomplete="new-password"` and `:disabled="vis !== 'password'"` expectations, and add a check that `value="password"` is absent.
      7. Run `mise run tailwind` and commit internal/web/assets/pines.css. If the download fails, stop with status=blocked; never hand-edit pines.css.
      8. Tests in internal/server/web_dashboard_test.go. Use the helpers in internal/server/access_test.go (`newViewer`, `restrictedPage`, `grant`, `fakeGroups`; read only, do not change that file) and `asSession` / `doRequest` from the server test helpers: `TestDashboardRowShowsTitleOnly` (the body contains the page name inside the /p/<slug> link, and contains neither `peek-copy-button` nor `>/p/<slug><`); `TestDashboardListsPagesSharedWithMe` (a grantee sees the row with `Shared with you by <owner>. View only`, there is no `/dashboard/delete/<slug>` form and no `/dashboard/visibility/<slug>` form for it, and a second grantee's email is absent from the body); `TestDashboardSharedViaGroup` (`s.groups = fakeGroups{…}` making bob a member of team@…; a group grant for team@… on alice's restricted page; bob's dashboard has `Shared with you by`, eve's does not); `TestDashboardSkipsNonRestrictedShares` (a user grant for bob on alice's signed-in page and on her public page; neither appears on bob's dashboard); `TestDashboardAdminRoleIcon` (an admin sees `You can edit it as an admin` on another user's page and `You own this page and can edit it` on their own); `TestDashboardNoPasswordOption` (the body has no `value="password"`).
      9. Run `mise run check-full`.
    acceptance:
      - go test ./internal/db -run '^(TestListUploadsSharedWith|TestListRestrictedGroupGrantEmails)$' -count=1 passes
      - go test ./internal/server -run '^(TestDashboardRowShowsTitleOnly|TestDashboardListsPagesSharedWithMe|TestDashboardSharedViaGroup|TestDashboardSkipsNonRestrictedShares|TestDashboardAdminRoleIcon|TestDashboardNoPasswordOption)$' -count=1 passes
      - grep -n 'peek-copy-button\|value="password"' internal/web/templates/dashboard.gohtml prints nothing
      - grep -rn '"password"' internal/web/assets/dashboard-alpine.js internal/web/assets/app.js prints nothing
      - go test ./internal/web -count=1 passes
      - mise run check-full passes

  - id: p5b-empty-page
    title: "Dashboard: create a new empty page with a given name"
    depends_on: [p5-dashboard-pages]
    complexity: S
    touches:
      - internal/server/web_dashboard.go
      - internal/server/web_dashboard_test.go
      - internal/web/templates/dashboard.gohtml
      - internal/web/assets/dashboard-alpine.js
    brief: |
      Read Design 3.6 of docs/plans/collaboration-sharing-plan.md; it fixes the markup, the strings and `emptyPageHTML`.
      1. internal/server/web_dashboard.go: add `emptyPageHTML` and the `mode == "empty"` branch in `handleDashboardUpload`, before the file branch, as specified.
      2. internal/web/templates/dashboard.gohtml: add the third mode option, the name input changes and the button text from Design 3.6. Use only classes that already appear in the template, so pines.css does not change. Stop with status=blocked if `mise run build` changes internal/web/assets/pines.css.
      3. internal/web/assets/dashboard-alpine.js: add `name: ""` and the empty-mode clause of `canUpload`.
      4. Tests in internal/server/web_dashboard_test.go (copy the setup of the existing dashboard upload test): `TestDashboardCreateEmptyPage` (mode=empty, name "Q3 notes", no visibility field sent → 303 with uploaded=<slug>; the stored upload has name "Q3 notes" and visibility restricted, and its object bytes equal emptyPageHTML("Q3 notes")); `TestDashboardCreateEmptyPageRequiresName` (mode=empty, blank name → redirect with err=upload_name_required, no upload created); `TestEmptyPageHTMLEscapesName` (emptyPageHTML("<b>&") contains `<title>&lt;b&gt;&amp;</title>`); `TestDashboardHasEmptyPageMode` (the dashboard body contains `value="empty"`).
      5. Run `mise run check-full`.
    acceptance:
      - go test ./internal/server -run '^(TestDashboardCreateEmptyPage|TestDashboardCreateEmptyPageRequiresName|TestEmptyPageHTMLEscapesName|TestDashboardHasEmptyPageMode)$' -count=1 passes
      - after mise run build, git diff --exit-code $(git merge-base HEAD origin/feat/collaboration-sharing) -- internal/web/assets/pines.css exits 0
      - mise run check-full passes

  - id: p6-smtp-settings
    title: SMTP settings on the Admin page, a test-email button, and invite-free wording under Google org sign-in
    depends_on: [p4-mail-package, p5-dashboard-pages]
    complexity: M
    touches:
      - internal/server/settings.go
      - internal/server/settings_test.go
      - internal/server/security.go
      - internal/server/server.go
      - internal/server/routes.go
      - internal/server/web_email.go
      - internal/server/web_email_test.go
      - internal/server/web_helpers.go
      - internal/server/web_admin_test.go
      - internal/web/renderer.go
      - internal/web/templates/admin.gohtml
      - internal/web/assets/pines.css
    brief: |
      Read Design 3.4 of docs/plans/collaboration-sharing-plan.md; the table there has every key, label, description and error.
      1. internal/server/settings.go: add the six smtp_* entries to `settingsMeta` and their normalize cases to `normalizeSettingValue`; add `Email: dashboardEmailSettings(raw)` to `dashboardSettingsPanel`; apply the Domain description override and the new Google org description from Design 3.4. internal/server/security.go: add "smtp_password" to `secretSettingKeys`.
      2. internal/web/renderer.go: add `EmailSettings` and the `Email` field to `DashboardSettings`.
      3. internal/server/server.go: add `mailer mail.Sender`, set it to `mail.SMTPSender{}` in New, and add `mailSender()`. Put `smtpConfig` in the new internal/server/web_email.go, together with `handleDashboardEmailTest` as specified. internal/server/routes.go: `mux.HandleFunc("POST /dashboard/email/test", s.handleDashboardEmailTest)` next to /dashboard/settings. internal/server/web_helpers.go: the four flash codes and their texts.
      4. internal/web/templates/admin.gohtml: the Email tab button after Limits and its panel (`x-show="settingsTab === 'email'" x-cloak`), with the fields and the select (mark the stored TLSValue as `selected`), the "Send test email" button with `form="hn-email-test"`, and the hint; the `hn-email-test` form after the settings `</form>`. Copy the markup of the Storage tab's S3 inputs.
      5. Run `mise run tailwind` and commit pines.css if it changes (stop with status=blocked if the download fails).
      6. Tests. settings_test.go: `TestSMTPSettingNormalization` (a table covering every row of the Design table, valid and invalid) and `TestSMTPPasswordStoredEncrypted` (save through POST /dashboard/settings; read the raw value with `s.store.GetSetting(ctx, "smtp_password")` and assert it differs from the input, and that `s.encryptedGetSetting` returns the input; see `TestDecryptedStoreSettingDecryptsSecretValues` in runtime_settings_test.go for the pattern). web_email_test.go, with the `fakeMailer` from Design 3.4: `TestEmailTestSendsToAdmin`, `TestEmailTestNotConfigured`, `TestEmailTestSendFailure` (the fake returns an error → the email_test_failed flash), `TestEmailTestRequiresAdmin` (a non-admin is redirected and nothing is sent). web_admin_test.go: `TestAdminGoogleOrgHidesInvites` (set up like `TestGoogleOrgAdminPageReflectsSetting` in auth_google_org_dashboard_test.go: enable Google org sign-in with valid settings, GET /admin, and `strings.Contains(strings.ToLower(body), "invite")` is false) and `TestAdminShowsEmailTab` (the body contains `name="smtp_host"` and `action="/dashboard/email/test"`).
      7. Run `mise run check-full`.
    acceptance:
      - go test ./internal/server -run '^(TestSMTPSettingNormalization|TestSMTPPasswordStoredEncrypted|TestEmailTestSendsToAdmin|TestEmailTestNotConfigured|TestEmailTestSendFailure|TestEmailTestRequiresAdmin|TestAdminGoogleOrgHidesInvites|TestAdminShowsEmailTab)$' -count=1 passes
      - grep -n 'smtp_password' internal/server/security.go matches (inside secretSettingKeys)
      - grep -n 'POST /dashboard/email/test' internal/server/routes.go matches
      - mise run check-full passes

  - id: p7-share-notifications
    title: Email grantees when a restricted page is shared or switched to restricted
    depends_on: [p6-smtp-settings, p5b-empty-page]
    complexity: M
    touches:
      - internal/db/grants.go
      - internal/db/grants_test.go
      - internal/db/faults_test.go
      - internal/server/access_test.go
      - internal/server/page_versions_test.go
      - internal/server/share_notify.go
      - internal/server/share_notify_test.go
      - internal/server/web_grants.go
      - internal/server/web_grants_test.go
      - internal/server/api_grants.go
      - internal/server/api_grants_test.go
      - internal/server/web_dashboard.go
      - internal/server/web_dashboard_test.go
      - internal/server/api_uploads.go
      - internal/server/api_uploads_test.go
      - internal/server/web_helpers.go
    brief: |
      Read Design 3.5 of docs/plans/collaboration-sharing-plan.md; it fixes the signatures, the exact email text, the triggers, the flash and the API fields.
      1. internal/db/grants.go: `AddUploadGrant` returns `(*models.UploadGrant, bool, error)` (true when RowsAffected of the INSERT is 1). Update its callers (web_grants.go, api_grants.go) and the test callers in internal/db/faults_test.go, internal/db/grants_test.go, internal/server/access_test.go (the `grant` helper) and internal/server/page_versions_test.go; add `TestAddUploadGrantReportsCreated` (first call true, second false).
      2. Create internal/server/share_notify.go with `shareNotifyTimeout`, `notifyShare` and `shareMessage` exactly as specified (it takes the *http.Request, sends under `context.WithTimeout(r.Context(), shareNotifyTimeout)` with `s.smtpConfig` and `s.mailSender().Send`, and audits with `s.auditRequest(r, sharerName, "upload.share.notify", …)`; with email off or no recipients it returns false, nil without auditing).
      3. internal/server/web_grants.go `handleDashboardGrantAdd`: after a created grant on a restricted page, call notifyShare(r, owner.Name, owner.Email, u, []models.UploadGrant{*g}); on error, add `"err": {flashShareNotifyFailed}` to the existing redirect values. internal/server/web_helpers.go: `flashShareNotifyFailed = "share_notify_failed"` with the Design text.
      4. internal/server/web_dashboard.go `handleDashboardVisibility`: remember the old visibility; after the update, when old != restricted and new == restricted, ListUploadGrants and notifyShare; on error, redirect with both the ok and err codes plus manage/slug (build the url.Values directly).
      5. internal/server/api_grants.go `handleAddGrant`: the same trigger with owner.Name and owner.Email from the token; answer `grantAddOut{grantOut: grantToOut(*g), Notified: sent}`. internal/server/api_uploads.go `handleSetVisibility`: the same switch trigger; answer `{"visibility": v, "notified": sent}`.
      6. Tests, with `fakeMailer` from internal/server/web_email_test.go (p6) and SMTP settings stored through `s.encryptedSetSetting`: share_notify_test.go `TestShareMessageUserGrant` and `TestShareMessageGroupGrant` (exact subject and body from Design 3.5, ReplyTo set) and `TestNotifyShareSkipsSharerAndWhenOff`, `TestNotifyShareSkipsOutsideAllowedDomain` (allowed domain example.com; grants for a@example.com and b@other.org → only a@example.com is mailed), `TestShareMessageSanitizesName` (a page name with "\n" and "\r" and 200 runes → the subject has no control character and at most 80 runes of the name plus `…`), `TestShareMessageEmptySharerName` (falls back to the email); web_grants_test.go `TestDashboardGrantAddNotifies` (one message to the grantee, link `<baseURL>/p/<slug>`), `TestDashboardGrantAddExistingDoesNotNotify`, `TestDashboardGrantAddNonRestrictedDoesNotNotify`, `TestDashboardGrantAddNotifyFailureFlash` (the redirect carries both grant_added and share_notify_failed); web_dashboard_test.go `TestDashboardSwitchToRestrictedNotifiesAllGrantees`; api_grants_test.go `TestAPIAddGrantNotified`; api_uploads_test.go `TestAPISetVisibilityRestrictedNotifies`.
      7. Run `mise run check-full`. If the build changes internal/web/assets/pines.css, run `git checkout -- internal/web/assets/pines.css` and stop with status=blocked.
    acceptance:
      - go test ./internal/db -run '^TestAddUploadGrantReportsCreated$' -count=1 passes
      - go test ./internal/server -run '^(TestShareMessageUserGrant|TestShareMessageGroupGrant|TestNotifyShareSkipsSharerAndWhenOff|TestNotifyShareSkipsOutsideAllowedDomain|TestShareMessageSanitizesName|TestShareMessageEmptySharerName|TestDashboardGrantAddNotifies|TestDashboardGrantAddExistingDoesNotNotify|TestDashboardGrantAddNonRestrictedDoesNotNotify|TestDashboardGrantAddNotifyFailureFlash|TestDashboardSwitchToRestrictedNotifiesAllGrantees|TestAPIAddGrantNotified|TestAPISetVisibilityRestrictedNotifies)$' -count=1 passes
      - grep -n 'upload.share.notify' internal/server/share_notify.go matches
      - mise run check-full passes

  - id: p8-docs-and-retire
    title: Update docs, skills and scripts for the new sharing model; delete the plan
    depends_on: [p1a-migrate-password-pages, p1b-remove-password-gate, p2-remove-password-input, p3-cli-drop-password, p4-mail-package, p5-dashboard-pages, p5b-empty-page, p6-smtp-settings, p7-share-notifications]
    complexity: M
    touches:
      - README.md
      - docs/architecture.md
      - docs/operations.md
      - docs/src/content/docs/*.md
      - skills/peek/SKILL.md
      - skills/peek-server/SKILL.md
      - scripts/gen-screenshots.sh
      - scripts/demo-report.html
      - docs/plans/collaboration-sharing-plan.md
      - docs/plans/collaboration-sharing-plan-manual-steps.html
    brief: |
      Read Design 3.1–3.7 of docs/plans/collaboration-sharing-plan.md and the code as merged. Write prose as natural lines without manual wrapping (AGENTS.md).
      1. docs/operations.md: Page Access lists three visibilities (public, signed-in, restricted) and drops the password text, including the page-gate lockout sentence in Startup Configuration (keep the account sign-in lockout). Add an "Email" section: the smtp_* settings, the on-condition (host + From), the TLS modes and that PLAIN auth needs TLS unless the host is localhost, the test button, when share emails are sent and that send failures are logged and audited as upload.share.notify. Add to Google Group Grants that the dashboard's shared-with-me list checks at most 25 groups per render, each a cached lookup of up to 5 s. Under Upgrades And Rollbacks: migration 15 turns password pages into restricted pages (owner and admins only until shared); a rollback cannot restore them as password pages; the CLI's --password flags are gone and the default visibility is restricted.
      2. docs/architecture.md: add `internal/mail` to Package Boundaries ("owns SMTP delivery and message formatting for notification emails; knows nothing about uploads or HTTP") and to Dependency Direction (server may depend on mail; mail depends on no internal package). Remove "bcrypt password limit enforcement for upload passwords" and "password hashing" from the uploads and Storage text, and change "validates later visibility/password changes" to "validates later visibility changes".
      3. README.md, docs/src/content/docs/*.md (auth-access, using-peek, manual, index, reference and any other page grep finds), skills/peek/SKILL.md, skills/peek-server/SKILL.md: remove page-password usage; describe restricted as the default, the dashboard's Empty page mode, the shared-with-me list and role icons, title-only rows, share emails, and the Email admin tab (reference.md gets the six smtp_* settings in its settings table). Keep account-password and setup text.
      4. scripts/gen-screenshots.sh: replace `-F "visibility=password" -F "password=review"` with `-F "visibility=restricted"` (do not regenerate screenshots). scripts/demo-report.html: reword the two mentions of password-protected uploads and the password gate (around lines 506 and 523) to restricted pages shared with people and groups.
      5. Delete docs/plans/collaboration-sharing-plan.md and docs/plans/collaboration-sharing-plan-manual-steps.html; grep that nothing links to them.
      6. Push this phase's branch, then dispatch the `pages.yml` workflow with the GitHub MCP `actions_run_trigger` and `ref` set to this phase's branch (the workflow is on the default branch; its deploy job is skipped off main), and read the result with `actions_get`; the docs site must build. Run `mise run check-full`. If the build changes internal/web/assets/pines.css, run `git checkout -- internal/web/assets/pines.css` and stop with status=blocked.
    acceptance:
      - "grep -rniIE 'password-protected|page password|password visibility|visibility[= ]password|--password' README.md docs/src/content/docs skills scripts/demo-report.html | grep -v 'were removed' prints nothing"
      - grep -n 'Migration 15' docs/operations.md matches
      - grep -n 'internal/mail' docs/architecture.md matches
      - grep -n 'smtp_host' docs/operations.md docs/src/content/docs/reference.md matches in both
      - test -e docs/plans/collaboration-sharing-plan.md fails
      - the pages.yml run dispatched with ref set to this phase's branch concludes success
      - mise run check-full passes
```
