# Dashboard visibility, password and grants editing

## Goal

Owners and admins can change an already published page from the dashboard. They can switch its visibility between `private`, `restricted`, `password` and `public`, set a new password, and manage who a `restricted` page is shared with: add or remove person (user) grants, and Google group grants when group lookup is configured. Today the API and the CLI (`peek visibility`, `peek grant`, `peek revoke`, `peek grants`) can do all of this, but the dashboard can only pick a visibility at upload time.

Changing a page's password also revokes access for viewers who unlocked it with the old one. Today their 7-day unlock cookie keeps working, because it is signed over the slug only.

There is no issue for this; it was asked for directly.

## Current state

All references are to `main` at `81d039d`.

**Visibility validation is duplicated.**
- `uploads.Service.Create` (`internal/uploads/service.go:107`, switch at :124-147) validates visibility and password and bcrypt-hashes the password.
- `handleSetVisibility` (`internal/server/api_uploads.go:230-287`) repeats the same rules inline at :253-280. It checks `ValidatePasswordLength(body.Password)` on the *untrimmed* password (:267) but hashes the trimmed one.
- Both accept four values: `public`, `password`, `private` and `restricted` (`models.UploadVisibilityRestricted`). The invalid-value message is `"visibility must be public, password, private, or restricted"`.
- No server test calls `POST /api/uploads/{slug}/visibility`.

**Password unlock cookie.**
- `setPageAuthCookie(w, slug)` (`internal/server/pages.go:138`) sets `hn_auth_<slug>` to `makeSessionCookieValue(s.secret, slug, sessionTTL)` (`internal/server/security.go:101-110`), which is `slug.exp.hmac`. It is called at `pages.go:90` and `pages.go:134`.
- It is verified by `verifySessionCookie` in `viewerCanAccessUpload` (`internal/server/comments.go:273-292`, call at :282).
- Nothing about the password is in the cookie.
- Slugs contain only `[A-Za-z0-9_-]`. `viewSubject` (`security.go:70`) already relies on `:` never occurring in a slug.

**Restricted pages and grants.**
- `accountCanViewRestricted` (`internal/server/access.go`) admits the owner, admins, user grants matching the account email, and group grants via `s.groups` (a `GroupChecker`; nil unless the `PEEK_GOOGLE_*` flags are set).
- The grant store is `internal/db/grants.go`: `AddUploadGrant` (idempotent, lowercases), `RemoveUploadGrant` (`sql.ErrNoRows` when missing), and `ListUploadGrants` (ordered by kind, email). Grants cascade on upload delete.
- The grants API is `internal/server/api_grants.go`. `decodeGrantBody` validates kind (`"kind must be user or group"`), email (`"invalid email address"`), and that group grants need `s.groups` (long message). Audit actions are `upload.grant.add` and `upload.grant.remove`, with detail `slug=<slug> kind=<kind> email=<email>`.

**Dashboard.**
- `internal/web/templates/dashboard.gohtml`: the "Your uploads" card starts at line 76. Row actions are `<div class="peek-row-actions">` at line 97 (Stats link :98, Delete form after it). The upload form's segmented control is lines 56-69 (Private, Restricted, Password, Public) and its password input is line 70.
- `handleDashboard` (`internal/server/web_dashboard.go:17`) builds `[]dashUpload` at :39-46.
- `handleDashboardDelete` (:158) is the pattern for row actions: `webAuth` → `parseDashboardForm` (CSRF) → `GetUpload` → owner-or-admin → act → audit → flash redirect.
- Flash helpers are in `internal/server/web_helpers.go:15-34`. `dashboardFlash` uses `url.Values.Encode`, so `/` becomes `%2F`, a space becomes `+` and `@` becomes `%40`. `parseDashboardForm` with an empty csrf value redirects to `/dashboard?err=invalid+session`.
- View models are in `internal/web/renderer.go`: `DashboardUpload` at :103 and `DashboardData` at :184.

**CSS.** `internal/web/assets/pines.css` is generated from `internal/web/tailwind-input.css` by `mise run tailwind`, which downloads the Tailwind CLI into the gitignored `bin/tailwindcss`. Row-button classes are at `tailwind-input.css:52-103`. Tailwind's preflight zeroes `margin` on every element, including `dialog`.

**Test harness.** `internal/server/handler_helpers_test.go` provides:
- `newHandlerTestServer`, `doRequest`, `asSession`, `asBearer`, `withJSON` and `newAccountWithToken`.
- In `access_test.go`: `restrictedPage(t, s, slug)` (its owner is `owner-<slug>@example.test`), `grant(...)`, `auditActions(...)` and `fakeGroups{members: map[string]bool{"group|user": true}}`.

`visibility_e2e_test.go` has `uploadMultipartHTML`, `postPagePassword`, `findCookie` and `addComment(t, app, slug, []*http.Cookie, want)`.

## Design

### D1. `uploads.PrepareVisibility` (new `internal/uploads/visibility.go`)

```go
// VisibilityChange is a validated visibility plus the bcrypt hash to store with it
// ("" unless Visibility is password).
type VisibilityChange struct {
	Visibility   string
	PasswordHash string
}

// PrepareVisibility validates a visibility/password pair and hashes the password.
// Both inputs are trimmed. An empty visibility is invalid here; Create applies its
// own default before calling this.
func PrepareVisibility(visibility, password string) (VisibilityChange, error)
```

Rules, in this order. Use the existing `newError` and kinds, with these exact messages:
1. `public`, `private` or `restricted` with a non-empty password → `KindPasswordNotAllowed`, `"password is only allowed with password visibility"`.
2. `password` with an empty password → `KindPasswordRequired`, `"password visibility requires a password"`.
3. Anything else, including `""` → `KindInvalidVisibility`, `"visibility must be public, password, private, or restricted"`.
4. `password` with `!ValidatePasswordLength(password)` (the trimmed password) → `KindPasswordTooLong`, `"password must be 72 characters or fewer"`.
5. bcrypt fails → `KindPasswordHash`, `"hash failed"`.

`Service.Create` keeps its trimming, its `""`→`password` default, and its empty-file and HTML checks first. It then replaces the switch and hashing block with `change, err := PrepareVisibility(in.Visibility, in.Password)` and returns `err` unchanged. The `bcrypt` import leaves `service.go`.

### D2. API uses D1

In `handleSetVisibility`, the block from `visibility := strings.TrimSpace(body.Visibility)` to the end of the switch becomes:

```go
change, err := uploads.PrepareVisibility(body.Visibility, body.Password)
if err != nil {
	status, msg := uploadHTTPError(err)
	jsonError(w, status, msg)
	return
}
```

It then calls `SetUploadVisibility(..., change.Visibility, change.PasswordHash)`, audits with `visibilityAuditDetail(slug, change.Visibility)` (D4), and responds `{"visibility": change.Visibility}`. `uploadHTTPError` already maps those kinds to the same 400/500 statuses and messages.

One behaviour change: the API length check now uses the trimmed password.

The `bcrypt` import leaves `api_uploads.go`.

### D3. Unlock cookie bound to the password hash (`internal/server/security.go`)

`makeSessionCookieValue` and `verifySessionCookie` are deleted and replaced by:

```go
// pageAuthSubject binds a password-gate session to the upload's current password
// hash, so setting a new password (or leaving password visibility and coming back)
// revokes every earlier unlock. bcrypt salts each hash, so even re-entering the same
// password yields a new subject. The fingerprint is keyed with the server secret so
// the cookie reveals nothing derived from the hash.
func pageAuthSubject(secret, slug, passwordHash string) string {
	return slug + ":" + hmacSHA256(secret, "page-auth:"+passwordHash)[:16]
}

func makePageAuthCookieValue(secret, slug, passwordHash string, ttl time.Duration) string {
	return signToken(secret, pageAuthSubject(secret, slug, passwordHash), time.Now().Add(ttl).Unix())
}

func verifyPageAuthCookie(secret, val, slug, passwordHash string) bool {
	return verifyToken(secret, val, pageAuthSubject(secret, slug, passwordHash))
}
```

`setPageAuthCookie` becomes `setPageAuthCookie(w http.ResponseWriter, u *models.Upload)`. Both callers pass `u`, and `comments.go:282` calls `verifyPageAuthCookie(s.secret, c.Value, u.Slug, u.PasswordHash)`. The cookie name is unchanged.

Effects:
- Cookies issued before deploy stop verifying once, so viewers re-enter the password.
- Already issued `/raw` view tokens (1 h, visitor-bound) are out of scope.

Rejected alternatives:
- *A `password_version` column*: it needs a migration for nothing extra.
- *`sha256(hash)` in the cookie*: it exposes a value derived from the hash.

### D4. Audit detail helper (`internal/server/api_uploads.go`)

```go
func visibilityAuditDetail(slug, visibility string) string {
	detail := "slug=" + slug + " visibility=" + visibility
	if visibility == models.UploadVisibilityPassword {
		detail += " password=updated"
	}
	return detail
}
```

### D5. Dashboard visibility route and handler

**Route** (`routes.go`, after the dashboard delete route): `mux.HandleFunc("POST /dashboard/visibility/{slug}", s.handleDashboardVisibility)`.

**Handler** `handleDashboardVisibility` (`web_dashboard.go`, directly after `handleDashboardDelete`):
1. `owner, ok := s.webAuth(r)`. If not ok, redirect to `/login` (303).
2. `slug := r.PathValue("slug")`. If `!s.parseDashboardForm(w, r)`, return.
3. `GetUpload`. On error, `dashboardError(w, r, "not found")`.
4. If `u.OwnerAccountID != owner.ID && !owner.IsAdmin`, `dashboardError(w, r, "not owner")`.
5. `change, err := uploads.PrepareVisibility(r.FormValue("visibility"), r.FormValue("password"))`. On error, `dashboardError(w, r, uploadErrorMessage(err))`.
6. `SetUploadVisibility`. On error, `slog.Error("dashboard visibility update failed", "slug", slug, "err", err)` and `dashboardError(w, r, "visibility update failed")`.
7. `s.auditRequest(r, owner.Name, "upload.visibility.set", visibilityAuditDetail(slug, change.Visibility))`.
8. Flash: `password` → `dashboardOK(w, r, "Password updated for /p/"+slug)`. Otherwise → `dashboardOK(w, r, "/p/"+slug+" is now "+change.Visibility)`. Phase 3 changes the `restricted` case to also reopen the dialog (D9).

### D6. Dashboard visibility dialog markup

Insert this exactly in `dashboard.gohtml`, inside `<div class="peek-row-actions">`, before the Stats link. Phase 3 adds the grants section where the comment marks it; phase 2 leaves that comment out.

```html
<div x-data="{ vis: '{{.Visibility}}' }" class="m-0">
  <button type="button" class="peek-row-button" x-on:click="$refs.visibilityDialog.showModal()">Access</button>
  <dialog x-ref="visibilityDialog" class="peek-visibility-dialog" aria-labelledby="hn-visibility-title-{{.Slug}}">
    <form method="POST" action="/dashboard/visibility/{{.Slug}}" class="flex flex-col gap-3.5">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <h3 id="hn-visibility-title-{{.Slug}}" class="text-sm font-semibold text-card-foreground">Access for /p/{{.Slug}}</h3>
      <div class="inline-flex gap-0.5 self-start rounded-lg bg-muted p-0.5">
        <label class="cursor-pointer rounded-md px-3 py-1.5 text-sm transition" :class="vis === 'private' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground'">
          <input type="radio" name="visibility" value="private" x-model="vis" class="sr-only"> Private
        </label>
        <label class="cursor-pointer rounded-md px-3 py-1.5 text-sm transition" :class="vis === 'restricted' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground'">
          <input type="radio" name="visibility" value="restricted" x-model="vis" class="sr-only"> Restricted
        </label>
        <label class="cursor-pointer rounded-md px-3 py-1.5 text-sm transition" :class="vis === 'password' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground'">
          <input type="radio" name="visibility" value="password" x-model="vis" class="sr-only"> Password
        </label>
        <label class="cursor-pointer rounded-md px-3 py-1.5 text-sm transition" :class="vis === 'public' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground'">
          <input type="radio" name="visibility" value="public" x-model="vis" class="sr-only"> Public
        </label>
      </div>
      <input x-show="vis === 'password'" :disabled="vis !== 'password'" :required="vis === 'password'" type="password" name="password" autocomplete="new-password" placeholder="new password" class="h-10 rounded-lg border border-input bg-secondary px-4 text-sm text-foreground placeholder:text-muted-foreground transition focus:border-ring focus:outline-none focus:ring-2 focus:ring-ring/20">
      <p x-show="vis === 'password'" class="text-xs text-muted-foreground">Saving a password signs out everyone who unlocked this page before.</p>
      <div class="flex justify-end gap-2">
        <button type="button" class="peek-row-button" x-on:click="$refs.visibilityDialog.close()">Close</button>
        <button type="submit" class="h-9 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition hover:bg-primary/90">Save</button>
      </div>
    </form>
    <!-- D8 grants section goes here (phase 3) -->
  </dialog>
</div>
```

How it behaves:
- A disabled password input is not submitted, so other modes post no password.
- The native `<dialog>` sits in the top layer, so the table's `overflow-x-auto` cannot clip it.
- Alpine `x-data`/`x-on` are already used by the dashboard and `$refs` by `page.gohtml`. A nested per-row `x-data` scopes `$refs` to the row, and `DashboardCSP` allows `'unsafe-eval'`.
- No new JS asset.

CSS appended to `tailwind-input.css` right after the `.peek-row-button-copied` block (ends at line 103):

```css
.peek-visibility-dialog {
  margin: auto;
  width: min(400px, calc(100vw - 32px));
  max-height: calc(100vh - 32px);
  overflow: auto;
  padding: 20px;
  border: 1px solid hsl(var(--border));
  border-radius: 12px;
  background: hsl(var(--card));
  color: hsl(var(--card-foreground));
  box-shadow: 0 16px 48px hsl(0 0% 0% / 0.18);
  white-space: normal;
}

.peek-visibility-dialog::backdrop {
  background: hsl(0 0% 0% / 0.35);
}
```

Rejected alternative: a `<details>` dropdown, because `overflow-x-auto` clips it.

### D7. Grant view models, store query, shared validation

**`internal/web/renderer.go`:**
- Add `type DashboardGrant struct { Kind string; Email string }`.
- Add `Grants []DashboardGrant` as the last field of `DashboardUpload`.
- Add `GroupGrantsEnabled bool` and `ManageSlug string` as the last fields of `DashboardData`.

**`internal/db/grants.go`:**
- Extract the row loop of `ListUploadGrants` into `func scanUploadGrants(rows *sql.Rows) ([]models.UploadGrant, error)`, which closes `rows`.
- Add:

```go
// ListUploadGrantsForUploads returns the grants of several uploads keyed by upload
// id, each list ordered by kind, then email. Uploads without grants are absent.
func (s *Store) ListUploadGrantsForUploads(ctx context.Context, uploadIDs []int64) (map[int64][]models.UploadGrant, error)
```

It returns an empty non-nil map for an empty slice without querying. Otherwise it runs one query, `... WHERE upload_id IN (?,?,…) ORDER BY upload_id, kind, email`, with one placeholder per id built via `strings.Repeat("?,", n)` trimmed, and groups the rows into the map.

**`internal/server/api_grants.go`:** extract the kind/email/groups checks of `decodeGrantBody` into:

```go
// normalizeGrantInput validates a grant kind and email address. It returns the
// lowercased, trimmed email, or a non-empty user-facing error message.
func (s *Server) normalizeGrantInput(kind, email string) (string, string)
```

It keeps the same messages and order: kind, then email, then groups. `decodeGrantBody` calls it and writes `jsonError(w, http.StatusBadRequest, msg)` on a message. API behaviour is unchanged.

**`handleDashboard`:**
- After building `uploads`, collect the ids. Call `grants, err := s.store.ListUploadGrantsForUploads(r.Context(), ids)`.
- On error, `slog.Error("dashboard grant list failed", "account_id", owner.ID, "err", err)` and continue with no grants.
- Fill each `dashUpload.Grants` with `DashboardGrant{Kind: g.Kind, Email: g.Email}`.
- Set `GroupGrantsEnabled: s.groups != nil`.
- Set `ManageSlug: r.URL.Query().Get("manage")`.

### D8. Dashboard grant routes, handlers and markup

**Routes** (`routes.go`, after the D5 route):
- `mux.HandleFunc("POST /dashboard/grants/{slug}", s.handleDashboardGrantAdd)`
- `mux.HandleFunc("POST /dashboard/grants/{slug}/remove", s.handleDashboardGrantRemove)`

**`internal/server/web_helpers.go`** gets:

```go
// dashboardFlashManage redirects to the dashboard with a flash and reopens the
// access dialog of slug.
func dashboardFlashManage(w http.ResponseWriter, r *http.Request, key, msg, slug string) {
	q := url.Values{key: {msg}, "manage": {slug}}
	http.Redirect(w, r, dashboardPath+"?"+q.Encode(), http.StatusSeeOther)
}
```

**New file `internal/server/web_grants.go`** with both handlers. Steps 1-4 match D5. After them:

*`handleDashboardGrantAdd`:*
1. `kind := r.FormValue("kind")`. Then `email, msg := s.normalizeGrantInput(kind, r.FormValue("email"))`. On a message, `dashboardFlashManage(w, r, "err", msg, slug)`.
2. `s.store.AddUploadGrant(r.Context(), u.ID, kind, email, owner.ID)`. On error, `slog.Error("dashboard grant add failed", "slug", slug, "err", err)` and `dashboardFlashManage(w, r, "err", "grant update failed", slug)`.
3. `s.auditRequest(r, owner.Name, "upload.grant.add", "slug="+u.Slug+" kind="+kind+" email="+email)`.
4. `dashboardFlashManage(w, r, "ok", "Shared /p/"+slug+" with "+email, slug)`.

*`handleDashboardGrantRemove`:*
1. Same normalization as the add handler.
2. `s.store.RemoveUploadGrant(...)`. `errors.Is(err, sql.ErrNoRows)` → `dashboardFlashManage(w, r, "err", "grant not found", slug)`. Any other error → slog plus `"grant update failed"`.
3. Audit `upload.grant.remove` with the same detail format.
4. `dashboardFlashManage(w, r, "ok", "Removed "+email+" from /p/"+slug, slug)`.

**Change to D5 step 8:** when `change.Visibility == models.UploadVisibilityRestricted`, call `dashboardFlashManage(w, r, "ok", "/p/"+slug+" is now restricted", slug)`, so the dialog reopens with the grants section. The other modes keep `dashboardOK`.

**Markup, part 1.** On the D6 row wrapper `<div x-data="{ vis: '{{.Visibility}}' }" class="m-0">`, add this attribute exactly. The value is empty for rows that are not being managed:

```
x-init="{{if eq $.ManageSlug .Slug}}$nextTick(() => $refs.visibilityDialog.showModal()){{end}}"
```

**Markup, part 2.** Replace the D6 comment `<!-- D8 grants section goes here (phase 3) -->` with:

```html
{{$slug := .Slug}}
<section x-show="vis === 'restricted'" class="mt-4 flex flex-col gap-2.5 border-t border-border pt-4">
  <h4 class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">People and groups with access</h4>
  {{if ne .Visibility "restricted"}}<p class="text-xs text-muted-foreground">Grants apply once you save Restricted above.</p>{{end}}
  {{if .Grants}}
  <ul class="flex flex-col gap-1">
    {{range .Grants}}
    <li class="flex items-center justify-between gap-2 text-sm">
      <span class="truncate">{{.Email}}{{if eq .Kind "group"}} <span class="text-xs text-muted-foreground">(group)</span>{{end}}</span>
      <form method="POST" action="/dashboard/grants/{{$slug}}/remove" class="m-0">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <input type="hidden" name="kind" value="{{.Kind}}">
        <input type="hidden" name="email" value="{{.Email}}">
        <button type="submit" class="peek-row-button peek-row-button-danger">Remove</button>
      </form>
    </li>
    {{end}}
  </ul>
  {{else}}
  <p class="text-xs text-muted-foreground">Only you and admins can open this page until you share it.</p>
  {{end}}
  <form method="POST" action="/dashboard/grants/{{.Slug}}" class="flex gap-2">
    <input type="hidden" name="csrf" value="{{$.CSRF}}">
    {{if $.GroupGrantsEnabled}}
    <select name="kind" aria-label="Grant type" class="h-9 rounded-lg border border-input bg-secondary px-2 text-sm text-foreground">
      <option value="user">Person</option>
      <option value="group">Google group</option>
    </select>
    {{else}}
    <input type="hidden" name="kind" value="user">
    {{end}}
    <input type="email" name="email" required maxlength="254" placeholder="name@example.com" aria-label="Email address" class="h-9 min-w-0 flex-1 rounded-lg border border-input bg-secondary px-3 text-sm text-foreground placeholder:text-muted-foreground transition focus:border-ring focus:outline-none focus:ring-2 focus:ring-ring/20">
    <button type="submit" class="h-9 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition hover:bg-primary/90">Share</button>
  </form>
</section>
```

`$.CSRF` and `$.GroupGrantsEnabled` resolve against the root `DashboardData`. `$slug` exists because `.Slug` is shadowed inside `{{range .Grants}}`.

Rejected alternatives:
- *A JSON fetch-based grants editor*: it would be the first fetch-driven dashboard form. The dashboard uses plain POST + redirect + flash everywhere.
- *A separate grants page*: owners expect sharing next to the visibility choice.
- *Per-row `ListUploadGrants` calls*: N+1 queries on every dashboard load.

## Manual steps

None. Everything is covered by Go tests and the docs build. There is no HTML artifact.

## Risks and open questions

- **Refactoring `Create` onto `PrepareVisibility`.** It must not change error order or messages. If a pre-existing `internal/uploads` test fails, the phase stops with `status=blocked` rather than editing that test.
- **Callers of the unlock cookie helpers.** If `grep -rn "setPageAuthCookie\|verifySessionCookie\|makeSessionCookieValue" internal` shows callers other than `pages.go:90`, `pages.go:134`, `pages.go:138` (definition), `comments.go:282` and the `security.go` definitions, the D3 brief is incomplete. Stop with `status=blocked`.
- **Tailwind CLI download.** `mise run tailwind` downloads the Tailwind CLI from GitHub. If the download is blocked, the phase stops with `status=blocked`; it never hand-edits the minified `pines.css`.
- **Baseline `pines.css` diff.** If `mise run check` on the phase's starting point leaves a `pines.css` diff, the generator and the committed file disagree. Stop with `status=blocked` and report.
- **Template parsing of `x-init`.** html/template could reject the conditional inside the `x-init` attribute value; it is a plain attribute, so it should parse. If `NewRenderer` fails to parse the dashboard, the phase stops with `status=blocked` and quotes the error, rather than inventing another reopen mechanism.
- **Line references.** These come from `81d039d`. If `main` moved and a referenced symbol is gone or renamed, stop with `status=blocked`. Line shifts alone are fine: locate by symbol.

## Implementation manifest

```yaml
plan_slug: dashboard-visibility-grants
feature_branch: feat/dashboard-visibility-grants
max_parallel: 1
manual_before: []
manual_after: []
verify_after_merge:
  - go test ./internal/uploads/ ./internal/db/ ./internal/server/ ./internal/web/
final_checks:
  - docs/plans/dashboard-visibility-grants-plan.md is deleted and nothing links to it
  - grep -rn "makeSessionCookieValue\|verifySessionCookie" internal prints nothing
  - mise run check-full exits 0
  - cd docs && pnpm build exits 0
phases:
  - id: p1-visibility-core
    title: Shared PrepareVisibility, API refactor, and unlock cookie bound to the password hash
    depends_on: []
    complexity: M
    touches:
      - internal/uploads/visibility.go
      - internal/uploads/visibility_test.go
      - internal/uploads/service.go
      - internal/server/api_uploads.go
      - internal/server/api_test.go
      - internal/server/security.go
      - internal/server/security_test.go
      - internal/server/pages.go
      - internal/server/comments.go
      - internal/server/visibility_e2e_test.go
    brief: |
      Read AGENTS.md, CONTRIBUTING.md, docs/architecture.md and docs/operations.md, then the plan sections "Current state", D1, D2, D3 and D4. Run `mise install` and `mise run check` first. If it is red, or `git status` then shows a change to internal/web/assets/pines.css, stop with status=blocked.
      1. Create internal/uploads/visibility.go with VisibilityChange and PrepareVisibility exactly as in D1, in package uploads.
      2. In internal/uploads/service.go, refactor Service.Create to call PrepareVisibility as described in D1, and remove the bcrypt import. Run `go test ./internal/uploads/...`. If any pre-existing test fails, stop with status=blocked.
      3. Add internal/uploads/visibility_test.go with table test TestPrepareVisibility. Check kinds with `var uploadErr *Error; if !errors.As(err, &uploadErr) || uploadErr.Kind != tc.kind { t.Fatalf(...) }`. Cases:
         - public, private and restricted with no password → no error, empty hash;
         - public with password "x" → KindPasswordNotAllowed;
         - restricted with password "x" → KindPasswordNotAllowed;
         - password with "" and with "   " → KindPasswordRequired;
         - visibility "" and "secret" → KindInvalidVisibility, message "visibility must be public, password, private, or restricted";
         - password with strings.Repeat("a", 73) → KindPasswordTooLong;
         - password with "  pw  " → no error, Visibility "password", and bcrypt.CompareHashAndPassword(hash, "pw") succeeds.
      4. In internal/server/api_uploads.go, add visibilityAuditDetail (D4) and rewrite handleSetVisibility as in D2. Remove the bcrypt import.
      5. Add TestSetVisibilityAPIValidation to internal/server/api_test.go:
         - Use app := newTestApp(t) and up := uploadRawHTML(t, app, "vis-api", "public").
         - Send each case with app.requestString(t, http.MethodPost, "/api/uploads/"+up.Slug+"/visibility", body, withAuth(app.AdminToken), withContentType("application/json")).
         - Assert the status and that the body contains the text:
           - {"visibility":"password"} → 400, "password visibility requires a password";
           - {"visibility":"public","password":"x"} → 400, "password is only allowed with password visibility";
           - {"visibility":"nope"} → 400, "visibility must be public, password, private, or restricted";
           - {"visibility":"password","password":"<73 a's>"} → 400, "password must be 72 characters or fewer";
           - {"visibility":"restricted"} → 200, "\"visibility\":\"restricted\"";
           - {"visibility":"private"} → 200, "\"visibility\":\"private\"".
      6. Implement D3:
         - Run `grep -rn "setPageAuthCookie\|verifySessionCookie\|makeSessionCookieValue" internal` first. If it lists any caller other than pages.go (two calls plus the definition), comments.go (one call) and the security.go definitions, stop with status=blocked.
         - Replace the two functions in security.go.
         - Change setPageAuthCookie to take u *models.Upload and update both pages.go callers to pass u.
         - Update the comments.go verify call.
      7. Add TestPageAuthCookieBoundToPasswordHash to internal/server/security_test.go. With secret strings.Repeat("0", 64), a value from makePageAuthCookieValue(secret, "page", "hashA", time.Hour):
         - verifies for ("page", "hashA");
         - fails for ("page", "hashB");
         - fails for ("other", "hashA").
      8. In internal/server/visibility_e2e_test.go, add subtest "password change revokes earlier unlocks" to TestUploadVisibilityE2E:
         a. up := uploadMultipartHTML(t, app, "rotate-page", "password", "old"). Unlock it with postPagePassword(t, app, up.Slug, "old") and assert 303. oldCookie := findCookie(resp.Cookies, "hn_auth_"+up.Slug). Then addComment(t, app, up.Slug, []*http.Cookie{oldCookie}, http.StatusOK).
         b. Change the password: app.requestString(t, http.MethodPost, "/api/uploads/"+up.Slug+"/visibility", `{"visibility":"password","password":"new"}`, withAuth(app.AdminToken), withContentType("application/json")) → 200.
         c. Assert addComment with oldCookie → 401.
         d. Assert postPagePassword "old" → 401. Assert postPagePassword "new" → 303, take newCookie from it, and assert addComment with newCookie → 200.
         e. POST {"visibility":"public"} and then {"visibility":"password","password":"new"} the same way, both → 200. Then assert addComment with newCookie → 401.
      9. Run `mise run fmt`, then `mise run check-full`.
    acceptance:
      - go test ./internal/uploads/ -run TestPrepareVisibility -v passes, and all pre-existing internal/uploads tests pass unmodified
      - go test ./internal/server/ -run 'TestSetVisibilityAPIValidation|TestPageAuthCookieBoundToPasswordHash|TestUploadVisibilityE2E|TestRestrictedVisibilityE2E|TestPagePasswordCookieAuthorizesProtectedCommentAPI' -v passes, including subtest password_change_revokes_earlier_unlocks
      - grep -rn "makeSessionCookieValue\|verifySessionCookie" internal prints nothing
      - grep -n "bcrypt" internal/server/api_uploads.go internal/uploads/service.go prints nothing
      - mise run check-full exits 0

  - id: p2-dashboard-visibility
    title: Dashboard access dialog that changes visibility and password
    depends_on: [p1-visibility-core]
    complexity: M
    touches:
      - internal/server/routes.go
      - internal/server/web_dashboard.go
      - internal/server/web_dashboard_test.go
      - internal/web/templates/dashboard.gohtml
      - internal/web/renderer_test.go
      - internal/web/tailwind-input.css
      - internal/web/assets/pines.css
    brief: |
      Read AGENTS.md, CONTRIBUTING.md and docs/architecture.md, then the plan sections "Current state", D5 and D6. p1 is merged: uploads.PrepareVisibility and visibilityAuditDetail exist.
      1. Add the D5 route to internal/server/routes.go, directly after `mux.HandleFunc("POST /dashboard/delete/{slug}", ...)`.
      2. Add handleDashboardVisibility to internal/server/web_dashboard.go, directly after handleDashboardDelete, following D5 steps 1-8 exactly.
      3. In internal/web/templates/dashboard.gohtml, insert the D6 markup inside `<div class="peek-row-actions">`, before the Stats link. Leave out the `<!-- D8 grants section goes here (phase 3) -->` comment line entirely.
      4. Append the D6 CSS to internal/web/tailwind-input.css after the `.peek-row-button-copied` block. Run `mise run tailwind` and commit the regenerated internal/web/assets/pines.css. If the Tailwind download fails, stop with status=blocked; do not hand-edit pines.css.
      5. In internal/server/web_dashboard_test.go, use the harness from handler_helpers_test.go:
         - Add helper `dashboardPost(t *testing.T, s *Server, accountID int64, path string, form url.Values, withCSRF bool) *httptest.ResponseRecorder`. When withCSRF is true, it sets form "csrf"="csrf-token" and adds cookie &http.Cookie{Name: csrfCookie, Value: "csrf-token"}. It sets Content-Type application/x-www-form-urlencoded, applies asSession(s, accountID), and calls doRequest(t, s, http.MethodPost, path, strings.NewReader(form.Encode()), ...).
         - Add these tests. Each uses s, _ := newHandlerTestServer(t), u := restrictedPage(t, s, "page") unless stated, and asserts status 303 and the exact Location:
           a. TestDashboardVisibilitySetsPasswordAndAudits: post visibility=password&password=pw as u.OwnerAccountID.
              - Location "/dashboard?ok=Password+updated+for+%2Fp%2Fpage".
              - GetUpload shows visibility "password" and a hash that verifies "pw".
              - ListAuditLog(ctx, 10) has Action "upload.visibility.set" with Detail "slug=page visibility=password password=updated".
           b. TestDashboardVisibilityMakesPublic: post visibility=public as the owner.
              - Location "/dashboard?ok=%2Fp%2Fpage+is+now+public".
              - Visibility "public", PasswordHash "".
           c. TestDashboardVisibilityRejectsPasswordWithoutValue: post visibility=password with no password.
              - Location "/dashboard?err=password+visibility+requires+a+password".
              - Visibility still "restricted".
           d. TestDashboardVisibilityRejectsNonOwner: other, _ := s.store.CreateAccount(ctx, "user@example.test", "User", false); post visibility=public as other.ID.
              - Location "/dashboard?err=not+owner".
              - Visibility still "restricted".
           e. TestDashboardVisibilityRejectsMissingCSRF: post visibility=public with withCSRF=false.
              - Location "/dashboard?err=invalid+session".
              - Visibility still "restricted".
      6. In internal/web/renderer_test.go, add TestDashboardRendersAccessDialogPerUpload, modelled on TestDashboardUploadFormShowsSelectedFileAndDisablesEmptySubmit.
         - Render DashboardData{CSRF: "csrf", User: "Admin", Uploads: []DashboardUpload{{Slug: "page", Name: "page.html", Visibility: "password"}}}.
         - Assert the HTML contains each literal string (single quotes stay literal):
           - `action="/dashboard/visibility/page"`
           - `x-data="{ vis: 'password' }"`
           - `x-ref="visibilityDialog"`
           - `value="restricted" x-model="vis"`
           - `autocomplete="new-password"`
           - `:disabled="vis !== 'password'"`
      7. Run `mise run fmt`, then `mise run check-full`.
    acceptance:
      - go test ./internal/server/ -run 'TestDashboardVisibility' -v passes (5 tests)
      - go test ./internal/web/ -run TestDashboardRendersAccessDialogPerUpload -v passes
      - grep -n '"POST /dashboard/visibility/{slug}"' internal/server/routes.go prints exactly one line
      - grep -c "peek-visibility-dialog" internal/web/assets/pines.css prints at least 1
      - grep -c "D8 grants section" internal/web/templates/dashboard.gohtml prints 0
      - mise run check-full exits 0

  - id: p3-dashboard-grants
    title: Grants editor in the dashboard access dialog
    depends_on: [p2-dashboard-visibility]
    complexity: M
    touches:
      - internal/db/grants.go
      - internal/db/grants_test.go
      - internal/server/api_grants.go
      - internal/server/web_grants.go
      - internal/server/web_grants_test.go
      - internal/server/web_helpers.go
      - internal/server/web_dashboard.go
      - internal/server/web_dashboard_test.go
      - internal/server/routes.go
      - internal/web/renderer.go
      - internal/web/renderer_test.go
      - internal/web/templates/dashboard.gohtml
      - internal/web/assets/pines.css
    brief: |
      Read AGENTS.md, CONTRIBUTING.md and docs/architecture.md, then the plan sections "Current state", D7 and D8. p2 is merged: the D6 dialog, handleDashboardVisibility and the dashboardPost test helper in web_dashboard_test.go exist.
      1. internal/db/grants.go:
         - Extract scanUploadGrants and add ListUploadGrantsForUploads exactly as in D7.
         - In internal/db/grants_test.go, add TestListUploadGrantsForUploads, using the same setup as TestListUploadGrantsOrdersByKindThenEmail. Create two uploads: give the first two grants inserted out of order, and the second one grant.
         - Assert: the map has exactly 2 keys; the first list is ordered by kind then email; the second has 1 entry; and a call with an empty slice returns a non-nil empty map.
      2. internal/server/api_grants.go:
         - Extract normalizeGrantInput (D7) and make decodeGrantBody use it.
         - Run `go test ./internal/server/ -run Grant`; pre-existing tests must pass unmodified.
      3. internal/web/renderer.go: add DashboardGrant, DashboardUpload.Grants, DashboardData.GroupGrantsEnabled and DashboardData.ManageSlug (D7).
      4. In handleDashboard (internal/server/web_dashboard.go), load grants and set GroupGrantsEnabled and ManageSlug as in D7.
      5. In handleDashboardVisibility, make the restricted case use dashboardFlashManage (D8, "Change to D5 step 8"). Add dashboardFlashManage to internal/server/web_helpers.go exactly as in D8.
      6. Create internal/server/web_grants.go with handleDashboardGrantAdd and handleDashboardGrantRemove exactly as in D8. Add both routes to internal/server/routes.go after the dashboard visibility route.
      7. In internal/web/templates/dashboard.gohtml:
         - Add the D8 x-init attribute to the row wrapper div.
         - Insert the D8 grants section inside the `<dialog>`, after the visibility `</form>` and before `</dialog>`.
         - Run `mise run tailwind` and commit pines.css if it changed. If the download fails, stop with status=blocked.
         - If `go test ./internal/web/` fails because the template does not parse, stop with status=blocked and quote the error.
      8. Tests in new internal/server/web_grants_test.go. Use newHandlerTestServer, u := restrictedPage(t, s, "page") and the dashboardPost helper from web_dashboard_test.go. Assert status 303 and the exact Location:
         a. TestDashboardGrantAddAndRemove (as owner u.OwnerAccountID):
            - Post kind=user&email=Alice@Example.com to /dashboard/grants/page.
              - Location "/dashboard?manage=page&ok=Shared+%2Fp%2Fpage+with+alice%40example.com".
              - ListUploadGrants has one user grant "alice@example.com".
              - auditActions(t, s) contains "upload.grant.add".
            - Then post kind=user&email=alice@example.com to /dashboard/grants/page/remove.
              - Location "/dashboard?manage=page&ok=Removed+alice%40example.com+from+%2Fp%2Fpage".
              - No grants remain.
              - auditActions contains "upload.grant.remove".
         b. TestDashboardGrantRejectsInvalidEmail: email=not-an-email → Location "/dashboard?err=invalid+email+address&manage=page"; no grants.
         c. TestDashboardGrantRejectsGroupWithoutLookup: with s.groups nil, kind=group&email=team@example.com → Location starting "/dashboard?err=group+grants+need+Google+group+lookup"; no grants.
         d. TestDashboardGrantAcceptsGroupWithLookup: set s.groups = fakeGroups{members: map[string]bool{}}, kind=group&email=team@example.com → ok Location; one group grant.
         e. TestDashboardGrantRemoveMissing: remove alice@example.com when there are no grants → Location "/dashboard?err=grant+not+found&manage=page".
         f. TestDashboardGrantRejectsNonOwner: account from s.store.CreateAccount(ctx, "user@example.test", "User", false), add → Location "/dashboard?err=not+owner"; no grants.
         g. TestDashboardGrantRejectsMissingCSRF: withCSRF=false → Location "/dashboard?err=invalid+session"; no grants.
      9. In internal/server/web_dashboard_test.go:
         - Add TestDashboardVisibilityRestrictedReopensDialog: seed with newTwoVersionPage(t, s, "page", "public", ""), post visibility=restricted as the owner → Location "/dashboard?manage=page&ok=%2Fp%2Fpage+is+now+restricted".
         - Add TestDashboardListsGrantsInAccessDialog: restrictedPage, grant(t, s, u, models.UploadGrantUser, "alice@example.com"), then GET /dashboard?manage=page with asSession(s, u.OwnerAccountID) via doRequest. Assert 200 and that the body contains each of:
           - `alice@example.com`
           - `action="/dashboard/grants/page/remove"`
           - `action="/dashboard/grants/page"`
           - `$nextTick(() => $refs.visibilityDialog.showModal())`
           - `<input type="hidden" name="kind" value="user">`
         - Then set s.groups = fakeGroups{members: map[string]bool{}}, GET again, and assert the body contains `<option value="group">Google group</option>`.
      10. In internal/web/renderer_test.go, add TestDashboardAccessDialogShowsGrantHintWhenNotRestricted. Render one upload {Slug: "page", Visibility: "public"} with no grants, and assert the HTML contains "Grants apply once you save Restricted above." and "Only you and admins can open this page until you share it.".
      11. Run `mise run fmt`, then `mise run check-full`.
    acceptance:
      - go test ./internal/db/ -run TestListUploadGrantsForUploads -v passes
      - go test ./internal/server/ -run 'TestDashboardGrant|TestDashboardVisibility|TestDashboardListsGrantsInAccessDialog|Grant' -v passes
      - go test ./internal/web/ -run 'TestDashboardAccessDialog|TestDashboardRendersAccessDialogPerUpload' -v passes
      - grep -n '"POST /dashboard/grants/{slug}' internal/server/routes.go prints exactly two lines
      - mise run check-full exits 0

  - id: p4-docs-retire
    title: Document dashboard access editing and password revocation; delete the plan
    depends_on: [p3-dashboard-grants]
    complexity: S
    touches:
      - README.md
      - docs/architecture.md
      - docs/src/content/docs/using-peek.md
      - docs/src/content/docs/auth-access.md
      - docs/src/content/docs/manual.md
      - skills/peek-server/SKILL.md
      - skills/peek/SKILL.md
      - docs/plans/dashboard-visibility-grants-plan.md
    brief: |
      Read AGENTS.md (do not hard-wrap Markdown lines). Find each anchor below by its text; line numbers may have shifted. This repo has no changelog and no ADRs.
      1. docs/src/content/docs/using-peek.md, in "Pick Visibility": after the paragraph that starts "Restricted pages are opened up with grants", add a new paragraph: "In the dashboard, the **Access** button on an upload's row changes its visibility, sets a new password, and for restricted pages adds or removes people and Google groups. Setting a new password signs out everyone who unlocked the page with the previous one."
      2. docs/src/content/docs/auth-access.md, "Upload Visibility": after the paragraph that starts "A restricted page is opened up with grants", add: "Owners and admins can change a page's mode, password and grants later from the dashboard's **Access** dialog or with `peek visibility` and `peek grant`. A new password revokes every earlier unlock of that page."
      3. docs/src/content/docs/manual.md: after the code block containing `peek visibility <slug> public|password|private|restricted`, add: "The dashboard's **Access** row action does the same, and manages grants on restricted pages, without the CLI."
      4. README.md:
         - At the end of the paragraph starting "Upload visibility is set at creation time", append: "Setting a new password signs out viewers who unlocked the page with the old one. The dashboard's **Access** row action changes visibility, password and grants from the browser."
         - In the paragraph starting "A browser dashboard at `/login` lets users", replace "password-protect" with "change visibility, password and grants of".
         - In the threat table row starting "| Bypassing password gate |", append "; changing the password revokes earlier unlocks" before the closing " |".
      5. docs/architecture.md:
         - In the `internal/uploads` bullet, replace "owns upload creation behavior:" with "owns upload creation and visibility-change rules (`PrepareVisibility`):".
         - At the end of the "## Storage" paragraph, append: "`PrepareVisibility` validates later visibility/password changes for both the API and the dashboard."
      6. skills/peek-server/SKILL.md, under "### Manage page passwords", after its code block, add: "Setting a new password revokes every earlier unlock of the page. Owners and admins can do the same, and manage grants, from the dashboard's **Access** row action."
      7. skills/peek/SKILL.md: after the paragraph that starts "Restricted pages admit only the owner", add one line: "Owners can also manage grants in the dashboard's **Access** dialog." If that paragraph is hard-wrapped, keep that file's existing wrapping style for the new line.
      8. Delete docs/plans/dashboard-visibility-grants-plan.md (git rm). Run `grep -rn "dashboard-visibility-grants-plan" .`; it must print nothing.
      9. Run `cd docs && pnpm install --frozen-lockfile && pnpm build`. Do not dispatch pages.yml, because it deploys the live site. If pnpm is unavailable, or the build also fails on the phase's starting commit before your edits, stop with status=blocked.
      10. Run `mise run check`.
    acceptance:
      - test ! -e docs/plans/dashboard-visibility-grants-plan.md
      - grep -rn "dashboard-visibility-grants-plan" . prints nothing
      - grep -c "Access" docs/src/content/docs/using-peek.md prints at least 1
      - grep -n "PrepareVisibility" docs/architecture.md prints at least 2 lines
      - cd docs && pnpm build exits 0
      - mise run check exits 0
```
