# Dashboard access editing: visibility, password, grants and rename

## Goal

Owners and admins can change an already published page from the dashboard, the API and the CLI:

- **Visibility**: switch between `private`, `restricted`, `password` and `public`.
- **Password**: set a new password. A new password revokes access for viewers who unlocked the page with the old one. Today their 7-day unlock cookie keeps working, because it is signed over the slug only.
- **Grants**: manage who a `restricted` page is shared with (person grants, and Google group grants when group lookup is configured). The API and CLI already do this; the dashboard gets it.
- **Rename**: change the page's name, and with it its link. The link follows the new name the same way it does at upload. Old links keep redirecting to the new one and stay reserved, so they can never point at someone else's page.

Today the dashboard can only pick a visibility at upload time, the name can only be set at upload, and the link never changes.

There is no issue for this; it was asked for directly.

## Current state

All references are to `main` at `81d039d`. Line numbers may shift between phases; locate code by symbol.

### Visibility validation (duplicated)

- `uploads.Service.Create` (`internal/uploads/service.go:107`, switch at :124-147) validates visibility and password and bcrypt-hashes the password.
- `handleSetVisibility` (`internal/server/api_uploads.go:230-287`) repeats the same rules inline (:253-280).
  - It checks `ValidatePasswordLength(body.Password)` on the *untrimmed* password (:267) but hashes the trimmed one.
- Both accept `public`, `password`, `private` and `restricted`. The invalid-value message is `"visibility must be public, password, private, or restricted"`.
- Only `TestRestrictedVisibilityE2E` (`internal/server/visibility_e2e_test.go:119`) calls the endpoint, for the happy path. No test covers its validation errors.
- `SetUploadVisibility` is only called at `api_uploads.go:281`. The CLI validates visibility itself and parses the unchanged `{"visibility"}` response.

### Password unlock cookie

- `setPageAuthCookie(w, slug)` (`internal/server/pages.go:138`) sets `hn_auth_<slug>` to `makeSessionCookieValue` (`internal/server/security.go:100-109`), which is `slug.exp.hmac`.
  - It is called at `pages.go:90` and `pages.go:134`.
- It is verified by `verifySessionCookie` in `viewerCanAccessUpload` (`internal/server/comments.go:273-292`, call at :282).
- Slugs contain only `[A-Za-z0-9_-]`. `viewSubject` (`security.go:70`) already relies on `:` never occurring in a slug.

### Restricted pages and grants

- `accountCanViewRestricted` is in `internal/server/access.go`. `s.groups` is a `GroupChecker`, nil unless the `PEEK_GOOGLE_*` flags are set.
- `internal/db/grants.go`:
  - `AddUploadGrant` is idempotent and lowercases the email.
  - `RemoveUploadGrant` returns `sql.ErrNoRows` when nothing matches.
  - `ListUploadGrants` orders by kind, then email.
  - Grants cascade when the upload is deleted.
- The grants API is `internal/server/api_grants.go`:
  - `decodeGrantBody` checks, in order, kind (`"kind must be user or group"`), email (`"invalid email address"`), and that group grants need lookup (the long `"group grants need Google group lookup; …"` message).
  - It writes the normalized email back into `body.Email` (:56).
  - Audit actions are `upload.grant.add` and `upload.grant.remove`, with detail `slug=<slug> kind=<kind> email=<email>`.

### Names, slugs and storage

- At upload, `generateSlugFromName` (`internal/uploads/slug.go:47`) slugifies the name. On a clash it appends a random suffix, and an empty base gives a random slug. It checks availability through `slugChecker.UploadSlugExists` (`internal/db/uploads.go:81`).
- The name is stored in `uploads.filename`. It is shown as the page `<title>`, on the stats page and in API/CLI listings. The dashboard list shows only the link.
- Every version's bytes live under `upload_versions.object_key`; v1's key is the original slug, later versions use `versions/<slug>/<hex>`. Raw serving (`pages.go` `serveRawObject`), delete and retention all use `ObjectKey`, so changing `uploads.slug` moves no objects.
- `CreateUploadChecked` saves v1 under key = slug. A new upload that reused an old slug would therefore overwrite the renamed page's v1, so old slugs must stay reserved.
- Migrations live in `internal/db/migrations.go`; the last is `{8, "upload_grants", …}`. Each new table is also added to `internal/db/schema.go`. `internal/db/errors.go` holds sentinel errors. SQLite foreign keys are on (grants cascade).

### Dashboard

- `internal/web/templates/dashboard.gohtml`:
  - The "Your uploads" card starts at :75.
  - Row actions are `<div class="peek-row-actions">` at :97 (Stats link :98, Delete form :99).
  - The Delete form puts `{{.Name}}` inside an Alpine JS string: `x-on:submit="confirm($event, 'Delete {{.Name}}? …')"`. html/template does not JS-escape plain `x-on` attributes, so a name containing `'` breaks out of that string. Admins see every upload, so this is a stored script injection from any uploader into an admin's dashboard. It exists today and renaming makes it easier, so this plan fixes it (D13).
  - The upload form's segmented control is lines 56-69 and its password input is line 70.
- `internal/server/web_dashboard.go`:
  - `handleDashboard` (:17) builds `[]dashUpload` at :39-46 from `list`. Inside that function the local `uploads` slice shadows the `uploads` package.
  - `handleDashboardDelete` (:158) is the row-action pattern: `webAuth` → `parseDashboardForm` (CSRF) → `GetUpload` → owner-or-admin → act → audit → flash redirect.
- Flash helpers are `internal/server/web_helpers.go:15-34`. `dashboardFlash` uses `url.Values.Encode`: keys are sorted, `/`→`%2F`, space→`+`, `@`→`%40`. Missing csrf leads to `/dashboard?err=invalid+session`.
- View models are in `internal/web/renderer.go` (`DashboardUpload` :103, `DashboardData` :184), with aliases in `internal/server/view_models.go`.
- Alpine is used by the dashboard (`x-data`, `x-on`). `$refs` is used in `internal/web/assets/app.js`. `DashboardCSP` allows `'unsafe-eval'`.

### CSS and tooling

- `internal/web/assets/pines.css` is generated from `internal/web/tailwind-input.css` (row-button classes at :52-103). The `.peek-row-button-copied` block ends at :103.
- Tailwind's preflight zeroes `margin`, including on `dialog`.
- `mise run tailwind` downloads the Tailwind CLI with `curl -o bin/tailwindcss`, which fails when `bin/` does not exist. `bin/` is gitignored and absent on a fresh checkout.
- In the planning container `mise` is not installed, and `https://mise.run` is blocked by the network proxy (403). Go 1.26.9 is at `/usr/local/go/bin/go`, pnpm at `/opt/node22/bin/pnpm`, and both GitHub release downloads and `proxy.golang.org` work. See D0.

### Test harness

- `internal/server/handler_helpers_test.go` (package `server`): `newHandlerTestServer(t) (*Server, string)`, `doRequest(t, s, method, path, io.Reader, ...func(*http.Request)) *httptest.ResponseRecorder`, `asSession(s, id)`, `asBearer`, `withJSON`, `newAccountWithToken`.
- `internal/server/access_test.go`: `restrictedPage(t, s, slug)` (its owner is a non-admin "Owner", `owner-<slug>@example.test`), `grant(t, s, u, kind, email)`, `auditActions(t, s) map[action]actor`, `fakeGroups{members: map[string]bool{"group|user": true}}`.
- `internal/server/page_versions_test.go`: `newTwoVersionPage(t, s, slug, visibility, passwordHash)` gives v1 under key = slug and v2.
- Package `server_test` (`api_test.go`, `visibility_e2e_test.go`, `setup_test.go`, `http_test_helpers_test.go`):
  - `newTestApp`, `uploadRawHTML`, `uploadMultipartHTML`;
  - `postPagePassword`, which returns a `testResponse` with the cookies in `.Cookies`;
  - `findCookie`, `addComment(t, app, slug, []*http.Cookie, want)`;
  - `app.requestString`, `withAuth`, `withContentType`, `app.AdminToken`, `noRedirectClient()`.
- `internal/db/versions_test.go`: `seedVersionUpload(t, s, email, slug, size) (accountID, uploadID int64)` creates a new account each call, and emails are UNIQUE.
- `internal/cli/uploads_command_requests_test.go`: the `httptest` + `configureTestClient` + `captureStdout` pattern (see `TestCmdVisibilitySendsSetVisibilityRequest`).

## Design

### D0. Environment and quality gate (every phase)

Every phase starts with:

```sh
mkdir -p bin
command -v mise && mise install
```

If this exits 1, `mise` is absent; continue with the equivalents below.

If `mise` exists, run `mise run check` / `mise run check-full` / `mise run tailwind` as the briefs say. If `command -v mise` fails, do not try to install it; run these exact equivalents (from `mise.toml`) instead.

**`check`:**
```sh
git add -A   # stage (do not commit) so new files are included in the format check
test -z "$(gofmt -l $(git ls-files '*.go'))"
go vet ./...
go test ./...
# tailwind:
test -x bin/tailwindcss || { curl -fsSL -o bin/tailwindcss https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.1/tailwindcss-linux-x64 && chmod +x bin/tailwindcss; }
bin/tailwindcss -i internal/web/tailwind-input.css -o internal/web/assets/pines.css --minify
go build -o bin/peekd ./cmd/peekd && go build -o bin/peek ./cmd/peek
```

**`check-full`:** everything in `check`, plus:
```sh
go test -race -count=1 ./...
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
```

**`fmt`:** `git add -A && gofmt -w $(git ls-files '*.go')`. `bin/`, `*.out` and `data/` are gitignored.

Do not commit `coverage.out`; delete it.

**govulncheck in the cloud container.** The network proxy blocks `vuln.go.dev` (CONNECT 403), so govulncheck cannot download its database. If its output mentions `vuln.go.dev`, `403` or `CONNECT tunnel failed`, write `govulncheck: not run (vuln.go.dev blocked); CI runs it on the PR` in the phase report and treat that step as passed. Any other govulncheck failure falls under the stop conditions below.

**Stop conditions:**
- Go is not 1.26.x.
- The Tailwind download fails. Never hand-edit `pines.css`.
- The phase's starting point is red before any change.
- After the starting-point check, `git status` shows `pines.css` changed even though the phase changed nothing yet.
- `check-full` fails only in govulncheck or staticcheck, on code the phase did not change. Quote the output.

In each case stop with `status=blocked`.

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

1. `public`, `private` or `restricted`:
   - with a non-empty password → `KindPasswordNotAllowed`, `"password is only allowed with password visibility"`;
   - with an empty password → valid, return `VisibilityChange{Visibility: v}`.
2. `password` with an empty password → `KindPasswordRequired`, `"password visibility requires a password"`.
3. Any visibility that is not one of `public`, `private`, `restricted`, `password` (including `""`) → `KindInvalidVisibility`, `"visibility must be public, password, private, or restricted"`.
4. `password` with `!ValidatePasswordLength(password)` (on the trimmed password) → `KindPasswordTooLong`, `"password must be 72 characters or fewer"`.
5. bcrypt fails → `KindPasswordHash`, `"hash failed"`.
6. Otherwise → `VisibilityChange{Visibility: "password", PasswordHash: string(hash)}`.

`Service.Create`:
- keeps its trimming, its `""`→`password` default, and its empty-file and HTML checks first;
- replaces its switch and hashing block with `change, err := PrepareVisibility(in.Visibility, in.Password)`, returning `err` unchanged;
- drops the `bcrypt` import from `service.go`.

### D2. API uses D1

In `handleSetVisibility`, replace the block from `visibility := strings.TrimSpace(body.Visibility)` to the end of the switch with:

```go
change, err := uploads.PrepareVisibility(body.Visibility, body.Password)
if err != nil {
	status, msg := uploadHTTPError(err)
	jsonError(w, status, msg)
	return
}
```

Then:
- call `SetUploadVisibility(..., change.Visibility, change.PasswordHash)`;
- audit with `visibilityAuditDetail(slug, change.Visibility)` (D4);
- respond `{"visibility": change.Visibility}`.

`uploadHTTPError` already maps those kinds to the same 400/500 statuses and messages. One behaviour changes: the API length check now uses the trimmed password, matching upload creation. The `bcrypt` import leaves `api_uploads.go`.

### D3. Unlock cookie bound to the password hash (`internal/server/security.go`)

Delete `makeSessionCookieValue` and `verifySessionCookie`, with their comment lines. Replace them with:

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

Update the callers:
- `setPageAuthCookie` becomes `setPageAuthCookie(w http.ResponseWriter, u *models.Upload)`, using `authCookieName(u.Slug)` and `makePageAuthCookieValue(s.secret, u.Slug, u.PasswordHash, sessionTTL)`.
- Both callers in `pages.go` pass `u`.
- `comments.go` calls `verifyPageAuthCookie(s.secret, c.Value, u.Slug, u.PasswordHash)`.

Consequences:
- Cookies issued before the deploy stop verifying once; viewers re-enter the password.
- An already open iframe keeps its `/raw` view token (1 h, visitor-bound); that is out of scope.

Rejected alternatives:
- *A `password_version` column*: it needs a migration for nothing more.
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
8. Flash:
   - `password` → `dashboardOK(w, r, "Password updated for /p/"+slug)`;
   - anything else → `dashboardOK(w, r, "/p/"+slug+" is now "+change.Visibility)`;
   - D8 later changes the `restricted` case.

### D6. Dashboard access dialog markup

Insert exactly this inside `<div class="peek-row-actions">`, before the Stats link:

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
  </dialog>
</div>
```

How it behaves:
- A disabled password input is not submitted.
- The native `<dialog>` sits in the top layer, so the table's `overflow-x-auto` cannot clip it.
- A closed dialog is `display:none`, so the flex row is unaffected.
- A nested per-row `x-data` scopes `$refs` to the row.
- No new JS asset.

CSS goes into `tailwind-input.css` right after the `.peek-row-button-copied` block:

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
- In `internal/server/view_models.go`, add `type dashGrant = webui.DashboardGrant`.

**`internal/db/grants.go`:**
- Extract the row loop of `ListUploadGrants` into `func scanUploadGrants(rows *sql.Rows) ([]models.UploadGrant, error)`; it closes `rows`.
- Add:

```go
// ListUploadGrantsForUploads returns the grants of several uploads keyed by upload
// id, each list ordered by kind, then email. Uploads without grants are absent.
func (s *Store) ListUploadGrantsForUploads(ctx context.Context, uploadIDs []int64) (map[int64][]models.UploadGrant, error)
```

For an empty slice it returns `map[int64][]models.UploadGrant{}` without querying. Otherwise it runs one query, `SELECT … FROM upload_grants WHERE upload_id IN (?,?,…) ORDER BY upload_id, kind, email`, with the placeholders built as `strings.TrimSuffix(strings.Repeat("?,", len(uploadIDs)), ",")`.

**`internal/server/api_grants.go`:**

```go
// normalizeGrantInput validates a grant kind and email address and returns the
// lowercased, trimmed email, or a non-empty user-facing error message. Group grants
// need Google group lookup only when requireGroupLookup is true, so a stored group
// grant can always be removed.
func (s *Server) normalizeGrantInput(kind, email string, requireGroupLookup bool) (string, string)
```

- Checks and messages are the same as `decodeGrantBody` today, in the same order: kind, email, then groups (only when `requireGroupLookup`).
- `decodeGrantBody` calls it with `true`. On a message it writes `jsonError(w, http.StatusBadRequest, msg)`; otherwise it sets `body.Email = email` and returns `body, true`.
- API behaviour is unchanged.

**`handleDashboard`:**

```go
ids := make([]int64, 0, len(list))
for _, u := range list {
	ids = append(ids, u.ID)
}
grantsByUpload, err := s.store.ListUploadGrantsForUploads(r.Context(), ids)
if err != nil {
	slog.Error("dashboard grant list failed", "account_id", owner.ID, "err", err)
}
for i, u := range list {
	for _, g := range grantsByUpload[u.ID] {
		uploads[i].Grants = append(uploads[i].Grants, dashGrant{Kind: g.Kind, Email: g.Email})
	}
}
```

Place it right after the `uploads` slice is built. Reading a nil map is safe. Also set `GroupGrantsEnabled: s.groups != nil` and `ManageSlug: r.URL.Query().Get("manage")` in `dashData_`.

### D8. Dashboard grant routes, handlers and markup

**Routes** (`routes.go`, after the D5 route):
- `mux.HandleFunc("POST /dashboard/grants/{slug}", s.handleDashboardGrantAdd)`
- `mux.HandleFunc("POST /dashboard/grants/{slug}/remove", s.handleDashboardGrantRemove)`

**`web_helpers.go`** gets:

```go
// dashboardFlashManage redirects to the dashboard with a flash and reopens the
// access dialog of slug.
func dashboardFlashManage(w http.ResponseWriter, r *http.Request, key, msg, slug string) {
	q := url.Values{key: {msg}, "manage": {slug}}
	http.Redirect(w, r, dashboardPath+"?"+q.Encode(), http.StatusSeeOther)
}
```

**New `internal/server/web_grants.go`.** Both handlers follow D5 steps 1-4, then:

- **`handleDashboardGrantAdd`:**
  1. `kind := r.FormValue("kind")`; `email, msg := s.normalizeGrantInput(kind, r.FormValue("email"), true)`. On a message, `dashboardFlashManage(w, r, "err", msg, slug)`.
  2. `AddUploadGrant(r.Context(), u.ID, kind, email, owner.ID)`. On error, `slog.Error("dashboard grant add failed", "slug", slug, "err", err)` and `dashboardFlashManage(w, r, "err", "grant update failed", slug)`.
  3. Audit `upload.grant.add` with `"slug="+u.Slug+" kind="+kind+" email="+email`.
  4. `dashboardFlashManage(w, r, "ok", "Shared /p/"+slug+" with "+email, slug)`.
- **`handleDashboardGrantRemove`:** the same, except:
  - `normalizeGrantInput(..., false)`;
  - `RemoveUploadGrant`, where `errors.Is(err, sql.ErrNoRows)` → `dashboardFlashManage(w, r, "err", "grant not found", slug)`;
  - audit `upload.grant.remove`;
  - success → `dashboardFlashManage(w, r, "ok", "Removed "+email+" from /p/"+slug, slug)`.

**Change to D5 step 8:** when `change.Visibility == models.UploadVisibilityRestricted`, call `dashboardFlashManage(w, r, "ok", "/p/"+slug+" is now restricted", slug)`.

**Markup, part 1.** Add this attribute to the D6 row wrapper `<div x-data="{ vis: '{{.Visibility}}' }" class="m-0">`:

```
x-init="{{if eq $.ManageSlug .Slug}}$nextTick(() => $refs.visibilityDialog.showModal()){{end}}"
```

**Markup, part 2.** Insert this inside `<dialog>`, after the visibility `</form>` and before `</dialog>`:

```html
{{$slug := .Slug}}
<section x-show="vis === 'restricted' || {{if .Grants}}true{{else}}false{{end}}" class="mt-4 flex flex-col gap-2.5 border-t border-border pt-4">
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

Rejected alternatives:
- *A fetch/JSON grants editor*: every dashboard form uses POST + redirect + flash.
- *A separate grants page*: owners expect sharing next to the visibility choice.
- *Per-row `ListUploadGrants`*: N+1 queries on every dashboard load.

### D9. Slug aliases in the database

**Migration 9**, appended to `migrations` in `internal/db/migrations.go`. Add the same `CREATE TABLE`/`CREATE INDEX` to the end of the `schema` string in `internal/db/schema.go`:

```go
{9, "upload_slug_aliases", `
CREATE TABLE IF NOT EXISTS upload_slug_aliases (
	slug TEXT PRIMARY KEY,
	upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_upload_slug_aliases_upload ON upload_slug_aliases(upload_id);`},
```

**`internal/db/errors.go`:** add `ErrSlugTaken = errors.New("slug is already in use")` to the `var` block.

**`UploadSlugExists`** (`internal/db/uploads.go`) also counts aliases, so new uploads never take an old link. Its body becomes exactly:

```go
func (s *Store) UploadSlugExists(ctx context.Context, slug string) (bool, error) {
	var exists bool
	err := s.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uploads WHERE slug=?) OR EXISTS(SELECT 1 FROM upload_slug_aliases WHERE slug=?)`, slug, slug).Scan(&exists)
	return exists, err
}
```

Remove the now-unused `errors` import from `uploads.go`; `database/sql` stays.

**New `internal/db/slug_aliases.go`:**

```go
// RenameUpload sets an upload's slug and display name in one transaction. When the
// slug changes, the old slug becomes an alias that redirects to the upload and stays
// reserved; an alias the upload itself already owns is reclaimed. It returns
// ErrSlugTaken when newSlug belongs to another upload or another upload's alias, and
// sql.ErrNoRows when the upload does not exist.
func (s *Store) RenameUpload(ctx context.Context, uploadID int64, newSlug, newName string) error

// ResolveSlugAlias returns the current slug of the upload that slug used to name,
// or sql.ErrNoRows.
func (s *Store) ResolveSlugAlias(ctx context.Context, slug string) (string, error)
```

**`RenameUpload`**, inside one transaction:
1. `SELECT slug FROM uploads WHERE id=?`; this returns `sql.ErrNoRows` when the upload does not exist.
2. If `newSlug != oldSlug`:
   1. `SELECT COUNT(*) FROM uploads WHERE slug=? AND id<>?` > 0 → `ErrSlugTaken`.
   2. `SELECT COUNT(*) FROM upload_slug_aliases WHERE slug=? AND upload_id<>?` > 0 → `ErrSlugTaken`.
   3. `DELETE FROM upload_slug_aliases WHERE slug=? AND upload_id=?` (newSlug).
   4. `INSERT INTO upload_slug_aliases(slug,upload_id,created_at) VALUES(?,?,?)` (oldSlug, id, now).
3. `UPDATE uploads SET slug=?, filename=? WHERE id=?`.

**`ResolveSlugAlias`:** `SELECT u.slug FROM upload_slug_aliases a JOIN uploads u ON u.id=a.upload_id WHERE a.slug=?`.

Rejected alternatives:
- *Moving object keys on rename*: keys are stored per version, so moving is unnecessary and risks losing bytes.
- *Freeing old slugs*: a new upload would save v1 under that key and overwrite the renamed page's v1 object.

### D10. `uploads.Rename` (new `internal/uploads/rename.go`)

```go
const (
	KindNameRequired ErrorKind = "name_required"
	KindNameTooLong  ErrorKind = "name_too_long"
)

const maxNameLength = 200

// RenameRepository is the persistence a rename needs.
type RenameRepository interface {
	UploadSlugExists(ctx context.Context, slug string) (bool, error)
	ResolveSlugAlias(ctx context.Context, slug string) (string, error)
	RenameUpload(ctx context.Context, uploadID int64, newSlug, newName string) error
}

type RenameInput struct {
	UploadID    int64
	CurrentSlug string
	CurrentName string
	Name        string
}

type RenameResult struct {
	Slug        string
	URL         string // baseURL + "/p/" + Slug
	Name        string
	SlugChanged bool
}

// Rename changes an upload's display name and derives its link from the new name
// the same way upload does. The link is kept when the new name's slug form is
// empty, equals the current slug, or equals the old name's slug form; a page's own
// old link is taken back instead of minting a suffixed one.
func Rename(ctx context.Context, repo RenameRepository, baseURL string, in RenameInput) (*RenameResult, error)
```

Steps:
1. Trim `in.Name`. If it is `""` → `KindNameRequired`, `"name is required"`. If `utf8.RuneCountInString(name) > maxNameLength` → `KindNameTooLong`, `"name must be 200 characters or fewer"`.
2. Pick the slug:
   - start with `slug := in.CurrentSlug` and `base := slugify(name)`;
   - keep the current slug when `base == ""`, `base == in.CurrentSlug`, or `base == slugify(in.CurrentName)` (the name changed but its slug form did not, for example a suffixed `index-html-ab12cd` page renamed from `index.html` to `Index.HTML`);
   - otherwise, if `cur, err := repo.ResolveSlugAlias(ctx, base); err == nil && cur == in.CurrentSlug`, set `slug = base` (take back this page's own old link);
   - otherwise `slug, err = generateSlugFromName(ctx, name, repo)`, and on error return `KindSlugGeneration`, `"slug generation failed"`.
3. `repo.RenameUpload(ctx, in.UploadID, slug, name)`. On any error, `slog.Error("rename upload failed", "upload_id", in.UploadID, "err", err)` and return `KindPersistenceFailure`, `"rename failed"`. (`uploads` must not import `db`, so `db.ErrSlugTaken` from a race is reported generically.)
4. Return `&RenameResult{Slug: slug, URL: baseURL + "/p/" + slug, Name: name, SlugChanged: slug != in.CurrentSlug}`.

`Service.Create` is unchanged.

**`internal/server/upload_service.go`:** in `uploadHTTPError`, add `uploads.KindNameRequired, uploads.KindNameTooLong` to the 400 case.

### D11. Old links redirect (`internal/server/pages.go`)

Add:

```go
// redirectRenamedPage sends an old link to the page's current link. 302, not 301:
// a page can be renamed back, and a cached permanent redirect would then loop.
func redirectRenamedPage(w http.ResponseWriter, r *http.Request, path string) {
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, path, http.StatusFound)
}
```

- **`handlePage`:** when `GetUpload` fails, first try `if cur, aerr := s.store.ResolveSlugAlias(r.Context(), slug); aerr == nil { redirectRenamedPage(w, r, "/p/"+cur); return }`, then render the existing 404.
- **`handlePageVersion`:** when `GetUpload` fails, resolve the alias the same way. On a hit, parse `n, err := strconv.Atoi(r.PathValue("n"))`:
  - if `err != nil || n < 1`, call `s.renderVersionNotFound(w)`;
  - otherwise `redirectRenamedPage(w, r, "/p/"+cur+"/v/"+strconv.Itoa(n))`.

No other route resolves aliases:
- API, CLI and `/raw` URLs use the current slug.
- `/raw` tokens are minted per page load.
- A re-upload with `--slug <old>` gets 404 `"page was renamed; use slug <current>"` (D12).
- The password cookie is per slug, so password-page viewers unlock once more after a rename.

### D12. Rename API and CLI

**Route** (`routes.go`, after the visibility API route): `mux.HandleFunc("POST /api/uploads/{slug}/name", s.authToken(s.handleRenameUpload))`.

**New `internal/server/api_rename.go`**, `handleRenameUpload`:
1. `requireAPIToken`. `GetUpload` failure → 404 `"not found"`. Not owner or admin → 403 `"not owner"`.
2. Decode `{"name": string}` with `decodeJSON(w, r, &body, smallJSONBodyLimit)`. On error → 400 `"bad json"`.
3. `res, err := uploads.Rename(r.Context(), s.store, s.baseURL, uploads.RenameInput{UploadID: u.ID, CurrentSlug: u.Slug, CurrentName: u.Name, Name: body.Name})`. On error → `status, msg := uploadHTTPError(err)` and `jsonError`.
4. Audit `upload.rename` with detail `renameAuditDetail(u.Slug, res)`, where:

```go
func renameAuditDetail(oldSlug string, res *uploads.RenameResult) string {
	return "slug=" + oldSlug + " new_slug=" + res.Slug + " name=" + res.Name
}
```

   `renameAuditDetail` lives in `api_rename.go`.
5. `jsonOK(w, map[string]any{"slug": res.Slug, "url": res.URL, "name": res.Name})`.

**Version upload to an old slug** (`internal/server/api_uploads.go`, `handleUploadVersion`). When `GetUpload` fails, add this before the existing `"not found"`:

```go
if cur, aerr := s.store.ResolveSlugAlias(r.Context(), slug); aerr == nil {
	jsonError(w, http.StatusNotFound, "page was renamed; use slug "+cur)
	return
}
```

**CLI.** In `internal/cli/commands.go`, add `case "rename": err = cmdRename(rest)` after `case "visibility"`. Add a usage line after the `peek visibility <slug> password --password-stdin` line:

```
  peek rename <slug> <new name>        rename a page; its link follows the name and old links redirect
```

In `internal/cli/uploads_command.go`, add `cmdRename(args []string) error` after `cmdVisibility`:
- With fewer than 2 args, return `fmt.Errorf("usage: peek rename <slug> <new name>")`.
- `slug := args[0]`; `name := strings.TrimSpace(strings.Join(args[1:], " "))`. If the name is empty, return the same usage error.
- `LoadConfig` and `newClient` as in `cmdVisibility`.
- `c.postJSON("/api/uploads/"+url.PathEscape(slug)+"/name", map[string]any{"name": name}, &out)` (add the `net/url` import, as `grants_command.go` does), where `out` is `struct{ Slug, URL, Name string }` with json tags `slug`, `url` and `name`.
- Print `slug: <slug>`, `url: <url>` and `name: <name>`, each on its own line, in that order, using `fmt.Printf`.

### D13. Dashboard rename form, name in the list, safe delete confirm

**Route** (`routes.go`, after the D8 routes): `mux.HandleFunc("POST /dashboard/rename/{slug}", s.handleDashboardRename)`.

**New `internal/server/web_rename.go`**, `handleDashboardRename`:
1. Follow D5 steps 1-4.
2. `res, err := uploads.Rename(r.Context(), s.store, s.baseURL, uploads.RenameInput{UploadID: u.ID, CurrentSlug: u.Slug, CurrentName: u.Name, Name: r.FormValue("name")})`. On error → `dashboardFlashManage(w, r, "err", uploadErrorMessage(err), slug)`.
3. Audit `upload.rename` with `renameAuditDetail(u.Slug, res)`.
4. `dashboardFlashManage(w, r, "ok", "Renamed to /p/"+res.Slug, res.Slug)`.

**Markup in `dashboard.gohtml`:**

- (a) Insert this as the first child of `<dialog>`, before the visibility `<form>`:

```html
<form method="POST" action="/dashboard/rename/{{.Slug}}" class="mb-4 flex flex-col gap-2 border-b border-border pb-4">
  <input type="hidden" name="csrf" value="{{$.CSRF}}">
  <label for="hn-rename-{{.Slug}}" class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Name</label>
  <div class="flex gap-2">
    <input id="hn-rename-{{.Slug}}" type="text" name="name" value="{{.Name}}" required maxlength="200" class="h-9 min-w-0 flex-1 rounded-lg border border-input bg-secondary px-3 text-sm text-foreground placeholder:text-muted-foreground transition focus:border-ring focus:outline-none focus:ring-2 focus:ring-ring/20">
    <button type="submit" class="h-9 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition hover:bg-primary/90">Rename</button>
  </div>
  <p class="text-xs text-muted-foreground">The link follows the new name. Old links keep redirecting here.</p>
</form>
```

- (b) In the row's link cell, inside `<div class="flex items-center gap-2 whitespace-nowrap">` and after the copy button's closing `</button>`, add:

```html
<span class="max-w-[16rem] truncate text-xs text-muted-foreground">{{.Name}}</span>
```

- (c) Replace the Delete form's opening tag with:

```html
<form method="POST" action="/dashboard/delete/{{.Slug}}" data-confirm="Delete {{.Name}}? This cannot be undone." x-on:submit="confirm($event, $el.dataset.confirm)" class="m-0">
```

  `$el` is the form. html/template escapes `{{.Name}}` correctly inside a plain attribute value, so no name can reach Alpine's expression evaluator.

## ADRs

This project has no ADR directory. Not applicable.

## Manual steps

There is nothing to do before implementation. After implementation, one browser check (`ma1-dashboard-access-dialog`) covers the Alpine dialog behaviour, the reopen-after-redirect, real cookie revocation and old-link redirects; the Go tests check strings and handlers, not browser behaviour. The step-by-step page is the artifact linked in the manifest.

## Risks and open questions

Each risk below names what the worker would see if the plan is wrong. In every case the phase stops with `status=blocked`; it never improvises.

- **Tooling.** `mise` is missing (D0), the Tailwind download fails, or `go` is not 1.26.x. Never hand-edit `pines.css`. `vuln.go.dev` is blocked by the proxy; see D0.
- **The `Create` refactor.** It must keep the error order and messages, so a pre-existing `internal/uploads` test failing means it did not.
- **Unexpected cookie callers.** Before D3, `grep -rn "setPageAuthCookie\|verifySessionCookie\|makeSessionCookieValue" internal` must print exactly 9 lines: `pages.go` 90, 134, 138, 141; `security.go` 100, 101, 106, 107; `comments.go` 282. Line numbers may differ by a few if p1 edits earlier lines first, but the files and the count must match.
- **Template parsing.** If `NewRenderer` fails to parse `dashboard.gohtml` after D8 or D13, stop and quote the error.
- **Migration numbering.** If `migrations.go` already has an entry with id 9 when p4 starts, `main` moved: stop.
- **Unrelated gate failures.** `check-full` fails in govulncheck or staticcheck on files the phase did not change.
- **`/implement`'s own `verify.fast`.** The profile's `verify.fast` uses `mise run …`. If the orchestrator's container also lacks `mise`, those post-merge checks fail even though the phases are fine. Then run the D0 equivalents instead and report it. A SessionStart hook that installs `mise` would fix this repo-wide, but that is outside this plan.

## Implementation manifest

```yaml
plan_slug: dashboard-visibility-grants
feature_branch: feat/dashboard-visibility-grants
max_parallel: 2
manual_steps_artifact: https://claude.ai/artifact/XJaLxv5xngoH5BFC5CcQBu
manual_steps_source: docs/plans/dashboard-visibility-grants-plan-manual-steps.html
manual_before: []
manual_after:
  - id: ma1-dashboard-access-dialog
    title: In a browser, use the dashboard Access dialog to rename a page, switch visibility, set a password and add/remove a grant, and check old-link redirect and old-password sign-out
    why: Alpine dialog behaviour, the reopen-after-redirect, real cookie revocation and the redirect in a real browser are not covered by the Go tests, which only check rendered strings and handler responses
verify_after_merge:
  - go test ./internal/uploads/ ./internal/db/ ./internal/server/ ./internal/web/ ./internal/cli/
final_checks:
  - docs/plans/dashboard-visibility-grants-plan.md and docs/plans/dashboard-visibility-grants-plan-manual-steps.html are deleted and `git grep -n "dashboard-visibility-grants-plan"` prints nothing
  - "`grep -rn \"makeSessionCookieValue\\|verifySessionCookie\" internal` prints nothing"
  - mise run check-full (or the D0 equivalents, with D0's govulncheck exception) exits 0
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
      Read AGENTS.md, CONTRIBUTING.md, docs/architecture.md and docs/operations.md, then this plan's "Current state", D0, D1, D2, D3 and D4. Do D0's setup and run `check` on the starting point.
      1. Create internal/uploads/visibility.go with VisibilityChange and PrepareVisibility exactly as in D1, in package uploads.
      2. Refactor Service.Create in internal/uploads/service.go per D1 and remove the bcrypt import. Run `go test ./internal/uploads/...`. If any pre-existing test fails, stop with status=blocked.
      3. Add internal/uploads/visibility_test.go with table test TestPrepareVisibility. Check kinds with `var uploadErr *Error; if !errors.As(err, &uploadErr) || uploadErr.Kind != tc.kind { t.Fatalf(...) }`. Cases:
         - public, private and restricted with no password → no error, empty hash;
         - public with "x" → KindPasswordNotAllowed;
         - restricted with "x" → KindPasswordNotAllowed;
         - password with "" and with "   " → KindPasswordRequired;
         - visibility "" and "secret" → KindInvalidVisibility, message "visibility must be public, password, private, or restricted";
         - password with strings.Repeat("a", 73) → KindPasswordTooLong;
         - password with "  pw  " → no error, Visibility "password", and bcrypt.CompareHashAndPassword(hash, "pw") passes.
      4. In internal/server/api_uploads.go, add visibilityAuditDetail (D4), rewrite handleSetVisibility per D2, and remove the bcrypt import.
      5. Add TestSetVisibilityAPIValidation to internal/server/api_test.go (package server_test):
         - app := newTestApp(t); up := uploadRawHTML(t, app, "vis-api", "public").
         - For each case, resp := app.requestString(t, http.MethodPost, "/api/uploads/"+up.Slug+"/visibility", body, withAuth(app.AdminToken), withContentType("application/json")). Assert the status and that string(resp.Body) contains the text:
           - {"visibility":"password"} → 400, "password visibility requires a password";
           - {"visibility":"public","password":"x"} → 400, "password is only allowed with password visibility";
           - {"visibility":"nope"} → 400, "visibility must be public, password, private, or restricted";
           - {"visibility":"password","password":"<strings.Repeat("a", 73)>"} → 400, "password must be 72 characters or fewer";
           - {"visibility":"restricted"} → 200, `"visibility":"restricted"`;
           - {"visibility":"private"} → 200, `"visibility":"private"`.
      6. Before changing code, run `grep -rn "setPageAuthCookie\|verifySessionCookie\|makeSessionCookieValue" internal`. It must print exactly 9 lines: pages.go 90, 134, 138, 141; security.go 100, 101, 106, 107; comments.go 282. Otherwise stop with status=blocked. Then implement D3 in security.go, pages.go and comments.go.
      7. Add TestPageAuthCookieBoundToPasswordHash to internal/server/security_test.go (package server). With secret strings.Repeat("0", 64) and v := makePageAuthCookieValue(secret, "page", "hashA", time.Hour):
         - verifyPageAuthCookie(secret, v, "page", "hashA") is true;
         - with ("page", "hashB") it is false;
         - with ("other", "hashA") it is false.
      8. In internal/server/visibility_e2e_test.go, add subtest "password change revokes earlier unlocks" to TestUploadVisibilityE2E:
         a. up := uploadMultipartHTML(t, app, "rotate-page", "password", "old"); resp := postPagePassword(t, app, up.Slug, "old"); assert 303. oldCookie := findCookie(resp.Cookies, "hn_auth_"+up.Slug). addComment(t, app, up.Slug, []*http.Cookie{oldCookie}, http.StatusOK).
         b. app.requestString(t, http.MethodPost, "/api/uploads/"+up.Slug+"/visibility", `{"visibility":"password","password":"new"}`, withAuth(app.AdminToken), withContentType("application/json")) → 200.
         c. addComment with oldCookie → 401.
         d. postPagePassword "old" → 401. postPagePassword "new" → 303, newCookie from it, and addComment with newCookie → 200.
         e. POST {"visibility":"public"}, then {"visibility":"password","password":"new"}, both → 200. Then addComment with newCookie → 401.
      9. Run gofmt (D0 fmt), then check-full (D0).
    acceptance:
      - go test ./internal/uploads/ -run TestPrepareVisibility -v passes, and all pre-existing internal/uploads tests pass unmodified
      - go test ./internal/server/ -run 'TestSetVisibilityAPIValidation|TestPageAuthCookieBoundToPasswordHash|TestUploadVisibilityE2E|TestRestrictedVisibilityE2E|TestPagePasswordCookieAuthorizesProtectedCommentAPI' -v passes, including subtest password_change_revokes_earlier_unlocks
      - "`! grep -rqn \"makeSessionCookieValue\\|verifySessionCookie\" internal` exits 0"
      - "`! grep -qn bcrypt internal/server/api_uploads.go internal/uploads/service.go` exits 0"
      - check-full (D0) exits 0

  - id: p2-dashboard-visibility
    title: Dashboard Access dialog that changes visibility and password
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
      Read AGENTS.md, CONTRIBUTING.md, docs/architecture.md and docs/operations.md, then this plan's "Current state", D0, D5 and D6. p1 is merged: uploads.PrepareVisibility and visibilityAuditDetail exist. Do D0's setup and run `check` on the starting point.
      1. Add the D5 route to internal/server/routes.go, directly after the `POST /dashboard/delete/{slug}` route.
      2. Add handleDashboardVisibility to internal/server/web_dashboard.go, directly after handleDashboardDelete, following D5 steps 1-8 exactly.
      3. Insert the D6 markup in internal/web/templates/dashboard.gohtml, inside `<div class="peek-row-actions">` and before the Stats link.
      4. Append the D6 CSS to internal/web/tailwind-input.css after the `.peek-row-button-copied` block. Regenerate pines.css (D0 tailwind) and commit it.
      5. In internal/server/web_dashboard_test.go (package server):
         - Add the helper `dashboardPost(t *testing.T, s *Server, accountID int64, path string, form url.Values, withCSRF bool) *httptest.ResponseRecorder`. When withCSRF is true, it does form.Set("csrf", "csrf-token") and adds &http.Cookie{Name: csrfCookie, Value: "csrf-token"}. It sets Content-Type application/x-www-form-urlencoded, applies asSession(s, accountID), and returns doRequest(t, s, http.MethodPost, path, strings.NewReader(form.Encode()), opts...).
         - Add these tests. Each uses s, _ := newHandlerTestServer(t) and u := restrictedPage(t, s, "page"), and asserts status 303 plus the exact Location:
           a. TestDashboardVisibilitySetsPasswordAndAudits: post visibility=password&password=pw as u.OwnerAccountID.
              - Location "/dashboard?ok=Password+updated+for+%2Fp%2Fpage".
              - GetUpload shows "password", and the hash verifies "pw".
              - s.store.ListAuditLog(ctx, 10) has Action "upload.visibility.set" with Detail "slug=page visibility=password password=updated".
           b. TestDashboardVisibilityMakesPublic: post visibility=public as the owner.
              - Location "/dashboard?ok=%2Fp%2Fpage+is+now+public".
              - Visibility is "public" and PasswordHash is "".
           c. TestDashboardVisibilityRejectsPasswordWithoutValue: post visibility=password.
              - Location "/dashboard?err=password+visibility+requires+a+password".
              - Visibility is still "restricted".
           d. TestDashboardVisibilityRejectsNonOwner: other, _ := s.store.CreateAccount(ctx, "user@example.test", "User", false); post visibility=public as other.ID.
              - Location "/dashboard?err=not+owner".
              - Visibility is still "restricted".
           e. TestDashboardVisibilityRejectsMissingCSRF: post visibility=public with withCSRF=false.
              - Location "/dashboard?err=invalid+session".
              - Visibility is still "restricted".
      6. In internal/web/renderer_test.go, add TestDashboardRendersAccessDialogPerUpload, modelled on TestDashboardUploadFormShowsSelectedFileAndDisablesEmptySubmit.
         - Render DashboardData{CSRF: "csrf", User: "Admin", Uploads: []DashboardUpload{{Slug: "page", Name: "page.html", Visibility: "password"}}}.
         - Assert it contains each literal string:
           - `action="/dashboard/visibility/page"`
           - `x-data="{ vis: 'password' }"`
           - `x-ref="visibilityDialog"`
           - `value="restricted" x-model="vis"`
           - `autocomplete="new-password"`
           - `:disabled="vis !== 'password'"`
      7. Run gofmt, then check-full (D0).
      Pattern for a dashboard row action plus test: handleDashboardDelete and the TestDashboardDelete* tests.
    acceptance:
      - go test ./internal/server/ -run TestDashboardVisibility -v passes (5 tests)
      - go test ./internal/web/ -run TestDashboardRendersAccessDialogPerUpload -v passes
      - grep -c '"POST /dashboard/visibility/{slug}"' internal/server/routes.go prints 1
      - grep -c "peek-visibility-dialog" internal/web/assets/pines.css prints at least 1
      - check-full (D0) exits 0

  - id: p3-dashboard-grants
    title: Grants editor in the dashboard Access dialog
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
      - internal/server/view_models.go
      - internal/server/routes.go
      - internal/web/renderer.go
      - internal/web/renderer_test.go
      - internal/web/templates/dashboard.gohtml
      - internal/web/assets/pines.css
    brief: |
      Read AGENTS.md, CONTRIBUTING.md, docs/architecture.md and docs/operations.md, then this plan's "Current state", D0, D7 and D8. p2 is merged: the Access dialog, handleDashboardVisibility and the dashboardPost test helper exist. Do D0's setup and run `check` on the starting point. Pattern commit for grants handlers plus tests: fb0d8ce.
      1. internal/db/grants.go and its test:
         - Extract scanUploadGrants and add ListUploadGrantsForUploads (D7).
         - In internal/db/grants_test.go, add TestListUploadGrantsForUploads. Use `s := openTestStore(t)` (internal/db/store_test.go) and `ctx := context.Background()`. Seed two uploads with `_, id1 := seedVersionUpload(t, s, "o1@example.test", "grant-m1", 1)` and `_, id2 := seedVersionUpload(t, s, "o2@example.test", "grant-m2", 1)`.
         - Add to id1: user "zed@example.com", then group "team@example.com", then user "amy@example.com" (createdBy 0). Add to id2: user "bob@example.com".
         - Assert:
           - the map has exactly 2 keys;
           - id1's list is [group team@example.com, user amy@example.com, user zed@example.com];
           - id2's list has 1 entry;
           - ListUploadGrantsForUploads(ctx, nil) returns a non-nil empty map.
      2. internal/server/api_grants.go:
         - Add normalizeGrantInput (D7) and make decodeGrantBody use it with requireGroupLookup=true, setting body.Email = email.
         - Run `go test ./internal/server/ -run Grant`; the pre-existing tests must pass unmodified.
      3. Add DashboardGrant, DashboardUpload.Grants, DashboardData.GroupGrantsEnabled and DashboardData.ManageSlug in internal/web/renderer.go, and the dashGrant alias in internal/server/view_models.go (D7).
      4. In handleDashboard, load grants exactly as the D7 snippet shows, and set GroupGrantsEnabled and ManageSlug.
      5. Add dashboardFlashManage to internal/server/web_helpers.go (D8). In handleDashboardVisibility, make the restricted case use it (D8 "Change to D5 step 8").
      6. Create internal/server/web_grants.go with handleDashboardGrantAdd and handleDashboardGrantRemove (D8). Add both routes after the dashboard visibility route.
      7. In dashboard.gohtml:
         - Add the D8 x-init attribute to the row wrapper div.
         - Insert the D8 grants section inside `<dialog>`, after the visibility `</form>`.
         - Regenerate pines.css (D0) and commit it if it changed.
         - If `go test ./internal/web/` reports a template parse error, stop with status=blocked and quote it.
      8. New internal/server/web_grants_test.go (package server). Use s, _ := newHandlerTestServer(t), u := restrictedPage(t, s, "page") and dashboardPost, acting as u.OwnerAccountID unless stated. Assert status 303 and the exact Location:
         a. TestDashboardGrantAddAndRemove:
            - Add kind=user&email=Alice@Example.com → "/dashboard?manage=page&ok=Shared+%2Fp%2Fpage+with+alice%40example.com". ListUploadGrants has 1 user grant "alice@example.com", and auditActions(t, s) has key "upload.grant.add".
            - Remove kind=user&email=alice@example.com via /dashboard/grants/page/remove → "/dashboard?manage=page&ok=Removed+alice%40example.com+from+%2Fp%2Fpage". No grants remain, and auditActions has "upload.grant.remove".
         b. TestDashboardGrantRejectsInvalidEmail: email=not-an-email → "/dashboard?err=invalid+email+address&manage=page"; no grants.
         c. TestDashboardGrantRejectsGroupWithoutLookup: s.groups is nil; kind=group&email=team@example.com → Location has prefix "/dashboard?err=group+grants+need+Google+group+lookup" and contains "&manage=page"; no grants.
         d. TestDashboardGrantAcceptsGroupWithLookup: s.groups = fakeGroups{members: map[string]bool{}}; kind=group&email=team@example.com → "/dashboard?manage=page&ok=Shared+%2Fp%2Fpage+with+team%40example.com"; one grant, of Kind "group".
         e. TestDashboardGrantRemovesGroupWithoutLookup: grant(t, s, u, models.UploadGrantGroup, "team@example.com") with s.groups nil; remove kind=group&email=team@example.com → "/dashboard?manage=page&ok=Removed+team%40example.com+from+%2Fp%2Fpage"; no grants.
         f. TestDashboardGrantRemoveMissing: remove kind=user&email=alice@example.com → "/dashboard?err=grant+not+found&manage=page".
         g. TestDashboardGrantRejectsNonOwner: other, _ := s.store.CreateAccount(ctx, "user@example.test", "User", false); add as other.ID → "/dashboard?err=not+owner"; no grants.
         h. TestDashboardGrantRejectsMissingCSRF: withCSRF=false → "/dashboard?err=invalid+session"; no grants.
      9. In internal/server/web_dashboard_test.go:
         - Add TestDashboardVisibilityRestrictedReopensDialog: u := newTwoVersionPage(t, s, "page", "public", ""); post visibility=restricted as u.OwnerAccountID → "/dashboard?manage=page&ok=%2Fp%2Fpage+is+now+restricted".
         - Add TestDashboardListsGrantsInAccessDialog:
           - u := restrictedPage(t, s, "page"); grant(t, s, u, models.UploadGrantUser, "alice@example.com").
           - rec := doRequest(t, s, http.MethodGet, "/dashboard?manage=page", nil, asSession(s, u.OwnerAccountID)). Assert 200 and that the body contains each of:
             - `alice@example.com`
             - `action="/dashboard/grants/page/remove"`
             - `action="/dashboard/grants/page"`
             - `$nextTick(() => $refs.visibilityDialog.showModal())`
             - `<input type="hidden" name="kind" value="user">`
           - Then set s.groups = fakeGroups{members: map[string]bool{}}, GET again, and assert the body contains `<option value="group">Google group</option>`.
      10. In internal/web/renderer_test.go, add TestDashboardAccessDialogShowsGrantHintWhenNotRestricted. Render one upload {Slug: "page", Visibility: "public"} with no grants, and assert it contains "Grants apply once you save Restricted above." and "Only you and admins can open this page until you share it.".
      11. Run gofmt, then check-full (D0).
    acceptance:
      - go test ./internal/db/ -run TestListUploadGrantsForUploads -v passes
      - go test ./internal/server/ -run 'TestDashboardGrant|TestDashboardVisibility|TestDashboardListsGrantsInAccessDialog|Grant' -v passes
      - go test ./internal/web/ -run 'TestDashboardAccessDialog|TestDashboardRendersAccessDialogPerUpload' -v passes
      - grep -c '"POST /dashboard/grants/{slug}' internal/server/routes.go prints 2
      - check-full (D0) exits 0

  - id: p4-rename-core
    title: Slug aliases, uploads.Rename, and redirects from old links
    depends_on: [p1-visibility-core]
    complexity: M
    touches:
      - internal/db/migrations.go
      - internal/db/schema.go
      - internal/db/errors.go
      - internal/db/uploads.go
      - internal/db/slug_aliases.go
      - internal/db/slug_aliases_test.go
      - internal/uploads/rename.go
      - internal/uploads/rename_test.go
      - internal/server/pages.go
      - internal/server/upload_service.go
      - internal/server/page_rename_test.go
    brief: |
      Read AGENTS.md, CONTRIBUTING.md, docs/architecture.md and docs/operations.md, then this plan's "Current state" ("Names, slugs and storage"), D0, D9, D10 and D11. p1 is merged. Do D0's setup and run `check` on the starting point. If migrations.go already has an entry with id 9, stop with status=blocked.
      1. Database (D9):
         - Append migration 9 to internal/db/migrations.go and the same table and index to the end of the schema string in internal/db/schema.go.
         - Add ErrSlugTaken to internal/db/errors.go.
         - Change UploadSlugExists in internal/db/uploads.go.
         - Create internal/db/slug_aliases.go with RenameUpload and ResolveSlugAlias.
      2. New internal/db/slug_aliases_test.go (package db). Use `s := openTestStore(t)` (internal/db/store_test.go), `ctx := context.Background()`, and seedVersionUpload with a distinct email per upload. Tests:
         a. TestRenameUploadKeepsOldSlugAsAlias:
            - _, id := seedVersionUpload(t, s, "o1@example.test", "first", 1); RenameUpload(ctx, id, "second", "Second").
            - GetUpload("second") has Name "Second" and ID id; GetUpload("first") returns sql.ErrNoRows.
            - ResolveSlugAlias("first") returns "second"; UploadSlugExists("first") is true.
            - GetUploadVersion(ctx, id, 1).ObjectKey is still "first".
         b. TestRenameUploadRejectsTakenSlug: seed "a" (o1@) and "b" (o2@). RenameUpload(a, "b", …) returns ErrSlugTaken. Then rename b → "c", so "b" becomes b's alias, and RenameUpload(a, "b", …) still returns ErrSlugTaken.
         c. TestRenameUploadReclaimsOwnAlias: seed "a"; rename to "b", then back to "a" → no error. GetUpload("a") works, ResolveSlugAlias("a") returns sql.ErrNoRows, and ResolveSlugAlias("b") returns "a".
         d. TestRenameUploadNameOnly: seed "a"; RenameUpload(id, "a", "New name") → the name changes and ResolveSlugAlias("a") returns sql.ErrNoRows.
         e. TestRenameUploadMissingUpload: RenameUpload(ctx, 9999, "x", "x") returns sql.ErrNoRows.
         f. TestSlugAliasesCascadeOnUploadDelete: seed "a"; rename to "b"; DeleteUpload(ctx, id) → ResolveSlugAlias("a") returns sql.ErrNoRows and UploadSlugExists("a") is false.
      3. Create internal/uploads/rename.go exactly as in D10.
      4. New internal/uploads/rename_test.go (package uploads) with a fake `type fakeRenameRepo struct{ taken map[string]bool; aliases map[string]string; renamed []string; err error }`. Declare all three methods on `*fakeRenameRepo` and pass `&fakeRenameRepo{…}`:
         - UploadSlugExists returns taken[slug].
         - ResolveSlugAlias returns aliases[slug], nil when present, else "", sql.ErrNoRows.
         - RenameUpload appends newSlug+"|"+newName to renamed and returns err.
         Tests (baseURL "http://h" unless stated):
         - TestRenameRequiresName: "  " → KindNameRequired, and nothing is renamed.
         - TestRenameRejectsLongName: strings.Repeat("a", 201) → KindNameTooLong.
         - TestRenameKeepsSlugWhenNameSlugifiesToCurrent: CurrentSlug "my-report", CurrentName "my report", Name "My Report" → Slug "my-report", SlugChanged false, renamed == ["my-report|My Report"].
         - TestRenameKeepsSlugWhenNameHasNoSlugChars: CurrentSlug "old", CurrentName "old", Name "!!!" → Slug "old".
         - TestRenameKeepsSlugWhenSlugFormUnchanged: CurrentSlug "index-html-ab12cd", CurrentName "index.html", Name "Index.HTML", taken {"index-html": true} → Slug "index-html-ab12cd", SlugChanged false.
         - TestRenameDerivesNewSlug: CurrentSlug "old", CurrentName "old", Name "New Page" → Slug "new-page", URL "http://h/p/new-page", SlugChanged true.
         - TestRenameAddsSuffixOnClash: CurrentSlug "old", CurrentName "old", Name "New Page", taken {"new-page": true} → Slug has prefix "new-page-" and is not "new-page".
         - TestRenameReclaimsOwnAlias: CurrentSlug "b", CurrentName "B", Name "A", taken {"a": true}, aliases {"a": "b"} → Slug "a", SlugChanged true.
         - TestRenameReportsPersistenceFailure: CurrentSlug "old", CurrentName "old", Name "New Page", err errors.New("boom") → KindPersistenceFailure, message "rename failed".
      5. In internal/server/upload_service.go, add KindNameRequired and KindNameTooLong to uploadHTTPError's 400 case (D10).
      6. Implement D11 in internal/server/pages.go: redirectRenamedPage, plus alias resolution in handlePage and handlePageVersion.
      7. New internal/server/page_rename_test.go (package server), one test named TestRenamedPageRedirects. s, _ := newHandlerTestServer(t); u := newTwoVersionPage(t, s, "old", "public", ""); then s.store.RenameUpload(ctx, u.ID, "new", "New"). Then, with doRequest:
         - GET /p/old?x=1 → 302, Location "/p/new?x=1".
         - GET /p/old/v/2 → 302, Location "/p/new/v/2".
         - GET /p/old/v/abc → 404.
         - GET /p/new → 200.
         - GET /p/missing → 404.
      8. Run gofmt, then check-full (D0).
    acceptance:
      - go test ./internal/db/ -run 'TestRenameUpload|TestSlugAliases' -v passes (6 tests)
      - go test ./internal/uploads/ -run TestRename -v passes (9 tests)
      - go test ./internal/server/ -run TestRenamedPageRedirects -v passes
      - grep -c '{9, "upload_slug_aliases"' internal/db/migrations.go prints 1
      - check-full (D0) exits 0

  - id: p5-rename-surfaces
    title: Rename via API, CLI and the dashboard Access dialog; show names; safe delete confirm
    depends_on: [p3-dashboard-grants, p4-rename-core]
    complexity: M
    touches:
      - internal/server/routes.go
      - internal/server/api_rename.go
      - internal/server/api_uploads.go
      - internal/server/rename_e2e_test.go
      - internal/server/web_rename.go
      - internal/server/web_rename_test.go
      - internal/web/templates/dashboard.gohtml
      - internal/web/renderer_test.go
      - internal/web/assets/pines.css
      - internal/cli/commands.go
      - internal/cli/uploads_command.go
      - internal/cli/uploads_command_requests_test.go
    brief: |
      Read AGENTS.md, CONTRIBUTING.md, docs/architecture.md and docs/operations.md, then this plan's "Current state", D0, D12 and D13. p3 and p4 are merged: uploads.Rename, dashboardFlashManage, the Access dialog with grants, and the dashboardPost test helper exist. Do D0's setup and run `check` on the starting point.
      1. Add the D12 API route, and create internal/server/api_rename.go with handleRenameUpload and renameAuditDetail. Add the D12 "Version upload to an old slug" check to handleUploadVersion in internal/server/api_uploads.go.
      2. Add the D13 dashboard route, and create internal/server/web_rename.go with handleDashboardRename.
      3. Make D13 markup changes (a), (b) and (c) in internal/web/templates/dashboard.gohtml. Regenerate pines.css (D0) and commit it if it changed.
      4. Add the CLI command and usage line to internal/cli/commands.go and internal/cli/uploads_command.go (D12).
      5. New internal/server/rename_e2e_test.go (package server_test), TestRenameE2E. app := newTestApp(t); app.client = noRedirectClient().
         a. up := uploadRawHTML(t, app, "first", "public").
         b. POST /api/uploads/<up.Slug>/name with `{"name":"Second Report"}`, withAuth(app.AdminToken) and withContentType("application/json") → 200, body contains `"slug":"second-report"` and `"name":"Second Report"`.
         c. GET /p/<up.Slug> → 302 with Location "/p/second-report". GET /p/second-report → 200.
         d. POST the same endpoint for second-report with `{"name":"  "}` → 400 with "name is required".
         e. uploadRawHTML(t, app, "first", "public") again → its Slug is not equal to up.Slug (the old link is reserved).
      6. New internal/server/web_rename_test.go (package server). Use s, _ := newHandlerTestServer(t), u := newTwoVersionPage(t, s, "page", "public", "") and dashboardPost:
         a. TestDashboardRenameChangesLinkAndAudits: post name=Quarterly Report to /dashboard/rename/page as u.OwnerAccountID.
            - 303, Location "/dashboard?manage=quarterly-report&ok=Renamed+to+%2Fp%2Fquarterly-report".
            - GetUpload("quarterly-report") has Name "Quarterly Report".
            - auditActions(t, s) has "upload.rename".
         b. TestDashboardRenameRejectsEmptyName: name="" → "/dashboard?err=name+is+required&manage=page".
         c. TestDashboardRenameRejectsNonOwner: account from s.store.CreateAccount(ctx, "user@example.test", "User", false) → "/dashboard?err=not+owner".
         d. TestDashboardRenameRejectsMissingCSRF: withCSRF=false → "/dashboard?err=invalid+session".
         e. TestUploadVersionToRenamedSlugExplains: s, admin := newHandlerTestServer(t); u := newTwoVersionPage(t, s, "page", "public", ""); s.store.RenameUpload(ctx, u.ID, "renamed", "Renamed"); rec := uploadPage(t, s, admin, "<html><body>v3</body></html>", map[string]string{"slug": "page"}) (helper in upload_versions_test.go) → 404, body contains "page was renamed; use slug renamed".
      7. In internal/web/renderer_test.go, add TestDashboardRendersRenameFormAndSafeDeleteConfirm. Render one upload {Slug: "page", Name: "it's <b>", Visibility: "public"}. Assert the HTML contains:
         - `action="/dashboard/rename/page"`
         - `name="name" value="it&#39;s &lt;b&gt;"`
         - `data-confirm="Delete it&#39;s &lt;b&gt;? This cannot be undone."`
         - `x-on:submit="confirm($event, $el.dataset.confirm)"`
         and does NOT contain `'Delete it`.
         If the exact escaped forms differ (html/template may emit &#39; or &#x27;), print the rendered snippet and assert the form it actually produces, as long as no raw `'` from the name appears inside an x-on attribute.
      8. In internal/cli/uploads_command_requests_test.go, add TestCmdRenameSendsRenameRequest, modelled on TestCmdVisibilitySendsSetVisibilityRequest:
         - The server expects POST /api/uploads/page/name with JSON {"name":"New Name"} and responds {"slug":"new-name","url":"http://x/p/new-name","name":"New Name"}.
         - Call cmdRename([]string{"page", "New", "Name"}). Assert the body name is "New Name" and stdout contains "slug: new-name" and "url: http://x/p/new-name".
         - Also assert cmdRename([]string{"page"}) returns an error containing "usage: peek rename".
      9. Run gofmt, then check-full (D0).
    acceptance:
      - go test ./internal/server/ -run 'TestRenameE2E|TestDashboardRename|TestUploadVersionToRenamedSlugExplains' -v passes
      - go test ./internal/web/ -run TestDashboardRendersRenameFormAndSafeDeleteConfirm -v passes
      - go test ./internal/cli/ -run TestCmdRename -v passes
      - "`! grep -q \"confirm(\\$event, 'Delete\" internal/web/templates/dashboard.gohtml` exits 0"
      - grep -c '"POST /api/uploads/{slug}/name"' internal/server/routes.go prints 1
      - check-full (D0) exits 0

  - id: p6-docs-retire
    title: Document access editing, rename and password revocation; delete the plan
    depends_on: [p5-rename-surfaces]
    complexity: S
    touches:
      - README.md
      - docs/architecture.md
      - docs/operations.md
      - docs/src/content/docs/using-peek.md
      - docs/src/content/docs/auth-access.md
      - docs/src/content/docs/manual.md
      - docs/src/content/docs/reference.md
      - skills/peek-server/SKILL.md
      - skills/peek/SKILL.md
      - docs/plans/dashboard-visibility-grants-plan.md
      - docs/plans/dashboard-visibility-grants-plan-manual-steps.html
    brief: |
      Read AGENTS.md (never hard-wrap Markdown lines), CONTRIBUTING.md, docs/architecture.md and docs/operations.md. Pattern commit: f625dc2. Find each anchor below by its text. There is no changelog and there are no ADRs. Do D0's setup.
      1. docs/src/content/docs/using-peek.md, "Pick Visibility": after the paragraph starting "Restricted pages are opened up with grants", add the paragraph: "In the dashboard, the **Access** button on an upload's row renames the page, changes its visibility, sets a new password and, for restricted pages, adds or removes people and Google groups. Renaming changes the link to follow the new name; old links keep redirecting and are never given to another page. Setting a new password signs out everyone who unlocked the page with the previous one." Inside the ```sh block under "Change visibility after upload", after the line `peek visibility <slug> restricted`, add the line `peek rename <slug> "New name"`. In the "Common user commands" ```text block, after `peek visibility <slug> public|password|private|restricted`, add `peek rename <slug> <new name>`.
      2. docs/src/content/docs/auth-access.md, "Upload Visibility": after the paragraph starting "A restricted page is opened up with grants", add: "Owners and admins can change a page's name, mode, password and grants later from the dashboard's **Access** dialog or with `peek rename`, `peek visibility` and `peek grant`. A new password revokes every earlier unlock of that page."
      3. docs/src/content/docs/manual.md: in the code block containing `peek visibility <slug> public|password|private|restricted`, add a line `peek rename <slug> <new name>` after it. After that block, add: "The dashboard's **Access** row action does the same, and manages grants on restricted pages, without the CLI."
      4. docs/src/content/docs/reference.md: after the line `peek visibility <slug> public|private|password|restricted [--password <pw> | --password-stdin]`, add `peek rename <slug> <new name>`. In the "## Page And API Routes" table, after the row `| \`DELETE /api/uploads/<slug>/grants\` | Remove a grant. Same JSON body. |`, add the row `| \`POST /api/uploads/<slug>/name\` | Rename a page. JSON body \`{"name":"..."}\`; returns the new \`slug\`, \`url\` and \`name\`. The link follows the name; old links redirect. |`. If that row is not there verbatim, stop with status=blocked.
      5. README.md:
         - Append to the paragraph starting "Upload visibility is set at creation time": "Setting a new password signs out viewers who unlocked the page with the old one. `peek rename <slug> <new name>` renames a page; its link follows the name and old links redirect. The dashboard's **Access** row action does all of this from the browser."
         - In the CLI block that contains `peek visibility <slug> restricted      only the owner, admins and grantees`, add the line `peek rename <slug> <new name>         rename; old links redirect`.
         - In the paragraph starting "A browser dashboard at `/login` lets users", replace "lets users upload, list, delete, password-protect, and view stats." with "lets users upload, list, rename and delete pages, change their visibility, password and grants, and view stats." If that phrase is not there verbatim, stop with status=blocked.
         - Replace the threat-table row starting "| Bypassing password gate |" with: "| Bypassing password gate | `/raw` requires a short-lived HMAC-signed view token bound to visitor cookie. Changing the password revokes earlier unlocks. |"
      6. docs/architecture.md:
         - In the `internal/uploads` bullet, replace "owns upload creation behavior:" with "owns upload creation, rename and visibility-change rules (`PrepareVisibility`, `Rename`):".
         - Append to the "## Storage" paragraph: "`PrepareVisibility` validates later visibility/password changes and `Rename` derives a new link from a new name, for both the API and the dashboard. Renaming never moves objects: each version keeps its stored object key, and old slugs stay reserved as redirecting aliases (`upload_slug_aliases`)."
      7. docs/operations.md:
         - In "## Page Access", after "or the grants API", insert ", or the dashboard's **Access** dialog".
         - Append to the paragraph starting "The uploaded HTML is served to the sandboxed iframe": "Setting a new password revokes earlier password unlocks on the next request in the same way. Renaming a page redirects its old links (302) to the new one; password-page viewers unlock once more after a rename. Pages already open under the old link must be reloaded before comments work again."
         - In "## Upgrades And Rollbacks", after the paragraph about migrations 7 and 8, add: "Migration 9 (`upload_slug_aliases`) keeps the old links of renamed pages reserved. After upgrading, existing password-page unlock cookies stop working once; viewers re-enter the password. Do not roll back to an older binary once a page has been renamed: older binaries do not reserve old links, so a new upload could overwrite a renamed page's first version. Restore the pre-upgrade backup and object storage instead."
      8. skills/peek-server/SKILL.md, under "### Manage page passwords", after its code block, add the line: "Setting a new password revokes every earlier unlock of the page. Owners and admins can also do this, manage grants and rename pages from the dashboard's **Access** row action; `peek rename <slug> <new name>` renames from the CLI (old links redirect)."
      9. skills/peek/SKILL.md: directly after the line ending "...also switch an existing page with `peek visibility <slug> restricted`." (the paragraph starting "Restricted pages admit only the owner"), append one unwrapped line: "Owners can manage grants in the dashboard's **Access** dialog, and rename a page with `peek rename <slug> <new name>` (old links redirect)."
      10. `git rm docs/plans/dashboard-visibility-grants-plan.md docs/plans/dashboard-visibility-grants-plan-manual-steps.html`. Then `git grep -n "dashboard-visibility-grants-plan"` must print nothing.
      11. Run `cd docs && pnpm install --frozen-lockfile && pnpm build`. Do not dispatch pages.yml; it deploys the live site. If pnpm is missing, or the build also fails before your edits, stop with status=blocked.
      12. Run check (D0).
    acceptance:
      - test ! -e docs/plans/dashboard-visibility-grants-plan.md && test ! -e docs/plans/dashboard-visibility-grants-plan-manual-steps.html
      - "`! git grep -q \"dashboard-visibility-grants-plan\"` exits 0"
      - grep -c "peek rename" README.md prints at least 2
      - grep -c "PrepareVisibility" docs/architecture.md prints at least 2
      - grep -c "upload_slug_aliases" docs/operations.md prints at least 1
      - cd docs && pnpm build exits 0
      - check (D0) exits 0
```
