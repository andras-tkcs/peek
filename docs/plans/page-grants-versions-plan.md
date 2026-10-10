# Page grants, Google group membership, and page versions

## Goal

Peek pages today are public, password-gated, or "private" (any signed-in account). This plan adds three things for internal, single-organization use:

1. **Grants and a `restricted` visibility.** A page owner can grant access to individual user emails and to group emails. A new fourth visibility, `restricted`, admits only the owner, admins, and signed-in viewers who match a grant. Grants are checked from the database on every view of `/p/...`, the comment API and the views API. Existing `private` pages keep their current meaning ("any signed-in account"), so existing data does not change.
2. **Google group membership.** Group grants are resolved through the Google Admin SDK Directory API (`members.hasMember`), with a service account that has domain-wide delegation. Results are cached in memory for 5 minutes by default (configurable).
3. **Page versions.** Re-uploading to an existing page with `peek upload file.html --slug <slug>` creates version N+1. `/p/<slug>` serves the latest version and `/p/<slug>/v/<n>` serves any retained version. Comments belong to the version they were written on. Visits stay per page and record the version that was viewed.

There is no tracking issue. The user chose these product decisions during planning:
- grants come with a new `restricted` visibility rather than narrowing `private`;
- a re-upload targets a page by explicit slug;
- comments are kept per version, visits are shared.

## Current state

- **Schema.** `internal/db/schema.go:1-140` creates `uploads` with one HTML object per page, keyed by `slug`. `comments` and `visits` reference `uploads(id) ON DELETE CASCADE`. Migrations live in `internal/db/migrations.go:9-29`; the last is id 6, `upload_visibility`. Non-SQL migrations dispatch in the `if m.id == ...` chain at `internal/db/migrations.go:57-77`, and ALTERs tolerate duplicate columns via `isDuplicateColumnError`. `db.Open` (`internal/db/store.go:12-45`) runs `schema`, then `runMigrations`, then `migrateAccounts`, `migrateUploadsOwner` (which rebuilds `uploads` with foreign keys off), then `migrateInviteTokenCipher`. The DB is SQLite with `SetMaxOpenConns(1)`.
- **Upload queries.** `internal/db/uploads.go` repeats the same 10-column SELECT in `GetUpload`, `GetUploadByID`, `ListUploadsByOwner`, `ListAllUploads` and `ListUploadsOlderThan`. Quotas in `CreateUploadChecked` (`internal/db/uploads.go:13-60`) sum `uploads.size`, as do `SumUploadSizes` and `SumUploadSizesByOwner`.
- **Object storage.** `internal/objectstore/storage.go` exposes `Save/Open/Delete(ctx, slug)`. `objectName` (`internal/objectstore/slug.go:10-31`) accepts only `[A-Za-z0-9_-]+` and appends `.html`. `FileStorage.Save` only creates `fs.Dir` (`internal/objectstore/file.go:22-39`).
- **Upload creation.** `uploads.Service.Create` (`internal/uploads/service.go:89-150`) validates, generates a slug, saves the object, then calls `Repository.CreateUploadChecked`, deleting the object if persistence fails (`CleanupError`). Slugs come from `slugify` (`[a-z0-9-]`) or `randID`, which is base64url and may contain `_` and `-` (`internal/uploads/slug.go`).
- **API and CLI upload.** `handleUpload` (`internal/server/api_uploads.go:31-112`) accepts multipart or raw HTML. The CLI `cmdUpload` (`internal/cli/upload_command.go:15-121`) always sends `visibility` (default `password`).
- **Page view.** `handlePage` (`internal/server/pages.go:15-47`) checks visibility via `viewerCanAccessUpload` (`internal/server/comments.go:181-197`). `private` means any session that `webAuth` accepts (`internal/server/web_auth.go:12-43`). It then records a visit and renders `page.gohtml` with an iframe pointing at `/raw/<slug>?t=<view token>&v=<vid>`. `handleRaw` (`internal/server/pages.go:84-125`) checks only the HMAC view token, which is bound to slug and visitor id with a 1 hour TTL (`makeViewToken`/`verifyViewToken`, `internal/server/security.go:71-94`), and streams `storage.Open(slug)`.
- **Password gate.** The gate form posts to `/p/{slug}` (`internal/web/templates/gate.gohtml:14`), and `handlePagePassword` redirects back to `/p/{slug}`.
- **Comments.**
  - `handleListComments` and `handleAddComment` (`internal/server/comments.go:32-170`) use `store.ListComments(ctx, uploadID)` and `store.AddComment(ctx, uploadID, ...)`.
  - Bearer-token callers (the CLI) must own the page or be an admin.
  - The page JS calls `/api/uploads/<slug>/comments` (`internal/web/assets/app.js:174,432`), reading `data-slug` from `<body>` (`page.gohtml:14`).
- **Visits.** `recordVisit` enqueues a `visitEvent{UploadID,...}` (`internal/server/analytics.go:15-70`). `startVisitWorker` calls `store.RecordVisit(ctx, uploadID, cookie, name, ip, ua)`.
- **Deletion and retention.** `deleteUpload` (`internal/server/upload_delete.go`) deletes one object, then the row. `cleanupExpired` (`internal/server/lifecycle.go:75-97`) deletes uploads whose `uploads.created_at` is older than `retention_days`.
- **Auth.** Google login uses OAuth with `openid email profile` (`internal/server/oauth_config.go:95-102`). `models.Account.Email` is the viewer identity, and it may be empty for token-only accounts. `golang.org/x/oauth2` (including `oauth2/google`) is already a direct dependency (`go.mod`), so `google.JWTConfigFromJSON` is available without new modules.
- **Startup config.** Flags and env vars are parsed in `parseServeConfig` (`internal/peekd/run.go:63-145`) into `serveConfig`, then copied into `server.Config` (`internal/peekd/run.go:~187`). Invalid config fails fast (`validateServeConfig`).
- **Architecture guard.** `internal/architecture_test.go` forbids certain imports per package. Dependency rules are written in `docs/architecture.md`.
- **Visibility literals.** `public|password|private` appear in `internal/models/models.go:5-9`, `internal/uploads/service.go:105-116`, `internal/server/api_uploads.go:213-236`, `internal/server/comments.go:181-203`, `internal/cli/upload_command.go:56-62,155-157`, `internal/cli/uploads_command.go:102-105`, `internal/cli/commands.go:69-73` and `internal/web/templates/dashboard.gohtml:57-58`.
- **Tests.**
  - Most server tests are internal (`package server`). They build a server with `newTestServer(t) *Server` (`internal/server/oauth_test.go:29`), drive `s.Handler()` with `httptest`, and reach `s.store`/`s.storage` directly; lifecycle tests use `newRetentionCleanupTestServer` (`internal/server/lifecycle_test.go:151`).
  - Four files are external (`package server_test`) and use `newTestApp` in `internal/server/http_test_helpers_test.go`; they cannot reach unexported fields.
  - Visibility end-to-end tests are in `internal/server/visibility_e2e_test.go`, page tests in `internal/server/pages_test.go`, and DB tests in `internal/db/store_test.go`.
  - Service tests with a fake repository are in `internal/uploads/service_test.go`.
- **Generated CSS.** `internal/web/assets/pines.css` is generated by `mise run tailwind` from the templates. A Tailwind class that does not already appear in some template is not in the CSS.

## Design

### 3.1 Versions: schema (migration 7, `upload_versions`)

New table, in `schema.go` (for fresh installs) and created by migration 7:

```sql
CREATE TABLE IF NOT EXISTS upload_versions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
	version INTEGER NOT NULL,
	object_key TEXT NOT NULL,
	size INTEGER NOT NULL,
	created_by_account_id INTEGER REFERENCES accounts(id),
	created_at INTEGER NOT NULL,
	UNIQUE(upload_id, version)
);
```

Two other tables gain a column:
- `comments` gains `version INTEGER NOT NULL DEFAULT 1`.
- `visits` gains `version INTEGER NOT NULL DEFAULT 1`.

Both columns are added to the `CREATE TABLE` statements in `schema.go`, and by idempotent ALTERs in migration 7. Do not add indexes on the new columns to `schema.go`, because `schema.go` runs before migrations on existing databases.

Migration entry: `{7, "upload_versions", ""}`, dispatched to a new `func (s *Store) migrateUploadVersions() error` in the `if m.id == ...` chain. It does the following, in order:
1. Run the `CREATE TABLE IF NOT EXISTS upload_versions ...` statement above.
2. `ALTER TABLE comments ADD COLUMN version INTEGER NOT NULL DEFAULT 1`, ignoring `isDuplicateColumnError`.
3. `ALTER TABLE visits ADD COLUMN version INTEGER NOT NULL DEFAULT 1`, ignoring `isDuplicateColumnError`.
4. Backfill: `INSERT OR IGNORE INTO upload_versions(upload_id,version,object_key,size,created_by_account_id,created_at) SELECT id,1,slug,size,NULL,created_at FROM uploads`. `created_by_account_id` is NULL because very old databases do not yet have `uploads.owner_account_id` when migrations run (`migrateUploadsOwner` runs later).

Invariant: every upload has at least one version row. Version 1's `object_key` is the slug, so existing objects need no move.

### 3.2 Versions: object keys

- A version-1 object key is the slug, unchanged.
- A version N≥2 object key is `versions/<slug>/<16 lowercase hex chars>`. The random suffix comes from `crypto/rand`, 8 bytes, hex-encoded.
- Because keys are random, two concurrent re-uploads never write the same object. The version number is allocated afterwards, inside the DB transaction, and the `UNIQUE(upload_id, version)` constraint plus the single-connection SQLite serialize that allocation.

Changes in `internal/objectstore/slug.go`:
- `objectName(key)` accepts either a valid slug or `versions/` + valid slug + `/` + exactly 16 chars of `[0-9a-f]`.
- Anything else still returns `ErrInvalidSlug`.
- The result is `key + ".html"`.

`FileStorage.Save` creates `filepath.Dir(path)` with `os.MkdirAll(..., 0o755)` instead of `fs.Dir`. S3 needs no change, since its keys already allow `/`.

The key is generated in `internal/uploads` by a new unexported `func versionObjectKey(slug string) (string, error)`.

### 3.3 Versions: models and store API

`internal/models/models.go`:
- `Upload` gains `LatestVersion int`.
- `Comment` gains `Version int`.
- `Visit` gains `Version int`.
- New type:

```go
type UploadVersion struct {
	ID                 int64
	UploadID           int64
	Version            int
	ObjectKey          string
	Size               int64
	CreatedByAccountID int64 // 0 when unknown (backfilled rows)
	CreatedAt          time.Time
}
```

`internal/db/uploads.go`:
- Replace the five duplicated SELECTs with one `const uploadSelect` that ends with `, COALESCE((SELECT MAX(v.version) FROM upload_versions v WHERE v.upload_id=u.id),1)` and the `FROM uploads u JOIN accounts a ON a.id=u.owner_account_id` clause.
- Add one `scanUpload(row interface{ Scan(...any) error }) (*models.Upload, error)` that both `QueryRow` and `scanUploads` use.

`CreateUploadChecked` (same signature):
- The total quota becomes `SELECT COALESCE(SUM(size),0) FROM upload_versions`.
- The owner storage quota becomes `SELECT COALESCE(SUM(v.size),0) FROM upload_versions v JOIN uploads u ON u.id=v.upload_id WHERE u.owner_account_id=?`.
- The count quota still counts `uploads` rows.
- In the same transaction, after inserting the upload, insert `upload_versions(upload_id, 1, slug, size, ownerAccountID, now)`.

`SumUploadSizes` and `SumUploadSizesByOwner` use the same two version-sum queries.

New functions in a new file `internal/db/versions.go`:
- `func (s *Store) CreateVersionChecked(ctx context.Context, uploadID int64, objectKey string, size int64, actorAccountID int64, limits uploadquota.Limits) (int, error)`. In one transaction:
  1. Read the upload's `owner_account_id` (`sql.ErrNoRows` passes through unwrapped).
  2. Run the total quota check and the owner storage quota check (the page owner's, not the actor's) with the queries above, returning `uploadquota.ErrTotalExceeded` / `ErrOwnerStorageExceeded`. There is no count check.
  3. Compute `next = COALESCE(MAX(version),0)+1`.
  4. Insert the row with `created_by_account_id = actorAccountID` (NULL if 0).
  5. `UPDATE uploads SET size=? WHERE id=?` (so `uploads.size` is the latest version's size).
  6. Commit and return `next`.
- `func (s *Store) GetUploadVersion(ctx context.Context, uploadID int64, version int) (*models.UploadVersion, error)` returns `sql.ErrNoRows` when the version is missing.
- `func (s *Store) ListUploadVersions(ctx context.Context, uploadID int64) ([]models.UploadVersion, error)`, ordered by `version ASC`.
- `func (s *Store) ListPrunableVersions(ctx context.Context, cutoff time.Time) ([]models.UploadVersion, error)` returns rows where `created_at < cutoff` and `version <` the upload's max version, ordered by `created_at ASC`.
- `func (s *Store) DeleteUploadVersion(ctx context.Context, uploadID int64, version int) error`. In one transaction it runs `DELETE FROM comments WHERE upload_id=? AND version=?`, then `DELETE FROM upload_versions WHERE upload_id=? AND version=?` (`requireRowsAffected`), then commits.

`ListUploadsOlderThan(ctx, cutoff)` keeps its name and signature. Its WHERE clause becomes `(SELECT MAX(v.created_at) FROM upload_versions v WHERE v.upload_id=u.id) < ?`, so a page expires when its newest version is older than the cutoff.

`internal/db/comments.go`:
- `AddComment(ctx, uploadID int64, version int, selector, text, anchorKind, author, cookie, body string) error` stores `version`.
- `ListComments(ctx, uploadID int64, version int) ([]models.Comment, error)`: `version == 0` means all versions, `>0` filters. It selects and scans `version`.

`internal/db/visits.go`:
- `RecordVisit(ctx, uploadID int64, version int, cookie, name, ip, ua string) error` stores `version`.
- `RecentVisits` scans `version` into `Visit.Version`.

### 3.4 Versions: upload service and API

`internal/uploads/service.go`:
- The `Repository` interface gains `CreateVersionChecked(ctx context.Context, uploadID int64, objectKey string, size int64, actorAccountID int64, limits uploadquota.Limits) (int, error)`.
- New types and method:

```go
type AddVersionInput struct {
	UploadID       int64
	Slug           string
	ActorAccountID int64
	Data           []byte
	Limits         uploadquota.Limits
}

type AddVersionResult struct {
	Slug       string
	URL        string // BaseURL + "/p/" + slug
	VersionURL string // BaseURL + "/p/" + slug + "/v/" + version
	Version    int
	Size       int
}

func (svc Service) AddVersion(ctx context.Context, in AddVersionInput) (*AddVersionResult, error)
```

`AddVersion` steps:
1. Check for empty data (`KindEmptyFile`) and run `looksLikeHTML` (`KindInvalidHTML`), as `Create` does.
2. `key, err := versionObjectKey(in.Slug)`; on error return `KindStorageWrite` "storage failed".
3. `Storage.Save(ctx, key, data)`.
4. Call `Repository.CreateVersionChecked`. On error, map it with `storeError` and delete the object with the same `CleanupError` joining as `Create`.
5. Return the result.

`CreateResult` gains `Version int` (always 1).

`internal/server/api_uploads.go` `handleUpload`:
- Read `slug`: `strings.TrimSpace(r.FormValue("slug"))` for multipart, `r.URL.Query().Get("slug")` for raw HTML.
- When `slug != ""`:
  1. If `visibility != "" || password != ""`, return 400 `visibility and password cannot be set when uploading a new version; use the visibility endpoint`. For raw HTML the existing "password visibility requires multipart" check runs first and is unchanged.
  2. Run `s.store.GetUpload(ctx, slug)`. On error return 404 `not found`.
  3. If `u.OwnerAccountID != owner.AccountID && !owner.IsAdmin`, return 403 `not owner`.
  4. Call `s.uploadService().AddVersion(...)` with `ActorAccountID: owner.AccountID` and `Limits: s.uploadLimits(ctx)`. Map errors with `uploadHTTPError`.
  5. Write the audit entry `s.auditRequest(r, owner.Name, "upload.version.create", "slug="+slug+" version="+strconv.Itoa(v)+" size="+strconv.Itoa(size))`.
  6. Respond with `uploadResp{Slug, URL, Visibility: u.Visibility, Version, VersionURL}`.
- `uploadResp` gains `Version int \`json:"version"\`` and `VersionURL string \`json:"version_url"\``. New pages return version 1 and `.../p/<slug>/v/1`.

### 3.5 Versions: deletion and retention

`deleteUpload` (`internal/server/upload_delete.go`):
1. `versions, err := s.store.ListUploadVersions(ctx, u.ID)`.
2. For each version, `s.storage.Delete(ctx, v.ObjectKey)`, returning the first error wrapped as `delete upload object %q: %w` with the key.
3. If the list is empty, delete `u.Slug` as before.
4. Then `s.store.DeleteUpload`.

`cleanupExpired` (`internal/server/lifecycle.go`) keeps the existing whole-page pass, which now uses latest-version age through `ListUploadsOlderThan`. After that pass it adds a second one:
1. `ListPrunableVersions(ctx, cutoff)`.
2. For each version, `storage.Delete(ctx, v.ObjectKey)`, then `store.DeleteUploadVersion(ctx, v.UploadID, v.Version)`. On error, log with `slog.Error("retention cleanup: delete version", "upload_id", ..., "version", ..., "err", err)` and continue.
3. If any were pruned, log `slog.Info("retention cleanup: pruned old versions", "count", n, "cutoff", ...)`.

Visits are not deleted by version pruning.

### 3.6 Versions: viewing, raw, comments, versions API

Routes (`internal/server/routes.go`), added next to the existing page routes:
- `GET /p/{slug}/v/{n}` → `s.handlePageVersion`
- `POST /p/{slug}/v/{n}` → `s.rateLimit(s.passwordLimiter, s.handlePagePassword)`
- `GET /raw/{slug}/v/{n}` → `s.handleRawVersion`
- `GET /api/uploads/{slug}/versions` → `s.authToken(s.handleListVersions)`

`internal/server/pages.go`:
- Factor the body of `handlePage` into `func (s *Server) servePage(w http.ResponseWriter, r *http.Request, u *models.Upload, version int, pagePath string)`.
  - `handlePage` calls it with `u.LatestVersion` and `"/p/"+slug`.
  - `handlePageVersion` parses `n` with `strconv.Atoi`. If `n < 1` or `GetUploadVersion` fails, it renders `renderWebError(w, 404, "Version not found", "This version of the page does not exist or is no longer available.")`. Otherwise it calls `servePage` with `n` and `"/p/"+slug+"/v/"+strconv.Itoa(n)`.
- Inside `servePage`:
  - The private redirect uses `s.setNextPath(w, pagePath)`.
  - The gate renders `GateData{Slug, Action: pagePath}`.
  - `recordVisit(r, u, vid, version)`.
  - The raw URL is `"/raw/" + slug + "/v/" + strconv.Itoa(version) + "?t=" + makeViewToken(s.secret, viewSubject(slug, version), vid) + "&v=" + vid`.
  - The page data gets `Version: version`, `LatestVersion: u.LatestVersion`.
- `handlePagePassword`: compute `pagePath` the same way, from `r.PathValue("n")`, and when `n` is set validate it as above. Render the gate with `Action: pagePath` on a wrong password, and redirect to `pagePath` on success. The cookie stays per slug, so one password unlocks all versions.
- New in `internal/server/security.go`: `func viewSubject(slug string, version int) string { return slug + ":" + strconv.Itoa(version) }`. `:` cannot occur in a slug, and `verifyViewToken` splits on `.`, so the subject is unambiguous.
- `handleRawVersion` works like `handleRaw`, except:
  1. It resolves `GetUploadVersion(u.ID, n)` (404 on error).
  2. It verifies the token against `viewSubject(slug, n)`.
  3. It opens `s.storage.Open(ctx, ver.ObjectKey)` twice exactly as today.
  
  Factor the shared streaming part into `func (s *Server) serveRawObject(w http.ResponseWriter, r *http.Request, slug, objectKey string)`.
- Legacy `handleRaw` (`/raw/{slug}`, tokens minted before this change, valid for up to 1 hour) keeps verifying the token against the bare slug. It serves the latest version's `ObjectKey`, using `GetUploadVersion(u.ID, u.LatestVersion)`.

`internal/server/analytics.go`:
- `visitEvent` gains `Version int`.
- `recordVisit(r, u, vid string, version int)`.
- The worker passes `ev.Version` to `RecordVisit`.

`internal/web/renderer.go`:
- `PageData` gains `Version int` and `LatestVersion int`.
- `GateData` gains `Action string`.

`gate.gohtml` uses `action="{{.Action}}"`. Every existing `GateData{...}` construction sets `Action: "/p/"+slug`.

`page.gohtml`:
- Add `data-version="{{.Version}}"` to `<body>`.
- Directly after the iframe, add this banner. It uses only classes that already exist in `pines.css`, so no Tailwind regeneration is needed:

```html
{{if lt .Version .LatestVersion}}
<div id="hn-version-banner" x-show="!commentMode"
     class="hn-floating-surface fixed top-[18px] left-1/2 z-[1200] -translate-x-1/2 flex items-center gap-2 h-[40px] px-2.5 pl-3.5 rounded-full text-[13px] whitespace-nowrap">
  Version {{.Version}} of {{.LatestVersion}}
  <a href="/p/{{.Slug}}" class="hn-hint-link">View latest</a>
</div>
{{end}}
```

`internal/web/assets/app.js` (`pageApp`):
- Add `version: 0` to state.
- In init, set `this.version = Number(dataset.version) || 0`.
- Both comment fetches (`app.js:174` and `app.js:432`) use `"/api/uploads/" + this.slug + "/comments" + (this.version ? "?v=" + this.version : "")`.

Keep the existing controller conventions from `CONTRIBUTING.md` (no HTML string insertion).

`internal/server/comments.go`:
- Add the helper `func (s *Server) commentVersion(r *http.Request, u *models.Upload) (int, bool)`:
  - an empty `v` query param gives `u.LatestVersion`;
  - otherwise `strconv.Atoi`, which must be ≥1 and exist via `GetUploadVersion`, or it returns false.
- In `handleListComments` and `handleAddComment`, after the access checks, call the helper. On false, respond 404 `version not found`. Pass the version to `ListComments` / `AddComment`.
- `commentOut` gains `Version int \`json:"version"\``.

`handleExportUpload` (`internal/server/api_stats.go`):
- Uses `ListComments(ctx, u.ID, 0)`.
- `exportComment` gains `Version int \`json:"version"\``.
- `exportVisit` gains `Version int \`json:"version"\``.
- The export map gains `"latest_version": u.LatestVersion` and `"versions": [{version,size,created_at}]` from `ListUploadVersions`.

`handleListVersions` in a new file `internal/server/api_versions.go`:
- Token auth, owner or admin, otherwise 403 `not owner`; 404 `not found` when the page is missing.
- Responds with a JSON array of `{"version":n,"size":bytes,"created_at":unix,"url":baseURL+"/p/"+slug+"/v/"+n}`, ordered by version ascending.

`handleListUploads` items gain `"version": u.LatestVersion`.

### 3.7 Versions: CLI

`internal/cli/upload_command.go`:
- New flag `--slug <slug>`.
- With `--slug`, reject `--visibility`, `--password` and `--password-stdin` with the error `--slug adds a new version to an existing page; change visibility with 'peek visibility'`. Do not default `visibility` to `password`, and send the multipart field `slug` and no `visibility` field.
- `writeMultipartUpload(mw, file, filename, visibility, password, slug string)` writes `visibility` only when non-empty, `password` only when non-empty, and `slug` only when non-empty.
- Output adds `fmt.Printf("version:  %d\n", out.Version)` after the `slug:` line. When `--slug` was used, it also adds `fmt.Printf("version url: %s\n", out.VersionURL)`.
- The usage error becomes `usage: peek upload <file.html> [--visibility public|password|private|restricted] [--password <pw>] [--name <name>] [--slug <slug>]`. Phase p2 writes it without `|restricted`, and p6 adds `|restricted`.

`internal/cli/stats_comments_command.go` `cmdComments`:
- Accepts `peek comments <slug> [--version <n>]`. `n` must be a positive integer, otherwise the error is `--version must be a positive integer`.
- It requests `/api/uploads/<slug>/comments?v=<n>` when given, and the struct gains `Version int \`json:"version"\``.
- Each printed comment shows `v<version>` in its header line, next to the author.

New command `peek versions <slug>`:
- Lives in `internal/cli/uploads_command.go` as `cmdVersions`, registered in the command switch in `internal/cli/commands.go`.
- `GET /api/uploads/<slug>/versions`.
- Prints one line per version with `text/tabwriter`: `v<n>\t<size> bytes\t<created_at as time.Unix(...).Format(time.RFC3339)>\t<url>`.

Usage text in `commands.go` gains these lines:
- `peek upload <file.html> --slug <slug>        upload a new version of an existing page`
- `peek versions <slug>                 list versions of one of your pages`
- `peek comments <slug> [--version <n>]  list comments (latest version by default)`. This replaces the existing comments line.

### 3.8 Grants: schema (migration 8, `upload_grants`)

```sql
CREATE TABLE IF NOT EXISTS upload_grants (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
	kind TEXT NOT NULL CHECK (kind IN ('user','group')),
	email TEXT NOT NULL,
	created_by_account_id INTEGER REFERENCES accounts(id),
	created_at INTEGER NOT NULL,
	UNIQUE(upload_id, kind, email)
);
CREATE INDEX IF NOT EXISTS idx_upload_grants_upload ON upload_grants(upload_id);
```

This SQL goes both in `schema.go` and as the `sql` of migration `{8, "upload_grants", <same SQL>}`, following the migration 3 / audit_log pattern. Emails are stored lowercased and trimmed.

`internal/models/models.go`:
- `UploadVisibilityRestricted = "restricted"`.
- `UploadGrantUser = "user"`.
- `UploadGrantGroup = "group"`.
- New type:

```go
type UploadGrant struct {
	ID                 int64
	UploadID           int64
	Kind               string // UploadGrantUser or UploadGrantGroup
	Email              string // lowercased
	CreatedByAccountID int64
	CreatedAt          time.Time
}
```

New file `internal/db/grants.go`:
- `func (s *Store) AddUploadGrant(ctx context.Context, uploadID int64, kind, email string, createdBy int64) (*models.UploadGrant, error)` runs `INSERT ... ON CONFLICT(upload_id,kind,email) DO NOTHING`, then selects the row, so it is idempotent and returns the existing row on a duplicate.
- `func (s *Store) RemoveUploadGrant(ctx context.Context, uploadID int64, kind, email string) error` returns `sql.ErrNoRows` when nothing was deleted.
- `func (s *Store) ListUploadGrants(ctx context.Context, uploadID int64) ([]models.UploadGrant, error)` is ordered by `kind, email`.

The db layer lowercases and trims `email` itself, and it does not validate the address format (the server does).

### 3.9 Grants: access rule

New file `internal/server/access.go`:

```go
// GroupChecker reports whether userEmail is a (direct or nested) member of groupEmail.
type GroupChecker interface {
	IsMember(ctx context.Context, groupEmail, userEmail string) (bool, error)
}

func (s *Server) accountCanViewRestricted(ctx context.Context, a *models.Account, u *models.Upload) bool
```

`Server` gains the field `groups GroupChecker`. It is nil until phase p7 wires it.

Rule, in order:
1. If `a.IsAdmin || a.ID == u.OwnerAccountID`, return true.
2. Take `email := strings.ToLower(strings.TrimSpace(a.Email))`. If it is empty, return false.
3. Run `ListUploadGrants`. On a DB error, call `slog.Error("grant lookup failed", ...)` and return false.
4. Any user grant whose email equals `email` returns true.
5. If `s.groups != nil`, check each group grant in list order with `s.groups.IsMember(ctx, g.Email, email)`. A true result returns true. An error is logged with `slog.Warn("group membership check failed", "group", g.Email, "err", err)` and the loop continues, so it fails closed for that group.
6. Return false.

Grants are stored for any visibility but are only enforced when the visibility is `restricted`.

`viewerCanAccessUpload` (`internal/server/comments.go`) gains this case: `case models.UploadVisibilityRestricted: a, ok := s.webAuth(r); return ok && s.accountCanViewRestricted(r.Context(), a, u)`.

`uploadAccessRequiredMessage` returns `"access denied"` for `restricted`.

The comment and view APIs use status 403 instead of 401 when the visibility is `restricted` and `webAuth` succeeded. Add the helper `func (s *Server) uploadAccessStatus(r *http.Request, u *models.Upload) int`, which returns 403 for `restricted` with a valid web session and 401 otherwise, and use it in the three call sites that currently hardcode `http.StatusUnauthorized` after `viewerCanAccessUpload`:
- `handleListComments`
- `handleAddComment`
- `handleViews` in `api_stats.go`

`servePage` (pages.go), restricted branch:
- If there is no valid `webAuth`, behave exactly like private: set the next path, clear the stale session cookie, and redirect to `/login`.
- If there is a session but `accountCanViewRestricted` is false, render `s.renderWebError(w, http.StatusForbidden, "Access denied", "You are signed in as "+a.Email+", which has not been given access to this page. Ask the page owner to share it with you.")`. Write the audit entry `s.auditRequest(r, a.Email, "page.access.denied", "slug="+u.Slug)`.

`uploads.Service.Create` and `handleSetVisibility` accept `restricted` exactly like `private`, with no password allowed. The error text in both places becomes `visibility must be public, password, private, or restricted`.

Raw objects stay protected by the view token, which is bound to the subject, the visitor and a 1 hour TTL and is only minted after the access check. Revoking a grant therefore takes effect on the next `/p` load, and an already-open iframe can keep reading for at most 1 hour. That is accepted, and it is documented in `docs/operations.md`.

### 3.10 Grants: API, CLI, dashboard

New file `internal/server/api_grants.go`. Routes go in `routes.go`, all `s.authToken(...)`, and all require the page owner or an admin (403 `not owner`; 404 `not found` for a missing page):
- `GET /api/uploads/{slug}/grants` → `[{"id":..,"kind":"user|group","email":..,"created_at":unix}]`.
- `POST /api/uploads/{slug}/grants` with body `{"kind":"user|group","email":"..."}` (decode with `decodeJSON(..., smallJSONBodyLimit)`).
  - Validation:
    - `kind` must be `user` or `group`, else 400 `kind must be user or group`.
    - `email` is trimmed and lowercased, and must parse with `net/mail.ParseAddress` such that `addr.Address == email` and `len(email) <= 254`, else 400 `invalid email address`.
    - When `kind == "group" && s.groups == nil`, return 400 `group grants need Google group lookup; set PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL on the server`.
  - On success the response is the grant object and the audit entry is `upload.grant.add` with detail `slug=<slug> kind=<kind> email=<email>`.
- `DELETE /api/uploads/{slug}/grants` with the same body. It returns 404 `grant not found` on `sql.ErrNoRows`, otherwise `{"removed":true}`, and the audit entry is `upload.grant.remove`.

`handleExportUpload` adds `"grants": [{kind,email,created_at}]`.

New file `internal/cli/grants_command.go`, registered in `commands.go`:
- `peek grant <slug> <email> [--group]` posts `{"kind":"user"|"group","email":...}` and prints `granted <kind> <email> on <slug>`.
- `peek revoke <slug> <email> [--group]` sends a DELETE with the same body and prints `revoked <kind> <email> on <slug>`.
- `peek grants <slug>` prints one tabwriter line per grant: `<kind>\t<email>\t<created_at RFC3339>`. When there are none it prints `no grants`.

For DELETE with a JSON body, use the existing client request helper (`c.req`) with `application/json`.

Visibility literals:
- `validVisibility` in `internal/cli/upload_command.go` accepts `restricted`.
- `cmdVisibility`'s usage and error in `internal/cli/uploads_command.go` become `public|private|password|restricted` and `visibility must be public, password, private, or restricted`.
- The usage block in `commands.go` gains `peek upload <file.html> --visibility restricted`, `peek visibility <slug> restricted`, and the three grant commands.

Dashboard (`internal/web/templates/dashboard.gohtml:57-58`): add a fourth radio label, a copy of the private one with `value="restricted"`, `visibility === 'restricted'` and the text `Restricted`. Grant management stays in the CLI and API; dashboard grant editing is out of scope.

### 3.11 Google group membership

New package `internal/groups` with file `internal/groups/directory.go`:

```go
package groups

const (
	DirectoryScope  = "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
	DefaultBaseURL  = "https://admin.googleapis.com"
	DefaultCacheTTL = 5 * time.Minute
	maxCacheEntries = 10000
	requestTimeout  = 5 * time.Second
)

type Directory struct {
	client  *http.Client
	baseURL string
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	cache   map[string]cacheEntry // key: lower(group) + "|" + lower(user)
}

type cacheEntry struct {
	member  bool
	expires time.Time
}

// NewDirectory builds a Directory that authenticates as the service account in keyJSON,
// impersonating adminEmail through domain-wide delegation.
func NewDirectory(keyJSON []byte, adminEmail string, ttl time.Duration) (*Directory, error)

func newDirectoryWithClient(client *http.Client, baseURL string, ttl time.Duration, now func() time.Time) *Directory

func (d *Directory) IsMember(ctx context.Context, groupEmail, userEmail string) (bool, error)
```

`NewDirectory`:
- `cfg, err := google.JWTConfigFromJSON(keyJSON, DirectoryScope)`, wrapping any error as `parse google service account key: %w`.
- `cfg.Subject = adminEmail`.
- `client := cfg.Client(context.Background())`.
- Then `newDirectoryWithClient(client, DefaultBaseURL, ttl, time.Now)`.

`IsMember`:
1. Lowercase and trim both emails, and build the cache key.
2. Under `mu`, a non-expired entry is returned.
3. Otherwise `GET baseURL + "/admin/directory/v1/groups/" + url.PathEscape(group) + "/hasMember/" + url.PathEscape(user)`, with `context.WithTimeout(ctx, requestTimeout)`.
4. Map the response status:
   - **200:** decode `{"isMember": bool}` from at most 64 KiB (`io.LimitReader`), then cache and return it.
   - **404** (the group does not exist) and **400** (for example, the user is outside the Workspace domain, so it cannot be a member): cache `false`, return `false, nil`. Log 400 once per call with `slog.Info("group membership lookup rejected", "group", group, "status", 400)`.
   - **Any other status or a transport error:** return `false, fmt.Errorf("directory hasMember %s: status %d", group, code)` (or the transport error) and do not cache.
5. Before inserting into the cache, if `len(cache) >= maxCacheEntries`, delete expired entries. If it is still full, replace the cache with an empty map.

`hasMember` reports direct and nested membership for groups and users in the same Workspace, which is the intended semantics.

Startup config (`internal/peekd/run.go`), new flags following the existing pattern:
- `--google-sa-key-file` (env `PEEK_GOOGLE_SA_KEY_FILE`, default "") is the path to the service account JSON key.
- `--google-admin-email` (env `PEEK_GOOGLE_ADMIN_EMAIL`, default "") is the Workspace admin user to impersonate.
- `--google-group-cache-ttl` (env `PEEK_GOOGLE_GROUP_CACHE_TTL`, default `5m`) is parsed with `time.ParseDuration`.

Validation in `parseServeConfig`, with these exact errors:
- `PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL must be set together`
- `google group cache ttl must be between 1s and 1h`
- `invalid PEEK_GOOGLE_GROUP_CACHE_TTL: <err>`

`serveConfig` gains `GoogleSAKeyFile`, `GoogleAdminEmail` and `GoogleGroupCacheTTL`. In the function that builds `server.Config` (around `run.go:187`), when the key file is set:
1. `os.ReadFile` it, failing with `read google service account key: %w`.
2. Call `groups.NewDirectory`, returning its error.
3. Set `server.Config.Groups`.
4. Log `slog.Info("google group lookup enabled", "admin_email", ..., "cache_ttl", ...)`.

`server.Config` gains `Groups GroupChecker`, and `New` copies it into `s.groups`. Keeping a `nil` interface when unset matters: assign it only when non-nil, so `s.groups == nil` checks work.

The key lives in a file on the server host, not in the settings DB. That keeps the private key out of SQLite backups and the dashboard, matches how deployments mount secrets, and rotating it means replacing the file and restarting. The rejected alternative was an encrypted runtime setting, like `s3_secret_key`, which would put the key in every DB backup and needs a multi-line input in the dashboard.

`internal/architecture_test.go` adds a rule: `github.com/puemos/peek/internal/groups` must not import `internal/db`, `internal/server`, `internal/uploads`, `internal/web`, `internal/cli` or `internal/objectstore`. `internal/server` must not import `internal/groups`; peekd wires it through the interface.

### 3.12 Out of scope

Dashboard grant editing, dashboard re-upload, per-version visit stats in the dashboard, and auto-pruning by version count are out of scope. So are group providers other than Google, and `/raw` re-checking grants per request (see 3.9).

## Manual steps

There are no `manual_before` steps. Every phase builds against fakes: an `httptest` Directory server for groups and the existing in-process test app for everything else.

`manual_after` has two items: setting up a Google Workspace service account with domain-wide delegation for the read-only group-member scope, then verifying real group grants and the version flow on a running server. The step-by-step page is the artifact linked in the manifest (`manual_steps_artifact`); its source is `docs/plans/page-grants-versions-plan-manual-steps.html`.

## Risks and open questions

- **Migration ordering on very old databases.** `migrateUploadsOwner` runs after `runMigrations` and rebuilds `uploads` with foreign keys off. The 3.1 backfill avoids `owner_account_id`, and upload ids are preserved by the rebuild. If a p1 worker finds `upload_versions` rows orphaned after `migrateUploadsOwner` in `TestMigrationBackfillsUploadVersions`, the brief is wrong: stop with `status=blocked`.
- **Changed store signatures.** `AddComment`, `ListComments` and `RecordVisit` change signature in p1, and p1 updates their callers to keep the build green. If `go build ./...` shows callers outside the listed `touches`, stop with `status=blocked` and list them.
- **Tailwind classes.** The version banner and the restricted radio reuse existing classes. If a worker needs a class not already in `internal/web/assets/pines.css` (`grep -c 'class-name' internal/web/assets/pines.css` returns 0), run `mise run tailwind` and commit the regenerated CSS. If the Tailwind download is blocked, stop with `status=blocked`.
- **View-token subject change.** Old `/raw/<slug>` tokens keep working for up to 1 hour through the legacy route, which serves the latest version.
- **The 400 mapping is an assumption.** Treating a Directory API 400 as "not a member" is based on documented behaviour for members outside the domain. The manual-after check covers it with a real external address.
- **`pages.yml` deploys the docs site.** It is listed in `.claude/toolkit.yaml` as dispatchable, but dispatching it runs its `deploy` job and publishes the branch's docs to GitHub Pages. No phase dispatches it. The retirement phase checks markdown edits only.

## Implementation manifest

```yaml
plan_slug: page-grants-versions
feature_branch: feat/page-grants-versions
max_parallel: 2
manual_steps_artifact: https://claude.ai/artifact/DCcUdxgMWd6FcMc7SqoTX5
manual_steps_source: docs/plans/page-grants-versions-plan-manual-steps.html
manual_before: []
manual_after:
  - id: ma1-google-dwd-setup
    title: Create a service account with domain-wide delegation for the Directory API and configure peekd with it
    why: The Directory API call, JWT impersonation and real Workspace groups cannot be exercised in CI; every phase uses an httptest fake.
  - id: ma2-verify-grants-groups-versions
    title: On a running server, verify user grants, a group grant (member, non-member, nested member, external address) and the version URLs
    why: Confirms end-to-end behaviour against real Google Workspace data and a real browser, including the 5 minute cache and the 400/404 mappings.
verify_after_merge:
  - mise run vet
  - mise run test
  - go test -race -count=1 ./internal/db/... ./internal/server/... ./internal/groups/... ./internal/uploads/...
final_checks:
  - docs/plans/page-grants-versions-plan.md and docs/plans/page-grants-versions-plan-manual-steps.html are deleted and nothing links to them (grep -rn "page-grants-versions-plan" . returns nothing outside .git)
  - mise run check-full passes
  - docs/architecture.md lists internal/groups and its dependency rule; docs/operations.md documents restricted visibility, grants, versions, retention of versions, and the PEEK_GOOGLE_* settings
phases:
  - id: p1-versions-store
    title: upload_versions table, migration 7, version-aware store API and object keys
    depends_on: []
    complexity: M
    touches:
      - internal/models/models.go
      - internal/db/schema.go
      - internal/db/migrations.go
      - internal/db/uploads.go
      - internal/db/versions.go
      - internal/db/comments.go
      - internal/db/visits.go
      - internal/db/store_test.go
      - internal/db/versions_test.go
      - internal/objectstore/slug.go
      - internal/objectstore/file.go
      - internal/objectstore/storage_test.go
      - internal/server/comments.go
      - internal/server/analytics.go
      - internal/server/api_stats.go
    brief: |
      Read AGENTS.md, CONTRIBUTING.md, docs/architecture.md, docs/operations.md, then the plan sections 3.1, 3.2 and 3.3 (docs/plans/page-grants-versions-plan.md). They give every name, signature and SQL statement; do not invent others.
      1. internal/models/models.go: add Upload.LatestVersion, Comment.Version, Visit.Version and the UploadVersion type exactly as in 3.3.
      2. internal/db/schema.go: add the upload_versions CREATE TABLE from 3.1, and add `version INTEGER NOT NULL DEFAULT 1` to the comments and visits CREATE TABLE statements. Add no index on the new columns.
      3. internal/db/migrations.go: add `{7, "upload_versions", ""}` to `migrations`, a `migrateUploadVersions` method doing the four steps in 3.1, and an `else if m.id == 7` branch calling it, copying the shape of the id 6 branch.
      4. internal/db/uploads.go: introduce `const uploadSelect` and `scanUpload` (3.3), and rewrite GetUpload, GetUploadByID, ListUploadsByOwner, ListAllUploads and ListUploadsOlderThan to use them. ListUploadsOlderThan gets the latest-version WHERE clause. Change the quota queries in CreateUploadChecked and the bodies of SumUploadSizes and SumUploadSizesByOwner to the version sums, and insert the version-1 row inside CreateUploadChecked's transaction.
      5. New file internal/db/versions.go: CreateVersionChecked, GetUploadVersion, ListUploadVersions, ListPrunableVersions and DeleteUploadVersion, as specified in 3.3.
      6. internal/db/comments.go and internal/db/visits.go: the new AddComment, ListComments and RecordVisit signatures, and the scans of version (3.3).
      7. internal/objectstore/slug.go: objectName accepts `versions/<slug>/<16 hex>` (3.2). internal/objectstore/file.go: Save runs MkdirAll on filepath.Dir(path).
      8. Keep the build green with minimal caller updates:
         - internal/server/comments.go: AddComment and ListComments pass u.LatestVersion.
         - internal/server/analytics.go: add `Version int` to visitEvent, set it from u.LatestVersion in recordVisit (keep recordVisit's current parameters in this phase), and pass ev.Version to RecordVisit.
         - internal/server/api_stats.go: handleExportUpload calls ListComments(ctx, u.ID, 0).
      9. Tests:
         - New internal/db/versions_test.go, using the helpers already in internal/db/store_test.go:
           - TestCreateUploadCheckedCreatesVersionOne
           - TestCreateVersionCheckedAllocatesSequentialVersions (creates v2 and v3, and checks that uploads.size equals v3's size and GetUpload().LatestVersion == 3)
           - TestCreateVersionCheckedEnforcesOwnerStorageQuota (the quota is the page owner's even when the actor is a different account)
           - TestCreateVersionCheckedEnforcesTotalQuota
           - TestListPrunableVersionsSkipsLatest
           - TestDeleteUploadVersionRemovesItsComments
           - TestListUploadsOlderThanUsesLatestVersion
           - TestMigrationBackfillsUploadVersions (create a DB file, insert an uploads row with no version row and remove the schema_migrations row for id 7, reopen with db.Open, and assert there is exactly one version row with object_key == slug and version == 1)
           - TestListCommentsFiltersByVersion (0 returns all)
         - internal/objectstore/storage_test.go: TestObjectNameAcceptsVersionKeys (valid version key, rejects `versions/x/ABC`, `versions/../x/0123456789abcdef`, and a 15-hex suffix) and TestFileStorageSavesVersionKeyInSubdirectory.
         - Update existing tests broken by the signature changes.
      10. Run `mise run fmt-check`, `mise run vet` and `mise run test`.
      Stop condition: if `go build ./...` fails in any file not listed in `touches`, stop with status=blocked and list the files. Do not widen the phase.
    acceptance:
      - go test ./internal/db/ -run 'TestCreateUploadCheckedCreatesVersionOne|TestCreateVersionChecked|TestListPrunableVersionsSkipsLatest|TestDeleteUploadVersionRemovesItsComments|TestListUploadsOlderThanUsesLatestVersion|TestMigrationBackfillsUploadVersions|TestListCommentsFiltersByVersion' -v passes and runs each named test
      - go test ./internal/objectstore/ -run 'TestObjectNameAcceptsVersionKeys|TestFileStorageSavesVersionKeyInSubdirectory' -v passes
      - grep -c 'FROM uploads u JOIN accounts a' internal/db/uploads.go prints 1
      - mise run vet and mise run test pass

  - id: p2-versions-upload
    title: Re-upload by slug creates a version; delete and retention handle all versions
    depends_on: [p1-versions-store]
    complexity: M
    touches:
      - internal/uploads/service.go
      - internal/uploads/slug.go
      - internal/uploads/service_test.go
      - internal/server/api_uploads.go
      - internal/server/upload_delete.go
      - internal/server/lifecycle.go
      - internal/server/upload_versions_test.go
      - internal/server/lifecycle_test.go
      - internal/cli/upload_command.go
      - internal/cli/upload_command_test.go
    brief: |
      Read the must-read docs (AGENTS.md, CONTRIBUTING.md, docs/architecture.md, docs/operations.md) and plan sections 3.2, 3.4, 3.5 and 3.7 (the upload part only).
      1. internal/uploads/slug.go: add `versionObjectKey(slug string) (string, error)`, returning "versions/" + slug + "/" + hex.EncodeToString(8 random bytes from crypto/rand).
      2. internal/uploads/service.go: extend Repository with CreateVersionChecked, add AddVersionInput, AddVersionResult and Service.AddVersion exactly as in 3.4, and add `Version: 1` to CreateResult.
      3. internal/server/api_uploads.go: implement the `slug` branch of handleUpload and the new uploadResp fields (3.4). Do not add routes; routes.go belongs to p3.
      4. internal/server/upload_delete.go: delete every version object (3.5). internal/server/lifecycle.go: add the version-prune pass to cleanupExpired (3.5).
      5. internal/cli/upload_command.go: add the `--slug` flag, its validation, the multipart change and the output lines (3.7). Use the usage string without `restricted`. Do not edit internal/cli/commands.go (p3 owns the usage block).
      6. Tests:
         - internal/uploads/service_test.go: extend the fake repository with CreateVersionChecked, and add TestAddVersionStoresUnderVersionKey (the saved key matches `^versions/<slug>/[0-9a-f]{16}$`) and TestAddVersionCleansUpObjectOnRepositoryError.
         - New internal/server/upload_versions_test.go, `package server`, using `newTestServer(t)` from internal/server/oauth_test.go and `httptest` against `s.Handler()` (copy the request style of internal/server/pages_test.go):
           - TestUploadWithSlugCreatesNextVersion (version 2 in the response; GET /api/uploads lists size == second upload's size)
           - TestUploadWithSlugRejectsVisibility (400 with the exact 3.4 message)
           - TestUploadWithSlugRequiresOwner (403 `not owner`; an admin token succeeds)
           - TestUploadWithUnknownSlugReturns404
           - TestDeleteUploadRemovesAllVersionObjects (after delete, storage.Open on each version key fails)
         - internal/server/lifecycle_test.go: TestRetentionPrunesOldVersionsButKeepsLatest (set created_at on rows via direct SQL on the test store, as existing lifecycle tests do).
         - internal/cli/upload_command_test.go: TestUploadWithSlugSendsSlugAndNoVisibility and TestUploadWithSlugRejectsVisibilityFlag.
      7. Run `mise run fmt-check`, `mise run vet`, `mise run test` and `mise run race`.
      Stop condition: if the existing lifecycle tests cannot age rows without a new store method, stop with status=blocked rather than adding one to internal/db.
    acceptance:
      - go test ./internal/uploads/ -run 'TestAddVersion' -v passes
      - go test ./internal/server/ -run 'TestUploadWithSlug|TestUploadWithUnknownSlugReturns404|TestDeleteUploadRemovesAllVersionObjects|TestRetentionPrunesOldVersionsButKeepsLatest' -v passes
      - go test ./internal/cli/ -run 'TestUploadWithSlug' -v passes
      - mise run race passes

  - id: p3-versions-view
    title: /p/<slug>/v/<n>, versioned raw URLs, per-version comments, versions API and CLI
    depends_on: [p1-versions-store]
    complexity: M
    touches:
      - internal/server/routes.go
      - internal/server/pages.go
      - internal/server/security.go
      - internal/server/comments.go
      - internal/server/analytics.go
      - internal/server/api_stats.go
      - internal/server/api_versions.go
      - internal/server/pages_test.go
      - internal/server/page_versions_test.go
      - internal/server/web_dashboard.go
      - internal/web/renderer.go
      - internal/web/templates/page.gohtml
      - internal/web/templates/gate.gohtml
      - internal/web/assets/app.js
      - internal/web/renderer_test.go
      - internal/cli/commands.go
      - internal/cli/uploads_command.go
      - internal/cli/stats_comments_command.go
      - internal/cli/commands_test.go
      - internal/cli/uploads_command_requests_test.go
    brief: |
      Read the must-read docs and plan sections 3.6 and 3.7. Section 3.6 has the exact routes, handler names, helper signatures, template snippet and JS changes.
      This phase runs in parallel with p2. It must not touch internal/server/api_uploads.go, upload_delete.go, lifecycle.go, internal/uploads or internal/cli/upload_command.go. New server tests are `package server` and use `newTestServer(t)` (internal/server/oauth_test.go) with `httptest` against `s.Handler()`, copying the style of internal/server/pages_test.go. To create version 2 in tests, call `s.storage.Save(ctx, "versions/<slug>/0123456789abcdef", data)` and then `s.store.CreateVersionChecked(...)` directly.
      1. internal/server/security.go: add viewSubject.
      2. internal/server/pages.go:
         - Factor servePage and serveRawObject out.
         - Add handlePageVersion and handleRawVersion.
         - Make handlePagePassword version-aware.
         - Make the legacy handleRaw serve the latest version's ObjectKey.
         Every GateData construction (pages.go and anywhere else `grep -rn 'GateData{' internal/` finds) sets Action.
      3. internal/server/analytics.go: recordVisit takes `version int` and uses it instead of u.LatestVersion.
      4. internal/server/comments.go: add commentVersion, use `?v=` in list and add, and add Version to commentOut.
      5. internal/server/api_stats.go: export gains comment and visit version, latest_version and versions (3.6).
      6. New internal/server/api_versions.go: handleListVersions. internal/server/routes.go: the four routes from 3.6.
      7. internal/server/web_dashboard.go: only if it constructs GateData or calls recordVisit; otherwise leave it untouched.
      8. internal/web/renderer.go: PageData.Version and LatestVersion, GateData.Action. Update gate.gohtml and page.gohtml exactly as in 3.6 (the banner uses only the listed classes).
      9. internal/web/assets/app.js: the version state and the `?v=` query on both comment fetches.
      10. CLI: cmdVersions in internal/cli/uploads_command.go, `--version` in cmdComments, and the command switch and usage lines in internal/cli/commands.go (3.7), including the `peek upload <file.html> --slug <slug>` usage line.
      11. Tests:
          - New internal/server/page_versions_test.go:
            - TestPageVersionServesRequestedVersion (fetch /p/<slug>/v/1 and /p/<slug>/v/2, follow the iframe src from the HTML to /raw/<slug>/v/<n>, and assert each body contains its own marker text)
            - TestPageLatestServesNewestVersion
            - TestPageVersionNotFound (v/0, v/abc, v/99 → 404 with "Version not found")
            - TestRawVersionRejectsTokenForOtherVersion (a token minted for v1 used on /raw/<slug>/v/2 → 403)
            - TestLegacyRawRouteServesLatest
            - TestCommentsArePerVersion (POST to ?v=1 and ?v=2, GET each returns only its own; GET without v returns latest)
            - TestPasswordGateOnVersionRedirectsToVersion
            - TestListVersionsAPI (owner OK, non-owner 403)
            - TestVersionBannerOnlyOnOlderVersions (body contains `hn-version-banner` on v1 and not on latest)
          - internal/web/renderer_test.go: extend existing page/gate render tests for the new fields.
          - CLI: TestVersionsCommandRequestsVersions and TestCommentsVersionFlag in the existing CLI request-test files.
      12. Run `mise run fmt-check`, `mise run vet`, `mise run test` and `mise run race`.
      Stop condition: if `grep -c 'z-\[1200\]' internal/web/assets/pines.css` prints 0, the banner classes are not available. Stop with status=blocked instead of regenerating CSS.
    acceptance:
      - go test ./internal/server/ -run 'TestPageVersion|TestPageLatestServesNewestVersion|TestRawVersionRejectsTokenForOtherVersion|TestLegacyRawRouteServesLatest|TestCommentsArePerVersion|TestPasswordGateOnVersionRedirectsToVersion|TestListVersionsAPI|TestVersionBannerOnlyOnOlderVersions' -v passes
      - go test ./internal/web/ ./internal/cli/ passes
      - grep -n 'GET /p/{slug}/v/{n}' internal/server/routes.go prints one line
      - grep -c '?v=' internal/web/assets/app.js prints at least 1
      - mise run race passes

  - id: p4-grants-store
    title: upload_grants table, migration 8, grant store API and models
    depends_on: [p1-versions-store]
    complexity: S
    touches:
      - internal/models/models.go
      - internal/db/schema.go
      - internal/db/migrations.go
      - internal/db/grants.go
      - internal/db/grants_test.go
    brief: |
      Read the must-read docs and plan section 3.8.
      1. internal/models/models.go: add UploadVisibilityRestricted, UploadGrantUser, UploadGrantGroup and the UploadGrant type (3.8).
      2. internal/db/schema.go: append the upload_grants table and index SQL from 3.8.
      3. internal/db/migrations.go: add `{8, "upload_grants", <the same SQL>}` to `migrations`. The generic `m.sql != ""` branch runs it; add no special branch.
      4. New internal/db/grants.go: AddUploadGrant, RemoveUploadGrant and ListUploadGrants (3.8).
      5. New internal/db/grants_test.go:
         - TestAddUploadGrantIsIdempotentAndLowercases ("Alice@Example.com" twice → one row, email "alice@example.com")
         - TestRemoveUploadGrantMissingReturnsErrNoRows
         - TestListUploadGrantsOrdersByKindThenEmail
         - TestGrantsCascadeOnUploadDelete
         - TestGrantKindCheckConstraint (kind "team" → error)
      6. Run `mise run fmt-check`, `mise run vet` and `mise run test`.
    acceptance:
      - go test ./internal/db/ -run 'TestAddUploadGrant|TestRemoveUploadGrant|TestListUploadGrants|TestGrantsCascadeOnUploadDelete|TestGrantKindCheckConstraint' -v passes
      - grep -n '{8, "upload_grants"' internal/db/migrations.go prints one line

  - id: p5-grants-access
    title: restricted visibility enforced on page views, comments and views API
    depends_on: [p2-versions-upload, p3-versions-view, p4-grants-store]
    complexity: M
    touches:
      - internal/uploads/service.go
      - internal/uploads/service_test.go
      - internal/server/access.go
      - internal/server/access_test.go
      - internal/server/server.go
      - internal/server/comments.go
      - internal/server/pages.go
      - internal/server/api_stats.go
      - internal/server/api_uploads.go
      - internal/server/visibility_e2e_test.go
    brief: |
      Read the must-read docs and plan section 3.9 (the access rule, the exact messages and status codes).
      1. internal/server/access.go (new): the GroupChecker interface and accountCanViewRestricted, implementing the rule in 3.9 in the stated order.
      2. internal/server/server.go: add the `groups GroupChecker` field to Server. Do not add a Config field; p7 does that.
      3. internal/server/comments.go: add the restricted case to viewerCanAccessUpload, change uploadAccessRequiredMessage, and add uploadAccessStatus. Use uploadAccessStatus in handleListComments and handleAddComment. internal/server/api_stats.go: use it in handleViews.
      4. internal/server/pages.go: the restricted branch of servePage (redirect, or 403 page plus the `page.access.denied` audit entry), with the exact strings from 3.9.
      5. internal/uploads/service.go and internal/server/api_uploads.go (handleSetVisibility): accept `restricted` like `private`, with the new error text.
      6. Tests:
         - New internal/server/access_test.go, `package server`, using `newTestServer(t)` (internal/server/oauth_test.go) and `httptest` against `s.Handler()`, with a `fakeGroups` type implementing GroupChecker (a map plus an error to return) assigned directly to `s.groups`:
           - TestRestrictedOwnerAndAdminCanView
           - TestRestrictedUserGrantAllowsView (grant "Bob@Example.com" matches account email "bob@example.com")
           - TestRestrictedWithoutGrantGets403Page (status 403, body contains "Access denied", audit log has page.access.denied)
           - TestRestrictedAnonymousRedirectsToLogin
           - TestRestrictedGroupGrantUsesChecker
           - TestRestrictedGroupCheckerErrorFailsClosed
           - TestRestrictedGroupGrantIgnoredWhenNoChecker
           - TestRestrictedCommentsAPIReturns403ForSignedInNonGrantee
           - TestRestrictedAccountWithoutEmailDenied
           - TestGrantsNotEnforcedOnPrivate (a private page with a grant for someone else still opens for any signed-in account)
         - internal/server/visibility_e2e_test.go: extend TestUploadVisibilityE2E with a restricted upload and a visibility switch to restricted.
         - internal/uploads/service_test.go: TestCreateAcceptsRestrictedWithoutPassword and TestCreateRejectsRestrictedWithPassword.
      7. Run `mise run fmt-check`, `mise run vet`, `mise run test` and `mise run race`.
      Stop condition: if webAuth's behaviour (internal/server/web_auth.go) would need to change to make these tests pass, stop with status=blocked; this phase must not change login rules.
    acceptance:
      - go test ./internal/server/ -run 'TestRestricted|TestGrantsNotEnforcedOnPrivate|TestUploadVisibilityE2E' -v passes
      - go test ./internal/uploads/ -run 'TestCreateAcceptsRestrictedWithoutPassword|TestCreateRejectsRestrictedWithPassword' -v passes
      - grep -rn 'visibility must be public, password, private, or restricted' internal/uploads/service.go internal/server/api_uploads.go prints two lines
      - mise run race passes

  - id: p6-grants-api-cli
    title: Grants API, peek grant/revoke/grants, restricted in CLI and dashboard
    depends_on: [p5-grants-access]
    complexity: M
    touches:
      - internal/server/api_grants.go
      - internal/server/api_grants_test.go
      - internal/server/routes.go
      - internal/server/api_stats.go
      - internal/cli/grants_command.go
      - internal/cli/grants_command_test.go
      - internal/cli/commands.go
      - internal/cli/upload_command.go
      - internal/cli/uploads_command.go
      - internal/cli/command_validation_test.go
      - internal/web/templates/dashboard.gohtml
      - internal/server/web_dashboard_test.go
    brief: |
      Read the must-read docs and plan section 3.10.
      1. New internal/server/api_grants.go: handleListGrants, handleAddGrant and handleRemoveGrant, with the validation, messages, audit actions and response shapes from 3.10. Register the three routes in internal/server/routes.go.
      2. internal/server/api_stats.go: add `grants` to the export.
      3. New internal/cli/grants_command.go: cmdGrant, cmdRevoke and cmdGrants. Register `grant`, `revoke` and `grants` in the internal/cli/commands.go switch, and add the usage lines from 3.10.
      4. internal/cli/upload_command.go and internal/cli/uploads_command.go: accept `restricted` (validVisibility, usage and error texts per 3.7 and 3.10).
      5. internal/web/templates/dashboard.gohtml: the Restricted radio (3.10), a copy of the Private label with only the value, the x-model comparison and the text changed.
      6. Tests:
         - New internal/server/api_grants_test.go, `package server`, using `newTestServer(t)` and `httptest` against `s.Handler()` (set `s.groups` to a small fake for the checker case):
           - TestGrantsAPIAddListRemove
           - TestGrantsAPIRequiresOwnerOrAdmin
           - TestGrantsAPIRejectsInvalidEmail (cases: "bob", "Bob <bob@example.com>", 255-char address)
           - TestGrantsAPIRejectsGroupWithoutChecker (exact 3.10 message)
           - TestGrantsAPIAcceptsGroupWithChecker
           - TestGrantsAPIRemoveMissing404
           - TestGrantsAPIWritesAuditLog
         - New internal/cli/grants_command_test.go, following the request-capture pattern in internal/cli/uploads_command_requests_test.go: TestGrantCommandPostsUserGrant, TestGrantCommandGroupFlag and TestRevokeCommandSendsDelete.
         - internal/cli/command_validation_test.go: restricted accepted by upload and visibility.
         - internal/server/web_dashboard_test.go: the dashboard HTML contains `value="restricted"`.
      7. Run `mise run fmt-check`, `mise run vet` and `mise run test`.
    acceptance:
      - go test ./internal/server/ -run 'TestGrantsAPI' -v passes
      - go test ./internal/cli/ -run 'TestGrantCommand|TestRevokeCommand' -v passes
      - grep -c 'value="restricted"' internal/web/templates/dashboard.gohtml prints 1
      - mise run test passes

  - id: p7-google-groups
    title: Google Directory hasMember checker with cache, wired through peekd flags
    depends_on: [p5-grants-access]
    complexity: M
    touches:
      - internal/groups/directory.go
      - internal/groups/directory_test.go
      - internal/peekd/run.go
      - internal/peekd/run_test.go
      - internal/server/server.go
      - internal/architecture_test.go
    brief: |
      Read the must-read docs and plan section 3.11 (constants, signatures, the status mapping, cache rules, flags and exact error strings). Add no new Go modules: `golang.org/x/oauth2/google` is already required in go.mod. Running `go mod tidy` must leave go.mod unchanged apart from possibly moving nothing; if it adds a requirement, stop with status=blocked.
      1. New internal/groups/directory.go: Directory, NewDirectory, newDirectoryWithClient and IsMember, exactly as in 3.11.
      2. internal/server/server.go: add `Groups GroupChecker` to Config, and in New set `srv.groups = cfg.Groups` only when `cfg.Groups != nil`.
      3. internal/peekd/run.go: the three flags and env vars, the validation errors, the serveConfig fields, and building the Directory where server.Config is built (3.11).
      4. internal/architecture_test.go: add the internal/groups rule and the internal/server-must-not-import-internal/groups rule (3.11).
      5. Tests:
         - New internal/groups/directory_test.go, using httptest.NewServer and newDirectoryWithClient with a controllable `now`:
           - TestIsMemberTrueAndCached (two calls, one HTTP request)
           - TestIsMemberCacheExpires (advance now past ttl → second request)
           - TestIsMember404IsFalseAndCached
           - TestIsMember400IsFalse
           - TestIsMember500IsErrorAndNotCached
           - TestIsMemberEscapesPathAndLowercases (assert r.URL.EscapedPath() == "/admin/directory/v1/groups/eng%2Bteam@example.com/hasMember/bob@example.com" for inputs "Eng+Team@Example.com", "Bob@Example.com"; adjust only the escaping assertion to url.PathEscape's real output)
           - TestCacheBoundedAtMaxEntries
           - TestNewDirectoryRejectsInvalidKey (keyJSON `{}` → error containing "parse google service account key")
         - internal/peekd/run_test.go: TestParseServeConfigGoogleFlagsMustBeSetTogether, TestParseServeConfigGoogleCacheTTLBounds and TestParseServeConfigGoogleDefaults (TTL 5m).
      6. Run `mise run fmt-check`, `mise run vet`, `mise run test` and `mise run race`.
      Stop condition: if google.JWTConfigFromJSON is not available from the existing golang.org/x/oauth2 version, stop with status=blocked.
    acceptance:
      - go test ./internal/groups/ -v passes and runs every test named in the brief
      - go test ./internal/peekd/ -run 'TestParseServeConfigGoogle' -v passes
      - go test ./internal/ -run TestInternalPackageDependencyDirection passes
      - git diff origin/main -- go.mod shows no added require lines
      - mise run race passes

  - id: p8-docs-retire
    title: Document grants, groups and versions; delete the plan
    depends_on: [p6-grants-api-cli, p7-google-groups]
    complexity: S
    touches:
      - docs/architecture.md
      - docs/operations.md
      - README.md
      - docs/src/content/docs/auth-access.md
      - docs/src/content/docs/using-peek.md
      - docs/src/content/docs/reference.md
      - docs/src/content/docs/storage-retention.md
      - docs/src/content/docs/server-setup.md
      - docs/plans/page-grants-versions-plan.md
      - docs/plans/page-grants-versions-plan-manual-steps.html
    brief: |
      Read the must-read docs and the whole plan. Follow AGENTS.md: do not hard-wrap Markdown lines.
      1. docs/architecture.md:
         - Package Boundaries: add `internal/groups` ("owns Google Workspace group membership lookups through the Admin SDK Directory API and their in-memory cache; it knows nothing about uploads or HTTP routing").
         - Dependency Direction: `internal/peekd` builds it and passes it to `internal/server` through the `server.GroupChecker` interface; `internal/server` must not import it.
         - Storage: one object per version, keys `<slug>` for v1 and `versions/<slug>/<hex>` after that.
      2. docs/operations.md:
         - A new "Page Access" section: the four visibilities, grants, the 403 behaviour, and the up-to-1-hour iframe token after revocation.
         - A new "Google Group Grants" section: PEEK_GOOGLE_SA_KEY_FILE, PEEK_GOOGLE_ADMIN_EMAIL, PEEK_GOOGLE_GROUP_CACHE_TTL (default 5m), the read-only scope `https://www.googleapis.com/auth/admin.directory.group.member.readonly`, that the key file is not in the SQLite backup and must be backed up and rotated separately, and that membership changes can take up to the cache TTL to apply.
         - Quotas/Retention: versions count toward storage quotas; retention deletes a page when its newest version is older than the cutoff and prunes older versions individually, along with their comments.
         - Upgrades: migrations 7 and 8.
      3. README.md and docs/src/content/docs/{auth-access,using-peek,reference,storage-retention,server-setup}.md: document `--visibility restricted`, `peek grant|revoke|grants`, `peek upload --slug`, `peek versions`, `peek comments --version`, `/p/<slug>/v/<n>`, and the three peekd flags, wherever the existing pages list the corresponding features. Leave a page untouched if it has no matching section.
      4. Delete docs/plans/page-grants-versions-plan.md and docs/plans/page-grants-versions-plan-manual-steps.html. If docs/plans/ is then empty, remove the directory.
      5. Run `grep -rn "page-grants-versions-plan" --exclude-dir=.git .` (expect no output), then `mise run check-full`.
      Do not dispatch pages.yml: it deploys to GitHub Pages.
    acceptance:
      - grep -rn "page-grants-versions-plan" --exclude-dir=.git . prints nothing
      - grep -n "internal/groups" docs/architecture.md prints at least one line
      - grep -n "PEEK_GOOGLE_SA_KEY_FILE" docs/operations.md prints at least one line
      - mise run check-full passes
```
