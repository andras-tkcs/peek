# Architecture

Peek is a small Go application, but the codebase is organized as if it needs to be reviewed, operated, and extended by people who care about clear ownership boundaries.

## Product Frame

Peek is an internal company tool, not a SaaS product. Architecture choices should optimize for a single organization or trusted team running its own server: simple deployment, clear admin controls, SSO-friendly login, auditability, backup/restore, retention, and safe handling of uploaded HTML. Do not introduce billing, tenant isolation layers, public signup funnels, marketplace flows, or growth-product abstractions unless the project explicitly changes direction.

## Package Boundaries

- `cmd/peekd` is only the server executable entrypoint. It should stay thin and delegate runtime behavior to `internal/peekd`.
- `cmd/peek` is only the CLI executable entrypoint. CLI commands, formatting, config files, and HTTP client behavior live in `internal/cli`.
- `internal/peekd` owns daemon process concerns: flag and environment parsing, structured logging setup, graceful shutdown, healthcheck command behavior, and SQLite backup command behavior.
- `internal/server` owns HTTP routing, request authentication, handler orchestration, browser workflows, API responses, comments, analytics, metrics, OAuth flow coordination, setup bootstrap, and runtime settings.
- `internal/groups` owns Google Workspace group membership lookups through the Admin SDK Directory API and their in-memory cache; it knows nothing about uploads or HTTP routing.
- `internal/uploads` owns upload creation, rename and visibility-change rules (`PrepareVisibility`, `Rename`): HTML sniffing, slug generation, object-store writes, database insert coordination, domain-level quota errors, and storage cleanup after failed persistence. It returns upload error kinds, not HTTP status codes.
- `internal/backends` owns the container engine client (Docker Engine API, also served by Podman), image reference rules, and the lifecycle of page backend containers: lazy start, idle stop, the running cap, and cleanup. It knows nothing about uploads, settings, or HTTP routing; `internal/server` resolves a page version into a `backends.Spec` and relays requests to the endpoint the manager returns.
- `internal/mail` owns SMTP delivery and message formatting for notification emails; it knows nothing about uploads or HTTP.
- `internal/uploadquota` owns the transport- and database-neutral upload quota contract shared by the upload service, HTTP server, and SQLite store.
- Provisioning persistence is `internal/db/provisioners.go` and `internal/db/provisioned_accounts.go`; its HTTP side is `internal/server/api_provisioners.go`, `internal/server/api_provisioning.go` and `internal/server/provisioning_auth.go`.
- `internal/db` owns SQLite schema, migrations, persistence rules, transactional constraints, and database-level invariants such as quota checks and last-admin protection.
- `internal/objectstore` owns upload byte storage. The server depends only on its `Storage` interface, while file and S3 implementation details stay outside the HTTP package.
- `internal/web` owns server-rendered templates, template view models, static asset embedding, and HTML rendering configuration.
- `internal/models` holds shared data shapes passed between packages. Keep it boring: no persistence or HTTP behavior belongs there.
- `internal/version` owns build metadata injected by release builds.

## Dependency Direction

The intended direction is executable packages to internal orchestration packages, orchestration packages to domain/runtime packages, and concrete infrastructure hidden behind small interfaces. `internal/server` may depend on `internal/uploads`, `internal/backends`, `internal/mail`, `internal/uploadquota`, `internal/db`, `internal/objectstore`, `internal/models`, and `internal/web`; `internal/uploads` may depend on `internal/uploadquota` and `internal/objectstore` but not `internal/db` or `net/http`; `internal/db` may depend on `internal/uploadquota`; `internal/mail` depends on no internal package; `internal/objectstore` must not depend on `internal/server`; `internal/db` must not depend on HTTP, CLI, or template packages. `internal/peekd` builds `internal/groups` and passes it to `internal/server` through the `server.GroupChecker` interface; `internal/server` must not import `internal/groups`. `internal/peekd` likewise builds the `backends.Runtime` and passes it to `internal/server` in `server.Config`. `internal/backends` imports no other internal package (enforced in `internal/architecture_test.go`).

## Rendering

Server-side rendering goes through `internal/web.Renderer` and `.gohtml` templates. Handlers build typed view-model aliases in `internal/server/view_models.go` and call `renderHTML`; they should not parse or execute templates directly. Browser JavaScript and CSS are embedded assets with hashed URLs so the server can send immutable cache headers for static files while keeping dynamic HTML non-cacheable.

## Storage

Uploads are created through `internal/uploads.Service`, which coordinates HTML validation, slug generation, object storage writes, and database inserts through a narrow upload repository interface. `internal/objectstore.Storage` is intentionally small: `Save`, `Open`, and `Delete`. S3 endpoint validation lives with S3 transport code, while the server remains responsible for decrypting secret settings before passing them into the storage package. Each page has one object per version: version 1 is keyed `<slug>`, later versions `versions/<slug>/<hex>`. `PrepareVisibility` validates later visibility changes and `Rename` derives a new link from a new name, for both the API and the dashboard. Renaming never moves objects: each version keeps its stored object key, and old slugs stay reserved as redirecting aliases (`upload_slug_aliases`).

## Quality Gates

Before committing behavior changes, run `mise run check`. For concurrency-sensitive changes, also run `mise run race`. Before opening a PR or after touching shared boundaries, run `mise run check-full`; it mirrors the CI quality gate with formatting, vet, build, tests, race tests, coverage, govulncheck, and staticcheck.

## Review Rules

Prefer package-boundary changes that reduce coupling over broad rewrites. Keep handlers thin when possible, push upload creation rules into `internal/uploads`, storage rules into `internal/objectstore`, persistence rules into `internal/db`, and runtime executable concerns into `internal/peekd`. Add tests near the package that owns the invariant.
