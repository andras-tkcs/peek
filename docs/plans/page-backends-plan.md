# Plan: page backends (one-page web services with a container backend)

## Goal

Today a Peek page is one HTML file shown in a sandboxed iframe. It can call public APIs from the browser, but it cannot send an email, keep data or use a secret, because nothing runs on the server for it.

After this plan, a page version can come with a **backend**: a Docker image that Peek runs as a container. The page talks to it with `peek.fetch("/api/contact", {method: "POST", body})`, a fetch-like call the existing bridge provides, and Peek relays the call to the container after the same access check that guards the page. The backend can do anything a container can: send email through the company's SMTP server, store form submissions in its `/data` volume, call internal APIs with secrets the page owner sets as environment variables. Peek stays generic: it does not know what the backend does.

For the people involved:

- **Operators** turn the feature on at startup (`--backends docker`, a Docker or Podman API socket) and stay in control: images must come from admin-allowed registry prefixes, every container gets fixed memory, CPU and PID limits, a read-only root filesystem, no capabilities and no published ports, containers stop when idle, and every change is audited.
- **Page owners** attach an image with `peek upload app.html --backend ghcr.io/acme/contact-form:1.2`, set secrets with `peek backend env set <slug> SMTP_PASSWORD --value-stdin`, and read logs with `peek backend logs <slug>`.
- **Viewers** see nothing new: the page just works, behind the same public / password / signed-in / restricted check as today. The backend learns who is calling (a stable per-page viewer id and, on signed-in and restricted pages, the account email) from headers Peek sets and the browser cannot forge.

The frontend stays one uploaded HTML file per version (inline the build, for example with a single-file bundler plugin, or load assets from a CDN as today). Zip bundles and container-served frontends are follow-ups, out of scope here.

There is no tracking issue; the request came from the user in the planning session ("any backend service is a docker container to make it flexible, generic and containerized").

## Current state

- **The page runs in an opaque-origin sandbox.** `internal/web/templates/page.gohtml:16` renders `<iframe sandbox="allow-scripts allow-popups">`; `/raw/{slug}/v/{n}` is served with CSP `sandbox allow-scripts allow-popups` (`internal/server/pages.go`, `rawContentCSP`). The iframe cannot use Peek cookies or call Peek as the viewer.
- **The bridge is the only channel to Peek.** `internal/web/assets/bridge.js` (434 lines) is injected into every page before `</body>` (`injectBridge`, `bridgeInsertOffset` in `internal/server/pages.go`). It talks to the parent with `parent.postMessage({hn: ...}, "*")` and already exposes `window.peek = {params, setParams}` (`bridge.js:382`). The parent controller `internal/web/assets/app.js` (609 lines) handles `hn` messages in `bindBridge()` (`app.js:262`) after checking `e.source === frame()`, and calls the page-side API with `fetch(..., {credentials: "same-origin"})` (`app.js:187`). `this.slug` and `this.version` come from `data-slug` / `data-version` on `<body>` (`app.js:167`); `data-version` is always the version being shown.
- **Access checks.** `viewerCanAccessUpload(r, u)` (`internal/server/comments.go:287`) decides public / password cookie / signed-in / restricted; `uploadAccessStatus` and `uploadAccessRequiredMessage` (`comments.go:308`) give the JSON error. `handleAddComment` (`comments.go:97`) is the pattern for a page-side endpoint: rate limit, `GetUpload`, access check, version check.
- **Owner-only API pattern.** `grantUpload` (`internal/server/api_grants.go:29`) = `requireAPIToken` + `GetUpload` + owner-or-admin check; handlers then `decodeJSON(w, r, &in, defaultJSONBodyLimit)` and `s.auditRequest(r, owner.Name, "upload.grant.add", auditDetail(...))`.
- **Uploads.** `handleUpload` (`internal/server/api_uploads.go:31`) reads multipart fields `visibility`, `password`, `slug`, `file` (or raw HTML with query params) and calls `uploadService().Create` or `handleUploadVersion` → `AddVersion`. The CLI writes those fields in `writeMultipartUpload` (`internal/cli/upload_command.go:167`).
- **Deletion and retention.** `deleteUpload` (`internal/server/upload_delete.go:10`) deletes objects then the row; `cleanupExpired` / `pruneOldVersions` (`internal/server/lifecycle.go:77`, `:102`) run in a background goroutine owned by `Server.wg` (`server.go:233`); `Server.Close` (`lifecycle.go:17`) cancels and waits.
- **Database.** `internal/db/schema.go` creates every table (including `upload_versions`, which has `UNIQUE(upload_id, version)`), then `internal/db/migrations.go` runs numbered migrations; the last one on `main` is `{14, "visibility_signed_in", ...}`. Foreign keys are on (`store.go:39`). Not-found is `sql.ErrNoRows` (`db/grants.go:45`).
- **Settings.** `settingsMeta` (`internal/server/settings.go:20`) lists every runtime setting; `normalizeSettingValue` (`settings.go:111`) validates; `secretSettingKeys` (`internal/server/security.go:207`) marks encrypted ones; the Admin page form (`handleDashboardSettings`, `settings.go:218`) saves every key of `settingsMeta` that was submitted, so a new text setting only needs a meta entry and a form field. `dashboardSettingsPanel` (`settings.go:334`) builds `webui.DashboardSettings` (`internal/web/renderer.go:148`), rendered by `internal/web/templates/admin.gohtml` with tabs Auth / Storage / Limits (`admin.gohtml:113`).
- **Startup config.** `internal/peekd/run.go:117-140` defines flags with env defaults and `validateServeConfig` (`run.go:204`); `server.Config` (`server.go:28`). Optional infrastructure is injected the way `Groups GroupChecker` is (`server.go:55`).
- **Request limits.** The middleware caps every body at 64 KiB except the two upload routes (`bodyLimitExempt`, `internal/server/middleware.go:25`); a global 300/min per-IP limiter applies to all routes.
- **Quality gate.** CI (`.github/workflows/ci.yml`) runs gofmt, vet, build, `go test -race`, a **90 % total coverage gate** (`scripts/coverage-gate.sh`, which counts packages without tests as 0 %), govulncheck and staticcheck on `ubuntu-latest`, where a Docker daemon is available. This container has the `docker` CLI but no daemon.
- **Dependencies.** `go.mod` has no Docker SDK; the codebase prefers the standard library (the S3 client in `internal/objectstore/s3*.go` is hand-written).

## Design

### D1. Architecture in one picture

```
iframe (opaque origin)                parent /p/<slug> (Peek origin)                 peekd                           container
peek.fetch(path, init) --postMessage {hn:"fetch"}--> app.js relayFetch -- fetch /svc/<slug>/v/<n><path> --> handleBackendProxy -- HTTP --> http://<ip>:<port><path>
       <--postMessage {hn:"fetch-result"}--------------        <------------------- response ----------------        <----------- response
```

Peek starts containers lazily on the first `/svc` request for a page version, keeps them while they are used, and stops them after an idle timeout. Containers live on one Docker network; peekd reaches them by their IP on that network and never publishes ports.

### D2. New package `internal/backends`

Owns the container engine client and the container lifecycle. It must not import `internal/server`, `internal/db`, `internal/web` or `internal/models`. `internal/server` imports it. `internal/peekd` builds the runtime and passes it in `server.Config`.

Files: `runtime.go` (interface and types), `docker.go` (Docker Engine API client), `image.go` (image reference rules), `manager.go` (lifecycle), and the test double package `internal/backends/backendstest` (`fake.go` plus its own `fake_test.go`, needed because the coverage gate counts an untested package as 0 %).

#### D2.1 `runtime.go`

```go
// Runtime is the container engine Peek drives. DockerRuntime implements it for
// the Docker Engine API (and Podman's compatible API).
type Runtime interface {
	Ping(ctx context.Context) error
	ImageExists(ctx context.Context, ref string) (bool, error)
	PullImage(ctx context.Context, ref, registryAuth string) error
	EnsureNetwork(ctx context.Context, name string) error
	CreateContainer(ctx context.Context, spec ContainerSpec) (string, error) // returns the container id
	StartContainer(ctx context.Context, id string) error
	ContainerIP(ctx context.Context, id, network string) (string, error)
	StopContainer(ctx context.Context, id string, timeout time.Duration) error
	RemoveContainer(ctx context.Context, id string) error // force; a missing container is not an error
	ListContainers(ctx context.Context, labels map[string]string) ([]ContainerInfo, error)
	ContainerLogs(ctx context.Context, id string, tail int) ([]byte, error)
	RemoveVolume(ctx context.Context, name string) error // a missing volume is not an error
}

// ContainerSpec is what the manager asks for. The runtime adds the fixed
// hardening in D2.2; callers cannot change it.
type ContainerSpec struct {
	Name        string
	Image       string
	Env         []string          // "KEY=value"
	Labels      map[string]string
	Network     string
	Volume      string            // named volume mounted at /data
	MemoryBytes int64
	NanoCPUs    int64
	Cmd         []string          // empty = the image's default; only tests set it
}

type ContainerInfo struct {
	ID     string
	Name   string // without the leading "/"
	Labels map[string]string
	State  string
}

// APIError is a non-2xx answer from the engine.
type APIError struct {
	Status  int
	Message string
}
func (e *APIError) Error() string // "docker api: <status>: <message>"
func IsNotFound(err error) bool   // errors.As *APIError with Status 404
```

#### D2.2 `docker.go`

- `func NewDockerRuntime(host string) (*DockerRuntime, error)`. `host` is `unix:///path/to/socket` or `tcp://host:port`; anything else returns `fmt.Errorf("unsupported docker host %q (use unix:// or tcp://)", host)`. The HTTP client dials the socket (or TCP address) itself and sends requests to `http://docker/v1.43/...` (API version constant `dockerAPIVersion = "v1.43"`, Docker 24+, also served by Podman 4+). Its `Transport` has `Proxy: nil` so `HTTP_PROXY` never applies.
- Non-2xx responses are decoded as `{"message": "..."}` into `*APIError` (empty message → the status text).
- Endpoints, one method each:
  - `Ping`: `GET /_ping`.
  - `ImageExists`: `GET /images/{ref}/json` (ref path-escaped with `url.PathEscape`); 200 → true, 404 → false.
  - `PullImage`: `POST /images/create?fromImage=<Repository(ref)>&tag=<t>` where `t` is the digest (`sha256:...`) when `ref` has `@`, else the tag after the last `:` that follows the last `/`, else `latest` (an empty `tag` makes the Engine pull every tag). Header `X-Registry-Auth: <registryAuth>` when non-empty. The body is a stream of JSON objects; read it to the end and return `fmt.Errorf("pull %s: %s", ref, msg)` for the first object with a non-empty `"error"` field.
  - `EnsureNetwork`: `GET /networks/{name}`; on 404, `POST /networks/create` with `{"Name": name, "Driver": "bridge", "Labels": {"peek.managed": "true"}}`.
  - `CreateContainer`: `POST /containers/create?name=<name>` with this body (fields not listed are omitted; `Cmd` only when non-empty):
    ```json
    {"Image": "<image>", "Env": [...], "Labels": {...}, "Cmd": [...],
     "HostConfig": {
       "NetworkMode": "<network>",
       "Memory": <memory>, "MemorySwap": <memory>, "NanoCpus": <nanocpus>, "PidsLimit": 256,
       "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
       "ReadonlyRootfs": true, "Tmpfs": {"/tmp": "rw,nosuid,size=64m"},
       "Mounts": [{"Type": "volume", "Source": "<volume>", "Target": "/data"}],
       "RestartPolicy": {"Name": "no"}, "Init": true,
       "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "2"}}}}
    ```
    Returns the `Id` from the response.
  - `StartContainer`: `POST /containers/{id}/start` (204 and 304 are success).
  - `ContainerIP`: `GET /containers/{id}/json`, `NetworkSettings.Networks[network].IPAddress`; empty → `fmt.Errorf("container %s has no address on network %q", id, network)`.
  - `StopContainer`: `POST /containers/{id}/stop?t=<seconds>` (204, 304 and 404 are success).
  - `RemoveContainer`: `DELETE /containers/{id}?force=1` (404 is success).
  - `ListContainers`: `GET /containers/json?all=1&filters=<url-encoded {"label":["k=v",...]}>`, labels sorted for a stable query; strips the leading `/` from `Names[0]`.
  - `ContainerLogs`: `GET /containers/{id}/logs?stdout=1&stderr=1&timestamps=1&tail=<n>`. The stream is multiplexed (8-byte header: byte 0 stream, bytes 4-7 big-endian payload length); demultiplex into one byte slice, reading at most 1 MiB.
  - `RemoveVolume`: `DELETE /volumes/{name}` (404 is success).

#### D2.3 `image.go`

- `func ValidateImageRef(ref string) error`: non-empty, at most 255 bytes, and matches
  `^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`; otherwise `errors.New("invalid image reference")`.
- `func Repository(ref string) string`: `ref` without `@digest`, then without `:tag` when that `:` comes after the last `/`.
- `func ParseAllowedImages(setting string) []string`: split on `,` and newlines, trim, drop empties.
- `func ImageAllowed(ref string, allowed []string) bool`: true when some entry `p` ends with `/` and `strings.HasPrefix(ref, p)`, or does not end with `/` and `Repository(ref) == p`. An empty list allows nothing.
- `func RegistryHost(ref string) string`: the first `/`-separated component when it contains `.` or `:` or equals `localhost`; otherwise `docker.io`.
- `func RegistryAuth(username, password, server string) string`: `base64.URLEncoding` of the JSON `{"username":..., "password":..., "serveraddress":...}`; empty string when `username` is empty.

#### D2.4 `manager.go`

```go
type Config struct {
	Runtime  Runtime
	Network  string
	Instance string // 8 hex chars; scopes names, labels and cleanup to this peekd
	Limits   func(ctx context.Context) Limits
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error) // readiness probe; nil = (&net.Dialer{}).DialContext
	Now      func() time.Time // nil = time.Now
}

type Limits struct {
	IdleTimeout time.Duration
	MaxRunning  int
}

// Spec is one page version's backend, resolved from settings by the server.
type Spec struct {
	UploadID     int64
	Version      int
	Image        string
	Port         int
	Env          map[string]string
	MemoryBytes  int64
	NanoCPUs     int64
	RegistryAuth string
}

// Endpoint is where a running backend listens and the token it expects.
type Endpoint struct {
	URL   string // "http://<ip>:<port>"
	Token string // value of PEEK_BACKEND_TOKEN in the container
}

var ErrNotRunning = errors.New("backend is not running")

func NewManager(cfg Config) *Manager
func (m *Manager) Start(ctx context.Context) error // EnsureNetwork, then remove every container labelled peek.managed=true and peek.instance=<Instance>
func (m *Manager) Ensure(ctx context.Context, spec Spec) (Endpoint, error)
func (m *Manager) StopVersion(ctx context.Context, uploadID int64, version int) error
func (m *Manager) StopUpload(ctx context.Context, uploadID int64) error
func (m *Manager) RemoveUploadData(ctx context.Context, uploadID int64) error // StopUpload, then RemoveVolume(VolumeName)
func (m *Manager) Logs(ctx context.Context, uploadID int64, version int, tail int) ([]byte, error) // ErrNotRunning when not tracked
func (m *Manager) Running(uploadID int64, version int) bool
func (m *Manager) ReapIdle(ctx context.Context)
func (m *Manager) Run(ctx context.Context) // calls ReapIdle every minute until ctx is done
func (m *Manager) Close(ctx context.Context) error // stops and removes every tracked container

func ContainerName(instance string, uploadID int64, version int) string // "peek-<instance>-u<uploadID>-v<version>"
func VolumeName(instance string, uploadID int64) string                 // "peek-<instance>-data-u<uploadID>"
```

Locking and start (all state under one `sync.Mutex`):

```go
type key struct{ uploadID int64; version int }
type entry struct {
	ready    chan struct{} // closed when the start attempt finished
	err      error         // start error; read only after ready is closed
	id, image string
	endpoint Endpoint
	lastUsed time.Time
}
```

`Ensure(ctx, spec)`:
1. Lock. If an entry exists for the key with `entry.image != spec.Image`, remove it from the map, unlock, wait on its `ready` (or `ctx.Done()`), stop-and-remove its container if it started (`err == nil`; step 4.6), and start over at step 1 (this is how a changed image takes effect). `entry.image` is set when the entry is inserted (step 3), never later, so a call arriving during a start sees the right image.
2. If an entry exists with the same image: unlock, wait for `ready` or `ctx.Done()` (return `ctx.Err()`); if `entry.err != nil` return it; otherwise lock, set `lastUsed = now`, unlock, return `entry.endpoint`.
3. Otherwise enforce the cap: count all entries in the map (started and starting); while `MaxRunning > 0` and count ≥ `MaxRunning` and a started entry exists, remove the least recently used started entry (ready closed, `err == nil`) from the map and remember it for stopping. Entries still starting are never evicted, so concurrent cold starts can exceed the cap briefly; that is accepted. Insert a new entry `e` with `image: spec.Image` and an open `ready`. Unlock. Stop-and-remove the evicted containers.
4. Start with `startCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)`, so a viewer closing the tab does not abort a start other requests wait on:
   1. `ImageExists`; if false, `PullImage(spec.Image, spec.RegistryAuth)`.
   2. `RemoveContainer(name)` (a leftover from a crash).
   3. `CreateContainer` with `Name: ContainerName`, `Image`, `Env` = the sorted `KEY=value` pairs of `spec.Env` plus `PORT=<port>`, `PEEK_BACKEND_TOKEN=<64 hex chars from crypto/rand>`, `PEEK_UPLOAD_ID=<id>`, `PEEK_VERSION=<n>`; `Labels` = `peek.managed=true`, `peek.instance=<Instance>`, `peek.upload_id=<id>`, `peek.version=<n>`; `Network`; `Volume: VolumeName`; `MemoryBytes`, `NanoCPUs` from the spec.
   4. `StartContainer`, then `ContainerIP`.
   5. Readiness: `Dial("tcp", ip:port)` every 200 ms until it succeeds (close the conn) or 30 s pass; on timeout remove the container and fail with `fmt.Errorf("backend did not listen on port %d within 30s", port)`.
   6. Stop-and-remove means `StopContainer(id, 10*time.Second)` then `RemoveContainer(id)`, logging errors with `slog.Warn("backend stop", ...)`.
5. On failure: lock, delete the entry from the map only `if m.entries[k] == e` (a newer entry may have replaced it), set `e.err`, close `ready`, unlock, return the error. On success: lock, fill `id`, `endpoint`, `lastUsed`, close `ready`, unlock, `slog.Info("backend started", "upload_id", ..., "version", ..., "image", ...)`, return the endpoint.

`ReapIdle`: lock, collect and delete started entries with `now - lastUsed > IdleTimeout`, unlock, stop-and-remove each, `slog.Info("backend stopped", "reason", "idle", ...)`. `StopVersion` / `StopUpload` / `Close` likewise remove matching entries under the lock and stop them outside it; entries still starting are waited on (`<-ready`) before stopping. No container call happens while the mutex is held.

#### D2.5 `backendstest.FakeRuntime`

An in-memory, mutex-guarded `backends.Runtime`: containers in a map, `ContainerIP` returns `"127.0.0.1"` (so a test points the backend `Port` at an `httptest.Server` it started), exported slices recording `Pulled`, `Created []backends.ContainerSpec`, `Stopped`, `Removed`, `VolumesRemoved`, settable errors `PullErr`, `CreateErr`, `StartErr`, a settable `Images map[string]bool` for `ImageExists`, and `LogsData []byte`. It has its own `fake_test.go`.

### D3. Database

The migration id is **the last id in `migrations` plus one** when the phase runs: 15 on today's `main`, 16 if the pending `plan/collaboration-sharing` plan (which takes 15) merged first. Below it is written as `<N>`.

Tables, added both to `internal/db/schema.go` (after `upload_slug_aliases`) and as migration `{<N>, "upload_backends", <same SQL>}`:

```sql
CREATE TABLE IF NOT EXISTS upload_backends (
	upload_id INTEGER NOT NULL,
	version INTEGER NOT NULL,
	image TEXT NOT NULL,
	port INTEGER NOT NULL DEFAULT 8080,
	created_by_account_id INTEGER REFERENCES accounts(id),
	created_at INTEGER NOT NULL,
	PRIMARY KEY (upload_id, version),
	FOREIGN KEY (upload_id, version) REFERENCES upload_versions(upload_id, version) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS upload_backend_env (
	upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	value TEXT NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (upload_id, name)
);
```

Deleting a page or pruning a version removes its backend rows by cascade. `value` is stored as given; the server encrypts it (D6).

`internal/models/models.go`:

```go
type UploadBackend struct {
	UploadID           int64
	Version            int
	Image              string
	Port               int
	CreatedByAccountID int64
	CreatedAt          time.Time
}

type BackendEnvVar struct {
	UploadID  int64
	Name      string
	Value     string // ciphertext as stored; the server decrypts
	UpdatedAt time.Time
}
```

`internal/db/backends.go` (all return `sql.ErrNoRows` when a get/delete matches nothing):

```go
func (s *Store) SetUploadBackend(ctx context.Context, b models.UploadBackend) error // upsert on (upload_id, version)
func (s *Store) GetUploadBackend(ctx context.Context, uploadID int64, version int) (*models.UploadBackend, error)
func (s *Store) ListUploadBackends(ctx context.Context, uploadID int64) ([]models.UploadBackend, error) // by version
func (s *Store) DeleteUploadBackend(ctx context.Context, uploadID int64, version int) error
func (s *Store) SetUploadBackendEnv(ctx context.Context, uploadID int64, name, value string) error // upsert, updated_at = now
func (s *Store) DeleteUploadBackendEnv(ctx context.Context, uploadID int64, name string) error
func (s *Store) ListUploadBackendEnv(ctx context.Context, uploadID int64) ([]models.BackendEnvVar, error) // by name
```

`created_by_account_id` is written as NULL when 0, like `AddUploadGrant`.

### D4. Startup configuration (`internal/peekd`)

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--backends` | `PEEK_BACKENDS` | `off` | `off` or `docker` |
| `--docker-host` | `PEEK_DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker/Podman API address, `unix://` or `tcp://` |
| `--backend-network` | `PEEK_BACKEND_NETWORK` | `peek-backends` | Docker network for backend containers |

A new `func validateBackendConfig(mode, network string) error`, called from `parseServeConfig` right after `validateServeConfig` (whose positional signature stays unchanged), checks `backends must be off or docker` and, for the network, `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$` → `backend network must be a valid docker network name`. Pass the three values through `serveConfig` (add `Backends`, `DockerHost`, `BackendNetwork` string fields). When `--backends docker`: `rt, err := backends.NewDockerRuntime(host)`; `rt.Ping` with a 5 s timeout; failure stops startup with `fmt.Errorf("docker is not reachable at %s: %w", host, err)`. Pass `rt` as `server.Config.BackendRuntime` (type `backends.Runtime`, nil when off) and the network as `server.Config.BackendNetwork`. To keep unit tests free of a daemon, the runtime constructor is a package variable in `run.go`: `var newBackendRuntime = func(host string) (backends.Runtime, error) { return backends.NewDockerRuntime(host) }`, overridden in tests with a `backendstest.FakeRuntime`.

### D5. Server wiring and runtime settings

`Server` gains `backends *backends.Manager` (nil = feature off), `backendLimiter *limiter` (`newLimiter(240, time.Minute)`) and `backendClient *http.Client` (`Timeout: 30 * time.Second`, `CheckRedirect` returning `http.ErrUseLastResponse`, `Transport: &http.Transport{Proxy: nil}`).

In `New`, when `cfg.BackendRuntime != nil`:
1. Read setting `backend_instance_id`; if missing or empty, generate `randHex(4)` and store it with `store.SetSetting`. It is not in `settingsMeta`, so nobody can edit it through the settings API.
2. `srv.backends = backends.NewManager(backends.Config{Runtime: cfg.BackendRuntime, Network: cfg.BackendNetwork, Instance: id, Limits: srv.backendLimits})`, then `srv.backends.Start` with `context.WithTimeout(startupCtx, 30*time.Second)`; an error stops startup (`fmt.Errorf("start backends: %w", err)`).
3. Add a third goroutine to `srv.wg` running `srv.backends.Run(ctx)`.

`Close`: after `s.wg.Wait()` and before closing the store, `s.backends.Close(ctx)` with a 30 s timeout when non-nil; log its error.

Runtime settings (added to `settingsMeta`; read with defaults, so `initDefaultSettings` does not change):

| Key | Label | Default when empty | Validation |
| --- | --- | --- | --- |
| `backend_allowed_images` | Allowed backend images | empty = no image allowed | each entry from `ParseAllowedImages` matches `^[a-z0-9][a-z0-9._:/@-]*$`, ≤ 255 bytes; stored joined with `,` |
| `backend_memory_mb` | Backend memory (MB) | 256 | empty or integer 16..65536 |
| `backend_cpu_millis` | Backend CPU (millicores) | 500 | empty or integer 50..64000 |
| `backend_idle_minutes` | Backend idle stop (minutes) | 15 | empty or integer 1..1440 |
| `backend_max_running` | Max running backends | 10 | empty or integer 1..1000 |
| `backend_registry_server` | Registry server | empty | free text, e.g. `ghcr.io` |
| `backend_registry_username` | Registry username | empty | free text |
| `backend_registry_password` | Registry password | empty | secret (`IsSecret: true` and in `secretSettingKeys`) |

Descriptions: allowed images: `Comma-separated registry prefixes ending in "/" (ghcr.io/acme/) or exact repositories (ghcr.io/acme/contact-form). Empty allows no backends.`; memory: `Memory limit per backend container`; CPU: `CPU limit per backend container (1000 = one core)`; idle: `Stop a backend after this many minutes without requests`; max running: `Stop the least recently used backend when more would run`; registry fields: `Credentials for pulling private backend images from this registry`.

Validation errors (from `normalizeSettingValue`): `backend_allowed_images entries must be registry prefixes or repositories`, and `<key> must be between <min> and <max>` for the integers.

`internal/server/backend_settings.go`:

```go
func (s *Server) backendLimits(ctx context.Context) backends.Limits // idle minutes and max running with the defaults above
func (s *Server) backendImageAllowed(ctx context.Context, ref string) bool // ValidateImageRef == nil && ImageAllowed(ref, ParseAllowedImages(setting))
func (s *Server) backendSpec(ctx context.Context, b *models.UploadBackend) (backends.Spec, error)
```

`backendSpec` decrypts every env value with `decryptSecret(s.secret, v.Value)`; because `decryptSecret` returns `"", nil` when authentication fails (`security.go:196`), an error **or** an empty result from a non-empty ciphertext fails the call with `fmt.Errorf("decrypt backend variable %s", v.Name)`, sets `MemoryBytes = memoryMB << 20`, `NanoCPUs = cpuMillis * 1_000_000`, and `RegistryAuth = backends.RegistryAuth(user, password, server)` only when `backends.RegistryHost(b.Image) == server`.

### D6. Owner API

All routes use `requireAPIToken` and owner-or-admin, through a helper `backendUpload(w, r) (*models.Token, *models.Upload, bool)` copied from `grantUpload`. `{n}` is a positive version number or the word `latest` (= `u.LatestVersion`); a version that does not exist is 404 `version not found`. When `s.backends == nil`, the mutating routes (PUT, DELETE, restart, env set) answer 409 `backends are not enabled on this server`; GET and env unset still work so owners can clean up.

| Route | Body / query | Success | Audit action and detail |
| --- | --- | --- | --- |
| `GET /api/uploads/{slug}/backend` | | `{"enabled": bool, "versions": [{"version", "image", "port", "running"}], "env": [{"name", "updated_at"}]}` (values never returned) | none |
| `PUT /api/uploads/{slug}/versions/{n}/backend` | `{"image": "...", "port": 8080}` (port optional, default 8080) | the version object | `backend.set` slug, version, image, port |
| `DELETE /api/uploads/{slug}/versions/{n}/backend` | | `{"status":"ok"}`; 404 `no backend for this version` | `backend.remove` slug, version |
| `GET /api/uploads/{slug}/versions/{n}/backend/logs` | `?tail=` 1..2000, default 200 | `text/plain; charset=utf-8` log text; 404 `backend is not running` | none |
| `PUT /api/uploads/{slug}/backend/env/{name}` | `{"value": "..."}` | `{"status":"ok","restart_required":true}` | `backend.env.set` slug, name |
| `DELETE /api/uploads/{slug}/backend/env/{name}` | | `{"status":"ok","restart_required":true}`; 404 `no such variable` | `backend.env.unset` slug, name |
| `POST /api/uploads/{slug}/backend/restart` | | `{"status":"ok"}` | `backend.restart` slug |

Rules:
- Image and port are checked by one helper in `api_backends.go`, `func (s *Server) validateBackendInput(ctx context.Context, image string, port int) (normalizedPort int, status int, msg string)` (status 0 = valid; port 0 means 8080), used by both the PUT route and the upload API: `ValidateImageRef` failing → 400 `invalid backend image reference`; not allowed → 400 `backend image is not allowed; ask an admin to add its registry to the allowed backend images`; port outside 1..65535 → 400 `backend port must be between 1 and 65535`.
- PUT and DELETE of a version backend write the database change first, then call `s.backends.StopVersion` (when enabled), so a request in between cannot restart the old image.
- Env name must match `^[A-Z_][A-Z0-9_]{0,63}$` and must not be `PORT` or start with `PEEK_` → 400 `invalid variable name; use A-Z, 0-9 and _, not PORT or PEEK_*`. Value at most 4096 bytes → 400 `value too long`. At most 50 variables per page → 400 `too many variables (max 50)`. The value is stored as `encryptSecret(s.secret, value)`. Changes apply on the next container start (restart).
- Restart = `s.backends.StopUpload(ctx, u.ID)`.

Upload API (`handleUpload`): new multipart fields (and query parameters on the raw-HTML path) `backend_image` and `backend_port`. They are validated as above **before** the upload is created (and refused with 409 `backends are not enabled on this server` when off). After a successful create or new version, `SetUploadBackend` writes the row with the uploader's account id; if that write fails, answer 500 `page uploaded but its backend could not be saved` (the page stays, without backend). On a new version (`slug` given) without `backend_image`, copy the backend row of the version that was latest before the upload, if there is one. The JSON response gains `"backend_image"` (omitted when empty).

Cleanup hooks: `deleteUpload` calls `s.backends.RemoveUploadData(ctx, u.ID)` **after** `s.store.DeleteUpload` succeeds (so no `/svc` request can start a new container in between) when enabled, and logs (does not return) its error; `pruneOldVersions` calls `s.backends.StopVersion` after `DeleteUploadVersion` succeeds.

### D7. The `/svc` relay

Routes, one per method (Go's mux panics on a method-less pattern that overlaps `GET /`):
`GET|POST|PUT|PATCH|DELETE /svc/{slug}/v/{n}/{path...}` → `handleBackendProxy`.

`bodyLimitExempt` also exempts paths starting with `/svc/`; the handler applies its own limit `const backendMaxBody = 1 << 20` (step 1).

`handleBackendProxy`, in order:
1. `s.backends == nil` → 404 `backends are not enabled on this server`. Then the body: `r.ContentLength > backendMaxBody` → 413 `request body too large`; otherwise `body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, backendMaxBody))`, and a `*http.MaxBytesError` → 413 `request body too large` (any other read error → 400 `bad request body`). The upstream request sends `bytes.NewReader(body)`.
2. Header `X-Peek-Svc` must equal `1`, and `Sec-Fetch-Site`, when present, must be `same-origin`; otherwise 403 `backend requests must come from the page viewer`. (The custom header forces a CORS preflight that Peek never answers, so other sites and the opaque iframe cannot call `/svc` directly.)
3. `s.backendLimiter.allow(s.rateLimitKey(r))` → else 429 `too many backend requests, slow down`.
4. `GetUpload(slug)` → 404 `not found`; `n` not a positive integer → 404 `not found`; `!s.viewerCanAccessUpload(r, u)` → `s.uploadAccessStatus(r, u)` with `uploadAccessRequiredMessage(u)`.
5. `GetUploadBackend(u.ID, n)` → `sql.ErrNoRows` → 404 `this page version has no backend`.
6. `backendSpec` then `s.backends.Ensure`; error → log `slog.Error("backend start failed", "slug", ..., "version", ..., "err", err)` and 502 `backend failed to start`.
7. Upstream request: same method, URL `endpoint.URL + rest` where `rest` is the still-escaped remainder `strings.TrimPrefix(r.URL.EscapedPath(), "/svc/"+r.PathValue("slug")+"/v/"+r.PathValue("n"))` (never the decoded `r.PathValue("path")`, which would turn `%3F` into `?`; slugs contain no characters that need escaping), plus `"?" + r.URL.RawQuery` when non-empty, body = the bytes read in step 1. Copy only `Content-Type` and `Accept` from the incoming request. Add `X-Peek-Backend-Token: <endpoint.Token>`, `X-Peek-Upload-Id`, `X-Peek-Version`, `X-Peek-Viewer` (when the `hn_vid` cookie is present: `hmacSHA256(s.secret, "backend-viewer:"+uploadID+":"+vid)[:32]`), and, only when the page's visibility is `signed-in` or `restricted` and `s.webAuth(r)` succeeds, `X-Peek-User-Id` and `X-Peek-User-Email` (email omitted when empty). Backends of public and password pages never learn who a signed-in viewer is. No cookies, no `Authorization`, no other incoming header is forwarded.
8. Send with `s.backendClient`. A timeout (`errors.Is(err, context.DeadlineExceeded)` or a `net.Error` with `Timeout()`) → 504 `backend timed out`; any other error → 502 `backend unavailable`.
9. Read at most `backendMaxResponse + 1` bytes (`const backendMaxResponse = 8 << 20`); more → 502 `backend response too large`. Write the upstream status, `Content-Type` (only if the backend set one), `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox; default-src 'none'`, then the body. A request body over the limit → 413 `request body too large`.

### D8. Browser side

`bridge.js` adds `window.peek.fetch(path, init)` and returns a `Promise<Response>`:
- `path` must be a string starting with `/`, else reject `new TypeError("peek.fetch path must start with /")`.
- `init.method` defaults to `GET`; allowed `GET POST PUT PATCH DELETE` (case-insensitive, sent upper-case), else reject `TypeError("peek.fetch method not allowed")`.
- `init.headers` (plain object or `Headers`): only `content-type` and `accept` are kept, lower-cased.
- `init.body`: `undefined`, `string`, `ArrayBuffer`, an `ArrayBuffer` view (sent as a copied `ArrayBuffer`), `Blob` (read with `arrayBuffer()`, its `type` as default content-type), or `URLSearchParams` (sent as a string, default content-type `application/x-www-form-urlencoded;charset=UTF-8`); anything else rejects `TypeError("peek.fetch body type not supported")`.
- Each call gets id `"f" + counter`, posts `{hn: "fetch", id, path, method, headers, body}` to `parent` with `"*"`, and waits for `{hn: "fetch-result", id, ...}`; after 35 s it rejects `new Error("peek.fetch timed out")`.
- On `{ok: true, status, contentType, body}` it resolves `new Response(status === 204 || status === 205 || status === 304 ? null : body, {status, headers: contentType ? {"content-type": contentType} : {}})`; on `{ok: false, error}` it rejects `new Error(error)`.
- The existing message listener (`bridge.js:423`, already checking `e.source !== parent`) gets `else if (d.hn === "fetch-result") settleFetch(d);`.
- Update the header comment: the bridge still never calls the server itself; `peek.fetch` is relayed by the parent.

`app.js` `bindBridge()` adds `if (data.hn === "fetch") { this.relayFetch(data); return; }` and a `relayFetch(d)` method. Every reply is sent with the existing `postToFrame(msg)` helper (`app.js:19`, which calls `frame().postMessage(msg, "*")`; `"*"` is required because the iframe's origin is opaque).
- **Navigation lock.** `bindBridge()` already listens for `load` on `#hn-frame`; count those events in a component field `frameLoads`. After the second `load` the frame has navigated away from the uploaded page (a link the viewer clicked can load a third-party site into the same iframe, with the same `WindowProxy` and origin `null`), so `relayFetch` refuses every request with `error: "page navigated; reload to use the backend"` while `frameLoads > 1`.
- Validate (after the navigation lock): `d.id` string ≤ 32 chars; `d.path` string starting with `/` and ≤ 2048 chars; `d.method` one of the five; `d.headers` an object whose keys are only `content-type` / `accept` with string values; `d.body` `undefined`, string or `ArrayBuffer`. Invalid → post `{hn: "fetch-result", id: d.id, ok: false, error: "invalid peek.fetch request"}`.
- At most 16 relays in flight (counter on the component); beyond → `error: "too many concurrent peek.fetch requests"`.
- Build `const prefix = "/svc/" + encodeURIComponent(this.slug) + "/v/" + this.version + "/"; const url = new URL(prefix + d.path.slice(1), location.origin);` and refuse with `error: "invalid peek.fetch path"` unless `url.origin === location.origin && url.pathname.startsWith(prefix)`. This blocks `..` and `%2e%2e` segments that would otherwise reach other Peek routes with the viewer's cookies.
- `fetch(url, {method, headers: Object.assign({}, d.headers, {"X-Peek-Svc": "1"}), body: d.body, credentials: "same-origin", redirect: "error", cache: "no-store"})`, then `arrayBuffer()`, then post `{hn: "fetch-result", id, ok: true, status: res.status, contentType: res.headers.get("content-type") || "", body}`; on any rejection post `{ok: false, error: "backend request failed"}`. Always decrement the in-flight counter.

### D9. CLI

- `peek upload <file> --backend <image> [--backend-port <n>]`: writes multipart fields `backend_image` and `backend_port`. `--backend-port` without `--backend` is an error `--backend-port requires --backend`. Both are allowed with `--slug`.
- `peek backend <slug>`: prints the GET response: a table `VERSION  IMAGE  PORT  RUNNING` (RUNNING is `yes` or `no`), then `ENV` names, or `no backend` when `versions` is empty; prints `backends are disabled on this server` when `enabled` is false.
- `peek backend set <slug> <image> [--version <n>|latest] [--port <n>]`
- `peek backend remove <slug> [--version <n>|latest]`
- `peek backend env set <slug> <NAME> (--value-stdin | --value <v>)`: `--value` prints the same kind of warning as `peek login --token` (`warning: --value leaks into shell history; prefer --value-stdin`).
- `peek backend env unset <slug> <NAME>`
- `peek backend restart <slug>`
- `peek backend logs <slug> [--version <n>|latest] [--tail <n>]`: writes the text to stdout.
- `--version` defaults to `latest`. Usage line for errors: `usage: peek backend <slug> | set|remove|env|restart|logs ...`.

### D10. Admin page

A fourth settings tab **Backends** on `/admin`, after Limits, holding the eight settings of D5 as text inputs (password input for the registry password, blank keeps the value, like the S3 secret). When backends are off (`s.backends == nil`), the tab starts with the line `Backends are off. Start peekd with --backends docker to run page backends.` `webui.DashboardSettings` gains `Backends BackendSettings` with `Enabled bool` and `Fields []SettingRow`; the server sets `Enabled` after calling `dashboardSettingsPanel`.

### D11. Example and CI integration test

`examples/contact-form/` is a separate Go module (`module github.com/andras-tkcs/peek/examples/contact-form`, `go 1.26`, standard library only), so the root `./...` (vet, tests, coverage, staticcheck) skips it; gofmt still checks its `.go` file.
- `main.go`: listens on `:$PORT` (default 8080). Every request must carry `X-Peek-Backend-Token` equal to `$PEEK_BACKEND_TOKEN`, else 401. `GET /api/healthz` → `ok`. `POST /api/contact` with JSON `{"name","email","message"}` (each required, message ≤ 5000 bytes) sends one plain-text email with `net/smtp` to `$MAIL_TO` from `$MAIL_FROM` through `$SMTP_HOST:$SMTP_PORT` (auth with `$SMTP_USERNAME`/`$SMTP_PASSWORD` when set), appends the submission as a JSON line to `/data/submissions.jsonl`, and answers `{"status":"sent"}`; `GET /api/submissions` returns the stored lines as a JSON array only when `X-Peek-User-Email` is set.
- `index.html`: a small form that calls `peek.fetch("/api/contact", {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(...)})` and shows the result.
- `Dockerfile`: multi-stage `golang:1.26` build → `gcr.io/distroless/static-debian12:nonroot`, with an empty `/data` owned by uid 65532 copied in (`COPY --from=build --chown=65532:65532 /data-empty /data`) so the named volume is writable by the non-root user.
- `README.md`: build, push, allow the prefix, upload, set the env vars, try it with Mailpit.
- `docker-compose.yml` gains profile `backends`: service `peek-backends` (peekd with `PEEK_BACKENDS: docker`, `/var/run/docker.sock` mounted, `group_add` with the socket's group id via `${DOCKER_GID:-0}` (the README tells Linux users to run `export DOCKER_GID=$(stat -c %g /var/run/docker.sock)` first; the default 0 only fits a root-owned socket), on network `peek-backends`, port 7722), service `mailpit` (`axllent/mailpit:v1.27`, ports 8025 and 1025, same network), and the network `peek-backends` declared with `name: peek-backends`.

The CI job `backend-integration` (new job in `ci.yml`, `ubuntu-latest`) builds the example image as `peek-example-contact:ci` and runs `PEEK_DOCKER_TEST=1 PEEK_DOCKER_TEST_IMAGE=peek-example-contact:ci go test -count=1 -run '^TestDockerIntegration' ./internal/backends`. The test file `internal/backends/docker_integration_test.go` skips with `t.Skip("set PEEK_DOCKER_TEST=1 to run against a Docker daemon")` otherwise.

### Rejected alternatives

- **Built-in services (email API, form store, key-value store) instead of containers.** Safer and smaller, but every new need would be a Peek feature; the user asked for a generic, containerized model.
- **User scripts in an embedded interpreter (goja, WASM).** Still a new runtime to secure, and less flexible than any language in a container.
- **Letting the iframe call `/svc` directly with CORS and a token.** It would need `Access-Control-Allow-Origin: null` and a bearer token in page JavaScript; the postMessage relay keeps today's rule that the opaque page never calls Peek, and cookies stay with the trusted parent.
- **Publishing container ports on 127.0.0.1.** Fails when peekd itself runs in a container; a shared Docker network works for both host and container deployments.
- **The Docker Go SDK.** A large dependency tree for twelve HTTP calls; the hand-written client follows the S3 client's precedent.
- **Always-on containers.** Lazy start plus idle stop bounds resource use on a shared internal host; the first request after idle pays a cold start (the image is cached, so it is the container start time).
- **Disabling inter-container traffic on the network.** It would also cut peekd off when it runs as a container on that network; each backend instead checks `X-Peek-Backend-Token`, which is unique per container start.
- **Building images inside Peek from an uploaded Dockerfile.** Needs BuildKit and turns peekd into a build server; owners push images with their usual CI.

## Manual steps

Nothing is needed before implementation: every phase builds against `backendstest.FakeRuntime` or an `httptest` fake of the Docker API, and CI's `backend-integration` job exercises a real daemon.

After implementation, one end-to-end check needs a machine with Docker and a browser: run the `backends` compose profile, upload the contact-form example, send the form, see the email in Mailpit, and watch the container stop when idle. See the step-by-step page: https://claude.ai/artifact/QumxcaN2UvxEirAAr5BttW (source: `docs/plans/page-backends-plan-manual-steps.html`).

## Risks and open questions

- **The Docker socket is root on the host.** Anyone who controls peekd controls the host. Peek never lets owners choose mounts, capabilities, network mode or privileges (they are fixed in `CreateContainer`), but the operations doc must say this plainly and recommend rootless Docker or Podman, or a dedicated VM. A worker must not add any owner-controlled field to `ContainerSpec` or the create body; if a brief seems to need one, stop with `status=blocked`.
- **Read-only root filesystem breaks some images** (anything writing outside `/tmp` and `/data`). This is deliberate and documented; do not relax it in a phase.
- **Volume ownership.** Docker creates the named volume root-owned unless the image already has `/data` with an owner; non-root images need that (the example shows how). Documented, not worked around.
- **Host-run peekd on macOS/Windows Docker Desktop** cannot reach container IPs; document "run peekd in a container on the backend network" there.
- **Migration numbering** collides with `plan/collaboration-sharing` (also 15). p2 uses the next free id when it runs; if `migrations` already has an entry named `upload_backends`, stop with `status=blocked`.
- **Password visibility may be gone** if `plan/collaboration-sharing` lands first. The relay only calls `viewerCanAccessUpload`, so nothing here depends on the password visibility; tests in p6 must not hard-code a password page. If `models.UploadVisibilityPassword` no longer exists, use the visibilities that do.
- **Go mux conflicts.** If registering a `/svc` or backend API pattern panics at startup in tests, the pattern overlaps an existing one; stop with `status=blocked` and report the panic text instead of renaming routes.
- **Coverage gate (90 %).** Every phase adds tests for its own code; `internal/backends/backendstest` needs its own test file. The integration test is skipped in the normal run and does not count.
- **`PullImage` stream errors** come with HTTP 200; a worker who only checks the status code gets it wrong. The test in p1 covers it.
- **A navigated frame keeps its `WindowProxy`.** `e.source === frame()` cannot tell the uploaded page from a site the viewer navigated the iframe to; the navigation lock in D8 is what stops that site from using the viewer's backend access. p7 asserts it.
- **The relay's path check is the main security boundary in the browser.** p7's tests must include the `..` and `%2e%2e` cases as asserted strings in `app.js` (the repository tests JavaScript by reading the asset source in Go tests, see `internal/web/assets_test.go`).

## Implementation manifest

```yaml
plan_slug: page-backends
feature_branch: feat/page-backends
max_parallel: 2
manual_steps_artifact: https://claude.ai/artifact/QumxcaN2UvxEirAAr5BttW
manual_steps_source: docs/plans/page-backends-plan-manual-steps.html
manual_before: []
manual_after:
  - id: ma1-compose-end-to-end
    title: Run the contact-form example end to end with Docker and Mailpit
    why: CI runs the container lifecycle against a real daemon, but not the browser relay (peek.fetch through the parent page), real email delivery, the idle stop, or the operator setup (socket permissions, network) on a real machine.
verify_after_merge:
  - >-
    go build ./...
  - >-
    go test -race -count=1 ./...
final_checks:
  - >-
    docs/plans/page-backends-plan.md and docs/plans/page-backends-plan-manual-steps.html are deleted and nothing links to them (grep -rn "page-backends-plan" . --exclude-dir=.git prints nothing)
  - >-
    mise run check-full passes
  - >-
    grep -n "PEEK_BACKENDS" README.md docs/operations.md docs/src/content/docs/reference.md matches in each file
  - >-
    the CI job backend-integration is green on the PR head
phases:
  - id: p1-docker-runtime
    title: Docker Engine API client and image reference rules in internal/backends
    depends_on: []
    complexity: M
    touches:
      - internal/backends/runtime.go
      - internal/backends/docker.go
      - internal/backends/docker_test.go
      - internal/backends/image.go
      - internal/backends/image_test.go
    brief: |
      Read docs/plans/page-backends-plan.md sections D2, D2.1, D2.2 and D2.3 first; they are the spec. Read AGENTS.md, CONTRIBUTING.md and docs/architecture.md. Look at internal/objectstore/s3.go for how this codebase writes a hand-made HTTP client.
      1. Create internal/backends/runtime.go with the package doc comment ("Package backends runs page backend containers through a container engine."), the Runtime interface, ContainerSpec, ContainerInfo, APIError (Error() returns "docker api: <status>: <message>") and IsNotFound exactly as in D2.1.
      2. Create internal/backends/docker.go: DockerRuntime, NewDockerRuntime(host) and one method per endpoint in D2.2, with dockerAPIVersion = "v1.43". Use net/http with a custom DialContext (unix socket path from the unix:// URL, or the host:port from tcp://), Transport.Proxy = nil, and requests to "http://docker/" + dockerAPIVersion + path. Build the create body from Go structs with json tags matching the field names in D2.2 (omit Cmd when empty). Use only the standard library; do not add a dependency.
      3. Create internal/backends/image.go with ValidateImageRef, Repository, ParseAllowedImages, ImageAllowed, RegistryHost and RegistryAuth exactly as in D2.3 (compile the regexp once at package level).
      4. internal/backends/docker_test.go: start an httptest.Server that plays the Docker API, and point NewDockerRuntime at "tcp://" + the server's host:port. Table-driven tests for every method: the request method, path (including the /v1.43 prefix and query string) and body it sends, and how it maps responses: 404 for ImageExists → false; 404 for RemoveContainer, RemoveVolume and StopContainer → nil; a non-2xx with {"message":"boom"} → *APIError with that message and IsNotFound only for 404; PullImage returning 200 with a stream containing {"error":"denied"} → error containing "denied"; the X-Registry-Auth header present only when registryAuth is non-empty; PullImage("alpine") sends fromImage=alpine&tag=latest, "ghcr.io/a/b:1.2" sends fromImage=ghcr.io/a/b&tag=1.2, and a digest ref sends tag=sha256:...; CreateContainer's body contains "ReadonlyRootfs":true, "CapDrop":["ALL"], "no-new-privileges:true", "PidsLimit":256 and the /data volume mount; ContainerLogs demultiplexes two frames (stdout and stderr) into their concatenated payloads; ListContainers sends filters={"label":[...]} and strips the "/" from names; ContainerIP errors when the network has no address. Also test NewDockerRuntime("unix:///tmp/x.sock") succeeds without dialing, and "https://x" returns the "unsupported docker host" error. Add one test that dials a real unix socket: listen on filepath.Join(t.TempDir(), "d.sock") with net.Listen("unix", ...) and serve a /_ping handler with http.Serve; Ping must succeed.
      5. internal/backends/image_test.go: table tests for ValidateImageRef (accept "alpine", "alpine:3.20", "ghcr.io/acme/app:1.2", "localhost:5000/x/y@sha256:" + 64 hex; reject "", "Alpine", "a b", "ghcr.io/acme/app:", 256-byte refs), Repository ("ghcr.io/acme/app:1.2" → "ghcr.io/acme/app", "localhost:5000/app" → "localhost:5000/app", digest stripped), ImageAllowed (prefix "ghcr.io/acme/" allows "ghcr.io/acme/app:1" and rejects "ghcr.io/acme-evil/app"; exact "ghcr.io/acme/app" allows "ghcr.io/acme/app:2" and rejects "ghcr.io/acme/app2"; empty list rejects everything), RegistryHost ("alpine" → "docker.io", "ghcr.io/a/b" → "ghcr.io", "localhost/x" → "localhost") and RegistryAuth (decodes back to the JSON; empty username → "").
      6. Run gofmt, go vet ./internal/backends/..., go test -race -count=1 ./internal/backends/..., and check coverage of the package is at least 90 % (go test -cover ./internal/backends).
      Stop condition: if the Docker API shape you need differs from D2.2 (for example a field name), stop with status=blocked and name the field; do not guess.
    acceptance:
      - >-
        go test -race -count=1 ./internal/backends/... passes
      - >-
        go test -cover ./internal/backends reports coverage of at least 90.0%
      - >-
        grep -n 'dockerAPIVersion = "v1.43"' internal/backends/docker.go matches
      - >-
        grep -n '"ReadonlyRootfs"' internal/backends/docker.go matches
      - >-
        go list -deps ./internal/backends | grep -c 'andras-tkcs/peek/internal/' prints 1 (only the package itself)
      - >-
        git diff --exit-code go.mod go.sum shows no change

  - id: p2-backend-store
    title: upload_backends and upload_backend_env tables, models and store methods
    depends_on: []
    complexity: S
    touches:
      - internal/db/schema.go
      - internal/db/migrations.go
      - internal/db/migrations_test.go
      - internal/db/backends.go
      - internal/db/backends_test.go
      - internal/models/models.go
    brief: |
      Read docs/plans/page-backends-plan.md section D3 first. Follow internal/db/grants.go and internal/db/grants_test.go as the pattern (sql.ErrNoRows on a miss, NULL for a zero creator id).
      1. internal/models/models.go: add UploadBackend and BackendEnvVar exactly as in D3, after UploadVersion, with doc comments.
      2. internal/db/schema.go: append the two CREATE TABLE statements from D3 after upload_slug_aliases.
      3. internal/db/migrations.go: append {<N>, "upload_backends", <the same SQL>} where <N> is the last id in the migrations slice plus one. If an entry named "upload_backends" already exists, stop with status=blocked.
      4. Create internal/db/backends.go with the seven methods in D3.
      5. internal/db/backends_test.go: set/get/list/delete round trips; the upsert replaces image and port; GetUploadBackend and DeleteUploadBackend return sql.ErrNoRows on a miss; DeleteUploadBackendEnv returns sql.ErrNoRows on a miss; env list is ordered by name; deleting the upload (Store.DeleteUpload) removes both kinds of rows; DeleteUploadVersion for a version removes only that version's backend row; SetUploadBackend for a version that does not exist fails (foreign key).
      6. internal/db/migrations_test.go: add TestMigrationAddsUploadBackends using migCovPrepare(t, <N-1>, ...) the way TestMigrationRenamesPrivateVisibilityToSignedIn does (around migrations_test.go:284). Because schema.go creates the tables on Open anyway, assert that <N> is recorded in schema_migrations and that both tables exist afterwards.
      7. Run gofmt, go vet ./internal/db/... ./internal/models/..., go test -race -count=1 ./internal/db/... .
    acceptance:
      - >-
        go test -race -count=1 ./internal/db/... passes
      - >-
        grep -n '"upload_backends"' internal/db/migrations.go matches
      - >-
        grep -n 'CREATE TABLE IF NOT EXISTS upload_backend_env' internal/db/schema.go matches
      - >-
        grep -n 'type UploadBackend struct' internal/models/models.go matches

  - id: p3-backend-manager
    title: Container lifecycle manager and the FakeRuntime test double
    depends_on: [p1-docker-runtime]
    complexity: M
    worker_model: opus
    worker_model_reason: The manager's start protocol (waiting on in-flight starts without holding the mutex, image changes during a start, eviction and idle reaping) is subtle concurrency that a race-detector test can only partly catch.
    touches:
      - internal/backends/manager.go
      - internal/backends/manager_test.go
      - internal/backends/backendstest/fake.go
      - internal/backends/backendstest/fake_test.go
    brief: |
      Read docs/plans/page-backends-plan.md sections D2.4 and D2.5 first; the locking design there is mandatory. This phase touches concurrency: run the race detector.
      1. Create internal/backends/backendstest/fake.go: FakeRuntime implementing backends.Runtime as in D2.5, guarded by a sync.Mutex, with a compile-time check `var _ backends.Runtime = (*FakeRuntime)(nil)`. CreateContainer returns ids "c1", "c2", ...; ContainerIP returns "127.0.0.1"; ListContainers filters its containers by all given labels; StopContainer marks State "exited"; RemoveContainer deletes. Provide func NewFakeRuntime() *FakeRuntime.
      2. internal/backends/backendstest/fake_test.go: exercise every method, the configured errors and the recorded slices, so the package reaches at least 90 % coverage on its own.
      3. Create internal/backends/manager.go with Config, Limits, Spec, Endpoint, ErrNotRunning, NewManager, the methods, ContainerName and VolumeName exactly as in D2.4, following the numbered Ensure algorithm and the rule that no Runtime call happens while the mutex is held. Generate the token with crypto/rand (32 bytes, hex). Default Dial is (&net.Dialer{}).DialContext and default Now is time.Now. Run uses a time.Ticker of one minute and returns when ctx is done.
      4. internal/backends/manager_test.go, using backendstest.FakeRuntime and an httptest.Server whose port is the Spec's Port (ContainerIP is 127.0.0.1): Ensure pulls only when the image is missing, creates with the expected name, labels, volume, env (PORT, PEEK_BACKEND_TOKEN of 64 hex chars, PEEK_UPLOAD_ID, PEEK_VERSION and the sorted user env) and returns "http://127.0.0.1:<port>"; a second Ensure reuses the container (one CreateContainer); 20 concurrent Ensure calls for the same key create exactly one container (use sync.WaitGroup; run with -race); a changed Image stops the old container and creates a new one; a second Ensure with the same image that arrives while the first is still starting (block the fake's StartContainer on a channel) waits and gets the same endpoint with one CreateContainer; a failed start does not delete a newer entry for the same key; MaxRunning 1 evicts the least recently used backend; ReapIdle with an injected Now stops only idle backends; a readiness failure (Dial always errors and a short wait) removes the container and returns an error mentioning the port — make the 30 s readiness timeout and 200 ms interval package-level variables (readinessTimeout, readinessInterval) so the test can shorten them; PullErr and StartErr propagate and leave no entry (the next Ensure tries again); StopUpload stops all versions of an upload; RemoveUploadData also removes the volume; Logs returns ErrNotRunning for an unknown backend; Start removes leftover containers with this instance's labels and leaves other instances' containers alone; Close stops everything; Ensure returns ctx.Err() when its context is cancelled while another call is starting the same backend.
      5. Run gofmt, go vet ./internal/backends/..., go test -race -count=1 ./internal/backends/... and go test -cover ./internal/backends/... .
      Stop condition: if a test can only pass by holding the mutex across a Runtime call, the design is being violated; stop with status=blocked and describe the case.
    acceptance:
      - >-
        go test -race -count=1 ./internal/backends/... passes
      - >-
        go test -cover ./internal/backends/... reports at least 90.0% for both internal/backends and internal/backends/backendstest
      - >-
        go test -race -count=5 -run 'Concurrent' ./internal/backends passes
      - >-
        grep -n 'func (m \*Manager) Ensure(ctx context.Context, spec Spec) (Endpoint, error)' internal/backends/manager.go matches

  - id: p4-server-wiring
    title: Startup flags, server wiring, runtime settings and backend spec helper
    depends_on: [p2-backend-store, p3-backend-manager]
    complexity: M
    touches:
      - internal/peekd/run.go
      - internal/peekd/run_test.go
      - internal/peekd/serve_test.go
      - internal/server/server.go
      - internal/server/lifecycle.go
      - internal/server/settings.go
      - internal/server/settings_test.go
      - internal/server/security.go
      - internal/server/backend_settings.go
      - internal/server/backend_settings_test.go
      - internal/server/backend_helpers_test.go
    brief: |
      Read docs/plans/page-backends-plan.md sections D4 and D5 first. Look at how Groups is passed from internal/peekd/run.go into server.Config (server.go:55) and copy that shape.
      1. internal/peekd/run.go: add the three flags of D4 next to the storage flags, validateBackendConfig with the exact error texts (called from parseServeConfig after validateServeConfig; do not change validateServeConfig's signature), the serveConfig fields, the package variable newBackendRuntime, the 5 s Ping on startup with the exact error text, and pass BackendRuntime and BackendNetwork into server.Config.
      2. internal/server/server.go: add Config.BackendRuntime (backends.Runtime) and Config.BackendNetwork (string); add the Server fields backends, backendLimiter, backendClient; in New, do steps 1–3 of D5 when BackendRuntime is non-nil (create backendLimiter and backendClient unconditionally).
      3. internal/server/lifecycle.go: in Close, stop the manager as described in D5.
      4. internal/server/settings.go: add the eight settingsMeta entries of D5 with the exact labels and descriptions, and their validation in normalizeSettingValue with the exact error texts. internal/server/security.go: add backend_registry_password to secretSettingKeys.
      5. Create internal/server/backend_settings.go with backendLimits, backendImageAllowed and backendSpec as in D5.
      6. Create internal/server/backend_helpers_test.go with a helper `newBackendTestServer(t *testing.T) (*Server, *backendstest.FakeRuntime, string)` that builds a Server the way newHandlerTestServer (internal/server/handler_helpers_test.go) does but with Config.BackendRuntime set to a new FakeRuntime and BackendNetwork "peek-test", returning the server, the fake and the admin token. Later phases reuse it; keep it general.
      7. Tests: internal/peekd/run_test.go — invalid --backends value and invalid network name fail with the exact messages; --backends docker with newBackendRuntime replaced by a FakeRuntime starts and passes the runtime through (use the runServeUntilSIGTERM harness in internal/peekd/serve_test.go, extending that file if the test fits there better); a Ping error stops startup with "docker is not reachable at". internal/server/settings_test.go — each new key accepts its valid range and rejects out-of-range values with the exact message; the registry password is stored encrypted and shown as "••••" by GET /api/settings. internal/server/backend_settings_test.go — defaults when settings are empty; backendImageAllowed with prefix and exact entries; backendSpec decrypts env values (and fails for a value encrypted with another secret), converts memory and CPU, and sets RegistryAuth only for the matching registry host; New with a FakeRuntime stores backend_instance_id once (a second New on the same data dir keeps it) and calls EnsureNetwork; Close stops a running backend.
      8. Run gofmt, go vet ./..., go test -race -count=1 ./internal/peekd/... ./internal/server/... .
    acceptance:
      - >-
        go test -race -count=1 ./internal/peekd/... ./internal/server/... passes
      - >-
        grep -n '"backend_allowed_images"' internal/server/settings.go matches
      - >-
        grep -n '"backend_registry_password": *true' internal/server/security.go matches
      - >-
        grep -n 'PEEK_BACKENDS' internal/peekd/run.go matches
      - >-
        go build ./... succeeds

  - id: p5-backend-api
    title: Owner API for backends and environment variables
    depends_on: [p4-server-wiring]
    complexity: M
    touches:
      - internal/server/api_backends.go
      - internal/server/api_backends_test.go
      - internal/server/routes.go
    brief: |
      Read docs/plans/page-backends-plan.md section D6 (the table and the Rules, not the "Upload API" and "Cleanup hooks" paragraphs, which are p6) first. Pattern: internal/server/api_grants.go and its test file.
      1. Create internal/server/api_backends.go with backendUpload (copied from grantUpload), validateBackendInput with the exact signature in D6 (p6 reuses it from the upload API), a version resolver for {n} accepting "latest", and one handler per row of the D6 table, with the exact status codes, messages, response shapes and audit actions (use auditDetail as api_grants.go does). Env values are encrypted with encryptSecret(s.secret, value) before SetUploadBackendEnv. "running" in the GET response is s.backends.Running(u.ID, version) when backends are enabled, else false.
      2. internal/server/routes.go: register the seven routes with methods, next to the grants routes, wrapped in s.authToken like the grants routes.
      3. internal/server/api_backends_test.go, using newBackendTestServer from internal/server/backend_helpers_test.go: owner and admin succeed, another account gets 403 "not owner", missing token 401; PUT validates image (invalid ref, not allowed — set backend_allowed_images first via s.encryptedSetSetting) and port; "latest" resolves; unknown version 404; PUT on a version with a running backend stores the new image, then stops the container (FakeRuntime.Stopped); DELETE 404 when none; env set rejects PORT, PEEK_X, lower-case names, 4097-byte values and the 51st variable with the exact messages; env values are stored encrypted (the stored value differs from the plaintext and decryptSecret returns it) and never appear in the GET response; logs returns the FakeRuntime's LogsData for a running backend and 404 otherwise; tail outside 1..2000 is 400 "tail must be between 1 and 2000"; restart stops all versions; each mutating route writes its audit action (read with s.store.ListAuditLog). Also build a Server without BackendRuntime (newHandlerTestServer) and check PUT answers 409 "backends are not enabled on this server" while GET returns "enabled": false.
      4. Run gofmt, go vet ./internal/server/..., go test -race -count=1 ./internal/server/... .
      Stop condition: if registering a route panics with a pattern conflict, stop with status=blocked and paste the panic.
    acceptance:
      - >-
        go test -race -count=1 ./internal/server/... passes
      - >-
        go test -count=1 -run 'Backend' ./internal/server -v lists at least 10 passing tests
      - >-
        grep -n 'PUT /api/uploads/{slug}/versions/{n}/backend' internal/server/routes.go matches

  - id: p6-upload-and-relay
    title: Backend fields on upload, cleanup hooks, and the /svc relay
    depends_on: [p5-backend-api]
    complexity: M
    touches:
      - internal/server/api_uploads.go
      - internal/server/upload_backend_test.go
      - internal/server/upload_delete.go
      - internal/server/lifecycle.go
      - internal/server/backend_proxy.go
      - internal/server/backend_proxy_test.go
      - internal/server/middleware.go
      - internal/server/middleware_test.go
      - internal/server/routes.go
    brief: |
      Read docs/plans/page-backends-plan.md section D6 ("Upload API" and "Cleanup hooks" paragraphs) and section D7 first.
      1. internal/server/api_uploads.go: read backend_image and backend_port (multipart fields, or query parameters on the raw-HTML path), validate before creating with s.validateBackendInput (defined in api_backends.go by p5; if it is missing, stop with status=blocked), write the row after create or version add, inherit on a version upload without backend_image, and add "backend_image" (omitempty) to uploadResp.
      2. internal/server/upload_delete.go and internal/server/lifecycle.go: the two cleanup hooks from D6.
      3. internal/server/middleware.go: exempt paths with the prefix "/svc/" in bodyLimitExempt.
      4. Create internal/server/backend_proxy.go with handleBackendProxy, backendMaxBody and backendMaxResponse following D7 steps 1–9 exactly (header names, messages, status codes). internal/server/routes.go: register the five method patterns of D7 in the "Page-side API" block.
      5. Tests in internal/server/upload_backend_test.go: upload with backend_image creates the row; invalid or disallowed image → 400 and no page created (ListUploadsByOwner is empty); backends off → 409; version upload without backend_image inherits the previous row; with backend_image replaces it; delete page calls RemoveUploadData after the row is gone (FakeRuntime.VolumesRemoved has the volume name and GetUpload already fails); pruning a version stops its backend.
      6. Tests in internal/server/backend_proxy_test.go, with newBackendTestServer and an httptest.Server as the backend (its port as the backend Port): a public page relays method, path, query and body and returns status, Content-Type and body, plus Cache-Control no-store and the sandbox CSP; the backend sees X-Peek-Backend-Token equal to the PEEK_BACKEND_TOKEN env of the created container, X-Peek-Upload-Id, X-Peek-Version, and X-Peek-Viewer only when the hn_vid cookie is sent; a signed-in viewer (asSession) on a signed-in page adds X-Peek-User-Id and X-Peek-User-Email, and on a public page does not; a path with %3F ("/svc/<slug>/v/1/api/a%3Fb") reaches the backend with RawPath "/api/a%3Fb" and an empty query; incoming Cookie, Authorization and X-Peek-User-Email headers are not forwarded; missing X-Peek-Svc → 403; Sec-Fetch-Site: cross-site → 403; a signed-in page without session → the same status and message as the comments API; a version without backend → 404 "this page version has no backend"; backends off → 404; a 2 MiB request body → 413; a backend answering 9 MiB → 502 "backend response too large"; a closed backend server → 502 "backend unavailable"; a backend sleeping longer than the client timeout → 504 (make the timeout testable by setting s.backendClient.Timeout in the test); 241 requests in a minute from one IP → 429. middleware_test.go: a 1 MiB POST to /svc/... is not cut at 64 KiB by the middleware.
      7. Run gofmt, go vet ./..., go test -race -count=1 ./internal/server/... .
    acceptance:
      - >-
        go test -race -count=1 ./internal/server/... passes
      - >-
        grep -n 'POST /svc/{slug}/v/{n}/{path...}' internal/server/routes.go matches
      - >-
        grep -n 'X-Peek-Backend-Token' internal/server/backend_proxy.go matches
      - >-
        grep -n '"/svc/"' internal/server/middleware.go matches

  - id: p7-bridge-fetch
    title: peek.fetch in the bridge and the parent relay in app.js
    depends_on: []
    complexity: M
    touches:
      - internal/web/assets/bridge.js
      - internal/web/assets/app.js
      - internal/web/assets_test.go
    brief: |
      Read docs/plans/page-backends-plan.md section D8 first, and the "Browser JavaScript" paragraph of CONTRIBUTING.md (IIFE, "use strict", no HTML string insertion, validate both sides of postMessage). The server route /svc may not exist yet on this branch; that is fine, the contract is D7.
      1. internal/web/assets/bridge.js: add peek.fetch exactly as D8 describes (null body for 204, 205 and 304), with a file-local pending map, the 35 s timeout, settleFetch, and the "fetch-result" branch in the existing message listener. Update the header comment as D8 says. Keep ES5-style syntax consistent with the rest of the file (var, function).
      2. internal/web/assets/app.js: add the "fetch" branch in bindBridge and the relayFetch method exactly as D8 describes, including the navigation lock (frameLoads counted in the existing load listener), replies through postToFrame, the URL prefix check, the 16-request cap and the error strings.
      3. internal/web/assets_test.go: the repository tests JavaScript by asserting on the asset source (see TestBridgeMessageHandlerChecksParentSource). Add tests that assert: bridge.js contains `hn: "fetch"`, `"peek.fetch path must start with /"`, `"peek.fetch timed out"` and handles `d.hn === "fetch-result"` inside the listener that checks `e.source !== parent`; app.js contains `data.hn === "fetch"`, `"X-Peek-Svc": "1"`, `cache: "no-store"`, `redirect: "error"`, `frameLoads`, `"page navigated; reload to use the backend"`, `url.pathname.startsWith(prefix)`, `url.origin === location.origin` and `"too many concurrent peek.fetch requests"`. TestRuntimeJSAvoidsHTMLStringInsertion must keep passing.
      4. Add a Playwright-free behavioural check with node only if node is available in the container (`node --version`): write a throwaway script under the scratchpad, not in the repo, that evaluates the URL check from relayFetch for "/../api/x", "/%2e%2e/api/x" and "/ok?a=1" with base "http://h" and slug "s", version 1, and confirm only the last is accepted. Report the result in your summary; do not commit the script.
      5. Run go test -count=1 ./internal/web/... and the full mise run test.
    acceptance:
      - >-
        go test -count=1 ./internal/web/... passes
      - >-
        grep -n 'peek.fetch path must start with /' internal/web/assets/bridge.js matches
      - >-
        grep -n 'url.pathname.startsWith(prefix)' internal/web/assets/app.js matches
      - >-
        grep -n '"X-Peek-Svc": "1"' internal/web/assets/app.js matches

  - id: p8-cli-backend
    title: peek upload --backend and the peek backend command
    depends_on: [p5-backend-api]
    complexity: M
    touches:
      - internal/cli/backend_command.go
      - internal/cli/backend_command_test.go
      - internal/cli/upload_command.go
      - internal/cli/upload_command_test.go
      - internal/cli/commands.go
      - internal/cli/commands_test.go
    brief: |
      Read docs/plans/page-backends-plan.md sections D6 (routes and response shapes) and D9 first. Patterns: internal/cli/grants_command.go (+ test) for a subcommand with a slug, internal/cli/login_command.go for the --token warning and stdin reading, internal/cli/path_segments.go for escaping slugs in URLs.
      1. internal/cli/upload_command.go: parse --backend and --backend-port, validate as D9 says, and write the backend_image / backend_port fields in writeMultipartUpload; print "backend: <image>" after the URL when the response has backend_image.
      2. Create internal/cli/backend_command.go with cmdBackend dispatching show / set / remove / env (set, unset, and listing when only a slug is given) / restart / logs, calling the D6 routes, with the D9 output formats, the --value warning text and the usage line.
      3. internal/cli/commands.go: add "backend" to the dispatcher and the help text lines for every D9 form (same column layout as the existing help).
      4. Tests with httptest servers as the other CLI tests do: each subcommand hits the right method and path (slug escaped, --version default latest), sends the right JSON, prints the expected output; env set reads the value from stdin with --value-stdin and warns on --value; --backend-port without --backend errors; upload sends the two multipart fields; commands_test.go covers the help text containing "peek backend logs".
      5. Run gofmt, go vet ./internal/cli/..., go test -race -count=1 ./internal/cli/... .
    acceptance:
      - >-
        go test -race -count=1 ./internal/cli/... passes
      - >-
        grep -n 'case "backend"' internal/cli/commands.go matches
      - >-
        grep -n 'backend_image' internal/cli/upload_command.go matches

  - id: p9-admin-backends-tab
    title: Backends tab on the Admin page
    depends_on: [p4-server-wiring]
    complexity: S
    touches:
      - internal/server/settings.go
      - internal/server/web_admin.go
      - internal/server/web_admin_test.go
      - internal/web/renderer.go
      - internal/web/renderer_test.go
      - internal/web/templates/admin.gohtml
    brief: |
      Read docs/plans/page-backends-plan.md section D10 first. Pattern: the Storage tab in internal/web/templates/admin.gohtml (lines ~114 and ~173) and dashboardStorageSettings in internal/server/settings.go.
      1. internal/web/renderer.go: add BackendSettings {Enabled bool; Fields []SettingRow} and the Backends field on DashboardSettings.
      2. internal/server/settings.go: fill Backends.Fields in dashboardSettingsPanel with dashboardSettingRow for the eight keys in the D5 table order. In internal/server/web_admin.go (around line 44) the struct literal sets `SettingsPanel: dashboardSettingsPanel(...)`; build the panel into a variable first, set `panel.Backends.Enabled = s.backends != nil`, and use it. Every other place that builds the admin view (grep -n dashboardSettingsPanel internal/server) gets the same treatment.
      3. internal/web/templates/admin.gohtml: add the Backends tab button after Limits and its panel with one labelled text input per field (type="password" and an empty value for the secret, as the S3 secret does), and the D10 line when Enabled is false. Use only CSS classes that already appear in admin.gohtml so internal/web/assets/pines.css does not need regenerating; if you need a class that is not in pines.css, stop with status=blocked.
      4. Tests: web_admin_test.go renders /admin as an admin and finds the Backends tab, the eight input names, and the "Backends are off" line on a server without BackendRuntime but not on newBackendTestServer; posting the form with backend_memory_mb=512 stores it, and an out-of-range value re-renders with the error. renderer_test.go: the template renders with an empty BackendSettings.
      5. Run gofmt, go vet ./..., go test -race -count=1 ./internal/server/... ./internal/web/... .
    acceptance:
      - >-
        go test -race -count=1 ./internal/server/... ./internal/web/... passes
      - >-
        grep -n "settingsTab === 'backends'" internal/web/templates/admin.gohtml matches
      - >-
        git diff --exit-code internal/web/assets/pines.css shows no change

  - id: p10-example-contact-form
    title: Contact-form example backend and the compose backends profile
    depends_on: []
    complexity: S
    touches:
      - examples/contact-form/**
      - docker-compose.yml
    brief: |
      Read docs/plans/page-backends-plan.md sections D7 (the headers a backend receives), D8 (peek.fetch) and D11 first.
      1. Create examples/contact-form/go.mod (module github.com/andras-tkcs/peek/examples/contact-form, go 1.26, no requires), main.go, index.html, Dockerfile and README.md exactly as D11 describes. main.go uses only the standard library, returns errors as JSON {"error": "..."} with the right status codes (400 for bad input, 401 for a wrong token, 502 when SMTP fails), and serializes writes to /data/submissions.jsonl with a sync.Mutex. Add main_test.go with httptest tests for the token check, input validation and the submissions file (point the data dir at t.TempDir() through a DATA_DIR env var defaulting to /data, and the mail sender at a function variable so tests do not need SMTP).
      2. docker-compose.yml: add the backends profile services and network from D11. Keep the existing services unchanged.
      3. Verify: (cd examples/contact-form && go vet ./... && go test -count=1 ./...), gofmt -l examples/ prints nothing, and from the repo root `go list ./... | grep -c examples` prints 0 (the nested module is outside the root module). If a docker daemon is reachable (docker info succeeds), also run docker build -t peek-example-contact:dev examples/contact-form; otherwise say in your summary that the image build is checked by CI in p11.
    acceptance:
      - >-
        (cd examples/contact-form && go test -count=1 ./...) passes
      - >-
        gofmt -l examples/ prints nothing
      - >-
        go list ./... | grep -c examples prints 0
      - >-
        grep -n 'profiles:' -A1 docker-compose.yml | grep -c backends prints at least 1

  - id: p11-ci-docker-integration
    title: Real-Docker integration test and CI job
    depends_on: [p3-backend-manager, p10-example-contact-form]
    complexity: S
    touches:
      - internal/backends/docker_integration_test.go
      - .github/workflows/ci.yml
    brief: |
      Read docs/plans/page-backends-plan.md section D11 (the CI paragraph) first.
      1. Create internal/backends/docker_integration_test.go with TestDockerIntegration: skip unless PEEK_DOCKER_TEST=1; image from PEEK_DOCKER_TEST_IMAGE. Build a DockerRuntime for unix:///var/run/docker.sock, a Manager with Network "peek-it-" + 6 random hex chars and Instance "itest001", Start it, Ensure a Spec (UploadID 1, Version 1, the image, Port 8080, Env MAIL_TO/MAIL_FROM/SMTP_HOST set to dummy values, MemoryBytes 128<<20, NanoCPUs 250_000_000). GET endpoint.URL + "/api/healthz" with X-Peek-Backend-Token = endpoint.Token → 200 "ok"; without the token → 401. Logs returns no error. Then Close; ListContainers with label peek.instance=itest001 returns none; RemoveVolume for VolumeName("itest001", 1); remove the network in t.Cleanup through a DELETE /networks/{name} call (add no method to Runtime for it; use a small raw HTTP helper in the test file).
      2. .github/workflows/ci.yml: add a job backend-integration (runs-on ubuntu-latest, timeout-minutes 15, same checkout and setup-go steps and pinned action SHAs as the build job, GOFLAGS -mod=readonly) with steps: docker build -t peek-example-contact:ci examples/contact-form, then PEEK_DOCKER_TEST=1 PEEK_DOCKER_TEST_IMAGE=peek-example-contact:ci go test -count=1 -run '^TestDockerIntegration' -v ./internal/backends.
      3. Run go vet ./internal/backends/... and go test -count=1 ./internal/backends/... locally (the test must report SKIP). CI only runs on pull requests to main, so the job first runs on the feature PR; final_checks requires it to be green there. Check the YAML parses: python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))".
    acceptance:
      - >-
        go test -count=1 -run '^TestDockerIntegration' -v ./internal/backends prints "--- SKIP" without PEEK_DOCKER_TEST
      - >-
        grep -n 'backend-integration:' .github/workflows/ci.yml matches
      - >-
        python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" exits 0

  - id: p12-docs-and-retire
    title: Documentation, skills, and retiring the plan
    depends_on: [p6-upload-and-relay, p7-bridge-fetch, p8-cli-backend, p9-admin-backends-tab, p11-ci-docker-integration]
    complexity: M
    touches:
      - README.md
      - docs/architecture.md
      - docs/operations.md
      - docs/src/content/docs/reference.md
      - docs/src/content/docs/server-setup.md
      - docs/src/content/docs/using-peek.md
      - skills/peek/SKILL.md
      - skills/peek-server/SKILL.md
      - docs/plans/page-backends-plan.md
      - docs/plans/page-backends-plan-manual-steps.html
    brief: |
      Read docs/plans/page-backends-plan.md in full first, then the code as merged (the design may have shifted in details; document what the code does). Write Markdown as flowing lines without manual wrapping (AGENTS.md).
      1. README.md: a "Page backends" feature bullet; the --backends, --docker-host, --backend-network rows in the server configuration table; the peek upload --backend and peek backend lines in the CLI reference; a short "Page backends" section (what peek.fetch is, the headers a backend receives, link to examples/contact-form); new Security model rows (backend containers: fixed limits, read-only rootfs, no capabilities, no published ports, image allowlist; /svc: same access check as the page, custom header against cross-site calls, per-container token).
      2. docs/architecture.md: internal/backends in Package Boundaries and the Dependency Direction rule from D2 (server and peekd may import backends; backends imports no other internal package).
      3. docs/operations.md: a "Page Backends" section: the three startup settings, that the Docker socket gives root on the host (recommend rootless Docker or Podman, or a dedicated VM), socket permissions for the scratch image (uid 65532, group_add), the network and why peekd must be on it when it runs in a container, the eight Admin settings, idle stop and the cap, logs, that backend volumes (peek-<instance>-data-u<id>) are not in peekd backup and are deleted with the page, macOS/Windows Docker Desktop note, and under Upgrades And Rollbacks the migration that adds upload_backends and upload_backend_env (older binaries ignore both tables).
      4. docs/src/content/docs/reference.md, server-setup.md, using-peek.md: the same facts in the site's structure (flags and settings in reference, operator setup in server-setup, peek.fetch and the CLI in using-peek).
      5. skills/peek/SKILL.md: how an agent uploads a page with --backend and uses peek.fetch; skills/peek-server/SKILL.md: enabling backends.
      6. Delete docs/plans/page-backends-plan.md and docs/plans/page-backends-plan-manual-steps.html; grep -rn "page-backends-plan" . --exclude-dir=.git must print nothing.
      7. Dispatch the pages.yml workflow on the feature branch with the GitHub MCP actions_run_trigger tool to check the docs site builds, and read the result with actions_get.
      8. Run mise run check-full.
    acceptance:
      - >-
        test ! -e docs/plans/page-backends-plan.md
      - >-
        grep -rn "page-backends-plan" . --exclude-dir=.git prints nothing
      - >-
        grep -n "PEEK_BACKENDS" README.md docs/operations.md docs/src/content/docs/reference.md matches in each file
      - >-
        grep -n "internal/backends" docs/architecture.md matches
      - >-
        the dispatched pages.yml run on the feature branch succeeds
      - >-
        mise run check-full passes
```
