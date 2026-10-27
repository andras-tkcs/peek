# Plan: fix the findings of the 2026-10-27 repository review

## Goal

Fix every finding in the "Findings to fix" section of the repository review [repo-2026-10-27](https://github.com/andras-tkcs/peek/blob/review/repo-2026-10-27/docs/plans/repo-2026-10-27-review.md) (45 findings: SEC-1 to SEC-11, TST-1 to TST-12 without TST-7, DOC-1 to DOC-17 without DOC-7 and DOC-11, WEB-1 to WEB-9 without WEB-7). For operators and contributors this means: every PR is gated by CI jobs that build the Docker image, cross-compile, build the docs site, run an end-to-end test of the real binaries and a browser test of the `peek.fetch` trust boundary; a release tag can only publish a commit on `main` that passed tests, and its artifacts carry provenance; a truncated `secret.key` stops `peekd` instead of silently destroying sessions and encrypted settings; `peek <command> --help` and `peekd --help` work; and the README, the agent skills, the operator guide and the docs website match the code. The repository owner finishes the GitHub settings half (required checks, merge-commit-only, tag ruleset, security features) from the step-by-step page linked in "Manual steps".

## Current state

Reviewed at `183ecc3`, which is still `origin/main` on 2026-10-27, so every finding's evidence was re-checked against the current code and all 45 hold. Notable facts beyond the review text:

- CI (`.github/workflows/ci.yml:16-66`) has two jobs, `build` and `backend-integration`. Only `build` is a required check (ruleset 24841195). `pages.yml:3-4` is `workflow_dispatch` only. `release.yml` has jobs `build` (matrix, `contents: write`), `checksums` (`needs: build`), `sbom` and `docker` (no `needs`); `:138` is `type=raw,value=latest`. `docker-main.yml:3-6` triggers on push to main. No checkout sets `persist-credentials`.
- `internal/server/access_matrix_test.go:226` builds the "bad signature" cookie as `strings.TrimSuffix(good, good[len(good)-1:]) + "0"`, which is the valid cookie when the last hex digit is already `0` (TST-1).
- `internal/server/bootstrap.go:37-60` `loadOrCreateSecret` silently regenerates a `secret.key` shorter than 32 bytes and writes it with `os.WriteFile` (not atomic). Two existing tests assert the replacement: `internal/server/bootstrap_test.go:81-123` (case `short_existing_secret_is_replaced`) and `:151-160` (subtest `short existing secret is replaced`).
- `internal/server/oauth_profile.go:54-58` `verifyIDTokenNonce` has the `nonce == ""` guard with no test (TST-10).
- `internal/objectstore/s3_signing.go:15` signs with `time.Now().UTC()`; `S3Storage` (`internal/objectstore/s3.go:13-17`) has no clock field. The signer signs every header present on the request (`canonicalHeaders`, `:52-69`).
- `internal/backends/manager_test.go:314` sleeps 20 ms to let a second `Ensure` caller reach its wait; the wait is the `select` on `e.ready` in `internal/backends/manager.go:191-196`. `internal/backends/export_test.go` already exports test hooks (`TrackedForTest`).
- `internal/peekd/serve_test.go:35-46` `freeAddr` closes the listener and binds later; `runServe` (`internal/peekd/run.go:280-387`) calls `hs.ListenAndServe()`.
- `internal/peekd/run.go:129` metrics-token help says "(empty = unauthenticated)"; `:30` struct comment says "(empty = open)"; `:337` logs `metrics_auth`. `parseServeConfig` (`:78`) has no `fs.Usage`; `Run` (`:66-70`) returns 2 for `flag.ErrHelp`. `runBackup` (`internal/peekd/backup.go:15-27`) and `runHealthcheck` (`internal/peekd/healthcheck.go:11-17`) also return 2 on `-h`.
- `internal/cli/commands.go:73-127` holds the whole usage text, printed to stderr; subcommands parse flags by hand and reject `--help` as "unknown flag". `peek login --oauth` (`internal/cli/login_command.go:55-56`, forces browser login and fails when the server has none), `peek version`, and `peek backend env set ... --value <v>` (`internal/cli/backend_command.go:262`) are missing from the usage text. `TestRunHelpVersionAndUnknown` (`internal/cli/commands_test.go:84`) asserts help goes to stderr.
- The CLI tests use 39 hand-written fakes; `internal/architecture_test.go` checks only non-test imports (`go list` `Imports`), so a test file in package `cli` may import `internal/server` and `internal/db`. `internal/server/api_test.go:18-43` `newTestServer` shows how to build a real server with a seeded admin token (`store.CreateToken`).
- `peek upload` prints `uploaded:`, `slug:`, `version:` and `visibility:` lines, plus `version url:` only with `--slug` (`internal/cli/upload_command.go:143-152`).
- First-run setup writes the setup code to `<data>/setup.key` (`internal/server/bootstrap.go:63-66`); `scripts/gen-screenshots.sh:66-101` already scripts setup + CSRF + CLI device-flow login with curl. The API key page renders the key in `<code id="hn-api-key" ...>` (`internal/web/templates/api_key_shown.gohtml:17`); keys start with `peek_` (`internal/server/web_api_keys.go:20`).
- The viewer's `relayFetch` (`internal/web/assets/app.js:325-375`) rejects any `peek.fetch` path that leaves `/svc/<slug>/v/<n>/` with `invalid peek.fetch path`; messages whose `e.source` is not the frame are ignored (`:275`). `#hn-bar` is shown by `x-show="!barHidden"` (`internal/web/templates/page.gohtml:40`) and toggled by `{hn: "togglebar"}`.
- Migrations by first release (computed from `git show <tag>:internal/db/migrations.go`): v0.7.1 has 1–6, v0.8.0 adds 7–9, v0.9.0 adds 10, v0.10.0 adds 11–13, v0.13.0 adds 14–15, v0.14.0 adds 16, and 17 (`provisioning`) is unreleased. The un-numbered "This release" notes in `docs/operations.md:143-161` (raw-route removal and CSP sandbox, trusted-proxy CIDRs, API-token domain rules) were all written in commit `d8379f0`, first released in v0.10.0.
- A database created by v0.10.0 and opened by today's code differs from a fresh database in exactly one column property: `uploads.visibility` defaults to `'password'` instead of `'restricted'` (measured on 2026-10-27 with v0.10.0's `db.Open`, comparing `pragma_table_info` of every table). It is harmless today because the only insert, `internal/db/uploads.go:60`, always sets `visibility`.
- v0.10.0's `mise.toml` pins Go 1.26.9, which `mise` cannot download in the container; building that tag works with the already-installed toolchain: `GO="$(go env GOROOT)/bin/go"` from the repo root, then `GOTOOLCHAIN=local "$GO" build ...` inside the worktree.
- `docs/public/assets/screenshots/*.png` and `assets/screenshots/*.png` hold the same 11 stale images (last regenerated in `fdf745e`); `scripts/gen-screenshots.sh` writes `assets/screenshots/` and mirrors to `docs/public/assets/screenshots/`. README references neither copy; the site uses `docs/public/assets/screenshots/`. `docs/public/assets/demo.mp4` is referenced nowhere (`scripts/gen-assets.sh:154-155` mirrors it). `gen-screenshots.sh` needs `sqlite3` (install with `apt-get update && apt-get install -y sqlite3` in the container), `pnpm install` at the repo root, and Chromium (`/opt/pw-browsers/chromium-*/chrome-linux64/chrome` in the container).
- The docs site's sidebar section links are hard-coded in `docs/src/components/DocsShell.astro:37-127` (`anchorsBySlug`); group titles are `<h2>` before the page `<h1>`; `docs/src/pages/manual.astro:35` hard-codes `/peek/docs/reference/`; `docs/src/pages/index.astro:35` shows literal backticks around `Peek`.
- The devflow profile schema allows `git.merge_style` values `merge-commit` and `squash` only, and `docs.changelog` needs `file` and `section` (for example `## [Unreleased]`).
- Coverage today: total 96.3%; `internal/server` 96.7%, `internal/db` 93.8%, `internal/objectstore` 99.1%. `scripts/coverage-gate.sh` checks only the total, default 90.0.

## Design

Every name, string and command below is final. Phases point here by subsection.

### D1. CI jobs on every PR (`.github/workflows/ci.yml`, `pages.yml`) — SEC-1 code part, SEC-6, TST-5, TST-12, WEB-5, DOC-9 (example module)

- Every `actions/checkout` step in every workflow gets `with: persist-credentials: false` (merge it into an existing `with:` where there is one). Keep the existing pinned SHAs and `# vX` comments; reuse these exact pins in new jobs: checkout `11d5960a326750d5838078e36cf38b85af677262 # v4.4.0`, setup-go `40f1582b2485089dde7abd97c1529aa768e1baff # v5.6.0`, pnpm/action-setup `b906affcce14559ad1aafd4ab0e942779e9f58b1 # v4.3.0` with `version: 10.24.0`, setup-node `49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0` with `node-version: 22`.
- No job has a `paths:` filter and no workflow-level `paths:` is added to `ci.yml`, so every required check reports on every PR.
- `backend-integration`: append a step `name: Example module tests`, `working-directory: examples/contact-form`, `run: go test ./...`.
- New job `docker` (`runs-on: ubuntu-latest`, `timeout-minutes: 15`): checkout; step `Build image` runs `docker build -t peek:ci .`; step `Start container and probe health` runs:
  ```sh
  set -euo pipefail
  id=$(docker run -d -p 7700:7700 peek:ci)
  for i in $(seq 1 30); do
    curl -fsS http://localhost:7700/healthz >/dev/null && break
    sleep 1
  done
  curl -fsS http://localhost:7700/healthz
  docker exec "$id" /peekd healthcheck --addr localhost:7700
  docker logs "$id"
  ```
- New job `cross-build` (`timeout-minutes: 15`, `env: GOFLAGS: -mod=readonly`): checkout, setup-go (`go-version-file: go.mod`, `cache: true`), step `Vet and build for windows and darwin`:
  ```sh
  set -eu
  for os in windows darwin; do
    CGO_ENABLED=0 GOOS=$os GOARCH=amd64 go vet ./...
    CGO_ENABLED=0 GOOS=$os GOARCH=amd64 go build ./cmd/...
  done
  ```
- New job `docs` (`timeout-minutes: 15`): checkout, pnpm/action-setup, setup-node (`cache: pnpm`, `cache-dependency-path: docs/pnpm-lock.yaml`), `Install dependencies` (`working-directory: docs`, `pnpm install --frozen-lockfile`), `Build docs` (`working-directory: docs`, `pnpm build`), `Check internal links` (`node scripts/check-docs-links.mjs docs/dist`). It always builds; there is no skip logic.
- `pages.yml`: add to `on:` a `push: { branches: [main], paths: ['docs/**', '.github/workflows/pages.yml'] }` trigger (block style YAML), keep `workflow_dispatch:` and the deploy job's `if: github.ref == 'refs/heads/main'`.
- New file `scripts/check-docs-links.mjs` (Node ≥ 20, no dependencies, ESM, header comment in the style of `scripts/gen-screenshots.mjs`). Usage `node scripts/check-docs-links.mjs <dist-dir>`. Base path constant `BASE = "/peek/"`. It walks every `*.html` under the dist dir; for each file collects the `id="..."` values and every `href="..."` and `src="..."` value (decode `&amp;` to `&`). For each link: skip values starting with `http:`, `https:`, `mailto:`, `data:`, `javascript:` or `//`; `#frag` must be an id in the same file; a value starting with `BASE` is split into path and `#frag`, the path resolves to `<dist>/<rest>` when that is a file, else `<dist>/<rest>/index.html` (a path ending in `/` resolves to `<dist>/<rest>index.html`), and a fragment must be an id in the resolved HTML file; any other value starting with `/` is an error `absolute link outside /peek/`; a relative value resolves against the file's directory with the same rules. It prints one line per problem as `<file relative to dist>: <link>: <reason>` and exits 1 when there is any, else prints `docs links: OK (<links> links in <files> files)` and exits 0.

### D2. Publishing workflows and images — SEC-2 code part, SEC-4 code part, SEC-5, SEC-6, SEC-7 workflow part, SEC-10

- `release.yml`: add a first job:
  ```yaml
  verify:
    name: verify
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    env:
      GOFLAGS: -mod=readonly
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5.6.0
        with:
          go-version-file: go.mod
      - name: Tag commit is on main
        run: git merge-base --is-ancestor "$GITHUB_SHA" origin/main
      - name: Vet
        run: go vet ./...
      - name: Test (with race detector)
        run: go test -race -count=1 ./...
      - name: Vulnerability scan
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
          govulncheck ./...
  ```
  Add `needs: verify` to `build`, `sbom` and `docker` (`checksums` keeps `needs: build`). `build` permissions become `contents: write`, `id-token: write`, `attestations: write`; after `Build & package` add:
  ```yaml
      - name: Attest build provenance
        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-path: ${{ steps.pkg.outputs.archive }}
  ```
  `docker` permissions become `contents: read`, `packages: write`, `id-token: write`, `attestations: write`; give the `Build & push` step `id: push`; change `type=raw,value=latest` to `type=raw,value=latest,enable=${{ !contains(github.ref_name, '-') }}`; after `Build & push` add:
  ```yaml
      - name: Attest image provenance
        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true
  ```
  (The inputs `subject-path`, `subject-name`, `subject-digest` and `push-to-registry` were checked in that SHA's `action.yml`.)
- `docker-main.yml`: `on:` becomes `workflow_run: { workflows: [CI], types: [completed], branches: [main] }` plus the existing `workflow_dispatch:`. The job gets
  `if: github.event_name == 'workflow_dispatch' || (github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push' && github.event.workflow_run.head_repository.full_name == github.repository)`. The `event == 'push'` and `head_repository` conditions are required: `branches: [main]` matches the head branch name, so without them a fork PR from a branch called `main` would build fork code with `packages: write`. Add a job-level `env: { SHA: "${{ github.event.workflow_run.head_sha || github.sha }}" }`; the checkout gets `ref: ${{ env.SHA }}` and `persist-credentials: false`; add a step `id: sha` running `echo "short=${SHA::7}" >> "$GITHUB_OUTPUT"`; the metadata `tags:` become `type=raw,value=main` and `type=raw,value=sha-${{ steps.sha.outputs.short }}`; the build args become `VERSION=main-${{ env.SHA }}` and `COMMIT=${{ env.SHA }}`. (`type=ref`/`type=sha` are dropped because under `workflow_run` `github.sha` is the latest default-branch commit, not necessarily the one CI tested.)
- New `.github/dependabot.yml`, `version: 2`, every entry `schedule: { interval: weekly }` and a `groups:` entry named `<ecosystem>-minor-patch` with `update-types: [minor, patch]` (use `npm-root-minor-patch` and `npm-docs-minor-patch` for the two npm entries): `gomod` directory `/`; `github-actions` directory `/`; `docker` with `directories: [/, /examples/contact-form]`; `npm` directory `/docs`; `npm` directory `/`.
- New `.github/workflows/vuln.yml`, `name: Vulnerability scan`, `on: { schedule: [{ cron: '23 4 * * 1' }], workflow_dispatch: {} }` (block style), `permissions: contents: read`, one job `govulncheck` (`timeout-minutes: 15`): checkout (`persist-credentials: false`), setup-go (`go-version-file: go.mod`), run `go install golang.org/x/vuln/cmd/govulncheck@v1.9.0` then `govulncheck ./...`.
- Base images pinned by index digest (resolved 2026-10-27 through `mirror.gcr.io` / `gcr.io`):
  - `Dockerfile:4` → `FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build`
  - `examples/contact-form/Dockerfile:1` → `FROM golang:1.26.10@sha256:24a707af49702fa44f02785475d02fb752f6982d3e9c0afb7696e1f0204e7ce9 AS build`
  - `examples/contact-form/Dockerfile:8` → `FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`
- `docker-compose.yml`: `minio` image `minio/minio:RELEASE.2025-09-07T16-13-09Z`, `minio-init` image `minio/mc:RELEASE.2025-08-13T08-35-41Z` (MinIO stopped publishing new community images after these; the tags could not be resolved from the container and are checked by the owner in `ma5`); `minio` ports `"127.0.0.1:9100:9000"` and `"127.0.0.1:9101:9001"`; a comment line directly above `minio:` reading `# Local development only: well-known credentials, bound to 127.0.0.1.`

### D3. `secret.key` fails closed — SEC-11

`loadOrCreateSecret(path string) (string, error)` in `internal/server/bootstrap.go`:
- If the file exists and is shorter than 32 bytes (including empty), return `fmt.Errorf("%s is %d bytes, expected at least 32; restore it from backup or delete it to generate a new key", filepath.Base(path), len(b))` and leave the file untouched.
- If it exists with ≥ 32 bytes: unchanged (chmod 0600 with the existing warning, return it).
- Read errors other than not-exist: unchanged (`read secret: %w`).
- Missing file: generate as today, then write with a new helper `writeSecretFile(path string, data []byte) error`: `os.CreateTemp(filepath.Dir(path), ".secret-*.tmp")`, `defer os.Remove(tmpName)` (a no-op after the rename), `f.Chmod(0o600)`, `f.Write`, `f.Sync`, `f.Close`, `os.Rename(tmpName, path)`; any error is returned and wrapped by the caller as `write secret: %w`. The old `os.WriteFile` + `os.Chmod` pair goes away.

### D4. Deterministic SigV4 test — TST-4

- `S3Storage` gets an unexported field `now func() time.Time` (nil in production; `NewS3Storage` is unchanged) and a method `func (s *S3Storage) clock() time.Time` returning `s.now()` when set, else `time.Now()`. `signRequest` uses `t := s.clock().UTC()`.
- New file `internal/objectstore/s3_signing_test.go` (package `objectstore`) with `TestS3SignRequestMatchesKnownVector`, using the "GET Object" example of the AWS S3 SigV4 documentation (https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html), whose signature the planner reproduced with an independent Python signer: settings `s3_access_key=AKIAIOSFODNN7EXAMPLE`, `s3_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, `s3_region=us-east-1`; `s.now` returns `time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)`; request `http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)` with header `Range: bytes=0-9`; call `s.signRequest(req, "test.txt", nil)`; the `Authorization` header must equal exactly
  `AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41`
  and `X-Amz-Date` must equal `20130524T000000Z`.

### D5. `peekd` help, metrics wording and a pre-opened listener — DOC-3, DOC-13 (peekd), TST-11 (peekd part)

- `run.go:129` help text: `bearer token (at least 16 characters) accepted on /metrics; when empty, an admin API token is required (prefer PEEK_METRICS_TOKEN_FILE)`.
- `run.go:30` comment: `// MetricsToken is a bearer token accepted on /metrics; when empty, an admin API token is required.`
- `run.go:337` log field `metrics_auth` → `metrics_token_set`.
- New `func writeServeUsage(w io.Writer, fs *flag.FlagSet)` in `run.go`, installed with `fs.Usage = func() { writeServeUsage(fs.Output(), fs) }` in `parseServeConfig`. It writes exactly this text to `w`, then calls `fs.PrintDefaults()` (which writes to `fs.Output()`, stderr, the same stream):
  ```text
  Usage:
    peekd [flags]                                run the server
    peekd backup [--data <dir>] [path]           write a consistent SQLite snapshot (default <data>/peek-backup.db)
    peekd healthcheck [--addr <host:port|url>]   exit 0 when /healthz answers 200
    peekd --version                              print the version

  Every flag except --version can also be set through an environment variable:
  PEEK_ plus the flag name in upper case with dashes as underscores (--base-url
  is PEEK_BASE_URL). PEEK_SECRET, PEEK_S3_SECRET_KEY and PEEK_METRICS_TOKEN also
  accept a _FILE variant holding a file path. PEEK_LOG_LEVEL (debug, info, warn)
  sets the log level and PEEK_HEALTHCHECK_ADDR the healthcheck address.

  Flags:
  ```
- `Run`, `runBackup` and `runHealthcheck` return 0 when parsing fails with `errors.Is(err, flag.ErrHelp)` (the FlagSet has already printed usage); `Run` does so before printing `peekd: %v`. `backupArgs` returns the parse error unchanged so `runBackup` can test it.
- `serveConfig` gets a field `Listener net.Listener // when set, runServe serves on it instead of listening on Addr (tests)`. In `runServe`, the goroutine calls `hs.Serve(cfg.Listener)` when `cfg.Listener != nil`, else `hs.ListenAndServe()`; the `http.ErrServerClosed` handling is unchanged.
- `serve_test.go`: delete `freeAddr`; `serveTestConfig` opens `ln, err := net.Listen("tcp", "127.0.0.1:0")`, registers `t.Cleanup(func() { _ = ln.Close() })`, and sets `Listener: ln, Addr: ln.Addr().String()`. A test that needs a real bind failure keeps setting `Addr` itself with `Listener` nil.

### D6. CLI help — DOC-13 (CLI)

- `usage()` keeps printing the whole text to stderr. Add these lines to the usage text, in these places: after `  peek login --token-stdin ...` add `  peek login --oauth                    always use browser login; fails when the server has none`; after `  peek config show` nothing; replace `  peek backend env set <slug> <NAME> --value-stdin   set a backend environment variable` with `  peek backend env set <slug> <NAME> --value <v>|--value-stdin   set a backend environment variable`; after the `peek provisioner revoke` line add `  peek version                         print the CLI version`.
- New `func commandUsage(cmd string) string` returns `"Usage:\n"` followed by every line of the usage text whose trimmed text starts with `"peek " + cmd + " "` or equals `"peek " + cmd`, each ending in `\n` (so `peek login --help` also shows the `peek login` lines from "Token input").
- New `func wantsHelp(args []string) bool`: true when any element is `-h` or `--help`.
- In `Run`, after `cmd, rest := args[0], args[1:]` and before the `switch`: if `cmd` is one of the dispatched command names (login, config, upload, list, delete, visibility, rename, grant, revoke, grants, versions, stats, comments, export, delete-all, token, provisioner, backend) and `wantsHelp(rest)`, print `commandUsage(cmd)` to stderr and return 0. Keep the names in one `var commandNames = []string{...}` next to `Run`.

### D7. CLI↔server contract test — TST-2

New file `internal/cli/server_contract_test.go`, package `cli` (so it reuses `runCaptured`, `setTestConfigHome` and `withStdin`). `TestCLIAgainstRealServer`:
1. `dir := t.TempDir()`; `db.Open(filepath.Join(dir, "peek.db"))`, `store.CreateToken(ctx, "contract-admin-token", "admin", true, 0)`, close; `server.New(server.Config{DataDir: dir, BaseURL: "http://localhost:7700", Secret: strings.Repeat("ab", 32), MaxUpload: 10 << 20})`; `t.Cleanup(func() { _ = srv.Close() })`; `ts := httptest.NewServer(srv.Handler())`, `t.Cleanup(ts.Close)` (copy of `internal/server/api_test.go:18-43`).
2. `setTestConfigHome(t)`, `t.Setenv("PEEK_HOST", ts.URL)`, `t.Setenv("PEEK_TOKEN", "contract-admin-token")`.
3. Write `<html><body><p id="t">contract</p></body></html>` to `page.html` in a temp dir. `runCaptured(t, "upload", page, "--visibility", "public", "--name", "Contract")`: exit 0, stdout has `uploaded: http://localhost:7700/p/`, a `slug:` line (parse the slug from it), `version:  1` and `visibility: public`.
4. `upload page --slug <slug>`: stdout has `version url: http://localhost:7700/p/<slug>/v/2`.
5. `list`: a line contains the slug, `public` and `Contract`.
6. `stats <slug>`: stdout has `slug:            <slug>`, `name:            Contract` and `total visits:`.
7. `grants <slug>`: exit 0, stdout `no grants`.
8. `delete <slug>`: stdout `deleted: <slug>`; then `list` stdout is `no uploads yet.`.
Every step asserts exit code 0 and prints stdout and stderr on failure.

### D8. End-to-end test of the built binaries — TST-3

- New package `internal/e2e`: `doc.go` (`// Package e2e holds the end-to-end test of the built peek and peekd binaries; it runs only with PEEK_E2E=1.` + `package e2e`) and `e2e_test.go` with `TestE2EBinaries`.
- The test skips with `t.Skip("set PEEK_E2E=1 to run the end-to-end test of the built binaries")` unless `os.Getenv("PEEK_E2E") == "1"`.
- Module root from `go list -m -f '{{.Dir}}'`. Build `peekd` and `peek` with `go build -o <bin>/peekd ./cmd/peekd` (and `./cmd/peek`) into `t.TempDir()`, `cmd.Dir` = module root.
- `startPeekd(t, dataDir) (base string)`: pick a port with `net.Listen("tcp", "127.0.0.1:0")` + close, run `peekd --addr 127.0.0.1:<port> --data <dataDir> --base-url http://127.0.0.1:<port>` with stdout/stderr into a mutex-guarded buffer, poll `GET /healthz` for 200 every 50 ms for 15 s; if the process exits during the wait, retry with a new port, at most 3 attempts, then `t.Fatalf` with the buffered output. `t.Cleanup` sends `os.Interrupt` and waits up to 10 s, then kills.
- Setup: read `<data>/setup.key` (trimmed), `GET /setup?code=<code>` with an `http.Client` that has a `cookiejar`, extract the CSRF token with ``regexp.MustCompile(`name="csrf" value="([^"]+)"`)``, `POST /setup` form `email=admin@example.com`, `name=Admin`, `password=e2e-admin-password`, `code`, `csrf`; the client follows the redirect and must end at `/dashboard` with 200.
- API key: `GET /dashboard` → CSRF; `POST /dashboard/api-keys` form `name=e2e`, `csrf`; extract the key with ``regexp.MustCompile(`id="hn-api-key"[^>]*>(peek_[^<]+)<`)``.
- CLI runs use `HOME=<tmp>`, `XDG_CONFIG_HOME=<tmp>/.config`, `PEEK_HOST` and `PEEK_TOKEN` removed from the environment. `peek login --host <base> --token-stdin` with the key on stdin; `peek upload <page> --visibility public --name e2e-page` (parse the `slug:` line); `peek list` contains the slug; `peek stats <slug>` contains `total visits:`.
- Backup while running: `peekd backup --data <data> <tmp>/backup.db` prints `backup written to`. Then `peek delete <slug>` prints `deleted: <slug>`.
- Restore: new data dir; copy `backup.db` to `<new>/peek.db`, `<data>/secret.key` to `<new>/secret.key`, and the `<data>/uploads` directory tree to `<new>/uploads`; `startPeekd` on it; `peek list` run with `PEEK_HOST=<base2>` added to the environment contains the slug; `GET <base2>/p/<slug>` returns 200.
- `mise.toml`: new task
  ```toml
  [tasks.e2e]
  description = "Run the end-to-end test of the built peek and peekd binaries"
  run = "PEEK_E2E=1 go test -count=1 -run '^TestE2E' ./internal/e2e"
  ```
- `ci.yml`: new job `e2e` (`timeout-minutes: 15`, `env: GOFLAGS: -mod=readonly`): checkout (`persist-credentials: false`), setup-go (`go-version-file: go.mod`, `cache: true`), step `End-to-end test of the binaries` running `PEEK_E2E=1 go test -count=1 -run '^TestE2E' -v ./internal/e2e`.

### D9. Browser test of the viewer's trust boundary — TST-6

- New `scripts/e2e-browser-page.html` (the probe page):
  ```html
  <!doctype html>
  <title>peek e2e probe</title>
  <p id="t">Hello from the probe page</p>
  <script>
    window.probe = async function (path) {
      try { const res = await peek.fetch(path); return "ok:" + res.status; }
      catch (e) { return "err:" + e.message; }
    };
  </script>
  ```
- New `scripts/e2e-browser.sh` (bash, `set -euo pipefail`, header comment like `gen-screenshots.sh`): `PORT="${PEEK_E2E_BROWSER_PORT:-7797}"`, temp data dir and cleanup trap as in `gen-screenshots.sh:21-31`; requires `go`, `node`, `playwright-core` (`node -e "import('playwright-core')"`), and Chrome found from `$CHROME`, then `google-chrome`, `chromium`, `chromium-browser`, then the first `/opt/pw-browsers/chromium-*/chrome-linux64/chrome`. It builds `bin/peekd` and `bin/peek`, starts peekd, creates the admin and a CLI token exactly as `gen-screenshots.sh:66-101` does (copy those lines), uploads the probe page with `curl -fsS -H "Authorization: Bearer $TOKEN" -F "file=@scripts/e2e-browser-page.html;type=text/html" -F "visibility=public" "$BASE/api/upload"`, extracts `SLUG`, and runs `BASE="$BASE" SLUG="$SLUG" CHROME="$CHROME" node scripts/e2e-browser.mjs`.
- New `scripts/e2e-browser.mjs` (ESM, `playwright-core`, fails with a message and exit 1 on the first failed check, prints `browser e2e: OK (<n> checks)` at the end): launch headless Chromium with `executablePath: CHROME`; a fresh context (anonymous viewer); `page.goto(BASE + "/p/" + SLUG)`; find the frame whose URL contains `/raw/` once `#hn-frame` has loaded; wait until `frame.evaluate(() => typeof window.peek?.fetch === "function")`. Checks, in order:
  1. `frame.evaluate((p) => window.probe(p), path)` returns exactly `err:invalid peek.fetch path` for each of `/../../api/tokens`, `/%2e%2e/%2e%2e/api/tokens` and `/../../../other-k7m2xq/v/1/x`.
  2. Positive control: `window.probe("/ok")` returns a string starting with `ok:` (the relay accepted the path; with no backend the server answers with an error status).
  3. Non-frame messages are ignored: `page.evaluate(() => window.postMessage({ hn: "togglebar" }, "*"))`, then `frame.evaluate(() => parent.postMessage({ hn: "togglebar" }, "*"))`; `page.waitForSelector("#hn-bar", { state: "hidden", timeout: 5000 })`; wait 500 ms; `#hn-bar` must still be hidden (if the page's own message had been honoured, the two toggles would cancel out).
  4. Comment round-trip: send `{ hn: "togglebar" }` from the frame again and wait for `#hn-bar` visible; click `#hn-comment-btn`; `frame.click("#t")`; wait for `#hn-body` visible; fill it with `e2e comment`; submit with `page.click("#hn-comment-form [type=submit]")`; if `#hn-name-modal` becomes visible within 2 s, click `#hn-name-skip`; then poll `GET ${BASE}/api/uploads/${SLUG}/comments` (from Node's `fetch`) every 200 ms for 10 s until the body contains `e2e comment`.
- Root `package.json` `scripts`: add `"e2e-browser": "scripts/e2e-browser.sh"`.
- `ci.yml`: new job `browser` (`timeout-minutes: 15`, `env: GOFLAGS: -mod=readonly`): checkout, setup-go, pnpm/action-setup, setup-node (`cache: pnpm`, `cache-dependency-path: pnpm-lock.yaml`), `pnpm install --frozen-lockfile`, step `Browser end-to-end test` running `CHROME="$(command -v google-chrome)" scripts/e2e-browser.sh`.

### D10. Real-release upgrade fixture — TST-8 (oldest supported in-place upgrade: v0.10.0, confirmed by the owner)

- New `scripts/make-release-fixture.sh <tag>` (bash, `set -euo pipefail`): creates a detached `git worktree` of `<tag>` in a temp dir (removed by trap); computes `GO="$(go env GOROOT)/bin/go"` in the repo root and builds the tag's `peekd` and `peek` inside the worktree with `GOTOOLCHAIN=local "$GO" build`; starts that peekd on port `${PEEK_FIXTURE_PORT:-7796}` with a temp data dir; creates the admin (`admin@example.com`) and a CLI token as `gen-screenshots.sh:66-101` does; seeds through that release's HTTP API:
  1. a `public` upload named `fixture-public`, then a second version of it (`slug=<that slug>`);
  2. an anonymous comment with body `Fixture comment` on the public page (`POST /api/uploads/<slug>/comments`, request shape read from `git show <tag>:internal/server/comments.go`);
  3. a `private` upload named `fixture-private`;
  4. a `password` upload named `fixture-password` with password `fixture-password` (form field names read from `git show <tag>:internal/server/api_uploads.go`);
  5. a `restricted` upload named `fixture-restricted` and a grant for `reviewer@example.com` (`POST /api/uploads/<slug>/grants`);
  6. an invite for `invitee@example.com` through `POST /dashboard/invites` with the dashboard CSRF token.
  It stops peekd, runs the tag's `peekd backup --data <data> internal/db/testdata/peek-<tag>.db` (delete an existing file first), and writes `internal/db/testdata/peek-<tag>.json`:
  `{"release":"<tag>","admin_email":"admin@example.com","api_token":"<token>","public_slug":"...","private_slug":"...","password_slug":"...","restricted_slug":"...","grant_email":"reviewer@example.com","invite_email":"invitee@example.com","comment_body":"Fixture comment"}`. The token is a throwaway credential of a fixture database and is fine to commit.
- New `internal/db/release_fixture_test.go` (package `db`), helper `openReleaseFixture(t) (*Store, fixtureInfo)` copying `testdata/peek-v0.10.0.db` to `t.TempDir()/peek.db`, reading the JSON and calling `Open`.
  - `TestOpenUpgradesReleaseFixture` asserts through Store methods (or `QueryRowContext` on the store where no method exists): the admin account exists and is admin; the token resolves to that account; `public_slug` is `public` with 2 versions and a comment with `comment_body`; `private_slug` is `signed-in` (migration 14); `password_slug` is `restricted` with an empty `password_hash` (migration 15); `restricted_slug` has a grant for `grant_email`; an invite for `invite_email` exists; `MAX(id)` in `schema_migrations` equals `migrations[len(migrations)-1].id`.
  - `TestUpgradedSchemaMatchesFresh` compares the upgraded fixture with a fresh `Open` of an empty path: the set of `(type, name)` in `sqlite_master` excluding names starting with `sqlite_`, and for every table the set of `pragma_table_info` rows `(name, type, notnull, dflt_value, pk)`, and for every index the ordered `pragma_index_info` column names. Exactly one difference is allowed and skipped by name: `dflt_value` of `uploads.visibility` (`'password'` upgraded, `'restricted'` fresh), with the comment `// Databases created before migration 15 keep the old column default; harmless because the only INSERT INTO uploads (uploads.go) always sets visibility.` Any other difference fails the test and lists every differing entry.

### D11. Coverage ratchet — TST-9

`scripts/coverage-gate.sh`: `min="${COVERAGE_MIN:-95.0}"`, new `pkg_min="${COVERAGE_PACKAGE_MIN:-93.0}"` and `packages="${COVERAGE_PACKAGES:-internal/server internal/db internal/objectstore}"`; after the total check (keep its message format), compute each package's statement coverage directly from the profile: `module=$(go list -m)`, then for each package `awk -v pkg="$module/$p" 'NR > 1 { split($1, a, ":"); f = a[1]; sub(/\/[^\/]*$/, "", f); if (f == pkg) { n += $2; if ($3 > 0) c += $2 } } END { if (n == 0) print "none"; else printf "%.1f", 100 * c / n }' "$profile"`; print `coverage gate: OK <pkg> <pct>% >= <min>%` or `coverage gate: FAIL <pkg> <pct>% < <min>%` (or `coverage gate: FAIL <pkg> has no statements in <profile>`), and exit 1 after checking all packages if any failed. Update the usage comment. `mise.toml` `[tasks.coverage]` description → `Run tests with coverage and fail below the 95% total or 93% per-core-package gates`. `ci.yml` step name → `Coverage (gate >= 95.0% total, >= 93.0% per core package)`.

### D12. Governance files — SEC-3 code part, SEC-9 code part, DOC-15, DOC-17, DOC-10 (profile)

- New `SECURITY.md` with sections `# Security policy`, `## Supported versions` (security fixes go into the latest release; older releases do not get backports; upgrade notes are in `docs/operations.md`), `## Reporting a vulnerability` (report privately at https://github.com/andras-tkcs/peek/security/advisories/new; do not open a public issue or PR; include the affected version from `peekd --version`, the deployment shape (storage, sign-in providers, page backends on or off), reproduction steps and the impact you expect), `## What to expect` (best effort: acknowledgement within 7 days, a fix or mitigation plan agreed in the advisory, credit in the advisory unless you prefer otherwise), `## How fixes are announced` (a GitHub Security Advisory and the release notes / `CHANGELOG.md` of the release with the fix), `## Past audits` (link `docs/audits/2026-10-security-and-coverage-audit.md` as the latest internal audit).
- New `CHANGELOG.md`:
  ```markdown
  # Changelog

  All notable user-visible changes to Peek are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and Peek uses [Semantic Versioning](https://semver.org/). Earlier releases are described in their [GitHub release notes](https://github.com/andras-tkcs/peek/releases); upgrade-relevant changes per version are in [docs/operations.md](docs/operations.md#upgrades-and-rollbacks).

  ## [Unreleased]
  ```
- New `.github/pull_request_template.md`:
  ```markdown
  ## What and why

  ## How it was tested

  ## Checklist

  - [ ] `mise run check` passes (and `mise run check-full` when the change touches server, database, storage, auth, backends or concurrency; see CONTRIBUTING.md)
  - [ ] Tests cover the changed behaviour
  - [ ] Docs updated (README, docs/, skills/) where behaviour or flags changed
  - [ ] `CHANGELOG.md` has a line under `## [Unreleased]` for a user-visible change
  ```
- `.claude/toolkit.yaml`: `git.merge_style: merge-commit` (the schema's name for "merge commits only"; the review's acceptance grep `merge_style: merge` matches it); add under `docs:` a `changelog:` block with `file: CHANGELOG.md` and `section: "## [Unreleased]"`; add `"internal/backends/**"` to the `dod_conditional` `when` list.
- `docs/audits/2026-10-security-and-coverage-audit.md:3` Status line → `Status: Critical, Medium and Low findings addressed in PR #16 (first released in v0.10.0). Info items remain open except the two page-password items, which no longer apply since page passwords were removed (migration 15).` and mark the two Info items at `:113-114` with a trailing ` (no longer applies: page passwords were removed in migration 15)`.

### D13. Exact replacement texts used by the docs phases

- DOC-5 sentence (README, skill, operations): `S3 endpoints must use HTTPS and must not resolve to private, link-local or metadata addresses; --s3-allow-private-endpoint / PEEK_S3_ALLOW_PRIVATE_ENDPOINT=true lifts both, for MinIO or internal stores.` (with the flag and variable in backticks).
- Slug examples: `mypage-k7m2xq` (README), `page-k7m2xq` (skill); real upload output is four lines: `uploaded: <url>`, `slug:     <slug>`, `version:  1`, `visibility: restricted`.
- Checksums cutoff: `(v0.9.2 and older)`. Skill install example: ``- `PEEK_VERSION=v0.14.0` — install a specific release (v0.10.0 or newer) instead of the latest.``
- Attestation sentence (README install section, after the checksums sentence): `Releases published after v0.14.0 also carry a GitHub build provenance attestation; check an archive with gh attestation verify <archive> -R andras-tkcs/peek.` (command in backticks).
- peekd subcommand sentence (README `### Server (peekd)` end, replacing `README.md:215`): `peekd --version` prints the version. `peekd backup [--data <dir>] [path]` writes a consistent SQLite snapshot via `VACUUM INTO` (default `<data>/peek-backup.db`), safe while the server runs. `peekd healthcheck [--addr <host:port|url>]` exits 0 when `/healthz` answers 200; the address defaults to `PEEK_HEALTHCHECK_ADDR`, then `PEEK_ADDR`. `peekd --help` lists every flag and subcommand.
- "Other environment variables" list (README, directly after the server flag table): `PEEK_LOG_LEVEL` — `debug`, `info` (default) or `warn`; `PEEK_HEALTHCHECK_ADDR` — the address `peekd healthcheck` probes (defaults to `PEEK_ADDR`).
- Comment-name sentence (README:101): `Signed-in viewers comment as their account; anonymous viewers are asked for a name once.`
- check-full sentence (architecture.md): `` `mise run check-full` matches CI's `build` job (formatting, vet, build, race tests, coverage, govulncheck, staticcheck); CI also runs the Docker backend integration, docker image, cross-build, docs, e2e and browser jobs (see CONTRIBUTING.md → Tests). ``
- Restore steps (site `storage-retention.md` and kept consistent with `docs/operations.md`): 1. Stop peekd. 2. Copy the backup over `<data>/peek.db` and delete `<data>/peek.db-wal` and `<data>/peek.db-shm` if present. 3. Restore `<data>/secret.key` and `<data>/uploads/` (or the S3 bucket) from the same point in time. 4. Start peekd. 5. Run the operator smoke test (`/healthz`, `/readyz`, `peek list`, open one page).

## Manual steps

Everything only the repository owner can do is a GitHub setting, and none of it is needed by a phase, so `manual_before` is empty and all of it is in `manual_after`. The step-by-step page is https://claude.ai/artifact/VdHCRuTPx2pugrGfti7tEY (`manual_steps_artifact`); its source is `docs/plans/repo-2026-10-27-fixes-plan-manual-steps.html`.

- `ma1-merge-commits-only` — General → Pull Requests: only merge commits; ruleset "main": allowed merge methods Merge only (SEC-9).
- `ma2-security-features` — enable private vulnerability reporting (SEC-3), Dependabot alerts and security updates (SEC-4), CodeQL default setup for Go and Actions (SEC-8).
- `ma3-release-tag-ruleset` — new tag ruleset "release tags" for `v*` (SEC-2).
- `ma4-actions-settings` — confirm workflow permissions are read-only by default and fork PRs from outside collaborators need approval (review group 6, step 5).
- `ma5-visual-and-compose-check` — look at the regenerated screenshots in the PR and confirm the pinned MinIO images pull (WEB-1, SEC-10).
- `ma6-required-checks` — right after the PR merges: require `backend-integration`, `docs`, `docker`, `cross-build`, `e2e` and `browser`, strict up-to-date branches, and conversation resolution (SEC-1); then confirm the post-merge runs (Pages deploy on push, Docker (main) after CI).

## Risks and open questions

- **Workflow changes cannot run in the container.** `docker`, `backend-integration`, `browser`, `e2e` (in CI), `docs`, `release.yml`, `docker-main.yml` and `vuln.yml` are checked locally only by YAML parsing and greps; they first run on the feature PR (release, docker-main and vuln only after merge or at the next tag). A worker never "fixes" a workflow by guessing; the PR's CI is the real check, driven by `pr-steward`.
- **D9 browser test depends on viewer behaviour.** If `#hn-comment-btn` + `frame.click("#t")` does not open the composer, or the positive control `probe("/ok")` returns anything but `ok:<status>`, the brief is wrong about the viewer: stop with `status=blocked` and report what the page did, rather than loosening a check.
- **D10 fixture needs v0.10.0's request shapes.** The comment, password-upload and grant request shapes must be read from the v0.10.0 sources (`git show v0.10.0:<path>`). If v0.10.0 cannot be built with the installed toolchain, or `TestUpgradedSchemaMatchesFresh` finds a difference other than `uploads.visibility`'s default, stop with `status=blocked` and report the difference; do not add it to the allow-list.
- **D3 changes behaviour other tests may rely on.** If any test other than the two named in "Current state" fails because it relied on a short `secret.key` being replaced, stop with `status=blocked`.
- **D4 vector.** If `TestS3SignRequestMatchesKnownVector` fails with the code unchanged except for the clock, the signer differs from AWS's canonical form (for example an extra signed header); stop with `status=blocked` and report the canonical request instead of changing the expected value.
- **MinIO tags (D2).** They could not be resolved from the container; `ma5` checks them. If the owner reports they do not exist, a follow-up replaces them.
- **Screenshots (WEB-1) are checked by eye.** Acceptance is mechanical only for the file set; `ma5` covers the content.
- **Coverage gate (D11).** If raising the defaults fails on the feature branch, a phase did not test its code: fix the tests, never lower the floor.
- **Required checks.** Adding them before the jobs exist on `main` blocks every PR; `ma6` is therefore done right after merge, and the page says so.

## Implementation manifest

```yaml
plan_slug: repo-2026-10-27-fixes
feature_branch: chore/repo-2026-10-27-fixes
max_parallel: 2
manual_steps_artifact: https://claude.ai/artifact/VdHCRuTPx2pugrGfti7tEY
manual_steps_source: docs/plans/repo-2026-10-27-fixes-plan-manual-steps.html
manual_before: []
manual_after:
  - id: ma1-merge-commits-only
    title: Allow only merge commits (repository setting and the "main" ruleset)
    why: SEC-9; the profile and CONTRIBUTING now say merge commits only, and only the owner can change the GitHub settings to match.
  - id: ma2-security-features
    title: Enable private vulnerability reporting, Dependabot alerts and security updates, and CodeQL default setup
    why: SEC-3, SEC-4 and SEC-8; SECURITY.md links the private reporting form, which 404s until it is enabled, and these features are settings, not code.
  - id: ma3-release-tag-ruleset
    title: Create the "release tags" tag ruleset for v*
    why: SEC-2; the release verify job blocks untested commits, but only a ruleset stops anyone with write access from pushing or moving a v* tag.
  - id: ma4-actions-settings
    title: Confirm default workflow permissions are read-only and outside-collaborator fork PRs need approval
    why: the review could not read these settings through the API; they bound what a malicious PR workflow could do.
  - id: ma5-visual-and-compose-check
    title: Check the regenerated screenshots and that the pinned MinIO images pull
    why: WEB-1 screenshots can only be judged by eye, and the MinIO tags in docker-compose.yml could not be resolved from the container (SEC-10).
  - id: ma6-required-checks
    title: Right after merging, make the new CI jobs required and turn on strict checks and conversation resolution
    why: SEC-1; a required check that has never reported on main would block every PR, so this happens after the jobs exist on main.
verify_after_merge:
  - go build ./...
  - go test -race -count=1 ./...
  - python3 -c "import sys, yaml; [yaml.safe_load(open(f)) for f in sys.argv[1:]]" .github/workflows/*.yml
  - sh scripts/coverage-gate.sh /tmp/peek-verify-coverage.out
final_checks:
  - docs/plans/repo-2026-10-27-fixes-plan.md and docs/plans/repo-2026-10-27-fixes-plan-manual-steps.html are deleted and `git grep -n 'repo-2026-10-27-fixes-plan'` has no output
  - CHANGELOG.md has entries under "## [Unreleased]" and no version heading
  - PEEK_E2E=1 go test -count=1 -run '^TestE2E' ./internal/e2e passes
  - 'pnpm install --frozen-lockfile && CHROME="$(ls /opt/pw-browsers/chromium-*/chrome-linux64/chrome | head -1)" scripts/e2e-browser.sh prints "browser e2e: OK"'
  - 'pnpm install --dir docs --frozen-lockfile && pnpm --dir docs build && node scripts/check-docs-links.mjs docs/dist prints "docs links: OK"'
  - every finding id of the review (SEC-1..11, TST-1..6, TST-8..12, DOC-1..6, DOC-8..10, DOC-12..17, WEB-1..6, WEB-8, WEB-9) appears in the acceptance of a merged phase, and the PR body lists the GitHub-settings parts of SEC-1, SEC-2, SEC-3, SEC-4, SEC-8 and SEC-9 as manual_after items
phases:
  - id: p1-ci-pr-jobs
    title: CI jobs on every PR (docker, cross-build, docs, example module) and the docs link check
    depends_on: []
    complexity: M
    touches:
      - .github/workflows/ci.yml
      - .github/workflows/pages.yml
      - scripts/check-docs-links.mjs
    brief: |
      Findings: SEC-1 (code part), SEC-6 (ci.yml, pages.yml), TST-5, TST-12, WEB-5, DOC-9 (example-module CI step). Spec: plan Design D1.
      1. In .github/workflows/ci.yml add `persist-credentials: false` to both existing checkout steps (D1 first bullet).
      2. Append the "Example module tests" step to the backend-integration job (D1).
      3. Add the jobs `docker`, `cross-build` and `docs` to ci.yml exactly as D1 specifies, with the pinned action SHAs listed there. No `paths:` filters anywhere in ci.yml.
      4. In .github/workflows/pages.yml add the push trigger from D1 and `persist-credentials: false` on its checkout; keep workflow_dispatch and the deploy job's `if:`.
      5. Write scripts/check-docs-links.mjs per D1.
      6. Run it against the current site: `pnpm install --dir docs --frozen-lockfile && pnpm --dir docs build && node scripts/check-docs-links.mjs docs/dist`. It must print `docs links: OK (...)`. Stop condition: if it reports problems, check one by hand in docs/dist; if the link really works in the built site, your resolver is wrong, fix the script; if the link is really broken, stop with status=blocked and list the broken links (the review found none, so the script would be wrong about the site's layout).
      7. Prove the checker can fail: copy docs/dist to a temp dir, append `<a href="#no-such-anchor">x</a>` to its index.html, run the script on the copy and confirm exit 1 with a line naming `#no-such-anchor`. Do not commit the copy.
      8. Parse every workflow: `python3 -c "import sys, yaml; [yaml.safe_load(open(f)) for f in sys.argv[1:]]" .github/workflows/*.yml`.
      These jobs cannot run in the container (Docker is not available); do not invent a way to run them. They run on the feature PR.
    acceptance:
      - "grep -c 'persist-credentials: false' .github/workflows/ci.yml equals grep -c 'actions/checkout@' .github/workflows/ci.yml (SEC-6)"
      - "grep -n 'docker build -t peek:ci .' .github/workflows/ci.yml matches (TST-5)"
      - "grep -n '/peekd healthcheck' .github/workflows/ci.yml matches (TST-5)"
      - "grep -n 'GOOS=\\$os' .github/workflows/ci.yml matches (TST-12)"
      - "grep -n 'pnpm build' .github/workflows/ci.yml matches and grep -n 'push:' .github/workflows/pages.yml matches (WEB-5)"
      - "grep -n 'check-docs-links.mjs docs/dist' .github/workflows/ci.yml matches (WEB-5)"
      - "grep -n 'working-directory: examples/contact-form' .github/workflows/ci.yml matches (DOC-9)"
      - "grep -c 'paths:' .github/workflows/ci.yml prints 0 (SEC-1: every required check reports on every PR)"
      - "node scripts/check-docs-links.mjs docs/dist (after a docs build) prints 'docs links: OK' and exits 0, and exits 1 on the planted broken anchor of step 7"
      - "the python3 yaml parse of .github/workflows/*.yml exits 0"

  - id: p2-publish-hardening
    title: Release verify job, provenance, docker-main after CI, Dependabot, weekly vuln scan, pinned images
    depends_on: []
    complexity: M
    touches:
      - .github/workflows/release.yml
      - .github/workflows/docker-main.yml
      - .github/workflows/vuln.yml
      - .github/dependabot.yml
      - Dockerfile
      - examples/contact-form/Dockerfile
      - docker-compose.yml
    brief: |
      Findings: SEC-2 (code part), SEC-4 (code part), SEC-5, SEC-6 (release.yml, docker-main.yml), SEC-7 (workflow part), SEC-10. Spec: plan Design D2. Copy the YAML in D2 exactly, including the pinned SHAs.
      1. release.yml: add the `verify` job first; add `needs: verify` to build, sbom and docker; `persist-credentials: false` on every checkout; build-job permissions and the "Attest build provenance" step; docker-job permissions, `id: push`, the conditional `latest` tag and the "Attest image provenance" step.
      2. docker-main.yml: the workflow_run trigger, the job `if:` with all three conditions (do not drop the `event == 'push'` and `head_repository` checks; D2 explains why), the `SHA` env, checkout `ref`, the `sha` step, the raw tags and build args.
      3. New .github/dependabot.yml and .github/workflows/vuln.yml per D2.
      4. Pin the three FROM lines and update docker-compose.yml per D2 (MinIO tags, 127.0.0.1 ports, the comment line).
      5. Parse every workflow and dependabot.yml with python3 yaml.safe_load.
      Stop condition: if a pinned digest or tag in D2 looks wrong to you, do not substitute another value from memory; keep D2's value and say so in your report. These workflows cannot run in the container.
    acceptance:
      - "grep -cE 'needs: \\[?verify' .github/workflows/release.yml prints 3 (SEC-2)"
      - "grep -c 'merge-base --is-ancestor' .github/workflows/release.yml prints 1 (SEC-2)"
      - "grep -n \"enable=\\${{ !contains(github.ref_name, '-') }}\" .github/workflows/release.yml matches (SEC-2)"
      - "grep -c 'actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8' .github/workflows/release.yml prints 2 (SEC-7)"
      - "grep -n 'workflow_run' .github/workflows/docker-main.yml matches and grep -n \"workflow_run.event == 'push'\" .github/workflows/docker-main.yml matches (SEC-5)"
      - "for f in release.yml docker-main.yml vuln.yml; do test $(grep -c 'persist-credentials: false' .github/workflows/$f) -eq $(grep -c 'actions/checkout@' .github/workflows/$f) || echo BAD $f; done prints nothing (SEC-6)"
      - "grep -c 'package-ecosystem' .github/dependabot.yml prints 5 and grep -ln 'schedule:' .github/workflows/*.yml lists vuln.yml (SEC-4)"
      - "grep -nE '^FROM .*@sha256:' Dockerfile examples/contact-form/Dockerfile prints 3 lines (SEC-10)"
      - "grep -n ':latest' docker-compose.yml prints nothing and grep -c '127.0.0.1:910' docker-compose.yml prints 2 (SEC-10)"
      - "python3 yaml.safe_load of .github/workflows/*.yml and .github/dependabot.yml exits 0"

  - id: p3-server-test-fixes
    title: Fix the flaky forged-cookie test, test the empty-nonce guard, make secret.key fail closed
    depends_on: []
    complexity: S
    touches:
      - internal/server/access_matrix_test.go
      - internal/server/oauth_profile_test.go
      - internal/server/bootstrap.go
      - internal/server/bootstrap_test.go
    brief: |
      Findings: TST-1, TST-10, SEC-11. Spec for SEC-11: plan Design D3.
      1. TST-1, internal/server/access_matrix_test.go:226: before the map literal add
         `last := good[len(good)-1]; repl := byte('0'); if last == '0' { repl = '1' }; tampered := good[:len(good)-1] + string(repl)` (one statement per line, gofmt'd) and use `"bad signature": tampered,`. Keep the 303 assertion.
      2. TST-10: add `TestVerifyIDTokenNonceRejectsEmptyExpected` to internal/server/oauth_profile_test.go: `err := verifyIDTokenNonce(&oidc.IDToken{Nonce: ""}, "")` must satisfy `errors.Is(err, errOIDCNonceMismatch)`. Prove it can fail: temporarily delete `nonce == "" ||` from internal/server/oauth_profile.go:55, run the test, see it fail, then `git checkout -- internal/server/oauth_profile.go`.
      3. SEC-11: rewrite loadOrCreateSecret and add writeSecretFile per D3.
      4. Update internal/server/bootstrap_test.go: in TestLoadOrCreateSecretTightensExistingFileMode replace the case `short_existing_secret_is_replaced` so the table only keeps the long case (the short case moves to step 5); in TestLoadOrCreateSecretFailures replace the subtest "short existing secret is replaced" with "short existing secret is refused" asserting an error and unchanged content.
      5. Add `TestLoadOrCreateSecretRefusesShortFile` (table: a 10-byte file "0123456789" and an empty file): the error contains `secret.key is 10 bytes, expected at least 32` (resp. `is 0 bytes`) and `restore it from backup or delete it`, and the file content is unchanged afterwards. Add `TestLoadOrCreateSecretLeavesNoTempFiles`: after generating into an empty dir, `os.ReadDir` lists only `secret.key` and its mode is 0600.
      6. `go test -race -count=1 ./internal/server` passes. Stop condition: if a test other than the two named in step 4 fails because it relied on a short secret being replaced, stop with status=blocked and name it.
    acceptance:
      - "for i in $(seq 1 40); do go test -count=1 -run '^TestSessionCookieForgeryIsRefused$' ./internal/server || exit 1; sleep 1; done exits 0 (TST-1)"
      - "grep -n '+ \"0\",' internal/server/access_matrix_test.go prints nothing (TST-1)"
      - "go test ./internal/server -run '^TestVerifyIDTokenNonceRejectsEmptyExpected$' -count=1 passes, and failed with the guard removed (step 2) (TST-10)"
      - "go test ./internal/server -run 'TestLoadOrCreateSecret' -count=1 passes, including TestLoadOrCreateSecretRefusesShortFile's 10-byte case asserting the error and an unchanged file (SEC-11)"
      - "grep -n 'os.CreateTemp' internal/server/bootstrap.go matches and grep -n 'os.WriteFile' internal/server/bootstrap.go has no match inside loadOrCreateSecret (SEC-11)"
      - "go test -race -count=1 ./internal/server passes"

  - id: p4-s3-signing-vector
    title: Inject a clock into S3 signing and test it against the AWS SigV4 example
    depends_on: []
    complexity: S
    touches:
      - internal/objectstore/s3.go
      - internal/objectstore/s3_signing.go
      - internal/objectstore/s3_signing_test.go
    brief: |
      Finding: TST-4. Spec: plan Design D4.
      1. Add the `now` field and `clock()` method to S3Storage in internal/objectstore/s3.go; use `s.clock().UTC()` in signRequest (internal/objectstore/s3_signing.go:15).
      2. Create internal/objectstore/s3_signing_test.go with TestS3SignRequestMatchesKnownVector exactly as D4 specifies (expected header as a string constant, with a comment linking the AWS page).
      3. Prove both review mutants fail it, one at a time, restoring with `git checkout -- internal/objectstore/s3_signing.go` after each: (a) `sed -i 's/\t\treq.URL.RawQuery,/\t\t"x",/' internal/objectstore/s3_signing.go`; (b) `sed -i '0,/"AWS4-HMAC-SHA256",/s//"AWS4-HMAC-SHA1",/' internal/objectstore/s3_signing.go`. Each time `go test ./internal/objectstore -run '^TestS3SignRequestMatchesKnownVector$' -count=1` must FAIL; confirm with `git diff` that the sed changed the intended line before running.
      Stop condition: if the test fails on unmutated code, stop with status=blocked and include the canonical request your code builds (see the D4 risk in "Risks and open questions"); never edit the expected value.
    acceptance:
      - "go test ./internal/objectstore -run '^TestS3SignRequestMatchesKnownVector$' -count=1 passes (TST-4)"
      - "the two mutants of step 3 each make that test fail, and git diff --stat internal/objectstore/s3_signing.go afterwards shows only the clock change (TST-4)"
      - "grep -n 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41' internal/objectstore/s3_signing_test.go matches"
      - "go test -race -count=1 ./internal/objectstore passes"

  - id: p5-peekd-help-and-test-timing
    title: peekd usage text, metrics-token wording, and race-free serve and backend-wait tests
    depends_on: []
    complexity: M
    touches:
      - internal/peekd/run.go
      - internal/peekd/run_test.go
      - internal/peekd/serve_test.go
      - internal/peekd/backup.go
      - internal/peekd/backup_test.go
      - internal/peekd/healthcheck.go
      - internal/peekd/healthcheck_test.go
      - internal/backends/manager.go
      - internal/backends/export_test.go
      - internal/backends/manager_test.go
    brief: |
      Findings: DOC-3, DOC-13 (peekd part), TST-11. Spec: plan Design D5.
      1. DOC-3: change internal/peekd/run.go:129 help text, :30 comment and :337 log field per D5. Grep the repo for `metrics_auth` (`git grep -n metrics_auth`) and update any test or doc that names it.
      2. DOC-13: add writeServeUsage and `fs.Usage` per D5; make Run, runBackup and runHealthcheck return 0 on flag.ErrHelp (internal/peekd/backup.go, internal/peekd/healthcheck.go).
      3. Tests in internal/peekd/run_test.go: add a helper `captureStderr(t *testing.T, fn func()) string` (swap os.Stderr for an os.Pipe, restore in t.Cleanup, read the pipe after fn returns); `TestRunHelpPrintsUsageAndExitsZero`: `Run([]string{"--help"})` returns 0 and the captured text contains `peekd backup [--data <dir>] [path]`, `peekd healthcheck`, `PEEK_BASE_URL`, `PEEK_LOG_LEVEL`, `PEEK_HEALTHCHECK_ADDR` and `-metrics-token`; `-h` also returns 0; `Run([]string{"backup", "-h"})` and `Run([]string{"healthcheck", "-h"})` return 0. Keep TestRunUnknownFlagReturnsUsageError (still 2).
      4. TST-11 peekd part: add `Listener` to serveConfig and the hs.Serve branch in runServe per D5; rewrite serveTestConfig and delete freeAddr per D5. Check every caller of serveTestConfig and freeAddr (`grep -n 'freeAddr\|serveTestConfig' internal/peekd/*_test.go`).
      5. TST-11 backends part: in internal/backends/manager.go add a field `onWait func() // test hook: called before Ensure waits for a start in progress` to Manager and call `if m.onWait != nil { m.onWait() }` in Ensure directly before the `select { case <-e.ready: ...` at manager.go:192. In internal/backends/export_test.go add `func (m *Manager) SetOnWaitForTest(f func()) { m.onWait = f }`. In TestManagerEnsureConcurrentWaitsForInflightStart (internal/backends/manager_test.go:293): before the first `go call()`, `waiting := make(chan struct{}, 1)` and `m.SetOnWaitForTest(func() { waiting <- struct{}{} })`; replace the `time.Sleep(20 * time.Millisecond)` line with `<-waiting`.
      6. Run `go test -race -count=1 ./internal/peekd ./internal/backends` and `go build ./... && ./bin/peekd --help` style check: `go run ./cmd/peekd --help; echo $?` prints the usage and 0.
    acceptance:
      - "git grep -n 'empty = unauthenticated\\|empty = open' internal/peekd prints nothing (DOC-3)"
      - "grep -n 'metrics_token_set' internal/peekd/run.go matches and git grep -n 'metrics_auth' prints nothing (DOC-3)"
      - "go run ./cmd/peekd --help 2>&1 | grep -c 'backup\\|healthcheck' prints at least 2, and go run ./cmd/peekd --help exits 0 (DOC-13)"
      - "go test ./internal/peekd -run '^TestRunHelpPrintsUsageAndExitsZero$' -count=1 passes (DOC-13)"
      - "grep -n 'time.Sleep(20 \\* time.Millisecond)' internal/backends/manager_test.go prints nothing (TST-11)"
      - "go test -race -count=20 ./internal/backends -run '^TestManagerEnsureConcurrentWaitsForInflightStart$' passes (TST-11)"
      - "grep -n 'func freeAddr' internal/peekd/serve_test.go prints nothing and go test -race -count=3 ./internal/peekd passes (TST-11)"

  - id: p6-cli-help
    title: Per-command --help for peek, and the missing commands in its usage text
    depends_on: []
    complexity: S
    touches:
      - internal/cli/commands.go
      - internal/cli/commands_test.go
    brief: |
      Finding: DOC-13 (CLI part). Spec: plan Design D6.
      1. In internal/cli/commands.go add the usage lines, commandNames, commandUsage, wantsHelp and the help check in Run exactly as D6 specifies.
      2. In internal/cli/commands_test.go add `TestRunCommandHelpExitsZero`: table over every name in commandNames, args `{name, "--help"}` and `{name, "-h"}`: `runCaptured` returns code 0, stderr starts with `Usage:` and contains `peek <name>`. Add cases asserting `peek token --help` stderr contains `peek token create`, `peek login --help` stderr contains `peek login --oauth` and `peek login --token-file`, and `peek upload --help` does not contain `peek login`. Extend TestRunHelpVersionAndUnknown to assert the full usage contains `peek version` and `peek login --oauth`.
      3. `go test -race -count=1 ./internal/cli` passes; `go run ./cmd/peek upload --help; echo $?` prints the upload lines and 0.
    acceptance:
      - "go run ./cmd/peek upload --help; echo $? prints the upload usage lines and 0 (DOC-13)"
      - "go run ./cmd/peek token --help 2>&1 | grep -c 'peek token' prints 3 (DOC-13)"
      - "go test ./internal/cli -run '^(TestRunCommandHelpExitsZero|TestRunHelpVersionAndUnknown)$' -count=1 passes (DOC-13)"
      - "grep -n 'peek login --oauth' internal/cli/commands.go matches and grep -n 'peek version' internal/cli/commands.go matches (DOC-13)"

  - id: p7-cli-contract-test
    title: Run the CLI against a real in-process server
    depends_on: []
    complexity: S
    touches:
      - internal/cli/server_contract_test.go
    brief: |
      Finding: TST-2. Spec: plan Design D7.
      1. Create internal/cli/server_contract_test.go (package cli) with TestCLIAgainstRealServer exactly as D7's eight steps describe.
      2. `go test ./internal/cli -run '^TestCLIAgainstRealServer$' -count=1 -race` passes, and `go test ./internal/` (the architecture test) still passes.
      3. Prove it catches the review's mutant: `sed -i 's/Name       string `json:"name"`/Name       string `json:"title"`/' internal/server/api_uploads.go`, confirm with `git diff` that exactly the list item's tag changed (api_uploads.go:272), run the test and see it FAIL, then `git checkout -- internal/server/api_uploads.go`. Repeat with `json:"version_url"` → `json:"versionUrl"` at api_uploads.go:22.
      Stop condition: if a step's output differs from D7 with an unmodified server (for example a column layout), assert on what the CLI really prints only when it is the documented output format in internal/cli; if it looks like a server/CLI mismatch, stop with status=blocked and report it, since that is exactly the bug class this test exists for.
    acceptance:
      - "go test ./internal/cli -run '^TestCLIAgainstRealServer' -count=1 passes (TST-2)"
      - "with the json:\"title\" mutant of step 3 applied the test fails, and with the json:\"versionUrl\" mutant it fails; git status shows internal/server/api_uploads.go unmodified afterwards (TST-2)"
      - "go test ./internal/ -count=1 passes (architecture rules)"

  - id: p8-e2e-binaries
    title: End-to-end test of the built peek and peekd binaries, mise task and CI job
    depends_on: [p1-ci-pr-jobs]
    complexity: M
    touches:
      - internal/e2e/doc.go
      - internal/e2e/e2e_test.go
      - mise.toml
      - .github/workflows/ci.yml
    brief: |
      Finding: TST-3. Spec: plan Design D8.
      1. Create internal/e2e/doc.go and internal/e2e/e2e_test.go per D8 (standard library only; helpers marked t.Helper()).
      2. Add the `[tasks.e2e]` task to mise.toml and the `e2e` job to .github/workflows/ci.yml per D8 (after the existing jobs; checkout with persist-credentials: false).
      3. Run `PEEK_E2E=1 go test -count=1 -run '^TestE2E' -v ./internal/e2e` until it passes, then `mise run e2e`. Run `go test ./internal/e2e -v -count=1` without the variable and confirm the SKIP line.
      Stop condition: if setup, the API-key page or the CLI output does not match D8 (for example the key is not inside `id="hn-api-key"`), read the handler named in plan "Current state" and adapt only the extraction; if the flow itself differs (an extra confirmation step, a different redirect), stop with status=blocked.
    acceptance:
      - "PEEK_E2E=1 go test -count=1 -run '^TestE2E' ./internal/e2e passes (TST-3)"
      - "go test -count=1 -v ./internal/e2e prints '--- SKIP: TestE2EBinaries' when PEEK_E2E is unset (TST-3)"
      - "grep -n 'PEEK_E2E=1 go test' .github/workflows/ci.yml matches and grep -n '^\\[tasks.e2e\\]' mise.toml matches (TST-3)"
      - "go vet ./... and mise run fmt-check pass"

  - id: p9-browser-e2e
    title: Browser test of the peek.fetch path check, postMessage source check and comments
    depends_on: [p8-e2e-binaries]
    complexity: M
    touches:
      - scripts/e2e-browser.sh
      - scripts/e2e-browser.mjs
      - scripts/e2e-browser-page.html
      - package.json
      - .github/workflows/ci.yml
    brief: |
      Finding: TST-6. Spec: plan Design D9.
      1. Create scripts/e2e-browser-page.html, scripts/e2e-browser.sh (chmod +x, commit the mode) and scripts/e2e-browser.mjs per D9. Add the `e2e-browser` script to the root package.json; do not change dependencies (playwright-core 1.60.0 is already there).
      2. Add the `browser` job to .github/workflows/ci.yml per D9.
      3. Run it in the container: `pnpm install --frozen-lockfile && CHROME="$(ls /opt/pw-browsers/chromium-*/chrome-linux64/chrome | head -1)" scripts/e2e-browser.sh`. It must print `browser e2e: OK`.
      4. Prove the path check is tested: in internal/web/assets/app.js temporarily replace `if (!(url.origin === location.origin && url.pathname.startsWith(prefix))) {` with `if (false) {`, rerun step 3 and see check 1 fail, then `git checkout -- internal/web/assets/app.js`. Same for `if (e.source !== frame()) return;` → delete the line, see check 3 fail, restore.
      Stop condition: the D9 risk in plan "Risks and open questions" (composer does not open, or the positive control is not `ok:<status>`): stop with status=blocked and report what happened. Never weaken a check to pass.
    acceptance:
      - "pnpm install --frozen-lockfile && CHROME=<container chromium> scripts/e2e-browser.sh prints 'browser e2e: OK' (TST-6)"
      - "the two app.js mutations of step 4 each make the script exit non-zero, and git status shows internal/web/assets/app.js unmodified afterwards (TST-6)"
      - "grep -n 'scripts/e2e-browser.sh' .github/workflows/ci.yml matches (TST-6)"
      - "grep -n 'invalid peek.fetch path' scripts/e2e-browser.mjs matches"

  - id: p10-release-fixture
    title: Commit a v0.10.0 database and test the upgrade and the resulting schema
    depends_on: []
    complexity: M
    touches:
      - scripts/make-release-fixture.sh
      - internal/db/testdata/**
      - internal/db/release_fixture_test.go
    brief: |
      Finding: TST-8 (oldest supported release v0.10.0, confirmed by the owner). Spec: plan Design D10; read plan "Current state" for the toolchain note.
      1. Write scripts/make-release-fixture.sh per D10 (chmod +x). Read the v0.10.0 request shapes with `git show v0.10.0:internal/server/comments.go`, `git show v0.10.0:internal/server/api_uploads.go` and `git show v0.10.0:internal/server/grants.go` (or whichever v0.10.0 file `git grep -n handleAddGrant v0.10.0 -- internal/server` names). `git fetch --tags origin` first if the tag is missing.
      2. Run `scripts/make-release-fixture.sh v0.10.0`; commit internal/db/testdata/peek-v0.10.0.db and peek-v0.10.0.json. `sqlite3` is not needed by the script.
      3. Write internal/db/release_fixture_test.go with openReleaseFixture, TestOpenUpgradesReleaseFixture and TestUpgradedSchemaMatchesFresh per D10.
      4. `go test -race -count=1 ./internal/db` passes.
      Stop condition: see the D10 risk in plan "Risks and open questions". In particular, a schema difference other than uploads.visibility's default is a real finding: stop with status=blocked and report it.
    acceptance:
      - "go test ./internal/db -run '^(TestOpenUpgradesReleaseFixture|TestUpgradedSchemaMatchesFresh)$' -count=1 passes (TST-8)"
      - "test -f internal/db/testdata/peek-v0.10.0.db && grep -c '\"release\":\"v0.10.0\"' internal/db/testdata/peek-v0.10.0.json prints 1 (TST-8)"
      - "grep -n \"'password'\" internal/db/release_fixture_test.go matches only the documented uploads.visibility exception"
      - "go test -race -count=1 ./internal/db passes"

  - id: p11-coverage-ratchet
    title: Raise the coverage gate to 95% total with 93% floors for server, db and objectstore
    depends_on: [p3-server-test-fixes, p4-s3-signing-vector, p5-peekd-help-and-test-timing, p6-cli-help, p7-cli-contract-test, p9-browser-e2e, p10-release-fixture]
    complexity: S
    touches:
      - scripts/coverage-gate.sh
      - mise.toml
      - .github/workflows/ci.yml
    brief: |
      Finding: TST-9. Spec: plan Design D11.
      1. Update scripts/coverage-gate.sh per D11 (POSIX sh, it runs under `sh`).
      2. Update the mise.toml coverage description and the ci.yml coverage step name per D11.
      3. Run `sh scripts/coverage-gate.sh /tmp/cov.out`: it prints the total line and one OK line per package and exits 0. Prove the floor works: `COVERAGE_PACKAGE_MIN=99.9 sh scripts/coverage-gate.sh /tmp/cov.out` exits 1 with a FAIL line for internal/server.
      Stop condition: if the defaults fail on this branch, a merged phase left code untested; stop with status=blocked naming the package and its percentage. Never lower a default.
    acceptance:
      - "grep -n 'COVERAGE_MIN:-95' scripts/coverage-gate.sh matches (TST-9)"
      - "sh scripts/coverage-gate.sh /tmp/cov.out prints 'coverage gate: OK' for the total and for internal/server, internal/db and internal/objectstore, and exits 0 (TST-9)"
      - "COVERAGE_PACKAGE_MIN=99.9 sh scripts/coverage-gate.sh /tmp/cov.out exits 1 (TST-9)"

  - id: p12-governance-files
    title: SECURITY.md, CHANGELOG.md, PR template, profile changes, audit status line
    depends_on: []
    complexity: S
    touches:
      - SECURITY.md
      - CHANGELOG.md
      - .github/pull_request_template.md
      - .claude/toolkit.yaml
      - docs/audits/2026-10-security-and-coverage-audit.md
    brief: |
      Findings: SEC-3 (SECURITY.md), SEC-9 (profile), DOC-9 (PR template), DOC-10 (dod_conditional), DOC-15, DOC-17. Spec: plan Design D12.
      1. Write SECURITY.md, CHANGELOG.md and .github/pull_request_template.md per D12. No hard-wrapped lines (AGENTS.md).
      2. Edit .claude/toolkit.yaml per D12 and validate it: run the devflow profile validator the project-profile skill names (`python3 <devflow root>/scripts/validate_profile.py .claude/toolkit.yaml`); it must exit 0.
      3. Edit docs/audits/2026-10-security-and-coverage-audit.md per D12.
    acceptance:
      - "test -f SECURITY.md && grep -n 'security/advisories/new' SECURITY.md matches (SEC-3)"
      - "grep -n 'docs/audits/2026-10-security-and-coverage-audit.md' SECURITY.md matches (DOC-15)"
      - "test -f CHANGELOG.md && grep -n '## \\[Unreleased\\]' CHANGELOG.md matches (DOC-17)"
      - "grep -n 'merge_style: merge-commit' .claude/toolkit.yaml matches and grep -n 'file: CHANGELOG.md' .claude/toolkit.yaml matches and grep -n 'internal/backends/\\*\\*' .claude/toolkit.yaml matches (SEC-9, DOC-17, DOC-10)"
      - "test -f .github/pull_request_template.md (DOC-9)"
      - "sed -n 3p docs/audits/2026-10-security-and-coverage-audit.md | grep -c v0.10.0 prints 1 (DOC-15)"
      - "the profile validator exits 0"

  - id: p13-readme
    title: README and contact-form example accuracy
    depends_on: [p5-peekd-help-and-test-timing, p6-cli-help, p12-governance-files]
    complexity: M
    touches:
      - README.md
      - examples/contact-form/README.md
    brief: |
      Findings: DOC-1, DOC-2, DOC-4 (README), DOC-5 (README), DOC-12 (README), DOC-13 (README), DOC-16 (a, b, c), SEC-3 (link), SEC-7 (README), WEB-6. Texts: plan Design D13. No hard wrapping.
      1. WEB-6: after the intro paragraph (README.md:9-11) add `Documentation: https://andras-tkcs.github.io/peek/ (sources in [docs/src/content/docs](docs/src/content/docs)).`
      2. DOC-2: replace every `mypage-html-k7m2xq` with `mypage-k7m2xq` and the `#  -> ...` output comment with the four output lines of D13, as `#  ` comments.
      3. DOC-12 + SEC-7: README.md:59 cutoff `(v0.9.2 and older)` and the attestation sentence of D13.
      4. DOC-16a: README.md:84 `sandbox="allow-scripts allow-popups"`. DOC-16b: README.md:101 the comment-name sentence of D13.
      5. DOC-1: README.md:116-120 becomes `peek upload app.html --visibility public --name contact --backend ghcr.io/acme/contact-form:1.2`, a comment line `#  note the slug: line, e.g. slug: contact-k7m2xq`, and `<slug>` instead of `contact` in the three backend commands. examples/contact-form/README.md: the upload command at :20 becomes `peek upload examples/contact-form/index.html --visibility public --name contact --backend ghcr.io/acme/contact-form:1.0`, followed by the sentence `Note the slug: line of the output (for example contact-k7m2xq) and use it as <slug> below.`; every later `contact` slug argument becomes `<slug>` and `/p/contact` becomes `/p/<slug>`, including the Mailpit walkthrough (step 3 drops `--slug contact` and adds `--name contact`).
      6. DOC-13: in the README "CLI reference" block add the `peek login --oauth` and `peek version` lines and the `--value <v>|--value-stdin` form, with the same wording as internal/cli/commands.go (D6).
      7. DOC-4: replace README.md:215 with the peekd subcommand sentence of D13; add the "Other environment variables" list of D13 after the server flag table.
      8. DOC-5: README.md:243 table cell becomes the DOC-5 sentence of D13.
      9. SEC-3: add `To report a vulnerability, see [SECURITY.md](SECURITY.md); please do not open a public issue.` as the first line under `## Security model`.
      10. DOC-16c: replace the code block under `## Architecture` with one sentence: `See [docs/architecture.md](docs/architecture.md) for the package map and dependency rules.` and keep the sentence about runtime CSS/JS and the root `assets/` directory.
    acceptance:
      - "grep -rn -- '--slug contact' README.md examples skills docs prints nothing (DOC-1)"
      - "grep -rn 'html-k7m2xq' README.md prints nothing (DOC-2)"
      - "grep -c 'PEEK_HEALTHCHECK_ADDR\\|PEEK_LOG_LEVEL' README.md prints at least 2 (DOC-4)"
      - "grep -n 'must be HTTP(S)' README.md prints nothing (DOC-5)"
      - "grep -n 'v0.8.1 and older' README.md prints nothing (DOC-12)"
      - "grep -c -- '--oauth' README.md prints at least 1 and grep -n 'peek version' README.md matches (DOC-13)"
      - "grep -c 'sandbox=\"allow-scripts\"' README.md prints 0 (DOC-16)"
      - "grep -n 'gh attestation verify' README.md prints 1 line (SEC-7)"
      - "grep -c SECURITY.md README.md prints at least 1 (SEC-3)"
      - "grep -c 'andras-tkcs.github.io/peek' README.md prints at least 1 (WEB-6)"

  - id: p14-skills
    title: Agent skills accuracy and unwrapped lines
    depends_on: []
    complexity: S
    touches:
      - skills/peek/SKILL.md
      - skills/peek-server/SKILL.md
    brief: |
      Findings: DOC-2 (skill), DOC-4 (skill), DOC-5 (skill), DOC-12 (skill), DOC-14, DOC-16e. Texts: plan Design D13.
      1. DOC-14 first: rejoin every hard-wrapped paragraph and list item in both files into single lines (leave code blocks, tables and front matter alone). Check with the acceptance awk; it must print 0.
      2. DOC-2: skills/peek/SKILL.md sample output becomes the four lines of D13 with `https://peek.example.com/p/page-k7m2xq` and `page-k7m2xq`; replace every `page-html-k7m2xq`.
      3. DOC-12: skills/peek/SKILL.md:36 becomes the skill install example line of D13.
      4. DOC-4: add rows for `--s3-allow-private-endpoint` (`PEEK_S3_ALLOW_PRIVATE_ENDPOINT`, `false`, `Allow private/link-local S3 endpoints and http:// for dev or internal stores`) and `--oidc-allow-private-issuer` (`PEEK_OIDC_ALLOW_PRIVATE_ISSUER`, `false`, `Allow http/private OIDC issuers for local SSO testing`) to the skills/peek-server/SKILL.md configuration table, and add `PEEK_HEALTHCHECK_ADDR` (address probed by `peekd healthcheck`, defaults to `PEEK_ADDR`) to the sentence about `PEEK_LOG_LEVEL`.
      5. DOC-5: the S3 sentence in skills/peek-server/SKILL.md (around :230) becomes the DOC-5 sentence of D13.
      6. DOC-16e: in "Manage OAuth and invitations", say admins can enable Google, GitHub or generic OpenID Connect on the Admin page (not "Settings"), and add `https://peek.example.com/oauth/oidc/callback` to the callback URL block.
    acceptance:
      - "awk '/^```/{c=!c;next} !c && /^[A-Za-z`*(]/ && length>50 && length<=82 {getline n; if (n ~ /^[a-z`(]/) k++} END{print k+0}' skills/*/SKILL.md prints 0 (DOC-14)"
      - "grep -rn 'html-k7m2xq' skills prints nothing (DOC-2)"
      - "grep -c 'oidc-allow-private-issuer\\|s3-allow-private-endpoint' skills/peek-server/SKILL.md prints at least 2 (DOC-4)"
      - "grep -rn 'HTTPS unless localhost\\|must be HTTP(S)' skills prints nothing (DOC-5)"
      - "grep -n 'PEEK_VERSION=v0.1.0' skills/peek/SKILL.md prints nothing (DOC-12)"
      - "grep -c 'oidc/callback' skills/peek-server/SKILL.md prints at least 1 (DOC-16)"

  - id: p15-operations-doc
    title: Versioned upgrade notes, S3 rule, secret.key behaviour and links in the operator guide
    depends_on: [p3-server-test-fixes, p12-governance-files]
    complexity: S
    touches:
      - docs/operations.md
    brief: |
      Findings: DOC-6, DOC-5 (operations), DOC-16d, SEC-3 (link), SEC-11 (operator note). Facts: plan "Current state" (migration-to-release table). No hard wrapping.
      1. DOC-6: in "## Upgrades And Rollbacks" keep the two general paragraphs at the top and the "Rollback is simplest..." paragraph at the end; regroup every release note under `### <version>` headings, newest first: `### Unreleased` (new note for migration 17), `### v0.14.0` (migration 16), `### v0.13.0` (new note for migration 14, then migration 15), `### v0.10.0` (migrations 11, 12, 13, then the raw-route/sandbox, trusted-proxy and API-token-rules notes, rewritten to start with what changed, for example "The unversioned `/raw/<slug>` route is removed ...", never with "This release" or "This version"), `### v0.9.0` (migration 10), `### v0.8.0` (migrations 7, 8 and 9). Remove every "This release".
      2. New notes, worded from internal/db/migrations.go: migration 14 (`visibility_signed_in`) renames the `private` visibility to `signed-in` for existing pages (`UPDATE uploads SET visibility='signed-in' WHERE visibility='private'`); older binaries do not know `signed-in`, so roll back by restoring the pre-upgrade backup. Migration 17 (`provisioning`) adds the `provisioners` and `provisioned_accounts` tables for provisioning keys; older binaries ignore both tables, so a rollback keeps accounts and tokens working but provisioning keys stop working until the upgrade is re-applied.
      3. DOC-5: the S3 paragraph (around docs/operations.md:127) starts with the DOC-5 sentence of D13, then keeps the existing details about CGNAT, NAT64 and bucket names.
      4. DOC-16d: docs/operations.md:57 links "the Provisioning keys section" to `src/content/docs/auth-access.md#provisioning-keys`.
      5. SEC-3: at the end of the two general upgrade paragraphs add `Security fixes and how to report a vulnerability: [SECURITY.md](../SECURITY.md).`
      6. SEC-11: in the backups guidance (the section that tells operators to back up the data dir; `grep -n -i 'backup' docs/operations.md`), add: `peekd refuses to start when secret.key exists but is shorter than 32 bytes, instead of replacing it: restore the file from the same backup as peek.db, or delete it only if losing every session, API token signature and encrypted setting (S3 keys, OAuth secret) is acceptable.`
    acceptance:
      - "grep -c 'This release' docs/operations.md prints 0 (DOC-6)"
      - "grep -c 'igration 14\\|igration 17' docs/operations.md prints at least 2 (DOC-6)"
      - "grep -c '^### v0.10.0\\|^### Unreleased' docs/operations.md prints 2 (DOC-6)"
      - "grep -n 'auth-access.md#provisioning-keys' docs/operations.md matches (DOC-16)"
      - "grep -n 'must use HTTPS' docs/operations.md matches (DOC-5)"
      - "grep -n 'SECURITY.md' docs/operations.md matches (SEC-3)"
      - "grep -n 'shorter than 32 bytes' docs/operations.md matches (SEC-11)"

  - id: p16-contributing
    title: CONTRIBUTING tests, docs-site and PR sections; one check-full trigger list
    depends_on: [p1-ci-pr-jobs, p9-browser-e2e, p11-coverage-ratchet, p12-governance-files, p17-screenshots]
    complexity: M
    touches:
      - CONTRIBUTING.md
      - AGENTS.md
      - docs/architecture.md
    brief: |
      Findings: DOC-8, DOC-9, DOC-10, TST-9 (doc), SEC-3 (link), SEC-9 (doc), DOC-17 (rule). No hard wrapping.
      1. DOC-8: replace the "no bundler or generated app-asset step" sentence in CONTRIBUTING.md:19 and the "do not add a frontend framework" clause of :21 with: `CSS is generated: mise run tailwind (also run by mise run build) downloads the pinned Tailwind v4.3.1 CLI, verifies its SHA-256 and regenerates internal/web/assets/pines.css; commit the result. The dashboard and admin pages use Alpine.js (alpine.min.js, dashboard-alpine.js); the viewer (app.js, bridge.js) is vanilla JavaScript. Do not add other frameworks or a bundler.` (commands and file names in backticks). Keep the rest of both paragraphs.
      2. Update CONTRIBUTING.md:23 to say the screenshots live only in docs/public/assets/screenshots/ and are regenerated with `pnpm gen-screenshots` (needs Chromium and sqlite3), and that the root `assets/` holds the README logo and demo GIF.
      3. DOC-10 + TST-9: in "## Quality Gates", make CONTRIBUTING the single trigger list: "Run `mise run check-full` before opening a PR, and always after touching `internal/server`, `internal/db`, `internal/objectstore`, `internal/uploads` or `internal/backends`, auth, settings, rendering, background workers, concurrency or package boundaries." Then: "`check-full` matches CI's `build` job; CI also runs the jobs listed under Tests." and a sentence on the ratchet: coverage must stay at or above 95% total and 93% for internal/server, internal/db and internal/objectstore (`scripts/coverage-gate.sh`, override with COVERAGE_MIN / COVERAGE_PACKAGE_MIN only to test the script); raise the floors when coverage rises, never lower them.
      4. DOC-9: add `## Tests` listing each suite with its exact command: unit `mise run test`; race `mise run race`; coverage gate `mise run coverage`; govulncheck `mise run govulncheck`; staticcheck `mise run staticcheck`; Docker integration `docker build -t peek-example-contact:ci examples/contact-form && PEEK_DOCKER_TEST=1 PEEK_DOCKER_TEST_IMAGE=peek-example-contact:ci go test -count=1 -run '^TestDockerIntegration' ./internal/backends`; example module `cd examples/contact-form && go test ./...`; binaries end-to-end `mise run e2e`; browser `pnpm install && pnpm e2e-browser` (needs Chrome or Chromium, `CHROME=` to point at it); docker image `docker build -t peek:ci .`; release-fixture refresh `scripts/make-release-fixture.sh v0.10.0`; manual smoke `mise run run` + `mise run smoke`. Name the matching CI job for each (build, backend-integration, e2e, browser, docker, cross-build, docs).
      5. DOC-9: add `## Docs site`: `pnpm install --dir docs`, `pnpm docs:dev`, `pnpm docs:build`, `node scripts/check-docs-links.mjs docs/dist`; pushes to main that touch docs/ are published by `.github/workflows/pages.yml`.
      6. DOC-9 + SEC-9 + DOC-17: add `## Pull requests`: branch names `<type>/<slug>` with type one of feat, fix, docs, refactor, test, chore, style; run `mise run check-full`; required checks build, backend-integration, docs, docker, cross-build, e2e and browser; PRs merge with merge commits only (no squash or rebase), so write each commit message for main's history; a user-visible change adds a line under `## [Unreleased]` in CHANGELOG.md; fill in `.github/pull_request_template.md`.
      7. SEC-3: add `Report security issues privately as described in [SECURITY.md](SECURITY.md).` at the end of the intro paragraph.
      8. AGENTS.md: replace the sentence "Before opening a PR or after touching shared server, database, storage, auth, or concurrency behavior:" with "Before opening a PR, and after the changes CONTRIBUTING.md → Quality Gates lists:". Keep the code block.
      9. docs/architecture.md:41: replace the "it mirrors the CI quality gate ..." clause with the check-full sentence of plan Design D13, and add `internal/e2e` (end-to-end test of the built binaries, test-only) to the package map.
    acceptance:
      - "grep -ci tailwind CONTRIBUTING.md prints at least 1 and grep -ci alpine CONTRIBUTING.md prints at least 1 (DOC-8)"
      - "grep -c 'no bundler or generated app-asset step' CONTRIBUTING.md prints 0 (DOC-8)"
      - "grep -c 'PEEK_DOCKER_TEST\\|docs:dev\\|examples/contact-form' CONTRIBUTING.md prints at least 3 (DOC-9)"
      - "grep -n 'merge commits only' CONTRIBUTING.md matches (SEC-9)"
      - "grep -n 'mirrors the CI' docs/architecture.md prints nothing (DOC-10)"
      - "grep -n '95%' CONTRIBUTING.md matches (TST-9)"
      - "grep -c SECURITY.md CONTRIBUTING.md prints at least 1 (SEC-3) and grep -n 'CHANGELOG.md' CONTRIBUTING.md matches (DOC-17)"
      - "grep -n 'CONTRIBUTING.md' AGENTS.md matches (DOC-10)"

  - id: p17-screenshots
    title: Regenerate the app screenshots into one location and drop unused media
    depends_on: []
    complexity: M
    touches:
      - scripts/gen-screenshots.sh
      - scripts/gen-assets.sh
      - docs/public/assets/**
      - assets/screenshots/**
    brief: |
      Findings: WEB-1, WEB-9 (b, f). Facts: plan "Current state".
      1. scripts/gen-screenshots.sh: set `OUT="$ROOT/docs/public/assets/screenshots"`, delete `DOCS_OUT` and the block that mirrors screenshots into it (keep the hero.png mirror), update the header comment and the last echo to name docs/public/assets/screenshots/.
      2. `git rm -r assets/screenshots` (README does not reference it; verify with `git grep -n 'assets/screenshots' -- ':!docs/public'` that nothing outside the site does, apart from the script you just changed).
      3. WEB-9b: `git rm docs/public/assets/demo.mp4` and delete the lines in scripts/gen-assets.sh that mirror demo.mp4 into docs/public/assets (around :152-156), keeping assets/demo.mp4 and the GIF.
      4. Regenerate: `apt-get update && apt-get install -y sqlite3`, `pnpm install --frozen-lockfile`, then `CHROME="$(ls /opt/pw-browsers/chromium-*/chrome-linux64/chrome | head -1)" scripts/gen-screenshots.sh`. All 11 PNGs and docs/public/assets/hero.png must be rewritten.
      5. Look at docs/public/assets/screenshots/05-dashboard-uploads.png and 08-admin-auth.png (open the images): 05 must show the Restricted default and no "Password" option; note in your report which fields 08 shows, because p18 adjusts its caption. Stop condition: if 05 still shows "Password", the script seeded old data or used an old binary; stop with status=blocked.
    acceptance:
      - "find . -name '05-dashboard-uploads.png' -not -path '*/node_modules/*' | wc -l prints 1 (WEB-1)"
      - "git diff --stat origin/main -- docs/public/assets/screenshots lists all 11 PNG files as changed (WEB-1)"
      - "test ! -e docs/public/assets/demo.mp4 (WEB-9)"
      - "grep -n 'DOCS_OUT' scripts/gen-screenshots.sh prints nothing"
      - "the worker's report states that 05-dashboard-uploads.png shows Restricted and no Password, and lists the fields visible in 08-admin-auth.png (WEB-1, WEB-9f)"

  - id: p18-site-content
    title: Complete the site reference, add restore, upgrade, email and audit guidance, fix naming
    depends_on: [p5-peekd-help-and-test-timing, p6-cli-help, p13-readme, p15-operations-doc, p17-screenshots]
    complexity: M
    touches:
      - docs/src/content/docs/**
    brief: |
      Findings: WEB-2, WEB-3, WEB-4, WEB-9 (c, f). Texts: plan Design D13. No hard wrapping. Use the current code as the source: internal/server/routes.go, `go run ./cmd/peek help`, `go run ./cmd/peekd --help`.
      1. WEB-2: in docs/src/content/docs/reference.md "## Page And API Routes", add one table row per route in internal/server/routes.go that is missing (at least: GET /api/uploads, DELETE /api/uploads/{slug}, POST /api/uploads/{slug}/visibility, POST /api/uploads/{slug}/name, GET /api/uploads/{slug}/stats, GET|PUT /api/settings, GET /api/audit, GET /api/uploads/{slug}/export, DELETE /api/uploads-by-owner, GET /api/auth/providers, GET /raw/{slug}/v/{n}, GET /api/uploads/{slug}/views, the /api/tokens and /api/provisioners routes), each with method, path, auth (`token`, `admin token`, `page access` or `none`, read from the wrapper in routes.go: authToken → token, authAdmin → admin token, no wrapper → page access or none per the handler) and one line. Replace the "CLI Commands" block with the full output of `go run ./cmd/peek help 2>&1` (the usage text after p6).
      2. WEB-3: add `## peekd Subcommands` to reference.md with a table: `peekd --version`; `peekd backup [--data <dir>] [path]` (default `<data>/peek-backup.db`, VACUUM INTO, safe while running); `peekd healthcheck [--addr <host:port|url>]` (reads PEEK_HEALTHCHECK_ADDR, then PEEK_ADDR; exit 0 on 200 from /healthz); and a row for PEEK_HEALTHCHECK_ADDR and PEEK_LOG_LEVEL in the server parameters section, same wording as README (p13).
      3. WEB-4: in storage-retention.md add `## Restore` with the five steps of D13 after "## Backups"; add `## Upgrades And Rollbacks` that condenses docs/operations.md's upgrade section (take a backup first, try on a staging copy, roll back by restoring the pre-upgrade backup plus object storage, and the per-version notes as a short list linking to https://github.com/andras-tkcs/peek/blob/main/docs/operations.md#upgrades-and-rollbacks); in server-setup.md add `## Email` (SMTP is configured by an admin on the Admin page, Email tab; what it is used for: grant and restricted-page emails, invites; the test-email button) worded from docs/operations.md:83-91; in auth-access.md add a `## Audit Log` section saying admins read it with `GET /api/audit` (admin token) and what is recorded, worded from docs/operations.md's Observability section.
      4. WEB-9c: replace `kicker: Settings / Auth` and `kicker: Settings / Storage` with `Admin / Auth` and `Admin / Storage`, and every "Settings" naming of the Admin page in image alt texts (`Peek Settings Auth tab` → `Peek Admin page, Auth tab`, same for Storage and Limits).
      5. WEB-9f: rewrite the 08-admin-auth caption/alt text in auth-access.md to list only the fields the regenerated image shows (p17's report).
      6. Build and check: `pnpm install --dir docs --frozen-lockfile && pnpm --dir docs build && node scripts/check-docs-links.mjs docs/dist`.
    acceptance:
      - "for r in /api/settings /api/audit /api/tokens /export /stats /visibility uploads-by-owner /raw/ 'delete-all' 'token create' 'config show' -- '--oauth'; do grep -qF -- \"$r\" docs/src/content/docs/reference.md || echo MISSING $r; done prints nothing (WEB-2)"
      - "grep -c 'PEEK_HEALTHCHECK_ADDR\\|peek-backup.db\\|peekd --version' docs/src/content/docs/reference.md prints at least 3 (WEB-3)"
      - "grep -n '^## Restore' docs/src/content/docs/storage-retention.md prints 1 line, grep -rln -i 'roll back\\|rollback' docs/src/content/docs prints at least 1 file, grep -rn '^## Email' docs/src/content/docs prints 1 line (WEB-4)"
      - "grep -rn 'Settings /\\|Peek Settings' docs/src/content prints nothing (WEB-9)"
      - "pnpm --dir docs build succeeds and node scripts/check-docs-links.mjs docs/dist prints 'docs links: OK'"

  - id: p19-site-shell
    title: Sidebar section links from page headings, heading order, base-path link, home-page backticks
    depends_on: []
    complexity: S
    touches:
      - docs/src/components/DocsShell.astro
      - docs/src/pages/**
      - docs/src/styles/site.css
    brief: |
      Findings: WEB-8, WEB-9 (a, d, e).
      1. WEB-8: in docs/src/pages/docs/[slug].astro use `const { Content, headings } = await render(entry);` and pass `headings` to DocsShell; do the same in docs/src/pages/docs/index.astro (it renders the `index` entry). In DocsShell.astro accept `headings: Array<{ depth: number; slug: string; text: string }> = []`, delete `anchorsBySlug`, and build `sectionNav` as one group titled `On this page` whose links are the depth-2 headings (`label: text`, `href: '#' + slug`). Pages without headings show no section group.
      2. WEB-9d: render every sidebar group title (in DocsShell.astro and docs/src/pages/manual.astro; the landing page docs/src/pages/index.astro has no sidebar) as `<p class="nav-heading">` instead of `<h2>`, and change the CSS selectors `.nav-section h2` (docs/src/styles/site.css:395 and :522) to `.nav-section .nav-heading` with the same rules.
      3. WEB-9e: in docs/src/pages/manual.astro replace `href="/peek/docs/reference/"` with the base helper used in that file or `${import.meta.env.BASE_URL}docs/reference/`.
      4. WEB-9a: docs/src/pages/index.astro:35 replace the literal `` `Peek` `` with `<code>Peek</code>`.
      5. `pnpm install --dir docs --frozen-lockfile && pnpm --dir docs build && node scripts/check-docs-links.mjs docs/dist` (the script exists once p1 has merged; if it is not on your branch yet, skip only that last command and say so).
    acceptance:
      - "after pnpm --dir docs build: grep -c 'href=\"#provisioning-keys\"' docs/dist/docs/auth-access/index.html prints at least 2 and grep -c 'href=\"#add-a-backend\"' docs/dist/docs/using-peek/index.html prints at least 1 (WEB-8)"
      - "grep -n 'anchorsBySlug' docs/src/components/DocsShell.astro prints nothing (WEB-8)"
      - "grep -c '`Peek`' docs/dist/index.html prints 0 (WEB-9)"
      - "grep -n '\"/peek/' docs/src/pages/*.astro prints nothing (WEB-9)"
      - "grep -rn '<h2>{group.title}</h2>' docs/src prints nothing (WEB-9)"

  - id: p20-retire
    title: Changelog entries, final consistency pass, delete the plan
    depends_on: [p1-ci-pr-jobs, p2-publish-hardening, p3-server-test-fixes, p4-s3-signing-vector, p5-peekd-help-and-test-timing, p6-cli-help, p7-cli-contract-test, p8-e2e-binaries, p9-browser-e2e, p10-release-fixture, p11-coverage-ratchet, p12-governance-files, p13-readme, p14-skills, p15-operations-doc, p16-contributing, p17-screenshots, p18-site-content, p19-site-shell]
    complexity: S
    touches:
      - CHANGELOG.md
      - docs/plans/**
    brief: |
      1. Add to CHANGELOG.md under `## [Unreleased]` (no version heading) a `### Added` list: build provenance attestations for release archives and images (`gh attestation verify <archive> -R andras-tkcs/peek`); SECURITY.md with private vulnerability reporting; `peek <command> --help` and `peekd --help` (subcommands and PEEK_* variables). A `### Changed` list: peekd refuses to start when `secret.key` is shorter than 32 bytes instead of replacing it, and writes new keys atomically; the startup log field `metrics_auth` is now `metrics_token_set`; a release tag must point at a commit on main and pass vet, race tests and govulncheck before anything is published, and pre-release tags no longer move the `:latest` image; the `:main` image is published only after CI passes on main. A `### Fixed` list: the contact-form example and README backend commands; slug examples; the `--metrics-token` help text.
      2. Run every acceptance grep of the phases above once more on the merged branch and fix any that regressed in files this phase may touch; for other files, report the regression with status=blocked.
      3. `git rm docs/plans/repo-2026-10-27-fixes-plan.md docs/plans/repo-2026-10-27-fixes-plan-manual-steps.html`; if docs/plans is then empty, nothing else is needed. `git grep -n 'repo-2026-10-27-fixes-plan'` must print nothing.
      4. `mise run check-full` passes.
    acceptance:
      - "test ! -e docs/plans/repo-2026-10-27-fixes-plan.md && test ! -e docs/plans/repo-2026-10-27-fixes-plan-manual-steps.html"
      - "git grep -n 'repo-2026-10-27-fixes-plan' prints nothing"
      - "grep -c '^### ' CHANGELOG.md prints at least 3 and grep -cE '^## \\[[0-9]' CHANGELOG.md prints 0"
      - "mise run check-full passes"
```
