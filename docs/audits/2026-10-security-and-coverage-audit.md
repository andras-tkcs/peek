# Security and test coverage audit — 2026-10-11

Status: Critical, Medium and Low findings addressed in PR #16 (first released in v0.10.0). Info items remain open except the two page-password items, which no longer apply since page passwords were removed (migration 15), and the `loadOrCreateSecret` item, which is fixed (see below).

Scope: the whole repository at `6380c6b` (server `peekd`, CLI `peek`, storage, DB, templates, CI, Docker, install script). Method: manual review of every package, cross-checked by tracing each finding to a concrete code path; one finding (S1) was confirmed with a throwaway end-to-end test. Tooling run: `go vet`, `go test -race`, coverage, `staticcheck`. `govulncheck` could not reach vuln.go.dev from the audit sandbox; CI runs it on every push.

## Summary

| Area | Result |
| --- | --- |
| `go vet`, `staticcheck`, `gofmt` | clean |
| `go test -race ./...` | all pass |
| Total statement coverage | **68.9%** |
| Critical findings | 1 |
| Medium findings | 6 |
| Low / Info | 15+ |

The codebase is in good shape overall: SQL is fully parameterised, templates use `html/template` with no `template.HTML` escapes, tokens/invites/device codes are 192–256-bit and stored as SHA-256 hashes, CSRF double-submit covers every cookie-authenticated POST, OAuth uses state + PKCE, object keys are traversal-safe, the S3 dialer re-validates resolved IPs (DNS-rebinding safe), and the container runs non-root on `scratch`. One design flaw, however, undermines the whole uploaded-HTML isolation model and must be fixed first.

## Findings

### S1 — Critical: uploaded HTML executes unsandboxed on the Peek origin → account takeover

- `internal/server/pages.go:117` builds the iframe URL `/raw/<slug>/v/<n>?t=<token>&v=<visitor-id>`.
- `internal/server/pages.go:172` (`rawViewerID`) takes the visitor id from the `?v=` query parameter first, so the URL alone is a complete credential, valid for `viewTokenTTL` (1 h) in any browser.
- `internal/server/pages.go:263` (`writeRawHTML`) sends a CSP with no `sandbox` directive and `connect-src https: http:` (which includes Peek itself). `frame-ancestors 'self'` restricts embedding only, not top-level navigation.
- The iframe `sandbox="allow-scripts allow-popups"` attribute (`internal/web/templates/page.gohtml:16`) is the only isolation, and it does not apply when the raw URL is opened directly.

Exploit: any account uploads a page with a script, opens its own `/p/<slug>`, copies the iframe `src`, and sends it to an admin (or hosts a redirector that mints a fresh one per click). The page runs on Peek's origin; same-origin `fetch` carries the `SameSite=Strict` session cookie; `hn_csrf` is readable (`web_csrf.go:18`, `HttpOnly: false`). The script can then `POST /dashboard/api-keys` and exfiltrate the key, `POST /dashboard/users/{id}/admin`, change OAuth/S3 settings, or delete pages. A leaked raw URL of a password/private/restricted page also bypasses its gate for an hour.

Confirmed during the audit: a cookie-less `GET` of a harvested raw URL with `Sec-Fetch-Dest: document` returned `200` with the CSP above and no `sandbox`.

Fix (in order of priority):
1. Add `sandbox allow-scripts allow-popups` to the raw CSP. This forces an opaque origin even on top-level navigation and is a one-line change.
2. Reject `/raw` unless `Sec-Fetch-Dest` is `iframe` (when the header is present).
3. Bind the view token to the HttpOnly `hn_vid` cookie only; drop the `?v=` override.
4. Make `hn_csrf` HttpOnly (the templates already embed the token).
5. Longer term: serve raw content from a separate registrable domain (`PEEK_CONTENT_ORIGIN`).

Add regression tests for 1–3.

### S2 — Medium: `X-Forwarded-For` spoofing defeats every rate limit when `--trusted-proxy` is on

`internal/server/analytics.go:111` (`clientIP`) returns the **leftmost** XFF entry, which the client controls (proxies append on the right). Rotating `X-Forwarded-For` gives unlimited bcrypt guesses on page passwords (`POST /p/{slug}`), password login, and setup, bypasses the global/upload/comment limiters, and forges audit-log IPs. Each spoofed key also adds an entry to the limiter map, which is only pruned of expired entries (`ratelimit.go`), so memory can grow without bound and the prune scan becomes a lock-held CPU hotspot. `analytics_test.go:52` currently pins the leftmost behaviour.

Fix: take the rightmost hop not in a configured trusted-proxy CIDR list; add a per-slug failure limiter on page passwords and a per-account limiter on logins; hard-cap the limiter map. Without `--trusted-proxy` behind a proxy, the whole organisation shares one bucket (10 logins/min) — document this.

### S3 — Medium: CLI device login is one-click phishable

`internal/server/cli_login.go:46` returns `verification_url = <base>/cli-login/<user_code>` with the code pre-filled, and the approval page (`cli_login.go:114-176`, `cli_login.gohtml`) shows only the code and the user's name. An attacker runs `peek login --host https://peek.corp`, sends the printed link to a victim, the victim signs in and clicks Approve, and the attacker's poll receives a non-expiring API token for the victim (admin if the victim is admin).

Fix: make the user type the code from their own terminal (no code in the URL), show the requesting IP/user agent/time and a "only approve if you just ran `peek login`" warning, and give CLI tokens a default expiry.

### S4 — Medium: API tokens bypass the email-domain allowlist and "OAuth required" policy

`authToken` / `authAdmin` (`internal/server/middleware.go:50-110`) only check `Disabled`, while `webAuth` (`web_auth.go:31-39`) also enforces the allowed domain and OAuth-required setting. The bearer path in `handleListComments` has the same gap. `TestDirectAPITokenAuthIgnoresAllowedEmailDomain` shows this is intentional, but the effect is that tightening SSO policy does not cut off existing API keys. Combined with tokens that never expire (`db/tokens.go:84`, `cli_login.go:103`) and have no scopes, offboarding relies entirely on manually disabling accounts.

Fix: decide policy explicitly. Recommended: a shared `accountActive(ctx, account)` used by all three auth paths, default token expiry (e.g. 90 days for CLI tokens), and an admin "revoke all tokens for user" action.

### S5 — Medium: supply chain — install script and images point at another owner, no integrity checks

- `install.sh:14` (`REPO="puemos/peek"`), README badges/links, `skills/*/SKILL.md`, and `ghcr.io/puemos/peek:latest` reference `puemos/peek`, while `go.mod`, release ldflags and the git remote use `andras-tkcs/peek`. Users of this fork who follow the docs install binaries and images built by a different owner, possibly from different code.
- `install.sh:56-65` downloads and extracts without a checksum or signature check; `release.yml` publishes no checksums, signatures, or provenance.
- `mise.toml` (`tailwind` task) downloads and executes the Tailwind binary via `curl -sL` with no `-f` and no hash pin.

Fix: point all references at the organisation's own repo/registry (pin images by digest); publish `checksums.txt` plus cosign or `actions/attest-build-provenance` and verify in `install.sh`; pin the Tailwind download by SHA-256.

### S6 — Medium: CLI opens a server-supplied URL without validation

`internal/cli/login_oauth.go:38-39` passes `verification_url` from the server straight to `openBrowser` (`browser.go`: `xdg-open`, `open`, `rundll32 url.dll,FileProtocolHandler`). No shell is involved, but a malicious or MITM'd server (plain `http://` hosts are accepted silently) can return `file:`, `smb://`, custom-protocol, or `-`-prefixed values; on Windows `FileProtocolHandler` will launch local or UNC executables.

Fix: only open `http`/`https` URLs on the same origin as the configured host; reject leading `-`; warn on non-loopback `http://` hosts.

### S7 — Medium-Low: data directory, database and uploads are world-readable

`server.go:78,149` and `objectstore/file.go:27,31` create directories `0755` and files `0644`; `peek.db` and `peek-backup.db` (`peekd/backup.go`) get SQLite's default `0644`. Only `secret.key` is `0600`. On a shared host (non-Docker install), any local user can read private/restricted pages, emails and password hashes.

Fix: `0700` dirs / `0600` files, or set `umask(077)` at startup; write backups `0600`.

### Low

- **L1 — No body limit on unauthenticated form endpoints.** `POST /p/{slug}` (`pages.go:147`), login (`web_login.go`), and setup call `ParseForm` without `MaxBytesReader` (up to ~10 MB urlencoded or 32 MB multipart per request). Wrap non-upload bodies in a 64 KB limit in `withMiddleware`.
- **L2 — OIDC claim mixing.** `oauth_profile.go:144-163` takes `email_verified` from userinfo while keeping the ID-token email, and never checks that userinfo `sub` equals the ID-token `sub` (OIDC Core §5.3.2). Require matching `sub` and take email + `email_verified` from the same source.
- **L3 — No OIDC `nonce`.** `oauth_flow.go:34`, `oauth_profile.go:130`. Mitigated by PKCE + state cookie; add for defence in depth.
- **L4 — Login timing reveals which accounts exist.** `web_login.go:68-81` only runs bcrypt for existing, enabled, password-bearing, in-domain accounts. Compare against a dummy hash on every failure path.
- **L5 — Sessions cannot be revoked server-side.** Signed account-id cookies valid for 7 days (`oauth_session.go:46-54`); logout only clears the browser cookie. Add a per-account `session_epoch`.
- **L6 — Raw view tokens outlive a visibility change.** A token minted while public works for up to 1 h after the page goes private/restricted or a grant is removed. Include visibility/password hash/grants version in the HMAC subject.
- **L7 — Audit-log field injection / unbounded names.** `api_uploads.go:117`, `web_dashboard.go:166`, and `api_grants.go:126` join `key=value` with spaces using raw upload names; `uploads.Service.Create` doesn't enforce the 200-char `maxNameLength` that `Rename` does. Quote values (or store JSON) and enforce the limit on create.
- **L8 — Comment author spoofing.** `comments.go:131-147` accepts any `name`, so anyone with view access can post as "Alice (owner)". For signed-in viewers, take the name from the account and show a verified marker.
- **L9 — Flash message spoofing.** `web_dashboard.go:85-93` renders `?err=`/`?ok=` verbatim (via `x-text`, so not XSS) — usable for phishing text on the real dashboard. Use fixed message codes.
- **L10 — `/metrics` and `/readyz` are unauthenticated.** `/metrics` exposes counts/storage/token totals and runs aggregate queries per request; `/readyz` echoes raw DB errors. Add an optional metrics token or separate listen address; return a generic readiness error.
- **L11 — S3 SSRF block list gaps (admin-only setting).** `objectstore/s3_endpoint.go:57-69` misses `100.64.0.0/10` (CGNAT, incl. Alibaba metadata `100.100.100.200`), `64:ff9b::/96` (NAT64), `0.0.0.0/8`, `198.18.0.0/15`, multicast. `s3_bucket` is not validated before going into the URL path.
- **L12 — CLI path segments not escaped.** `uploads_command.go:71,95,171`, `stats_comments_command.go:37,104`, `gdpr_command.go:22`. A slug like `x/../../tokens/5` passed by an agent → ServeMux 301 → Go client re-issues `DELETE /api/tokens/5` with the bearer token. Use `url.PathEscape` and validate against the slug charset.
- **L13 — CLI credential hygiene.** `upload --password` on argv without warning; `SaveConfig` (`client.go:61`) doesn't tighten an existing `0644` file; `peek config set --host` keeps the old token (sent to the new host); `peekd --secret` / `--s3-secret-key` visible in `ps` (offer `_FILE` env vars).
- **L14 — CI hardening.** Actions pinned to moving tags (`@v4`, `anchore/sbom-action@v0`); `govulncheck@latest`, staticcheck `latest`; `release.yml` grants `packages: write` to every job. No `pull_request_target` or `${{ }}`-in-`run:` injection was found.
- **L15 — Guessable public slugs.** Slugs derive from the page name (`internal/uploads/slug.go`), e.g. `q3-reorg-plan`. Consider a random suffix for public pages.

### Info

- The same HMAC key and `subject.exp.sig` format is used for session, OAuth-flow, page-password and view tokens (`security.go`). No confusion is exploitable today; add a purpose prefix per token type.
- Setup code compared with `!=` (`bootstrap.go:118`) — negligible with 192 bits + rate limit, but it is printed to stdout, so container logs hold an admin-takeover credential until setup completes.
- Admins can always use password/token login even when SSO is enforced; there is no MFA.
- `loadOrCreateSecret` silently regenerates a secret shorter than 32 bytes, making encrypted settings unreadable, and the write isn't atomic. (Fixed: peekd now refuses a short `secret.key` and writes new keys atomically.)
- `peekd backup` covers only the SQLite DB, not file-storage uploads or `secret.key`.
- Audit log has no retention.
- Password gate page is served without `DashboardCSP` (`pages.go:83`). (no longer applies: page passwords were removed in migration 15)
- No minimum length for page passwords (`internal/uploads/visibility.go`). (no longer applies: page passwords were removed in migration 15)

## Test coverage

Per-package statement coverage (`go test -coverprofile`):

| Package | Coverage |
| --- | --- |
| `internal/groups` | 85.1% |
| `internal/uploads` | 82.1% |
| `internal/db` | 71.8% |
| `internal/server` | 70.1% |
| `internal/web` | 65.2% |
| `internal/cli` | 64.1% |
| `internal/objectstore` | 59.6% |
| `internal/peekd` | 56.1% |
| `cmd/*`, `internal/version`, `internal/models`, `internal/uploadquota` | 0% / no tests |
| **Total** | **68.9%** |

The number is respectable, but coverage is uneven exactly where it matters for security. Notable gaps:

**Zero-coverage, security-relevant functions**

- `server/cli_login.go`: `handleCLILoginPage`, `handleCLILoginApprove`, `renderCLILoginForm` — the device-flow approval (S3) is entirely untested, including auth redirect, CSRF, deny, and approving an expired code.
- `server/admin.go`: `handleDashboardUserAdmin`, `handleDashboardUserDisabled` — privilege grant/revoke has no tests, including non-admin rejection and CSRF.
- `server/api_tokens.go`: `handleDeleteToken`.
- `server/api_uploads.go`: `handleDeleteAllByOwner` (GDPR delete-all).
- `server/api_stats.go`: `handleStats`; `server/metrics.go`: `handleMetrics`.
- `server/oauth_profile.go`: `fetchGoogleProfile`; `db/oauth.go`: `GetOAuthIdentity`, `UpsertOAuthIdentity`, `AccountHasOAuthIdentity`.
- `objectstore/s3.go`: the entire S3 client (`Save`, `Open`, `Delete`, `putObject`, `getObject`, `deleteObject`, `readS3ErrorBody`).
- `peekd`: `Run`, `runServe`, `runBackup`, `configureLogging`.
- `cli/browser.go`: `openBrowser`.

**Low-coverage (<60%) security-relevant functions**

`handleOAuthStart` 30.8%, `handleOAuthCallback` 42.6%, `fetchOAuthProfile` 40.0%, `fetchOIDCProfile` 42.9%, `resolveOAuthAccount` 56.4%, `authAdmin` 52.9%, `loginWithPassword` 50.0%, `handleLogout` 50.0%, `handleCLILoginPoll` 51.2%, `handleDashboardCreateInvite` 30.8%, `handleDeleteUpload` 52.9%, `serveRawObject` 58.8%, `handleDashboardUpload` 47.9%, `migrateInviteTokenCipher` 57.1%.

**Missing negative / abuse tests (no test asserts the secure behaviour)**

1. `/raw` carries a CSP `sandbox`, refuses `Sec-Fetch-Dest: document`, and refuses a token whose visitor id differs from the `hn_vid` cookie (S1).
2. `clientIP` with spoofed/multi-hop XFF; limiter map growth under many unique keys (S2).
3. Non-owner (non-admin) requests to `DELETE /api/uploads/{slug}`, `POST …/visibility`, `POST …/name`, `GET …/stats`, `GET …/export`, `POST /dashboard/delete/{slug}`, and bearer `GET …/comments`. The ownership checks exist and look correct, but nothing prevents a regression.
4. Non-admin rejection on `/dashboard/users/{id}/admin|disabled`, `/dashboard/invites*`, `/dashboard/settings`.
5. `authToken`/`authAdmin` vs domain allowlist and OAuth-required policy (whichever policy is chosen in S4).
6. Raw token after a public → private switch (L6).
7. OIDC userinfo `sub` mismatch / claim mixing (L2); `parseOAuthFlowCookie` tampering and provider mismatch; `safeNextPath` unit tests.
8. Disabled-account and unknown-email paths of password login (L4).
9. `isPrivateOrMetadataIP` edge cases (IPv6, IPv4-mapped, CGNAT, NAT64) and dial-time refusal on DNS rebinding/redirect (L11).
10. File modes for the data dir, uploads, `peek.db`, backups, `secret.key`, and the CLI config when the file already exists (S7, L13).
11. Body-size caps on non-upload form endpoints (L1).
12. CLI `verification_url` validation and slug escaping (S6, L12).
13. `loadOrCreateSecret` with a short or corrupt file; setup-code validation after the first account exists.
14. S3 storage against a fake server (`httptest`), including error bodies and redirects.

**Process gap:** CI prints total coverage but enforces no floor. Add a threshold (e.g. fail under 68%, ratcheting up) and consider per-package floors for `internal/server` and `internal/db`.

## Recommended order of work

1. **Now:** S1 (raw CSP `sandbox` + `Sec-Fetch-Dest` check + cookie-bound token + HttpOnly CSRF cookie) with regression tests.
2. **Next:** S2 (correct XFF parsing, per-slug and per-account limiters, map cap), S3 (typed device code + context on the approval page), S4 (token policy + default expiry).
3. **Then:** S5–S7 supply-chain and permissions hardening; the Low items in batches.
4. **Alongside:** the authz negative-test matrix (items 3–5 above) and the CLI-login/admin-toggle handler tests, then a CI coverage floor.
