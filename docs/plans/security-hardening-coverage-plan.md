# Security hardening and 90% test coverage plan

## Goal

Fix every Critical, Medium and Low finding of the 2026-10 security audit (`docs/audits/2026-10-security-and-coverage-audit.md`, on this branch) and raise total Go statement coverage from 68.9% to at least 90%, enforced by a CI gate. For users this means: uploaded HTML can no longer act as Peek even when its raw URL is opened directly; rate limits cannot be dodged with a forged `X-Forwarded-For`; `peek login` cannot be phished with a link; API tokens follow the same account rules as dashboard sign-in and CLI tokens expire after 90 days; OIDC logins check a nonce and never mix claims; sessions can be signed out server-side; data files are owner-only; `/metrics` can require a token; the install script, release and CI are pinned and verified; page links get a random suffix; audit details, dashboard flashes and comment authors can no longer be forged. Info-level items and a separate content origin are out of scope.

There is no tracking issue; the request came from the audit session (`/make-plan for all these target test coverage is 90%`). User decisions taken before planning: coverage is measured as the **total** of `go test -coverprofile ./...` and CI fails below 90.0%; API tokens follow the account policy and `peek login` tokens expire after 90 days; every `puemos/peek` reference moves to `andras-tkcs/peek` and `install.sh` verifies a `checksums.txt`; scope is Critical + Medium + Low.

## Current state

- **Audit.** 1 Critical (S1), 6 Medium (S2–S7), 15 Low (L1–L15), each traced to code; S1 was reproduced with an end-to-end test (a cookie-less `GET` of a harvested `/raw/...` URL with `Sec-Fetch-Dest: document` returned 200 with no CSP `sandbox`). The audit file lists file:line for each finding.
- **Tooling at 6380c6b.** `go vet`, `gofmt`, `staticcheck` clean; `go test -race ./...` passes. `govulncheck` cannot reach `vuln.go.dev` from a cloud container (HTTP 403 from the proxy); CI runs it.
- **Coverage at 6380c6b.** 5336 statements, 3675 covered, **68.9%**. Per package: server 70.1% (873 uncovered of 2916), db 71.8% (264/936), cli 64.1% (290/807), peekd 56.1% (93/212), objectstore 59.6% (88/218), uploads 82.1% (27/151), web 65.2% (16/46), groups 85.1% (7/47); `cmd/*` and `internal/version` 0% (3 statements). About 79 uncovered statements are effectively unreachable (Design E §3), so the reachable maximum is about 98.5%. CI prints coverage (`.github/workflows/ci.yml` "Coverage" step) but enforces no floor.
- **Security-relevant code with no tests today**: the CLI-login approval page, admin promote/disable toggles, token delete, delete-all-by-owner, `/metrics`, the whole S3 client, `peekd Run/runServe/runBackup`.
- **Last migration** is 10 (`token_hint_last_used`, `internal/db/migrations.go:48`). This plan adds 11, 12 and 13.
- The five design notes below (Design A–E) were written against 6380c6b/d7242f9 by reading every file they name; their `path:line` references are from that commit and drift as phases merge, so workers locate code by symbol name.

## Design

### Design §0 — how to read the design, and decisions that override Design A–E

The detailed design is in **Design A–E** below. They were written independently; this section reconciles them and **wins over them wherever they disagree**. In particular:

- **Phases.** The "Phases", "Phase plan", "Proposed phases", "Execution order" and "Files touched" groupings inside Design A–E are superseded by the implementation manifest. A phase changes only the paths in its `touches`; the brief says which Design subsections it implements.
- **Docs.** No security phase edits prose docs. Every "Docs", "Docs to update" and "Docs (Pn)" item in Design A–D is applied by the two docs phases (`p20-docs-operations`, `p21-docs-readme-skills`), with the text changes in §0.4 below. The only doc-adjacent files a security phase edits are `docs/astro.config.mjs` and `docs/src/components/SiteChrome.astro` (site config, in `p04-supply-chain-ci`).
- **Stop conditions** in Design A–E apply to the phase implementing that subsection. "Ask the user / the orchestrator" in a stop condition means: stop with `status=blocked` and say why. These are void: Design A › S1's two "manual browser smoke" stop conditions (now `ma1-browser-smoke`), Design B §0 "Blocking confirmation for the user" and the first Design B §2 stop condition (settled by §0.2), Design B §7's "manual smoke test" sentence (now `ma2-cli-login`), and Design D › L8's "use the next free id" (see §0.1).

#### §0.1 Migration numbers

- 11 `cli_login_request_context` and 12 `account_session_epoch`: both in `p02-db-auth-storage` (Design B §1 "Storage (P1)", §5 "Storage (P1)").
- 13 `comment_account_id`: in `p17-comment-authors` (Design D › L8), which runs after `p02`. Keep the `migrations` slice sorted by id; the `m.id == 13` branch goes after `m.id == 12` and before `m.sql != ""`. If id 13 is already taken when p17 starts, p17 stops with `status=blocked` (this overrides Design D's "use the next free id").

#### §0.2 API token policy: email-less automation accounts are exempt (overrides Design B §0 and §2)

The user chose "API tokens follow the same account policy as web sessions". Applied literally, that disables every token made by `peek token create` / `POST /api/tokens`, because those belong to accounts with no email (`db.CreateToken`, `internal/db/tokens.go:31`), which can never match a domain or link an OAuth identity. `docs/operations.md` ("First Run And Access") tells operators to use exactly those tokens for "internal automation, CI jobs, and agents", so breaking them contradicts a must-read doc. Decision:

- `accountActive(ctx, a)` stays exactly as Design B §2 specifies and is used by `webAuth` and the CLI-login poll.
- Add, in `internal/server/account_policy.go`:

```go
// tokenAccountActive applies the account policy to the account behind a bearer
// token. Accounts without an email are automation accounts created by
// `peek token create` / POST /api/tokens: they cannot match an allowed email
// domain or link an OAuth identity, so only the disabled check applies to them.
func (s *Server) tokenAccountActive(ctx context.Context, t *models.Token) error {
	if strings.TrimSpace(t.Email) == "" {
		if t.Disabled {
			return errAccountDisabled
		}
		return nil
	}
	return s.accountActive(ctx, tokenAccount(t))
}
```

- `authToken`, `authAdmin` and the bearer branch of `handleListComments` call `s.tokenAccountActive(r.Context(), t)` (not `accountActive(…, tokenAccount(t))`) and pass its error to `writeTokenPolicyError`.
- Tests: keep `TestAccountActive` as in Design B (its email-less row still expects `errAccountNotEligible`, because `accountActive` is unchanged). Add `TestTokenAccountActiveExemptsEmailLessAccounts` in `internal/server/account_policy_test.go`: on `newHandlerTestServer` (whose `dev-admin-token` belongs to an email-less admin account), set `authAllowedEmailDomainSetting` to `example.test` and enable GitHub OAuth (settings as in Design B `TestCLILoginPollDeniesAccountFailingPolicy`); seed an email-less non-admin token with `s.store.CreateToken(ctx, "bot-token-0123", "bot", false, 0)`; `GET /api/uploads` with `asBearer("dev-admin-token")` → 200 and with `asBearer("bot-token-0123")` → 200; then `SetAccountDisabled` on the bot's account (look up its id with `s.store.GetToken(ctx, "bot-token-0123")`) → 403 `account disabled`.
- Docs text (replaces the corresponding sentences of Design B §6): operations.md "First Run And Access" gets "API tokens follow the same account rules as dashboard sign-in: a token is refused with 403 when its account is disabled, when its email does not match the allowed email domain, or, while OAuth login is enabled, when a non-admin account has no linked OAuth identity. Tokens from `peek token create` / `POST /api/tokens` belong to automation accounts without an email; only disabling applies to them. Tokens from `peek login` expire 90 days after approval; dashboard keys and admin tokens do not expire unless created with `expires_hours`." auth-access.md "Allowed Email Domain": "It also applies to API bearer tokens of accounts with an email: a token whose account email is outside the domain is refused with 403. Automation tokens from `peek token create` have no email and are not affected." The Upgrades paragraph keeps "check which automation tokens that affects" → "check which personal API keys that affects".

#### §0.3 `peek login` on the CLI side: one phase for Design B §1 (CLI) and Design C › S6/L13

`p05-cli-login-host` implements both. Where they touch the same lines of `internal/cli/login_oauth.go`:

- Add the hook `oauthStderr io.Writer = os.Stderr` (Design B) and use it for every message in `loginOAuth`.
- When `validateBrowserURL(host, start.VerificationURL)` succeeds, print Design B's text and open the browser:
  `fmt.Fprintf(oauthStderr, "Opening browser for Peek login.\nURL:  %s\nCode: %s\nType this code on that page. Never enter a code that someone else sent you.\n", start.VerificationURL, start.UserCode)`, then `oauthOpenBrowser`; on its error print `Open the URL above to continue.`
- When it fails, print Design C's two lines through `oauthStderr`: `Peek login.\nURL:  %q\nCode: %s\n` (URL first, quoted) and `Not opening the browser automatically: %v\nOpen the URL above yourself only if you trust it.\n`. Polling continues.
- `postJSONNoAuth` sets `User-Agent: peek-cli/<version.Version>` (Design B).
- Test fixtures in `internal/cli/login_oauth_test.go` return `"verification_url": "http://" + r.Host + "/cli-login"` (no code; the server now sends a code-free URL). `TestLoginOAuthPollsUntilApproved` expects `openedURL == ts.URL + "/cli-login"`. Design B's `TestLoginOAuthPrintsCodeAndURL` uses `ts.URL + "/cli-login"` (not `auth.example.test`) and asserts `URL:  <ts.URL>/cli-login`, `Code: ABCD-EFGH` and `Never enter a code that someone else sent you.`. Design C's `TestLoginOAuthDoesNotOpenUntrustedVerificationURL` is unchanged. Design C's `TestValidateBrowserURL` OK cases become `https://peek.example.com/cli-login` and `https://PEEK.example.com:443/cli-login`.

#### §0.4 Docs collected in two phases

- `p20-docs-operations` owns `docs/operations.md`, `docs/src/content/docs/auth-access.md`, `docs/src/content/docs/using-peek.md`, `docs/src/content/docs/reference.md`.
- `p21-docs-readme-skills` owns `README.md`, `docs/src/content/docs/server-setup.md`, `docs/src/content/docs/deployment-platforms.md`, `skills/peek/SKILL.md`, `skills/peek-server/SKILL.md`.
- Each applies, for its files, every docs item in: Design A (S1, S2, L1 "Docs to update"), Design B §6 (as amended by §0.2), Design C (S5, S7, L10, L11, S6, L12, L13 "Docs"), Design D (L15, L7a, L7b, L8 "Docs"). Write prose as natural flowing lines without manual wrapping (AGENTS.md). Where an item names a line number, find the place by its surrounding text.
- In the README "Prebuilt binaries" sentence of Design C › S5, replace "releases before vX.Y (the first release cut after this change)" with "releases published before checksums were added (v0.8.1 and older)".
- `docs/operations.md` "Upgrades And Rollbacks" gets one combined paragraph per migration (11, 12, 13) plus the S1, S2 and §0.2 notes, in that order, after the migration 10 paragraph.

#### §0.5 Flash codes for "Sign out other sessions" (Design B §5 × Design D › L9)

`p11b-session-epoch` runs before `p16-flash-codes`. In `internal/server/web_sessions.go` declare

```go
const (
	flashSessionsRevoked      = "sessions_revoked"
	flashSessionsRevokeFailed = "sessions_revoke_failed"
)
```

and call `dashboardOK(w, r, flashSessionsRevoked)` / `dashboardError(w, r, flashSessionsRevokeFailed)`. Its tests expect `/dashboard?ok=sessions_revoked` and `/dashboard?err=sessions_revoke_failed`. (Until `p16` lands the dashboard shows the raw code; that intermediate state never leaves the feature branch.) `p16-flash-codes` adds `flashSessionsRevoked: "other sessions signed out"` and `flashSessionsRevokeFailed: "sign out failed"` to `flashMessages` in `web_helpers.go`, includes both in `TestFlashMessagesCoverAllCodes`, and does not edit `web_sessions.go`: the two constants stay declared there and `web_helpers.go` only adds `flashMessages` entries for them. Because p16 makes `parseDashboardForm` redirect with `flashInvalidSession`, p16 also updates `TestDashboardSessionsRevokeRequiresCSRF` in `web_sessions_test.go` to expect `/dashboard?err=invalid_session`.

#### §0.6 Design A › S2 is split in two phases

- `p09a-client-ip-limiter` does everything in Design A › S2 except the two handler changes: new `client_ip.go`, `clientIP` move, `rateLimitKey` and its four call sites, the limiter cap with `hasRoom`/`blocked`/`recordFailure`, the constants block (including the four failure-limit constants), the two new `Server` fields **and their construction in `New`**, the `--trusted-proxy-cidrs` flag, and the tests in `client_ip_test.go`, `ratelimit_test.go`, `analytics_test.go`, `internal/peekd/run_test.go`.
- `p09b-failure-limiters` does the `handlePagePassword` and `loginWithPassword`/`checkPasswordLogin`/`handleLogin` changes and their tests in `pages_test.go` and `web_login_test.go`.

#### §0.7 `web_login.go` sequence (Design A › S2, Design B §4 L4, Design B §5 L5)

1. `p09b` splits `loginWithPassword` into the throttle wrapper and `checkPasswordLogin` (Design A).
2. `p11a-login-timing` rewrites the body of `checkPasswordLogin` to Design B §4's order (one `checkPassword` call on every path past the empty-field check; policy errors only after a correct password). The throttle wrapper and its failure counting stay as `p09b` left them. `TestLoginWithPasswordRunsOneBcryptCompareOnEveryFailure` calls `s.loginWithPassword` with a fresh server per subtest, so the account limiter never trips.
3. `p11b-session-epoch` changes the return types to `(*models.Account, error)` for `loginWithPassword`, `checkPasswordLogin` and `loginWithToken` (Design B §5 "Callers") and updates the two call sites in `auth_domain_test.go` and the `p09b` tests in `web_login_test.go` to the new arity.

#### §0.8 Quality gate inside a phase

Every phase runs `mise run check`. Phases touching `internal/server/**`, `internal/db/**`, `internal/objectstore/**` or `internal/uploads/**` run `mise run check-full`. In a cloud container `govulncheck` cannot reach `vuln.go.dev` (HTTP 403); when that is the **only** failing step, run `mise run check && mise run race && mise run staticcheck && mise run coverage` instead and say so in the phase report (CI runs govulncheck on the PR). Any other failure is real.

`mise run check` runs `mise run build`, which regenerates `internal/web/assets/pines.css` with Tailwind. Until `p04-supply-chain-ci` lands, Tailwind also scans Markdown files, so docs and plan edits make `pines.css` drift (checked: a plain `mise run tailwind` on the plan branch changes it). A phase that does not list `internal/web/assets/pines.css` in its `touches` runs `git checkout -- internal/web/assets/pines.css` after each `mise run check` and never commits it. `p04` stops the drift (Tailwind no longer scans `docs/`, `skills/` and Markdown files) and commits one regenerated `pines.css`.

#### §0.9 Coverage phases

Coverage phases (`c01`–`c14`, `g01`) follow Design E §5 with these rules:

- **Metric.** `go test -coverprofile=coverage.out ./...`, total from `go tool cover -func`. Do not switch to `-coverpkg` (Design E §1.1).
- **Step 0** of every coverage phase: re-profile the package and list count-0 blocks of the phase's files (Design E §6). Write tests only for blocks still at 0. Do not re-test behaviour the security phases already assert.
- **No production code changes.** A coverage phase changes only `_test.go` files (and, for `g01`, the gate files). If a block is unreachable without a production seam, leave it and list it in the report. The one allowed exception is Design E's `var notifyShutdown = signal.Notify` in `internal/peekd/run.go`, only if the signal-driven `runServe` test is flaky under `-race` (then `c13` also touches `internal/peekd/run.go`; say so).
- **Helper names.** All server coverage phases compile into one package. New top-level identifiers outside `fault_helpers_test.go` carry the phase prefix: `adm` (c01), `apiCov` (c02), `setCov` (c03), `dashCov` (c04), `oauthCov` (c05), `cliLoginCov` (c06), `pageCov` (c07). Grep before adding.
- **Per-file floor.** At the end of a coverage phase each source file it owns reaches **≥ 90.0%** statement coverage, except the floors in this table, which account for blocks Design E §3 classes as unreachable:

| File | Floor |
| --- | --- |
| `internal/server/security.go` | 85% |
| `internal/server/web_setup.go` | 85% |
| `internal/server/server.go` | 85% |
| `internal/db/migrations.go` | 80% |
| `internal/db/store.go` | 85% |
| `internal/db/accounts.go`, `internal/db/tokens.go`, `internal/db/versions.go`, `internal/db/uploads.go`, `internal/db/slug_aliases.go` | 85% |
| `internal/cli/login_command.go` | 85% |
| `internal/cli/browser.go` | 50% |
| `internal/uploads/slug.go`, `internal/uploads/visibility.go` | 85% |
| `internal/web/assets.go`, `internal/web/renderer.go` | 85% |
| `internal/peekd/run.go` | 85% |
| `cmd/peek/main.go`, `cmd/peekd/main.go` | none |

  Per-file coverage command (prints files under 90% for one package):

```sh
go test -coverprofile=/tmp/c.out ./internal/<pkg>/ >/dev/null && awk -F'[:, ]' 'NR>1 { t[$1]+=$4; if ($5>0) c[$1]+=$4 } END { for (f in t) if (100*c[f]/t[f] < 90) printf "%.1f %s\n", 100*c[f]/t[f], f }' /tmp/c.out | sort -n
```

- **Unreachable blocks.** A file may end below its floor only when every block still at count 0 in it is listed in the phase report as unreachable, with the reason (Design E §3 class (c), or a reason of the same kind). That list is part of the phase's acceptance.
- **Package floors** (checked by `g01`, not by CI): server ≥ 91%, db ≥ 90%, cli ≥ 91%, objectstore ≥ 92%, peekd ≥ 90%, uploads ≥ 92%, web ≥ 90%, groups ≥ 95% (Design E §4). At those floors the total is about 90.9%.
- **Gate.** `g01` adds `scripts/coverage-gate.sh` exactly as Design E § "Phase G", wires it into `mise.toml` `[tasks.coverage]` and the `ci.yml` Coverage step, and may add top-up tests (≤ 300 lines, `_test.go` only) in any package below its floor until the total is ≥ 90.0%.

#### §0.10 Pinned tool versions

Use Design C › L14 as written: action SHAs from its table, `govulncheck@v1.9.0` (fallback `v1.8.0` if v1.9.0 itself fails to build or run, as Design C says), staticcheck `2026.2.1` / `honnef.co/go/tools@v0.8.1`.

### Design A–E

The five notes below are the detailed specification. Design §0 above overrides them.

### Design A — raw route sandbox, view tokens, client IP and rate limits, body cap (S1, L6, S2, L1)


Repo: /home/user/peek at d7242f9. All paths are relative to the repo root. Line numbers are from that commit. Every design decision below is final; a worker should not re-decide anything. If a "Stop condition" fires, stop and report instead of improvising.

#### Execution order and file overlap

| Phase | Findings | Files that overlap with other phases |
| --- | --- | --- |
| 1 | S1 + L6 (one change, same handler) | `internal/server/pages.go` (handleRawVersion, servePage), `page_versions_test.go`, `pages_test.go` |
| 2 | S2 | `pages.go` (handlePagePassword only), `ratelimit.go`, `middleware.go` (line 27 only), `comments.go`, `analytics.go`, `server.go`, `pages_test.go` |
| 3 | L1 | `middleware.go` (withMiddleware) |

Run them in this order on one branch (or rebase each phase on the previous one). S1 and L6 must be in the same commit series because L6 adds a check inside the handler S1 rewrites. L1 edits the same function as S2's middleware.go:27 change, so do L1 after S2.

Quality gate after each phase: `mise run check`; after the last phase: `mise run check-full` (auth/concurrency touched).

---

#### S1 — sandbox the raw route (Critical)

##### Current state

- `internal/server/pages.go:117` builds the iframe URL with the visitor id in the query:
  `rawURL := "/raw/" + slug + "/v/" + strconv.Itoa(version) + "?t=" + makeViewToken(s.secret, viewSubject(slug, version), vid) + "&v=" + vid`
- `pages.go:171-181` `rawViewerID` prefers `r.URL.Query().Get("v")` over the `hn_vid` cookie, so the URL alone is a credential.
- `pages.go:183-205` `handleRaw` (legacy `/raw/{slug}`, tokens bound to the bare slug). Route registered at `internal/server/routes.go:42`. Versioned raw URLs were introduced in commit 6512303 (2026-10-10); view tokens live `viewTokenTTL = 1 * time.Hour` (`server.go:19`), so legacy tokens are useless one hour after any upgrade that includes 6512303.
- `pages.go:207-231` `handleRawVersion`: no `Sec-Fetch-Dest` check, token checked against `rawViewerID(r)`.
- `pages.go:257-271` `writeRawHTML` CSP has no `sandbox` directive.
- `internal/web/templates/page.gohtml:16` `<iframe id="hn-frame" src="{{.RawURL}}" sandbox="allow-scripts allow-popups" ...>` — the only isolation today. No `allow-forms`, `allow-modals`, `allow-same-origin`; so uploaded pages today cannot submit forms or open `alert()`. The CSP sandbox must use exactly the same tokens so behaviour inside the frame is unchanged.
- `internal/server/security.go:75-98` `makeViewToken`/`verifyViewToken` (`subject.vid.exp.sig`).
- `internal/server/web_csrf.go:15-19` sets `hn_csrf` with `HttpOnly: false`.

Verified facts the design relies on:
- No browser JS reads cookies: `grep -rn "document.cookie\|hn_csrf" internal/web/assets/*.js` finds nothing (the only hit is `internal/web/assets_test.go:196`, which asserts app.js does NOT use `document.cookie`). Every CSRF token reaches the browser through `<input type="hidden" name="csrf" value="{{.CSRF}}">` in templates (login, setup, dashboard, cli_login). Dashboard JS does no `fetch` with CSRF. So making `hn_csrf` HttpOnly is safe.
- `hn_vid` is set by `visitorID` (`internal/server/analytics.go:27-44`): `Path: "/"`, `SameSite: Lax`, `HttpOnly: true`, 10-year `MaxAge`, set in the same `/p` response that contains the iframe (`servePage` calls `s.visitorID(w, r)` at `pages.go:114` before rendering). The browser stores Set-Cookie from the parent document before it requests the iframe. The iframe navigation request is initiated by the parent document (Peek origin, same-site), so Lax and Strict cookies are sent on it even though the loaded document is sandboxed (the sandbox only affects requests made by the framed document). Therefore cookie-only visitor binding works and `?v=` can be dropped.
- The only case where `hn_vid` is absent on the raw request is `randID` failure (`visitorID` returns `"anon"` without setting a cookie). That request will now get 403; acceptable (entropy failure).

##### Design

1. `internal/server/pages.go` — add near `writeRawHTML`:

```go
// rawSandbox is the sandbox applied to uploaded HTML. It must stay identical to
// the sandbox attribute of #hn-frame in internal/web/templates/page.gohtml;
// TestRawSandboxMatchesIframeAttribute enforces this.
const rawSandbox = "allow-scripts allow-popups"

// rawContentCSP lets uploaded HTML run inline scripts/styles and load remote
// resources. The sandbox directive gives the document an opaque origin even when
// /raw is opened as a top-level page, so it can never act as Peek's origin.
const rawContentCSP = "sandbox " + rawSandbox + "; " +
	"default-src 'none'; " +
	"script-src 'unsafe-inline' 'unsafe-eval' https: http: data: blob:; " +
	"style-src 'unsafe-inline' https: http:; " +
	"img-src https: http: data: blob:; " +
	"media-src https: http: data: blob:; " +
	"font-src https: http: data:; " +
	"connect-src https: http:; " +
	"frame-ancestors 'self'"
```

   Resulting header value (exact):
   `sandbox allow-scripts allow-popups; default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval' https: http: data: blob:; style-src 'unsafe-inline' https: http:; img-src https: http: data: blob:; media-src https: http: data: blob:; font-src https: http: data:; connect-src https: http:; frame-ancestors 'self'`

   In `writeRawHTML` replace the multi-line `w.Header().Set("Content-Security-Policy", ...)` and its comment with `w.Header().Set("Content-Security-Policy", rawContentCSP)`.

2. `rawViewerID` becomes cookie-only:

```go
// rawViewerID returns the visitor id from the HttpOnly hn_vid cookie. The raw URL
// alone is never a credential: without the cookie that /p set, it is refused.
func rawViewerID(r *http.Request) string {
	if c, err := r.Cookie(visitorCookie); err == nil {
		return c.Value
	}
	return ""
}
```

3. `servePage` (`pages.go:117`): drop `+ "&v=" + vid`:
   `rawURL := "/raw/" + slug + "/v/" + strconv.Itoa(version) + "?t=" + makeViewToken(s.secret, viewSubject(slug, version), vid)`

4. `security.go` `verifyViewToken`: reject an empty visitor id. Change `if tSlug != slug || tVid != vid {` to `if vid == "" || tSlug != slug || tVid != vid {`. Update the doc comment of `makeViewToken` to say "the hn_vid cookie must match" (it already does; keep).

5. Add to `pages.go`:

```go
// rawFetchAllowed reports whether a /raw request may be served. Browsers that send
// Sec-Fetch-Dest must be loading the page into an iframe; a top-level navigation
// ("document"), fetch ("empty") or any other destination is refused. Requests
// without the header (older browsers, non-browser clients) still need a valid
// view token and visitor cookie.
func rawFetchAllowed(r *http.Request) bool {
	dest := r.Header.Get("Sec-Fetch-Dest")
	return dest == "" || dest == "iframe"
}
```

6. `handleRawVersion` final body order (L6 adds step e):

```go
func (s *Server) handleRawVersion(w http.ResponseWriter, r *http.Request) {
	if !rawFetchAllowed(r) {                                     // a
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	slug := r.PathValue("slug")
	n, err := strconv.Atoi(r.PathValue("n"))                    // b
	if err != nil || n < 1 {
		http.NotFound(w, r)
		return
	}
	// Verify the token before any DB lookup so the response does not reveal
	// which versions exist.
	if !verifyViewToken(s.secret, r.URL.Query().Get("t"), viewSubject(slug, n), rawViewerID(r)) { // c
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	u, err := s.store.GetUpload(r.Context(), slug)              // d
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Re-check access on every load so a visibility, password or grant change
	// applies to raw URLs minted before it (L6).
	if !s.viewerCanAccessUpload(r, u) {                         // e
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ver, err := s.store.GetUploadVersion(r.Context(), u.ID, n)  // f
	...unchanged...
}
```

7. Remove the legacy route: delete `handleRaw` (`pages.go:183-205`) and `mux.HandleFunc("GET /raw/{slug}", s.handleRaw)` (`routes.go:42`). After removal `GET /raw/<slug>` falls through to `GET /` → `handleIndex` → 404 page. Justification: legacy tokens expire 1 h after issue; the only effect is that an iframe opened under a pre-6512303 binary in the hour before the upgrade must be reloaded.

8. `internal/server/web_csrf.go:18`: `SameSite: http.SameSiteStrictMode, HttpOnly: true,`.

9. Do NOT touch `page.gohtml` (its attribute already equals `rawSandbox`). Do NOT add `allow-forms`/`allow-modals`/`allow-same-origin`.

10. Out of scope (do not implement): separate content origin (`PEEK_CONTENT_ORIGIN`), narrowing `connect-src`.

##### Files touched

- `internal/server/pages.go`, `internal/server/security.go`, `internal/server/routes.go`, `internal/server/web_csrf.go`
- Tests: `internal/server/page_versions_test.go`, `internal/server/pages_test.go`, `internal/server/visibility_e2e_test.go`, `internal/server/web_csrf_test.go`, `internal/server/security_test.go` (only if it has a view-token test that uses an empty vid — grep `verifyViewToken` there; at d7242f9 there is none outside pages/page_versions tests).

##### Existing tests to update

- `pages_test.go:162` `TestHandleRawStreamsHTMLWithBridgeInjection`: build the request as `httptest.NewRequest(http.MethodGet, "/raw/page/v/1?t="+makeViewToken(secret, viewSubject("page", 1), vid), nil)`, `req.SetPathValue("slug", "page")`, `req.SetPathValue("n", "1")`, `req.AddCookie(&http.Cookie{Name: visitorCookie, Value: vid})`, call `s.handleRawVersion(rec, req)`. Upload is public so step (e) passes with the literal `&Server{store, storage, secret}`. Also assert `rec.Header().Get("Content-Security-Policy") == rawContentCSP`. `storage.openCount` stays 2.
- `page_versions_test.go:117` `TestRawVersionRejectsTokenForOtherVersion`: drop `&v=vid1` from both URLs and pass `func(r *http.Request) { r.AddCookie(&http.Cookie{Name: visitorCookie, Value: "vid1"}) }` as a doRequest option. Expectations unchanged (403 then 200).
- `page_versions_test.go:131` `TestRawVersionChecksTokenBeforeLookup`: URL `/raw/rawlookup/v/99?t=bad`, add the same `vid1` cookie option. Still 403.
- `page_versions_test.go:140` `TestLegacyRawRouteServesLatest`: replace with `TestLegacyRawRouteRemoved`: `doRequest(t, s, GET, "/raw/rawlegacy?t="+url.QueryEscape(makeViewToken(s.secret, "rawlegacy", "vid1")), nil, <vid1 cookie>)` must return 404 and body must not contain `v2Marker`.
- `visibility_e2e_test.go:156` `TestRawHTMLE2ERequiresIssuedViewToken`: change the first request from `"/raw/"+up.Slug` to `"/raw/"+up.Slug+"/v/1"` (expect 403). Rest unchanged (it already passes `withCookies(page.Cookies...)`, which contains `hn_vid`).
- `web_csrf_test.go:13` `TestCSRFTokenSetsCookie`: add `if !cookies[0].HttpOnly { t.Fatal("csrf cookie must be HttpOnly") }`.
- `internal/web/renderer_test.go` uses `RawURL: ".../?t=t&v=v"` as opaque template data: leave unchanged.

##### Tests to add

In `internal/server/page_versions_test.go` (package `server`; helpers `newHandlerTestServer`, `newTwoVersionPage`, `doRequest`, `asSession`, `rawSrcRe`):

First refactor: extract from `fetchRawFromPage` a helper

```go
// rawSrcFromPage GETs pagePath (with opts) and returns the iframe src and the
// response cookies.
func rawSrcFromPage(t *testing.T, s *Server, pagePath string, opts ...func(*http.Request)) (src string, cookies []*http.Cookie)
```
and a request option `withCookieList(cs []*http.Cookie) func(*http.Request)` and `withFetchDest(v string) func(*http.Request)` (sets `Sec-Fetch-Dest`). `fetchRawFromPage` keeps its signature and uses them.

- `TestRawSetsSandboxCSP`: public two-version page; src+cookies from `/p/<slug>`; raw request with cookies → 200 and `Content-Security-Policy` header has prefix `"sandbox allow-scripts allow-popups;"` and equals `rawContentCSP`.
- `TestRawRejectsNonIframeFetchDest`: same setup; table over `Sec-Fetch-Dest` values: `"document"`→403, `"empty"`→403, `"frame"`→403, `"iframe"`→200, header absent→200.
- `TestRawTokenRequiresVisitorCookie`: same setup; (1) src with no cookies → 403; (2) src with cookie `hn_vid=someone-else` → 403; (3) src + `"&v="+<the real vid from the hn_vid cookie>` and no cookies → 403 (the old query override is gone); (4) src with the page's cookies → 200.
- `TestRawSandboxMatchesIframeAttribute`: GET `/p/<slug>` of a public page; regex `sandbox="([^"]+)"` on body; captured group must equal `rawSandbox`.
- `TestRawRefusedAfterVisibilityChange` (L6): public page `rawvis`; src+cookies; `s.store.SetUploadVisibility(ctx, u.ID, models.UploadVisibilityPrivate, "")`; raw with same cookies → 403.
- `TestRawRefusedAfterGrantRemoved` (L6): restricted page `rawgrant` via `newTwoVersionPage(t, s, "rawgrant", models.UploadVisibilityRestricted, "")`; viewer `v, _ := s.store.CreateAccount(ctx, "viewer@example.test", "Viewer", false)`; `s.store.AddUploadGrant(ctx, u.ID, models.UploadGrantUser, "viewer@example.test", u.OwnerAccountID)`; `src, cookies := rawSrcFromPage(t, s, "/p/rawgrant", asSession(s, v.ID))`; raw with cookies + `asSession(s, v.ID)` → 200; `s.store.RemoveUploadGrant(ctx, u.ID, models.UploadGrantUser, "viewer@example.test")`; same raw request → 403.
- `TestRawRefusedAfterPasswordChange` (L6): password page (hash of "one", `bcrypt.MinCost`); POST `/p/<slug>` form `password=one` through `doRequest` (Content-Type `application/x-www-form-urlencoded`) → take `hn_auth_<slug>` cookie; src+cookies from GET `/p/<slug>` with that cookie; raw → 200; `SetUploadVisibility(ctx, u.ID, models.UploadVisibilityPassword, <hash of "two">)`; raw with the same cookies → 403.

In `internal/server/visibility_e2e_test.go` (package `server_test`; helpers `newTestApp`, `noRedirectClient`, `uploadRawHTML`, `rawPathFromPage`, `withCookies`, `assertStatus`):

- `TestRawHTMLE2ERejectsLeakedURL`: upload public page; `page := app.request(GET, "/p/"+slug)`; `rawPath := rawPathFromPage(...)`; define `fetchDest := func(v string) requestOption { return func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", v) } }`. Assert: no cookies + `fetchDest("iframe")` → 403; `withCookies(page.Cookies...)` + `fetchDest("document")` → 403; `withCookies(page.Cookies...)` + `fetchDest("iframe")` → 200 and `raw.Header.Get("Content-Security-Policy")` starts with `"sandbox allow-scripts allow-popups;"`.

##### Docs to update

- `README.md:189` row "Uploaded HTML steals data": `Rendered in <iframe sandbox="allow-scripts allow-popups">` and served with CSP `sandbox allow-scripts allow-popups`, so it has an opaque origin even when the raw URL is opened directly; `/raw` refuses non-iframe loads (`Sec-Fetch-Dest`).
- `README.md:190` row "Bypassing password gate": `/raw` requires a short-lived HMAC-signed view token bound to the HttpOnly visitor cookie, and re-checks page access on every load. Changing the password revokes earlier unlocks.
- `docs/operations.md:55`: replace the second and third sentences with: "Every load of that view URL re-checks access, so revoking a grant, changing visibility, or setting a new password applies to the frame on its next load; a frame already displayed keeps what it has rendered. The view URL works only in the browser that opened the page (it is bound to the `hn_vid` cookie) and only inside the page's iframe."
- `docs/src/content/docs/auth-access.md:130`: "Revoking a grant takes effect on the next page load; an iframe that is already open can keep working for up to 1 hour." → "Revoking a grant takes effect the next time the page or its frame loads."
- `docs/operations.md` "Upgrades And Rollbacks" (after line 97): add paragraph: "This release removes the unversioned `/raw/<slug>` route and serves uploaded HTML with a CSP `sandbox`. Pages opened before the upgrade must be reloaded. The `hn_csrf` cookie is now HttpOnly."

##### Stop conditions

- Any test or code path needs `?v=` on `/raw` to pass → design wrong; report.
- `grep -rn "document.cookie\|hn_csrf" internal/web/assets` (excluding `assets_test.go`) returns a hit → HttpOnly is unsafe; stop and report.
- Manual browser smoke (`mise run run`, upload a page with `<script>document.body.append(location.origin)</script>`, open `/p/<slug>`) shows a blank frame with a console error mentioning `frame-ancestors` → browsers are matching `'self'` against the sandboxed opaque origin; report (fallback would be the explicit origin from `--base-url`, not to be implemented without approval). Expected: frame renders and prints `null`.
- Same smoke: the frame gets 403 for a private or restricted page while `/p` rendered → cookies are not sent on the iframe request; report.
- `TestHandleRawStreamsHTMLWithBridgeInjection` fails on step (e) → `viewerCanAccessUpload` touches a nil field on the literal Server; report rather than adding fields blindly.

---

#### L6 — raw view tokens outlive a visibility change

##### Current state

`handleRawVersion` (`pages.go:207-231`) checks only the HMAC token (`viewSubject(slug, n)` + vid + exp). `servePage` (`pages.go:79-125`) does the access check only when minting. Grants have no version or `updated_at` column (`internal/db/migrations.go:30-40`, `upload_grants(id, upload_id, kind, email, created_by_account_id, created_at)`), so a "grants version" fingerprint would need a migration.

##### Design (decided)

Re-check access in `handleRawVersion` with the existing `s.viewerCanAccessUpload(r, u)` (`internal/server/comments.go:274`) — step (e) in S1 above. Do NOT change the token subject. Reasons: it covers visibility change, password change (`verifyPageAuthCookie` binds to the password hash), grant removal, group membership change (after the group cache TTL), account disable and email-domain policy, with no migration; it is the same check `/p`, the comments API and the views API already do per request. Cost: for public pages nothing; for password pages one HMAC; for private one session parse; for restricted one `ListUploadGrants` query plus cached group lookups — the same as a `/p` load. Cookies needed (`hn_session` Strict, `hn_auth_<slug>` Lax, path `/`) are sent on the same-site iframe navigation (see S1 facts).

Failure response: `403` `forbidden` (identical to a bad token, so no oracle).

##### Files touched / tests / docs

Covered in S1 (step e, `TestRawRefusedAfterVisibilityChange`, `TestRawRefusedAfterGrantRemoved`, `TestRawRefusedAfterPasswordChange`, operations.md:55, auth-access.md:130).

##### Stop conditions

- Any existing test that loads a raw URL for a restricted/private page without passing the session cookie starts failing → fix the test to pass the session (that mirrors the browser); if a production code path (not a test) loads `/raw` without cookies, report.

---

#### S2 — X-Forwarded-For spoofing, per-slug/per-account limits, limiter cap

##### Current state

- `internal/server/analytics.go:111-125` `clientIP`: when `s.trustedProxy`, returns the LEFTMOST `X-Forwarded-For` entry (client-controlled); otherwise `RemoteAddr` host.
- Callers: `ratelimit.go:56` (`rateLimit` wrapper), `middleware.go:27` (global limiter), `comments.go:102` and `comments.go:203` (`commentLimiter.allow(s.clientIP(r))`), `analytics.go:53` (visit IP hash), `lifecycle.go:33` (`auditRequest`).
- `internal/server/ratelimit.go:13-51` `limiter`: fixed window per key; when `len(l.hits) > 10000` it scans the whole map on EVERY call (lock held) and never caps size.
- `rateLimitError` (`ratelimit.go:64-70`): JSON `{"error":"too many requests, try again shortly"}` for `/api/` or `Accept: application/json`; else plain text `Too many requests. Try again shortly.` with 429.
- Limiters created in `server.go:171-177`: login 10/min, comment 30/min, upload 20/min, password 10/min, global 300/min, cliLogin 120/min, apiKey 10/min.
- Config: `internal/peekd/run.go:92` `getenvBool("PEEK_TRUSTED_PROXY")`, `:118` flag `--trusted-proxy`, `serveConfig.TrustedProxy` (`:39`), passed at `:229` to `server.Config.TrustedProxy` (`server/server.go:44`), stored in `Server.trustedProxy` (`server.go:70`, `:178`). Warning at `server.go:189-191`.
- `handlePagePassword` (`pages.go:127-158`): per-IP `passwordLimiter` only (route wrapper `routes.go:39,41`).
- `loginWithPassword` (`web_login.go:62-85`): per-IP `loginLimiter` only (`routes.go:68`).
- `internal/server/analytics_test.go:40,52`: `trustedProxy: true`, XFF `"203.0.113.10, 10.0.0.1"`, expects hash of `203.0.113.10` (leftmost) at line 78.

##### Design

###### Config

- New flag `--trusted-proxy-cidrs`, env `PEEK_TRUSTED_PROXY_CIDRS`, comma-separated CIDRs or bare IPs. Default `127.0.0.0/8,::1/128` (loopback only). Only consulted when `--trusted-proxy` is on. `--trusted-proxy` stays the on/off switch (no rename, no behaviour change when off).
- Why loopback-only and not RFC1918: Peek is an internal tool whose own users are usually on private ranges. If `10.0.0.0/8` were trusted by default, a user at `10.1.2.3` going through the proxy would have the proxy append `10.1.2.3`, which would be skipped as "trusted", and the user's own spoofed left entry would win — exactly the S2 bug. Loopback-only is safe for the documented topology (proxy on the same host, `reverse_proxy 127.0.0.1:7700`). Container/PaaS deployments must set the proxy's address range explicitly; a one-time warning (below) tells them when they have not.
- `internal/server/client_ip.go` (new file) exports:

```go
// DefaultTrustedProxyCIDRs is the default --trusted-proxy-cidrs value: only a
// reverse proxy on the same host is trusted to append X-Forwarded-For.
const DefaultTrustedProxyCIDRs = "127.0.0.0/8,::1/128"

// ParseTrustedProxyCIDRs parses a comma-separated list of CIDRs or bare IPs.
// Empty items are skipped. A bare IP becomes a single-address prefix.
func ParseTrustedProxyCIDRs(s string) ([]netip.Prefix, error)
```
  Implementation: split on `,`, `strings.TrimSpace`, skip `""`; if item contains `/` → `netip.ParsePrefix`, else `netip.ParseAddr` then `netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())`; store `p.Masked()`; on error return `nil, fmt.Errorf("invalid trusted proxy CIDR %q", item)`. For prefixes, if `p.Addr().Is4In6()` convert to the IPv4 prefix: `netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)` when `p.Bits() >= 96`, else error.
- `server.Config` gets `TrustedProxyCIDRs []netip.Prefix` (after `TrustedProxy bool`). `Server` gets `trustedProxyCIDRs []netip.Prefix` and `warnedUntrustedForwarder atomic.Bool`.
- `server.New`: `cidrs := cfg.TrustedProxyCIDRs; if cfg.TrustedProxy && len(cidrs) == 0 { cidrs = defaultTrustedProxyPrefixes() }` where `defaultTrustedProxyPrefixes()` calls `ParseTrustedProxyCIDRs(DefaultTrustedProxyCIDRs)` and panics on error (constant input). Assign `trustedProxyCIDRs: cidrs`. When `cfg.TrustedProxy`, log `slog.Info("trusted proxy enabled", "cidrs", <[]string of prefixes>)`.
- `internal/peekd/run.go`: add `TrustedProxyCIDRs []netip.Prefix` to `serveConfig`; flag `trustedProxyCIDRs := fs.String("trusted-proxy-cidrs", getenv("PEEK_TRUSTED_PROXY_CIDRS", server.DefaultTrustedProxyCIDRs), "comma-separated CIDRs of reverse proxies allowed to set X-Forwarded-For (used with --trusted-proxy)")`. After `fs.Parse`, `cidrs, err := server.ParseTrustedProxyCIDRs(*trustedProxyCIDRs)`; on error return `fmt.Errorf("trusted-proxy-cidrs: %w", err)`; if `*trustedProxy && len(cidrs) == 0` return `fmt.Errorf("trusted-proxy-cidrs must list at least one CIDR when trusted-proxy is set")`. Pass to `server.Config{TrustedProxyCIDRs: cfg.TrustedProxyCIDRs}`.

###### clientIP (move from analytics.go to client_ip.go; delete the old function)

```go
// clientIP returns the address used for rate limits, visit hashes and audit
// logs. Without --trusted-proxy it is the TCP peer. With it, X-Forwarded-For is
// honoured only when the peer is a trusted proxy, and the result is the rightmost
// hop that is not itself a trusted proxy: proxies append on the right, so
// everything left of the first untrusted hop is client-controlled.
func (s *Server) clientIP(r *http.Request) string {
	peer, ok := parseRemoteAddr(r.RemoteAddr)
	if !ok {
		return legacyRemoteHost(r.RemoteAddr) // the old LastIndexByte(':') + Trim("[]") logic, verbatim
	}
	if !s.trustedProxy {
		return peer.String()
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer.String()
	}
	if !s.isTrustedProxy(peer) {
		s.warnUntrustedForwarder(peer)
		return peer.String()
	}
	hops := strings.Split(strings.Join(values, ","), ",")
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseForwardedHop(hops[i])
		if !ok {
			return client.String()
		}
		client = hop
		if !s.isTrustedProxy(hop) {
			return hop.String()
		}
	}
	return client.String()
}
```

  Helpers in the same file:
  - `parseRemoteAddr(addr string) (netip.Addr, bool)`: `netip.ParseAddrPort(addr)` → `ap.Addr().Unmap().WithZone("")`; else `netip.ParseAddr(strings.Trim(addr, "[]"))` → `.Unmap().WithZone("")`; else false.
  - `parseForwardedHop(v string) (netip.Addr, bool)`: `v = strings.TrimSpace(v)`; try `netip.ParseAddr(strings.Trim(v, "[]"))`; else `netip.ParseAddrPort(v)` (handles `1.2.3.4:5678` and `[2001:db8::1]:443`); return `.Unmap().WithZone("")`.
  - `(s *Server) isTrustedProxy(a netip.Addr) bool`: any `p.Contains(a)` over `s.trustedProxyCIDRs`.
  - `(s *Server) warnUntrustedForwarder(peer netip.Addr)`: `if s.warnedUntrustedForwarder.CompareAndSwap(false, true) { slog.Warn("ignoring X-Forwarded-For from a peer outside the trusted proxy CIDRs; set PEEK_TRUSTED_PROXY_CIDRS to your reverse proxy's address", "peer", peer.String()) }`.

  IPv4 output for `RemoteAddr "192.0.2.1:1234"` stays `"192.0.2.1"` (same as today); IPv6 `[::1]:1234` stays `"::1"`.

###### Limiter keys (IPv6 /64 grouping)

In `client_ip.go`:

```go
// rateLimitKeyForIP groups IPv6 clients by /64, the smallest block a single
// site normally gets, so one client cannot rotate through its own addresses to
// reset limits or fill limiter maps. IPv4 and unparseable values are returned as is.
func rateLimitKeyForIP(ip string) string
func (s *Server) rateLimitKey(r *http.Request) string { return rateLimitKeyForIP(s.clientIP(r)) }
```
  For IPv6 (`a.Is6()` after `Unmap`): `p, _ := a.Prefix(64); return p.String()` (e.g. `"2001:db8:1:2::/64"`).
  Replace `s.clientIP(r)` with `s.rateLimitKey(r)` at exactly: `ratelimit.go:56`, `middleware.go:27`, `comments.go:102`, `comments.go:203`. Leave `analytics.go:53` and `lifecycle.go:33` on `clientIP` (full address for visit hash and audit).

###### Limiter hard cap (`ratelimit.go`)

```go
const (
	// limiterMaxKeys caps each limiter's map. When it is full and a new key
	// arrives, expired windows are pruned (at most once per limiterPruneInterval);
	// if it is still full the new key is denied. Failing closed keeps brute-force
	// limits intact under key flooding; existing keys keep working.
	limiterMaxKeys       = 50000
	limiterPruneInterval = time.Second

	accountLoginFailureMax    = 10
	accountLoginFailureWindow = 15 * time.Minute
	pagePasswordFailureMax    = 20
	pagePasswordFailureWindow = 10 * time.Minute
)
```
  `limiter` gains `maxKeys int` and `nextPrune time.Time`; `newLimiter` sets `maxKeys: limiterMaxKeys`.
  Remove the `if len(l.hits) > 10000 { ... }` block. Add (caller holds `l.mu`):

```go
func (l *limiter) hasRoom(key string, now time.Time) bool {
	if _, ok := l.hits[key]; ok || len(l.hits) < l.maxKeys {
		return true
	}
	if !now.Before(l.nextPrune) {
		for k, w := range l.hits {
			if now.After(w.reset) {
				delete(l.hits, k)
			}
		}
		l.nextPrune = now.Add(limiterPruneInterval)
	}
	return len(l.hits) < l.maxKeys
}
```
  `allow`: after lock, `if !l.hasRoom(key, now) { return false }`, rest unchanged.
  New methods (nil-receiver safe because several tests build `&Server{}` literals without these limiters):

```go
// blocked reports whether key has used up its window, without counting a hit.
// A new key on a full map counts as blocked.
func (l *limiter) blocked(key string) bool {
	if l == nil {
		return false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.hasRoom(key, now) {
		return true
	}
	w := l.hits[key]
	return w != nil && !now.After(w.reset) && w.count >= l.max
}

// recordFailure counts one failed attempt for key.
func (l *limiter) recordFailure(key string) {
	if l == nil {
		return
	}
	_ = l.allow(key)
}
```

###### Per-page password failure limiter

- `Server` fields: `pagePasswordFailLimiter *limiter`, `accountLoginLimiter *limiter`; in `New`: `pagePasswordFailLimiter: newLimiter(pagePasswordFailureMax, pagePasswordFailureWindow)`, `accountLoginLimiter: newLimiter(accountLoginFailureMax, accountLoginFailureWindow)`.
- `handlePagePassword` (`pages.go:127`): after the `u.Visibility != models.UploadVisibilityPassword` redirect block and before `r.ParseForm()`:

```go
	failKey := strconv.FormatInt(u.ID, 10) // upload id: stable across renames
	if s.pagePasswordFailLimiter.blocked(failKey) {
		rateLimitError(w, r)
		return
	}
```
  In the bcrypt-failure branch, call `s.pagePasswordFailLimiter.recordFailure(failKey)` before rendering the 401 gate. Success does not reset the counter. Response when blocked: 429 plain text `Too many requests. Try again shortly.` (existing `rateLimitError`, same as the per-IP limiter on this route). Trade-off to document: anyone can lock a password page's gate for 10 minutes; viewers who already unlocked it (7-day cookie) are unaffected.

###### Per-account login failure limiter

`web_login.go`:

```go
var errLoginThrottled = errors.New("too many failed sign-in attempts")

func loginFailureKey(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (s *Server) loginWithPassword(r *http.Request) (int64, string, error) {
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	if email == "" || password == "" {
		return 0, "", fmt.Errorf("missing credentials")
	}
	key := loginFailureKey(email)
	if s.accountLoginLimiter.blocked(key) {
		return 0, "", errLoginThrottled
	}
	id, name, err := s.checkPasswordLogin(r.Context(), email, password)
	if err != nil {
		s.accountLoginLimiter.recordFailure(key)
	}
	return id, name, err
}
```
  `checkPasswordLogin(ctx context.Context, email, password string) (int64, string, error)` is the current body from `GetAccountByEmail` to the end, unchanged (use `ctx` instead of `r.Context()`). Failures are counted for any email, existing or not, so the limiter does not reveal which accounts exist. In `handleLogin`, right after the `switch` and before `if err != nil {`: `if errors.Is(err, errLoginThrottled) { rateLimitError(w, r); return }`. Add `"errors"` import. Token login is not changed.

###### Startup warning text

`server.go:189-191` keep as is.

##### Files touched

- New: `internal/server/client_ip.go`, `internal/server/client_ip_test.go`.
- `internal/server/analytics.go` (remove `clientIP`), `ratelimit.go`, `middleware.go` (line 27), `comments.go` (102, 203), `pages.go` (handlePagePassword), `web_login.go`, `server.go` (Config, Server fields, New).
- `internal/peekd/run.go`, `internal/peekd/run_test.go`.
- Tests: `analytics_test.go`, `ratelimit_test.go`, `pages_test.go`, `web_login_test.go`.

##### Existing tests to update

- `analytics_test.go:37-41,51-52`: add `trustedProxyCIDRs: mustPrefixes(t, DefaultTrustedProxyCIDRs)` to the Server literal (helper defined in `client_ip_test.go`: `func mustPrefixes(t *testing.T, s string) []netip.Prefix`), set `req.RemoteAddr = "127.0.0.1:5000"`, and change XFF to `"198.51.100.7, 203.0.113.10"`. Keep `wantHash` on `203.0.113.10` (line 78): rightmost untrusted hop, while the old leftmost logic would give `198.51.100.7`.
- `ratelimit_test.go:55` `TestLimiterCapacityCleanup`: set `l.maxKeys = 100`, insert `k0..k99` (100 keys), advance `time.Minute + time.Nanosecond`, `allow("cleanup-key")` must be true, `len(l.hits) == 1`.

##### Tests to add

`internal/server/client_ip_test.go` (package `server`):
- `TestClientIPRightmostUntrustedHop` — table, Server `{trustedProxy: true, trustedProxyCIDRs: mustPrefixes(t, "127.0.0.0/8,::1/128,10.0.0.0/8")}`; build requests with `httptest.NewRequest` and set `RemoteAddr`:
  | RemoteAddr | XFF header(s) | want |
  | --- | --- | --- |
  | `127.0.0.1:5000` | `198.51.100.7, 203.0.113.10` | `203.0.113.10` |
  | `127.0.0.1:5000` | `198.51.100.7, 203.0.113.10, 10.0.0.1` | `203.0.113.10` |
  | `192.0.2.5:5000` | `203.0.113.10` | `192.0.2.5` |
  | `127.0.0.1:5000` | `10.0.0.2, 10.0.0.1` | `10.0.0.2` |
  | `127.0.0.1:5000` | `garbage, 203.0.113.10` | `203.0.113.10` |
  | `127.0.0.1:5000` | `203.0.113.10, garbage` | `127.0.0.1` |
  | `127.0.0.1:5000` | two headers `198.51.100.7` then `203.0.113.10` (use `Header.Add`) | `203.0.113.10` |
  | `[::1]:5000` | `2001:db8::1` | `2001:db8::1` |
  | `127.0.0.1:5000` | `::ffff:203.0.113.10` | `203.0.113.10` |
  | `127.0.0.1:5000` | `203.0.113.10:4711` | `203.0.113.10` |
  | `127.0.0.1:5000` | none | `127.0.0.1` |
- `TestClientIPIgnoresForwardedForWithoutTrustedProxy`: `trustedProxy: false`, RemoteAddr `127.0.0.1:5000`, XFF `203.0.113.10` → `127.0.0.1`.
- `TestClientIPWarnsOnceForUntrustedForwarder`: RemoteAddr `192.0.2.5:5000` with XFF twice; assert `s.warnedUntrustedForwarder.Load()` is true after the first call (no log capture needed).
- `TestParseTrustedProxyCIDRs`: `"127.0.0.0/8, ::1/128,,192.0.2.7"` → 3 prefixes, last is `192.0.2.7/32`; `"10.0.0.1/8"` → `10.0.0.0/8` (masked); `"nope"` → error `invalid trusted proxy CIDR "nope"`; `""` → empty, nil error; `DefaultTrustedProxyCIDRs` parses without error.
- `TestRateLimitKeyForIP`: `"203.0.113.10"`→same; `"2001:db8:1:2:3:4:5:6"`→`"2001:db8:1:2::/64"`; `""`→`""`; `"not-an-ip"`→`"not-an-ip"`.

`internal/server/ratelimit_test.go`:
- `TestLimiterFailsClosedWhenFull`: `l, advance := newTestLimiter(5, time.Minute); l.maxKeys = 3`; `allow` a, b, c true; `allow("d")` false; `allow("a")` true; `advance(time.Minute + time.Nanosecond)`; `allow("d")` true.
- `TestLimiterBlockedDoesNotCountHits`: `newTestLimiter(2, time.Minute)`; `blocked("k")` false and `len(l.hits) == 0`; `recordFailure("k")` twice; `blocked("k")` true; advance window; `blocked("k")` false.
- `TestLimiterNilIsNoop`: `var l *limiter`; `l.blocked("k")` false; `l.recordFailure("k")` does not panic.
- `TestRateLimitWrapperGroupsIPv6By64`: `s := &Server{}`, `l := newLimiter(1, time.Minute)`, wrapped handler; request 1 RemoteAddr `[2001:db8::1]:1` → 200; request 2 RemoteAddr `[2001:db8::2]:1` → 429.

`internal/server/pages_test.go`:
- `TestPagePasswordFailuresLockPageAfterLimit`: `s, _ := newHandlerTestServer(t)`; hash "right" with `bcrypt.MinCost`; `u := newTwoVersionPage(t, s, "pwlock", models.UploadVisibilityPassword, hash)`; replace the clock: `now := time.Unix(1700000000, 0); s.pagePasswordFailLimiter.now = func() time.Time { return now }`. Helper `post := func(pw string) *httptest.ResponseRecorder` builds `httptest.NewRequest(POST, "/p/pwlock", strings.NewReader("password="+pw))` with urlencoded Content-Type, `SetPathValue("slug", "pwlock")`, calls `s.handlePagePassword` directly (bypasses the per-IP route limiter). 20× `post("wrong")` → 401 each; `post("right")` → 429; a second password page `pwother` → `post` right on it → 303 (not affected); `now = now.Add(pagePasswordFailureWindow + time.Second)`; `post("right")` on pwlock → 303.

`internal/server/web_login_test.go`:
- `TestPasswordLoginFailuresLockAccountAfterLimit`: `s, _ := newHandlerTestServer(t)`; `CreateAccountWithPassword(ctx, "user@example.test", "User", <MinCost hash of "right">, false)` and a second `other@example.test`; helper `try := func(email, pw string) error { req := httptest.NewRequest(POST, "/login", strings.NewReader(url.Values{"email": {email}, "password": {pw}}.Encode())); set urlencoded; _, _, err := s.loginWithPassword(req); return err }`. 10× `try("user@example.test","wrong")` non-nil and not `errLoginThrottled`; `try("USER@example.test ", "right")` → `errors.Is(err, errLoginThrottled)` (key normalised); `try("other@example.test","right")` → nil.
- `TestPasswordLoginThrottlesUnknownEmails`: 10× `try("ghost@example.test","x")`, 11th → `errLoginThrottled`.
- `TestHandleLoginReturns429WhenAccountThrottled`: `newHandlerTestServer`; create the password account; pre-fill `for i := 0; i < accountLoginFailureMax; i++ { s.accountLoginLimiter.recordFailure("user@example.test") }`; `doRequest(t, s, POST, "/login", strings.NewReader(url.Values{"method": {"password"}, "email": {"user@example.test"}, "password": {"right"}, "csrf": {"tok"}}.Encode()), func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded"); r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "tok"}) })` → 429, body contains `Too many requests. Try again shortly.`.

`internal/peekd/run_test.go`:
- In `TestParseServeConfigMapsFlagsAndEnv` add `t.Setenv("PEEK_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.0.2.7")` and assert `len(cfg.TrustedProxyCIDRs) == 2` and `cfg.TrustedProxyCIDRs[1].String() == "192.0.2.7/32"`.
- `TestParseServeConfigDefaultsTrustedProxyCIDRsToLoopback`: no env; `--data t.TempDir()`; CIDRs stringify to `["127.0.0.0/8", "::1/128"]`.
- `TestParseServeConfigRejectsInvalidTrustedProxyCIDRs`: `PEEK_TRUSTED_PROXY_CIDRS=10.0.0.0/33` → error containing `trusted-proxy-cidrs: invalid trusted proxy CIDR "10.0.0.0/33"`.
- `TestParseServeConfigRejectsEmptyTrustedProxyCIDRs`: args `--trusted-proxy --trusted-proxy-cidrs ""` → error `trusted-proxy-cidrs must list at least one CIDR when trusted-proxy is set`.

##### Docs to update

- `docs/operations.md:41` replace with: "Set `--trusted-proxy` only when a reverse proxy you control appends to `X-Forwarded-For`. Peek then honours the header only on connections from `--trusted-proxy-cidrs` / `PEEK_TRUSTED_PROXY_CIDRS` (default `127.0.0.0/8,::1/128`, a proxy on the same host) and uses the rightmost address that is not one of those proxies. When the proxy runs in another container, pod or platform edge, set the CIDRs to the addresses it connects from; Peek logs one warning naming the peer when it ignores the header. Without `--trusted-proxy`, every request behind a proxy has the proxy's address, so the whole organisation shares one rate-limit bucket (for example 10 sign-in attempts per minute)."
- Add to `docs/operations.md` after that paragraph: "Besides per-IP limits, Peek locks password sign-in for an email address after 10 failed attempts for 15 minutes, and a password-protected page's gate after 20 failed attempts for 10 minutes. Anyone can trigger these locks, so a locked admin can still sign in with SSO or an API token, and viewers who already unlocked a page are not affected."
- "Upgrades And Rollbacks": "With `--trusted-proxy`, `X-Forwarded-For` is now trusted only from `PEEK_TRUSTED_PROXY_CIDRS` (default loopback). Deployments whose proxy connects from another address must set it, or all clients share the proxy's rate-limit bucket."
- `README.md:154` add row after `--trusted-proxy`: ``| `--trusted-proxy-cidrs` | `PEEK_TRUSTED_PROXY_CIDRS` | `127.0.0.0/8,::1/128` | Proxies allowed to set `X-Forwarded-For` (with `--trusted-proxy`) |``. `README.md:191`: "Per-IP rate limits on login, password gate, and comment posting, plus per-account sign-in and per-page password failure limits." `README.md:207`: "Set `--trusted-proxy` if your proxy forwards `X-Forwarded-For`, and `--trusted-proxy-cidrs` if it does not connect from localhost."
- `docs/src/content/docs/reference.md:18` add the same flag row after `--trusted-proxy`.
- `docs/src/content/docs/server-setup.md:100` append: "Peek accepts the header only from `--trusted-proxy-cidrs` (default loopback); set it to your proxy's address range when the proxy is not on the same host."
- `docs/src/content/docs/deployment-platforms.md` Render env block (~line 49): do not add a `PEEK_TRUSTED_PROXY_CIDRS` value to the block (the platform's range is not known); add one sentence after the block: "Also set `PEEK_TRUSTED_PROXY_CIDRS` to the range the platform's proxy connects from; Peek logs the peer address once if it is ignoring `X-Forwarded-For`."

##### Stop conditions

- `TestRecordVisitPersistsPrivacySafeAnalytics` passes without setting `RemoteAddr`/CIDRs → `clientIP` still trusts the leftmost or ignores the peer check; wrong.
- Any existing test that sends >10 password logins for the same email or >20 page-password failures for one page starts failing → report the test name (it pins old behaviour; confirm before changing it).
- A limiter call site other than the four listed uses `clientIP` → report it, do not silently convert.
- `go vet` complains about copying `Server` because of `atomic.Bool` → some code copies `Server` by value; report.

---

#### L1 — body cap for non-upload routes

##### Current state

- `internal/server/middleware.go:18-38` `withMiddleware`: security headers, global limiter, metrics; no body limit.
- Upload routes that legitimately take large bodies and already wrap `MaxBytesReader(maxUpload+1024)`: `POST /api/upload` (`api_uploads.go:44`), `POST /dashboard/upload` (`web_dashboard.go:109`). There is no other upload route (new versions go through `POST /api/upload` with a `slug` field; `routes.go:9,76`).
- JSON routes already cap through `decodeJSON` (`json_decode.go:11-12`: 8 KiB small, 64 KiB default; largest user is comments and `PUT /api/settings` at 64 KiB).
- Form routes without a cap: `POST /p/{slug}` and `/p/{slug}/v/{n}` (`pages.go:147`), `POST /login` (`web_login.go:26`), `POST /logout` (`web_login.go:140`), `POST /setup` (`web_setup.go:33`), `POST /cli-login/{code}` (`cli_login.go:142`), all dashboard forms via `parseDashboardForm` (`web_helpers.go:44`).

##### Design

In `middleware.go`:

```go
// maxRequestBodyBytes caps request bodies on every route except the two upload
// routes, which apply their own limit from the max_upload setting. 64 KiB matches
// the largest JSON body any handler accepts (defaultJSONBodyLimit).
const maxRequestBodyBytes = defaultJSONBodyLimit

// bodyLimitExempt reports whether r is an upload, whose handler sets its own
// MaxBytesReader.
func bodyLimitExempt(r *http.Request) bool {
	return r.Method == http.MethodPost && (r.URL.Path == "/api/upload" || r.URL.Path == "/dashboard/upload")
}

func requestTooLargeError(w http.ResponseWriter, r *http.Request) {
	if wantsJSONError(r) {
		jsonError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	http.Error(w, "Request body too large.", http.StatusRequestEntityTooLarge)
}
```

In `withMiddleware`, immediately after the global-limiter block and before `reqTotal.Add(1)`:

```go
		if r.Body != nil && r.Body != http.NoBody && !bodyLimitExempt(r) {
			if r.ContentLength > maxRequestBodyBytes {
				requestTooLargeError(w, r)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
```
Bodies without a declared length (chunked) are cut at 64 KiB by `MaxBytesReader`; handlers then see a read error from `ParseForm`/`decodeJSON` and answer with their existing 400 paths. Exact path match is intentional: anything else (including unclean paths that ServeMux would redirect) gets the cap.

##### Files touched

- `internal/server/middleware.go`; tests in `internal/server/web_security_test.go` (package `server`).

##### Tests to add (`internal/server/web_security_test.go`)

Use `newHandlerTestServer`, `doRequest`, `asBearer`, `newTwoVersionPage`.
- `TestRequestBodyCapRejectsDeclaredOversizedForm`: `doRequest(t, s, POST, "/p/anything", strings.NewReader("password="+strings.Repeat("a", maxRequestBodyBytes)), urlencoded)` → 413, body `Request body too large.\n`.
- `TestRequestBodyCapCutsChunkedForm`: password page `capped` (MinCost hash); request body `"password="+strings.Repeat("a", 100<<10)` with `r.ContentLength = -1` set in an option → 400 and body contains `The password form could not be read.` (the `ParseForm` error branch at `pages.go:147-149`).
- `TestRequestBodyCapJSONAPI`: `POST /api/uploads/anything/comments` with a `maxRequestBodyBytes+1` byte body and `Content-Type: application/json` → 413, JSON `{"error":"request body too large"}` (decode and compare the `error` field).
- `TestRequestBodyCapExemptsUploads`: `doRequest(t, s, POST, "/api/upload?filename=big.html&visibility=public", strings.NewReader("<!doctype html><html><body>"+strings.Repeat("x", 100<<10)+"</body></html>"), asBearer(adminToken), func(r *http.Request) { r.Header.Set("Content-Type", "text/html; charset=utf-8") })` → 200.
- `TestRequestBodyCapAllowsSmallForms`: GET `/healthz` → 200 (smoke that GETs are unaffected) and POST `/p/<password page>` with a correct short password → 303.

##### Docs to update

- `docs/operations.md` "Quotas, Retention, And Storage" (after line 73): "Request bodies are limited to 64 KiB on every route except page uploads, which use the maximum upload size."
- `README.md:192` row "Malicious content": append "; non-upload requests are capped at 64 KiB."

##### Stop conditions

- Any existing test posts more than 64 KiB to a non-upload route and fails → report it (likely a dashboard settings or comment test that pins a larger limit).
- `TestRequestBodyCapExemptsUploads` gets 413 → path/method matching is wrong; do not widen the exemption to a prefix.
- If `PUT /api/settings` or the dashboard settings form is found to need more than 64 KiB (e.g. a pasted key file), stop and report instead of raising the constant.


### Design B — CLI login, token policy, OIDC, login timing, session epoch (S3, S4, L2, L3, L4, L5)


Repo `/home/user/peek` at `d7242f9` (branch `plan/security-hardening-coverage`). Source of findings: `docs/audits/2026-10-security-and-coverage-audit.md`. Style follows `origin/plan/dashboard-api-keys:docs/plans/dashboard-api-keys-plan.md` (migration 10).

User decisions applied: S4 = API tokens follow exactly the same account policy as `webAuth` (allowed email domain, OAuth-required for non-admins), new tokens from CLI device login expire after 90 days, dashboard API keys and admin-API tokens stay non-expiring. `TestDirectAPITokenAuthIgnoresAllowedEmailDomain` is replaced.

#### 0. Cross-cutting decisions

- **Migrations.** The last migration is 10 (`token_hint_last_used`, `internal/db/migrations.go:48`). This note uses **11 = `cli_login_request_context`** (S3) and **12 = `account_session_epoch`** (L5). Both go into one storage phase (P1) so no two phases edit `schema.go` / `migrations.go`. If another design note also needs a migration, it takes 13+ and must run after P1.
- **No signature breaks across phases in `internal/db`.** New store functions are added next to the old ones (`CreateCLILoginDeviceWithContext`, `CreateAccountTokenExpiring`), so server tests that call the old functions keep compiling while phases run in parallel.
- **Session cookie compatibility (L5).** New subject is `"<id>:<epoch>"`; the old `"<id>"` subject is still accepted and counts as epoch 0. That keeps every existing session alive across the upgrade and keeps the ~20 test sites that build `makeWebSession(s.secret, strconv.FormatInt(id, 10), sessionTTL)` (incl. `asSession`) working unchanged.
- **Docs** for all six findings go into one final docs-only phase (P6) so `docs/operations.md`, `auth-access.md` and `README.md` are not edited by several parallel phases.

##### Blocking confirmation for the user (S4 consequence)

"Mirror `webAuth` exactly" has a consequence the user may not have weighed: tokens created by `peek token create` / `POST /api/tokens` (`db.CreateToken`, `internal/db/tokens.go:31-52`) belong to **token-only accounts with `email = NULL`**, and legacy installs migrated by `migrateAccounts` (`migrations.go:260`) have the same. Under exact mirroring:
- as soon as an allowed email domain is set, **every** such token (admin or not) gets 403, because `emailMatchesAllowedDomain("", "example.com")` is false (`auth_domain.go:41-52`);
- while any OAuth provider is enabled (the recommended company setup), every **non-admin** such token gets 403, because it has no OAuth identity.

The design below implements exact mirroring as decided. If the user instead wants email-less token-only accounts exempt, the only change is in `accountActive` (P2): wrap the domain and OAuth checks in `if a.Email != "" { … }`, and flip the two tests named in P2 accordingly. The orchestrator should ask before P2 starts; the default is exact mirroring.

#### 1. S3: CLI device login is one-click phishable

##### Current state

- `internal/server/cli_login.go:46` returns `"verification_url": s.baseURL + "/cli-login/" + userCode`. The code is in the URL.
- `randomUserCode` (`cli_login.go:187-197`): 8 chars from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (32 symbols, `byte % 32` is unbiased), no dash, stored upper-case in `cli_login_devices.user_code` (UNIQUE).
- `handleCLILoginPage` (`cli_login.go:114-130`, route `GET /cli-login/{code}`, `routes.go:72`) looks up the code, then `webAuth`, then renders `cli-login` with only `Code` and `User`.
- `handleCLILoginApprove` (`cli_login.go:132-176`, route `POST /cli-login/{code}`, `routes.go:73`): webAuth → ParseForm → `validateCSRF` → lookup → deny/approve. Approve audits `s.audit("cli login approved account=%d code=%s", …)`; deny is not audited.
- Template `internal/web/templates/cli_login.gohtml` defines `cli-login` (form `action="/cli-login/{{.Code}}"`, text "Code … will receive an API token for {{.User}}.") and `cli-login-done`. Data types `webui.CLILoginData{Code, CSRF, User, Error}` and `CLILoginDoneData` at `internal/web/renderer.go:275-285`; template names at `renderer.go:20-21`.
- Table `cli_login_devices` (`internal/db/schema.go:119-128`): `id, device_hash, user_code, status, account_id, created_at, expires_at, consumed_at`. No IP, no user agent. `created_at` is already the request time. `models.CLILoginDevice` (`internal/models/models.go:86-94`) has `CreatedAt` already.
- DB: `CreateCLILoginDevice(ctx, deviceCode, userCode, expiresAt)` (`internal/db/cli_login.go:12-16`), `getCLILoginWhere` SELECT (`cli_login.go:30`).
- Rate limits: only `POST /api/cli/login/start` and `/poll` are wrapped in `cliLoginLimiter` (120/min, `server.go:177`). The browser pages `GET/POST /cli-login/{code}` have **no** limiter.
- Token issue in `handleCLILoginPoll` (`cli_login.go:93-108`): checks `account.Disabled || !s.accountAllowedByEmailDomain(...)`, then `CreateTokenForAccount(ctx, token, account.ID, "CLI login")` → non-expiring.
- CLI: `internal/cli/login_oauth.go:38` prints `"Opening browser for Peek login.\nCode: %s\nURL:  %s\n"` to `os.Stderr` and opens `verification_url`. `postJSONNoAuth` (`login_oauth.go:80-102`) sends no `User-Agent`, so the server sees `Go-http-client/1.1`. CLI tests (`internal/cli/login_oauth_test.go`) assert only the opened URL equals the server's `verification_url` and stdout `"saved.\n"`; nothing asserts stderr or the URL shape, so they keep passing.
- Existing server tests for this area: `TestCLILoginPollIssuesTokenOnce`, `TestCLILoginStartDoesNotRequireOAuth` (`internal/server/oauth_test.go:530-599`), `TestCLILoginPollRejectsDisallowedDomain` (`auth_domain_test.go:290`). Handlers `handleCLILoginPage/Approve` are untested.

##### Design

**Flow.** `peek login` → `POST /api/cli/login/start` stores client IP + user agent → CLI prints the code `ABCD-EFGH` and opens `<base>/cli-login` → user signs in → types the code → `POST /cli-login` (rate-limited, CSRF) shows the approval page with request IP, the viewer's own IP, client, request time and a warning → `POST /cli-login/{code}` approves or denies (rate-limited, CSRF) → poll issues a token that expires after 90 days.

**Code format.** Stored form stays 8 chars without dash (no data change). Displayed and returned form is `ABCD-EFGH`.

```go
// internal/server/cli_login.go
const (
	cliLoginTTL      = 15 * time.Minute
	cliLoginInterval = 2
	// cliTokenTTL is how long a token issued through `peek login` stays valid.
	cliTokenTTL = 90 * 24 * time.Hour
	// cliLoginUserAgentMax caps the stored User-Agent of a login request, in bytes.
	cliLoginUserAgentMax = 200
	userCodeAlphabet     = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	cliLoginCodeError    = "That code is invalid or expired. Check the code in your terminal."
	cliLoginSessionError = "Invalid session. Enter the code again."
)

// formatUserCode renders a stored 8-character code as ABCD-EFGH.
func formatUserCode(code string) string // len(code)==8 ? code[:4]+"-"+code[4:] : code

// normalizeUserCode turns typed input into the stored form: upper-case, with
// spaces, tabs and dashes removed. ok is false unless the result is exactly 8
// characters from userCodeAlphabet.
func normalizeUserCode(raw string) (code string, ok bool)
```
`randomUserCode` uses `userCodeAlphabet` instead of its local const (behaviour unchanged).

**Start** (`handleCLILoginStart`): replace the `CreateCLILoginDevice` call with
`s.store.CreateCLILoginDeviceWithContext(r.Context(), deviceCode, userCode, time.Now().Add(cliLoginTTL), s.clientIP(r), cliLoginUserAgent(r))` where

```go
// cliLoginUserAgent returns the request's User-Agent cut to cliLoginUserAgentMax
// bytes, with any partial UTF-8 sequence dropped.
func cliLoginUserAgent(r *http.Request) string {
	ua := strings.TrimSpace(r.UserAgent())
	if len(ua) > cliLoginUserAgentMax {
		ua = ua[:cliLoginUserAgentMax]
	}
	return strings.ToValidUTF8(ua, "")
}
```
Response: `"user_code": formatUserCode(userCode)`, `"verification_url": s.baseURL + "/cli-login"`. Other fields unchanged.

**Routes** (`internal/server/routes.go`, replace lines 72-73):

```go
mux.HandleFunc("GET /cli-login", s.handleCLILoginEntry)
mux.HandleFunc("POST /cli-login", s.rateLimit(s.loginLimiter, s.handleCLILoginLookup))
mux.HandleFunc("GET /cli-login/{code}", s.handleCLILoginLegacyLink)
mux.HandleFunc("POST /cli-login/{code}", s.rateLimit(s.loginLimiter, s.handleCLILoginApprove))
```
`loginLimiter` is 10/min per client IP (`server.go:172`). Decision: reuse it instead of adding a limiter; code entry is a credential-guessing surface just like password login. `handleCLILoginPage` is deleted.

**Legacy links.** Decision: `GET /cli-login/{code}` answers `303 Location: /cli-login` without looking at the code, never pre-fills it (pre-filling would restore the phishing link). Old CLIs still work: they print the code, the user types it.

**Handlers** (all set `noCache(w)` and `w.Header().Set("Content-Security-Policy", webui.DashboardCSP)` first):

```go
// handleCLILoginEntry renders the form where a signed-in user types the code
// that `peek login` printed in their own terminal.
func (s *Server) handleCLILoginEntry(w http.ResponseWriter, r *http.Request)
//   owner, ok := s.webAuth(r); !ok → s.setNextPath(w, "/cli-login"); 303 /login
//   s.renderCLILoginEntry(w, http.StatusOK, webui.CLILoginEntryData{User: owner.Name})

// handleCLILoginLookup checks a typed code and shows the approval page for it.
func (s *Server) handleCLILoginLookup(w http.ResponseWriter, r *http.Request)
//   webAuth fail → setNextPath("/cli-login"); 303 /login
//   r.ParseForm() err → renderCLILoginEntry(200, {User, Error: cliLoginSessionError})
//   validateCSRF err → s.renderCSRFError(w, err); !valid → entry form, Error: cliLoginSessionError
//   code, ok := normalizeUserCode(r.FormValue("code")); !ok → entry form, Error: cliLoginCodeError
//   d, err := s.store.GetCLILoginByUserCode(ctx, code)
//   err != nil || d.Status != "pending" || time.Now().After(d.ExpiresAt) → entry form, Error: cliLoginCodeError
//   s.renderCLILoginForm(w, http.StatusOK, s.cliLoginApprovalData(r, owner, d, ""))

// handleCLILoginLegacyLink sends old /cli-login/<code> links to the empty code form.
func (s *Server) handleCLILoginLegacyLink(w http.ResponseWriter, r *http.Request)
//   noCache(w); http.Redirect(w, r, "/cli-login", http.StatusSeeOther)

// cliLoginApprovalData builds the approval page for device d.
func (s *Server) cliLoginApprovalData(r *http.Request, owner *models.Account, d *models.CLILoginDevice, errMsg string) webui.CLILoginData
//   Code: formatUserCode(d.UserCode), User: owner.Name, Error: errMsg,
//   RequestIP: orUnknown(d.RequestIP), UserAgent: orUnknown(d.UserAgent),
//   RequestedAt: d.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
//   CurrentIP: s.clientIP(r)
// orUnknown(s) returns "unknown" for "".

func (s *Server) renderCLILoginEntry(w http.ResponseWriter, status int, data webui.CLILoginEntryData)
//   same shape as renderCLILoginForm: csrf, ok := s.csrfToken(w); data.CSRF = csrf; renderHTML(TemplateCLILoginEntry)
```

`handleCLILoginApprove` new order:
1. `code, codeOK := normalizeUserCode(r.PathValue("code"))`.
2. `owner, ok := s.webAuth(r)`; not ok → `s.setNextPath(w, "/cli-login")`, 303 `/login` (was `"/cli-login/"+code`).
3. `ParseForm` error or CSRF invalid → `renderCLILoginEntry(200, {User: owner.Name, Error: cliLoginSessionError})`; CSRF generation error → `renderCSRFError`.
4. `!codeOK`, lookup error, not pending, or expired → existing done page `{Title: "CLI login expired", Message: "Start a new login from the CLI."}`.
5. `decision == "deny"`: `DenyCLILogin`; failure → `renderCLILoginForm(200, s.cliLoginApprovalData(r, owner, d, "Denial failed."))`; success → `s.audit("cli login denied account=%d code=%s request_ip=%q", owner.ID, code, d.RequestIP)` then the existing denied done page.
6. otherwise approve: failure → approval data with `"Approval failed."`; success → `s.audit("cli login approved account=%d code=%s request_ip=%q", owner.ID, code, d.RequestIP)` then the existing approved done page.

**Poll** (`handleCLILoginPoll`, approved branch) — needs P2's `accountActive` and P1's store function:

```go
account, err := s.store.GetAccountByID(r.Context(), d.AccountID)
if err != nil || s.accountActive(r.Context(), account) != nil {
	jsonOK(w, map[string]any{"status": "denied"})
	return
}
...
expiresAt := time.Now().Add(cliTokenTTL).Unix()
if _, err := s.store.CreateAccountTokenExpiring(r.Context(), account.ID, token, "CLI login", expiresAt); err != nil {
	jsonError(w, http.StatusInternalServerError, "token creation failed")
	return
}
s.audit("cli token issued account=%d email=%q expires_at=%d", account.ID, account.Email, expiresAt)
```
Poll response JSON stays `{"status":"approved","token":…}` (no new field; the CLI does not need it).

**View models** (`internal/web/renderer.go`):

```go
TemplateCLILoginEntry = "cli-login-entry" // add to the const block after TemplateCLILoginDone

type CLILoginData struct {
	Code        string // ABCD-EFGH
	CSRF        string
	User        string
	Error       string
	RequestIP   string // client IP of the `peek login` request, "unknown" when not recorded
	UserAgent   string // User-Agent of that request, "unknown" when not recorded
	RequestedAt string // request time, "2006-01-02 15:04:05 UTC"
	CurrentIP   string // client IP of the browser looking at the page
}

// CLILoginEntryData is the form where a signed-in user types a CLI login code.
type CLILoginEntryData struct {
	CSRF  string
	User  string
	Error string
}
```

**Templates** (`internal/web/templates/cli_login.gohtml`). Use only utility classes that already exist in `internal/web/assets/pines.css` (checked: `bg-destructive/10`, `text-destructive`, `py-3`, `px-4`, `font-mono`, `tracking-wider`, `uppercase`, `flex-col`, `gap-1`, `gap-4`, `inline`, `font-medium`, `break-all`, `text-xs`, `text-center`), so `pines.css` does not change. If `mise run build` still changes `pines.css`, commit it.

New `{{define "cli-login-entry"}}`: same head/body/card skeleton and toast block as `cli-login`, containing

```html
<form method="POST" action="/cli-login" class="flex flex-col gap-4">
  <h2 class="text-lg font-semibold tracking-tight text-card-foreground">Connect the Peek CLI</h2>
  <p class="text-sm text-muted-foreground">Signed in as {{.User}}. Enter the code that <span class="font-mono">peek login</span> printed in your terminal.</p>
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="text" name="code" required maxlength="16" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="ABCD-EFGH" aria-label="CLI login code" class="h-10 rounded-lg border border-input bg-secondary px-4 text-center font-mono text-sm uppercase tracking-wider text-foreground placeholder:text-muted-foreground transition focus:border-ring focus:outline-none focus:ring-2 focus:ring-ring/20">
  <button type="submit" class="h-10 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition hover:bg-primary/90">Continue</button>
  {{if .Error}}<p class="text-sm text-destructive">{{.Error}}</p>{{end}}
</form>
```

`cli-login` (approval) form body becomes, in this order: the existing `<h2>Approve CLI login</h2>`; the warning

```html
<p role="alert" class="rounded-lg bg-destructive/10 px-4 py-3 text-sm text-destructive">Only approve if you just ran <span class="font-mono">peek login</span> yourself and this code matches your terminal. If someone sent you a link or a code, click Deny: approving gives them an API token that acts as you.</p>
```
then `<p class="text-sm text-muted-foreground">Code <strong class="text-foreground">{{.Code}}</strong> will receive an API token for {{.User}}. The token expires after 90 days.</p>`; then

```html
<dl class="flex flex-col gap-1 text-xs text-muted-foreground">
  <div><dt class="inline font-medium text-foreground">Requested from:</dt> <dd class="inline font-mono">{{.RequestIP}}</dd></div>
  <div><dt class="inline font-medium text-foreground">Your IP:</dt> <dd class="inline font-mono">{{.CurrentIP}}</dd></div>
  <div><dt class="inline font-medium text-foreground">Client:</dt> <dd class="inline break-all font-mono">{{.UserAgent}}</dd></div>
  <div><dt class="inline font-medium text-foreground">Requested at:</dt> <dd class="inline">{{.RequestedAt}}</dd></div>
</dl>
```
then the existing csrf hidden input, Approve/Deny buttons and error paragraph. The form `action` stays `/cli-login/{{.Code}}` (now `ABCD-EFGH`, which `normalizeUserCode` accepts).

**CLI** (`internal/cli/login_oauth.go`):
- Add hook var `oauthStderr io.Writer = os.Stderr` to the existing `var (…)` block; use it for both `Fprint*` calls in `loginOAuth`.
- Replace the message at line 38 with
  `fmt.Fprintf(oauthStderr, "Opening browser for Peek login.\nURL:  %s\nCode: %s\nType this code on that page. Never enter a code that someone else sent you.\n", start.VerificationURL, start.UserCode)`.
- In `postJSONNoAuth`, after building the request: `req.Header.Set("User-Agent", "peek-cli/"+version.Version)` (import `github.com/andras-tkcs/peek/internal/version`).
- `restoreOAuthTestHooks` is unchanged; tests that need stderr swap `oauthStderr` themselves with `t.Cleanup`.

##### Files touched

- P1 (storage): `internal/db/schema.go`, `internal/db/migrations.go`, `internal/db/cli_login.go`, `internal/models/models.go`; tests `internal/db/cli_login_test.go` (new), migration test (see P1).
- P3a (server): `internal/server/cli_login.go`, `internal/server/routes.go`, `internal/web/templates/cli_login.gohtml`, `internal/web/renderer.go`; tests `internal/server/cli_login_test.go` (new), `internal/web/renderer_test.go`.
- P3b (CLI): `internal/cli/login_oauth.go`; test `internal/cli/login_oauth_test.go`.

##### Storage (P1)

- `schema.go` `cli_login_devices`: after `consumed_at INTEGER NOT NULL DEFAULT 0` add `,\n\trequest_ip TEXT NOT NULL DEFAULT '',\n\trequest_user_agent TEXT NOT NULL DEFAULT ''`.
- `migrations.go`: append `{11, "cli_login_request_context", `-- ALTER TABLE handled idempotently below`},`; in `runMigrations` add `} else if m.id == 11 {` calling `s.migrateCLILoginRequestContext()` right after the `m.id == 10` branch and **before** `} else if m.sql != "" {` (the comment SQL is non-empty, so a later branch would never run). Same error wrapping as the other branches.

```go
// migrateCLILoginRequestContext records where a `peek login` request came from,
// so the approval page can show it. Existing rows keep ''.
func (s *Store) migrateCLILoginRequestContext() error {
	for _, stmt := range []string{
		`ALTER TABLE cli_login_devices ADD COLUMN request_ip TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE cli_login_devices ADD COLUMN request_user_agent TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.Exec(stmt); err != nil && !isDuplicateColumnError(err) {
			return err
		}
	}
	return nil
}
```
- `models.CLILoginDevice` gains `RequestIP string` and `UserAgent string` (after `ConsumedAt`).
- `internal/db/cli_login.go`:

```go
// CreateCLILoginDeviceWithContext stores a pending CLI login together with the
// client IP and User-Agent of the request that started it.
func (s *Store) CreateCLILoginDeviceWithContext(ctx context.Context, deviceCode, userCode string, expiresAt time.Time, requestIP, userAgent string) error
// INSERT INTO cli_login_devices(device_hash,user_code,status,created_at,expires_at,request_ip,request_user_agent) VALUES(?,?,?,?,?,?,?)
```
`CreateCLILoginDevice` keeps its signature and calls it with `"", ""`. `getCLILoginWhere` SELECT appends `,request_ip,request_user_agent` and scans into `&d.RequestIP, &d.UserAgent`.

##### Tests to add

`internal/db/cli_login_test.go` (new, package `db`, use `openTokenTestStore` from `tokens_test.go`):
- `TestCreateCLILoginDeviceWithContextStoresRequestContext`: create with `"203.0.113.7"`, `"peek-cli/1.2.3"`; `GetCLILoginByUserCode` returns both and `Status == "pending"`.
- `TestCreateCLILoginDeviceLeavesRequestContextEmpty`: old function → both `""`.

`internal/server/cli_login_test.go` (new). Use `newHandlerTestServer`, `doRequest`, `asSession`, `dashboardPost` (generic: it posts any path with `csrf=csrf-token` + cookie when `withCSRF`), `newAccountWithToken`. Create devices directly with `s.store.CreateCLILoginDeviceWithContext(ctx, "device-code", "ABCDEFGH", time.Now().Add(cliLoginTTL), "203.0.113.7", "peek-cli/1.2.3")`. The handler test server's `loginLimiter` is 10/min per IP and all `httptest` requests share `192.0.2.1`, so each test except the rate-limit test makes at most 10 `POST /cli-login*` requests.
- `TestNormalizeUserCode` (table): `"abcd-efgh"`→`"ABCDEFGH",true`; `" ABCD EFGH "`→true; `"ABCD-EFGH-"`→true; `"ABCDEFG"`→false; `"ABCDEFGI"`→false (I not in alphabet); `"ABCDEFGH1"`→false; `""`→false. Plus `formatUserCode("ABCDEFGH") == "ABCD-EFGH"`.
- `TestCLILoginStartReturnsCodeFreeVerificationURL`: `POST /api/cli/login/start` with header `User-Agent: peek-test/1.0`; `verification_url == "http://localhost:7700/cli-login"`; `user_code` matches `^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`; stored device (lookup with the dash removed) has `RequestIP == "192.0.2.1"`, `UserAgent == "peek-test/1.0"`.
- `TestCLILoginLegacyLinkRedirectsWithoutCode`: `GET /cli-login/ABCDEFGH` → 303, `Location: /cli-login`.
- `TestCLILoginEntryRequiresSession`: `GET /cli-login` without session → 303 `/login`, response sets `hn_next` = `/cli-login`.
- `TestCLILoginEntryRendersCodeForm`: with session → 200, body contains `action="/cli-login"` and `name="code"`, `Content-Security-Policy` equals `webui.DashboardCSP`.
- `TestCLILoginLookupShowsRequestContext`: `dashboardPost(t, s, id, "/cli-login", url.Values{"code": {"abcd-efgh"}}, true)` → 200; body contains `ABCD-EFGH`, `203.0.113.7`, `peek-cli/1.2.3`, `Only approve if you just ran`, `action="/cli-login/ABCD-EFGH"`, `expires after 90 days`.
- `TestCLILoginLookupRejectsUnknownExpiredOrMalformedCode`: subtests `unknown` (`ZZZZ-ZZZZ`), `expired` (device with `expiresAt` in the past), `malformed` (`abc`) → 200, body contains `That code is invalid or expired.`, not `Approve CLI login`.
- `TestCLILoginLookupRequiresCSRF`: `withCSRF=false` → 200, body contains `Invalid session. Enter the code again.`, not `203.0.113.7`.
- `TestCLILoginLookupIsRateLimited`: 11 lookups with CSRF → the 11th answers 429.
- `TestCLILoginApproveIssuesNinetyDayToken`: `dashboardPost(…, "/cli-login/ABCD-EFGH", url.Values{"decision": {"approve"}}, true)` → body contains `CLI login approved`; then `POST /api/cli/login/poll` `{"device_code":"device-code"}` → `approved` + token; `s.store.GetToken` → `ExpiresAt` within ±60 s of `time.Now().Add(cliTokenTTL).Unix()`; `ListAccountTokens` shows name `CLI login`.
- `TestCLILoginApproveDeny`: decision `deny` → `CLI login denied`; poll → `{"status":"denied"}`.
- `TestCLILoginApproveRequiresCSRF`: `withCSRF=false` → body contains `Invalid session. Enter the code again.`; device still `pending`.
- `TestCLILoginApproveRequiresSession`: no session cookie → 303 `/login`.
- `TestCLILoginApproveExpiredCode`: expired device → body contains `CLI login expired`.
- `TestCLILoginPollDeniesAccountFailingPolicy`: enable GitHub OAuth (`SetSetting("oauth_github_enabled","true")`, `SetSetting("oauth_github_client_id","id")`, `s.encryptedSetSetting(ctx,"oauth_github_client_secret","secret")`); approved device for a non-admin account without OAuth identity → poll `denied`, no token row created.

`internal/web/renderer_test.go`: update the `TemplateCLILogin` case data to `CLILoginData{Code: "ABCD-EFGH", CSRF: "csrf", User: "Admin", RequestIP: "203.0.113.7", UserAgent: "peek-cli/dev", RequestedAt: "2026-10-11 10:00:00 UTC", CurrentIP: "198.51.100.2"}` with `want: "Only approve if you just ran"`; add `{name: TemplateCLILoginEntry, data: CLILoginEntryData{CSRF: "csrf", User: "Admin"}, want: `name="code"`}`.

`internal/cli/login_oauth_test.go`:
- `TestLoginOAuthPrintsCodeAndURL`: like `TestLoginOAuthPollsUntilApproved` but start returns `user_code: "ABCD-EFGH"`, `verification_url: "http://auth.example.test/cli-login"`; swap `oauthStderr` for a `bytes.Buffer`; assert it contains `URL:  http://auth.example.test/cli-login`, `Code: ABCD-EFGH`, `Never enter a code that someone else sent you.`
- `TestPostJSONNoAuthSendsUserAgent`: `httptest` server records `r.Header.Get("User-Agent")`; call `postJSONNoAuth(ts.URL, "/x", nil, &out)` with a JSON `{}` response; want `"peek-cli/" + version.Version`.

##### Stop conditions

- `GetCLILoginByUserCode` or any other caller expects the dashed form in the DB → stop (stored form must stay undashed).
- Another design note changes `clientIP` (S2): fine, call it as is; if its signature changes, stop and rebase.
- Any existing CLI test fails because of the new stderr text → stop (none should; they only read stdout).
- `mise run build` changes `pines.css` in a way that removes classes → stop and report.

#### 2. S4: API tokens bypass the account policy; CLI tokens never expire

##### Current state

- `webAuth` (`internal/server/web_auth.go:13-43`) refuses: disabled (`:30`), `!s.accountAllowedByEmailDomain(ctx, a.Email)` (`:33`), and `s.oauthLoginRequired(ctx) && !a.IsAdmin` without `AccountHasOAuthIdentity` (or on its error) (`:36-41`).
- `authToken` (`internal/server/middleware.go:52-71`) and `authAdmin` (`:85-108`) only check `t.Disabled` → `403 "account disabled"`. The bearer branch of `handleListComments` (`internal/server/comments.go:61-75`) does the same.
- `models.Token` carries `AccountID, Email, IsAdmin, Disabled` (joined from `accounts`, `internal/db/tokens.go:206`), so the policy can be evaluated without another account query (the OAuth-identity lookup is one extra query only while OAuth is enabled, only for non-admins).
- `oauthLoginRequired` is in `web_login.go:108-110`; `accountAllowedByEmailDomain` and `errAccountNotEligible` in `auth_domain.go:12,58`.
- `TestDirectAPITokenAuthIgnoresAllowedEmailDomain` (`internal/server/auth_domain_test.go:210-233`) pins the old behaviour.
- Expiry: `getTokenWhere` already rejects `expires_at > 0 && now > expires_at` (`tokens.go:218-221`). `CreateAccountToken` (`tokens.go:83-90`) never sets `expires_at`; `CreateTokenForAccount` (`:54-60`) wraps it. 18 call sites across 9 files use `CreateTokenForAccount`/`CreateAccountToken`, so their signatures stay.

##### Design

New file `internal/server/account_policy.go`:

```go
package server

var (
	errAccountDisabled = errors.New("account disabled")
	errOAuthRequired   = errors.New("oauth login required")
)

// accountActive reports whether account a may use Peek now. Dashboard sessions
// and API tokens use the same rules: not disabled, email in the allowed email
// domain, and, while OAuth login is enabled, a linked OAuth identity unless the
// account is an admin. It returns nil, errAccountDisabled, errAccountNotEligible,
// errOAuthRequired, or the error of the OAuth identity lookup.
func (s *Server) accountActive(ctx context.Context, a *models.Account) error {
	if a.Disabled {
		return errAccountDisabled
	}
	if !s.accountAllowedByEmailDomain(ctx, a.Email) {
		return errAccountNotEligible
	}
	if s.oauthLoginRequired(ctx) && !a.IsAdmin {
		hasOAuth, err := s.store.AccountHasOAuthIdentity(ctx, a.ID)
		if err != nil {
			return err
		}
		if !hasOAuth {
			return errOAuthRequired
		}
	}
	return nil
}

// tokenAccount returns the account fields of t that accountActive checks.
func tokenAccount(t *models.Token) *models.Account {
	return &models.Account{ID: t.AccountID, Email: t.Email, IsAdmin: t.IsAdmin, Disabled: t.Disabled}
}

// writeTokenPolicyError answers a bearer request whose account failed accountActive.
func writeTokenPolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAccountDisabled):
		jsonError(w, http.StatusForbidden, "account disabled")
	case errors.Is(err, errAccountNotEligible):
		jsonError(w, http.StatusForbidden, "account email domain is not allowed")
	case errors.Is(err, errOAuthRequired):
		jsonError(w, http.StatusForbidden, "account must sign in with OAuth")
	default:
		slog.Error("token account check failed", "err", err)
		jsonError(w, http.StatusInternalServerError, "account check failed")
	}
}
```

Exact JSON bodies (via `jsonError`): `{"error":"account disabled"}` (unchanged text), `{"error":"account email domain is not allowed"}`, `{"error":"account must sign in with OAuth"}`, all 403; lookup failure 500 `{"error":"account check failed"}`.

Call sites:
- `web_auth.go`: replace lines 30-41 with `if s.accountActive(r.Context(), a) != nil { return nil, false }`. Update the doc comment: "…revocable via account disablement, the allowed email domain and the OAuth-required setting…".
- `middleware.go` `authToken`: replace the `t.Disabled` block with `if err := s.accountActive(r.Context(), tokenAccount(t)); err != nil { writeTokenPolicyError(w, err); return }`. `authAdmin`: same, placed before the `!t.IsAdmin` check (order: missing → invalid → policy → admin only → record use).
- `comments.go` bearer branch: replace the `owner.Disabled` block the same way, before the owner check.
- `recordTokenUse` still runs only after all checks pass.
- `cli_login.go` poll uses `accountActive` too (done in P3a, see S3).
- `loginWithPassword` / `loginWithToken` keep their own checks (their error kinds are used by tests and by L4); not refactored here.

90-day expiry: `cliTokenTTL` and the poll change are specified in S3 (same file, phase P3a). Storage (P1), `internal/db/tokens.go`:

```go
// CreateAccountTokenExpiring stores a new token for an existing account that
// stops working at expiresAt (unix seconds, 0 = never) and returns its id.
func (s *Store) CreateAccountTokenExpiring(ctx context.Context, accountID int64, token, name string, expiresAt int64) (int64, error)
// INSERT INTO tokens(account_id,token,name,is_admin,created_at,expires_at,hint) VALUES(?,?,?,0,?,?,?)
// args: accountID, HashToken(token), strings.TrimSpace(name), time.Now().Unix(), expiresAt, nullableHint(token)
```
`CreateAccountToken` becomes `return s.CreateAccountTokenExpiring(ctx, accountID, token, name, 0)`. Dashboard keys (`web_api_keys.go`) and `CreateToken` (admin API, honours `expires_hours`) are unchanged.

##### Files touched

- P2: `internal/server/account_policy.go` (new), `internal/server/web_auth.go`, `internal/server/middleware.go`, `internal/server/comments.go`; tests `internal/server/account_policy_test.go` (new), `internal/server/auth_domain_test.go`.
- P1: `internal/db/tokens.go`; test `internal/db/tokens_test.go`.
- P3a: `internal/server/cli_login.go` (poll).

##### Tests to add

`internal/server/auth_domain_test.go`: delete `TestDirectAPITokenAuthIgnoresAllowedEmailDomain`; add in its place

```go
func TestDirectAPITokenAuthHonoursAllowedEmailDomain(t *testing.T)
```
`newHandlerTestServer`; `newAccountWithToken(t, s, "user@other.test", "other-token-0123", false)` and `newAccountWithToken(t, s, "user@example.test", "ok-token-0123", false)`; `s.store.SetSetting(ctx, authAllowedEmailDomainSetting, "example.test")`; `GET /api/uploads` with `asBearer("other-token-0123")` → 403 and decoded `error == "account email domain is not allowed"`; with `asBearer("ok-token-0123")` → 200; `tokenLastUsed(t, s, "other-token-0123")` is not `Valid`.

`internal/server/account_policy_test.go` (new):
- `TestAccountActive` (table on `newHandlerTestServer`): disabled → `errAccountDisabled`; off-domain (domain set to `example.test`, email `u@other.test`) → `errAccountNotEligible`; GitHub OAuth enabled (settings as in S3 test) + non-admin without identity → `errOAuthRequired`; same after `s.store.UpsertOAuthIdentity(ctx, id, "github", "42", email, name)` → nil; admin without identity → nil; email-less account (`s.store.CreateAccount(ctx, "", "bot", false)`) with domain set → `errAccountNotEligible` (documents the exact-mirror consequence).
- `TestAuthTokenRequiresOAuthIdentityWhenOAuthEnabled`: OAuth enabled; non-admin token → `GET /api/uploads` 403 `account must sign in with OAuth`; after `UpsertOAuthIdentity` → 200.
- `TestAuthAdminHonoursAllowedEmailDomain`: `newAccountWithToken(t, s, "admin@other.test", "admin2-token-0123", true)`; domain `example.test` (set with `SetSetting` directly); `GET /api/tokens` → 403 `account email domain is not allowed`.
- `TestAuthTokenDisabledAccountStillAnswersAccountDisabled`: `SetAccountDisabled` → 403 `account disabled`.
- `TestListCommentsBearerHonoursAccountPolicy`: upload with `uploadPage(t, s, token, versionTestHTML1, map[string]string{"visibility": "public"})` (as in `TestListCommentsRecordsTokenUse`), then set domain so the owner is off-domain → `GET /api/uploads/{slug}/comments` with `asBearer` → 403 `account email domain is not allowed`.

`internal/db/tokens_test.go`: `TestCreateAccountTokenExpiringStoresExpiry`: future expiry → `GetToken` ok and `ExpiresAt` equal; `ListAccountTokens` row has the same `ExpiresAt`; a second token with `time.Now().Add(-time.Minute).Unix()` → `GetToken` returns an error.

##### Stop conditions

- The user has not confirmed exact mirroring for email-less token-only accounts (see section 0) → ask before P2.
- An existing test in `internal/server` fails because it uses an email-less admin token (`newHandlerTestServer`'s `dev-admin-token`) after setting an allowed domain or enabling OAuth: fix the test only if it is about something else (give it an admin account with a matching email via `newAccountWithToken`); if it asserts the old policy, stop and report.
- L1 (another note) edits `withMiddleware` in `middleware.go`: P2 touches only `authToken`/`authAdmin`; if both phases run in parallel, rebase rather than share the file.

#### 3. L2 + L3: OIDC claim mixing and missing nonce

##### Current state

- `handleOAuthStart` (`internal/server/oauth_flow.go:13-36`): `state := randID(24)`, `verifier := oauth2.GenerateVerifier()`, cookie `oauthCookieName(p.Key)` (path `/oauth/<key>`, 10 min, Lax) with `s.makeOAuthFlowCookie(p.Key, state, verifier)`, redirect to `AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))`. No nonce.
- Flow cookie (`internal/server/oauth_session.go:20-43`): payload `base64url(provider|state|verifier)` signed with `makeWebSession(s.secret, payload, 10*time.Minute)`; `parseOAuthFlowCookie` splits with `SplitN(…, "|", 3)` and checks `parts[0] == provider`.
- Callback (`oauth_flow.go:38-94`): `profile, err := s.fetchOAuthProfile(ctx, p, tok)`; any profile error → 502 "OAuth profile lookup failed.".
- `fetchGoogleProfile` (`internal/server/oauth_profile.go:40-69`) **does** use an OIDC verifier: `oidc.NewProvider(ctx, "https://accounts.google.com")` + `Verifier(&oidc.Config{ClientID})`. Google's scopes include `openid` (`oauth_config.go:97`). So nonce applies to `google` and `oidc`; GitHub has no ID token.
- `fetchOIDCProfile` (`oauth_profile.go:117-175`): takes `sub`, `email`, `email_verified`, `name` from the ID token; if `email == "" || name == "user" || !emailVerified` it calls `provider.UserInfo` and fills each missing field **independently**: `sub` only if the ID token had none, `email` only if empty, `emailVerified` from userinfo when the ID token said false (`:149-160`). That mixes an ID-token email with a userinfo `email_verified`, and userinfo `sub` is never compared.
- go-oidc v3.19.0: `oidc.Nonce(nonce)` is an `oauth2.AuthCodeOption`; `IDToken.Nonce` holds the claim; the verifier does not check it. `oidctest.Server` serves discovery + keys only (no userinfo).
- Tests: `TestFetchOIDCProfileUsesVerifiedIDTokenClaims` (`oauth_test.go:255`, calls `s.fetchOIDCProfile(ctx, p, tok)`), `TestOIDCCallbackWithFakeSSOServerCreatesSessionAndConsumesInvite` (`:305`, builds the flow cookie with `makeOAuthFlowCookie("oidc", state, verifier)`), `newFakeOIDCServer(t, issuer, clientID, sub, email)` (`:405-466`, signs one fixed ID token at construction, mux paths under `/oidc/`, no userinfo handler; only caller is the callback test). No other caller of `makeOAuthFlowCookie`, `parseOAuthFlowCookie`, `fetchOAuthProfile`, `fetchOIDCProfile` or `fetchGoogleProfile` exists.

##### Design

**Flow cookie** (`oauth_session.go`):

```go
func (s *Server) makeOAuthFlowCookie(provider, state, verifier, nonce string) string
// payload base64url(provider|state|verifier|nonce)

func (s *Server) parseOAuthFlowCookie(r *http.Request, provider string) (state, verifier, nonce string, ok bool)
// SplitN(raw, "|", 4); ok only when len(parts) == 4, parts[0] == provider and parts[3] != "".
```
A cookie from before the upgrade (3 parts) fails to parse, so a login in flight during the upgrade sees "OAuth session expired. Try signing in again." (cookie lives 10 minutes). All values are base64url, so `|` cannot occur in them.

**Start** (`handleOAuthStart`): after the verifier, `nonce, err := randID(24)`; on error `slog.Error("oauth nonce generation failed", "provider", p.Key, "err", err)` and the same 500 "OAuth login could not start." Cookie value `s.makeOAuthFlowCookie(p.Key, state, verifier, nonce)`. Options:

```go
opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
if oauthProviderUsesIDToken(p.Key) {
	opts = append(opts, oidc.Nonce(nonce))
}
url := s.oauth2Config(p).AuthCodeURL(state, opts...)
```
New helper in `oauth_profile.go`: `// oauthProviderUsesIDToken reports whether provider key returns an OIDC ID token that carries the nonce.` `func oauthProviderUsesIDToken(key string) bool { return key == "google" || key == "oidc" }`. GitHub still gets a nonce in its cookie (uniform format) but it is neither sent nor checked.

**Callback**: `state, verifier, nonce, ok := s.parseOAuthFlowCookie(r, p.Key)`; `profile, err := s.fetchOAuthProfile(ctx, p, tok, nonce)`. Error handling unchanged (502 "OAuth profile lookup failed.", warn log carries the error text).

**Profile** (`oauth_profile.go`):

```go
var (
	errOIDCNonceMismatch    = errors.New("oidc nonce mismatch")
	errOIDCUserInfoSubject  = errors.New("oidc userinfo subject does not match id token")
	// googleIssuerURL is Google's OIDC issuer; tests point it at a fake issuer.
	googleIssuerURL = "https://accounts.google.com"
)

func (s *Server) fetchOAuthProfile(ctx context.Context, p *oauthProviderConfig, tok *oauth2.Token, nonce string) (*oauthProfile, error)
// google → s.fetchGoogleProfile(ctx, p, tok, nonce); github → s.fetchGitHubProfile(ctx, p, tok) (unchanged); oidc → s.fetchOIDCProfile(ctx, p, tok, nonce)

// verifyIDTokenNonce checks that the ID token carries the nonce of this login.
func verifyIDTokenNonce(idToken *oidc.IDToken, nonce string) error {
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return errOIDCNonceMismatch
	}
	return nil
}
```
`fetchGoogleProfile(ctx, p, tok, nonce)`: `oidc.NewProvider(ctx, googleIssuerURL)`; after `Verify`, `if err := verifyIDTokenNonce(idToken, nonce); err != nil { return nil, err }`. Rest unchanged (Google always returns email + email_verified in the ID token for the `email` scope; no userinfo call).

`fetchOIDCProfile(ctx, p, tok, nonce)` new body after `Verify`:

```go
if err := verifyIDTokenNonce(idToken, nonce); err != nil {
	return nil, err
}
var claims oidcProfileClaims
if err := idToken.Claims(&claims); err != nil {
	return nil, err
}
sub := strings.TrimSpace(claims.Sub)
if sub == "" {
	return nil, errors.New("missing oidc subject")
}
email := normalizeOAuthEmail(claims.Email)
emailVerified := bool(claims.EmailVerified)
name := displayName(claims.Name, claims.PreferredUsername, email)

if email == "" || !emailVerified || name == "user" {
	userInfo, err := provider.UserInfo(ctx, s.oauth2Config(p).TokenSource(ctx, tok))
	if err == nil {
		var info oidcProfileClaims
		if claimErr := userInfo.Claims(&info); claimErr == nil {
			// OIDC Core 5.3.2: userinfo must be about the ID token's subject.
			if strings.TrimSpace(info.Sub) != sub {
				return nil, errOIDCUserInfoSubject
			}
			// Email and email_verified always come from the same source.
			if (email == "" || !emailVerified) && normalizeOAuthEmail(info.Email) != "" {
				email = normalizeOAuthEmail(info.Email)
				emailVerified = bool(info.EmailVerified)
			}
			if name == "user" {
				name = displayName(info.Name, info.PreferredUsername, email)
			}
		}
	}
}
```
Rules in words: the ID token must have a `sub` (the old fallback to the userinfo `sub` is removed: `sub` is REQUIRED in an ID token). When userinfo is fetched and parses, its `sub` must equal the ID token's `sub` exactly (after `TrimSpace`); an empty userinfo `sub` also counts as a mismatch (it is REQUIRED there too). This is stricter than "only compare when both are non-empty" on purpose. Email and `email_verified` are taken as a pair: the ID token pair when it has a verified email, otherwise the userinfo pair when userinfo has an email, otherwise the ID token pair (possibly unverified, which `resolveOAuthAccount` then rejects). A failed userinfo request is still ignored (ID-token values are used), as today. Display name may still be filled from userinfo.

##### Files touched

P4: `internal/server/oauth_flow.go`, `internal/server/oauth_profile.go`, `internal/server/oauth_session.go` (only the two flow-cookie functions), test `internal/server/oauth_test.go`.

##### Tests to add / change (`internal/server/oauth_test.go`)

Replace `newFakeOIDCServer` with an options form (its only caller is the callback test):

```go
type fakeOIDCOptions struct {
	Issuer, ClientID, Sub, Email string
	EmailVerified                bool           // email_verified in the ID token
	Nonce                        string         // nonce claim; "" leaves it out
	UserInfo                     map[string]any // JSON served at /oidc/userinfo; nil answers 404
}

func newFakeOIDCServer(t *testing.T, opts fakeOIDCOptions) *fakeOIDCServer
```
Build the ID token claims with `json.Marshal` of a `map[string]any` (`iss, aud, sub, exp, email, email_verified, name: "OIDC User"`, plus `nonce` when set). Add `mux.HandleFunc("/oidc/userinfo", …)` that answers 404 when `opts.UserInfo == nil`, else `jsonOK(w, opts.UserInfo)`. Leave `/oidc/keys`, `/oidc/token` and discovery as they are (discovery already advertises `issuer + "/userinfo"`).

Helper for direct profile tests: `fakeOIDCProviderConfig(t, fake) (context.Context, *oauthProviderConfig)` → `ctx := oidc.ClientContext(context.Background(), fake.client())`, `provider, _ := oidc.NewProvider(ctx, fake.issuer)`, config with `ClientID`, `ClientSecret: "s"`, `IssuerURL: fake.issuer`, `Endpoint: provider.Endpoint()`, `OIDCProvider: provider`, key `oidc`. Token: `(&oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}).WithExtra(map[string]any{"id_token": fake.token})`. Use issuer `https://8.8.8.8/oidc` as the callback test does.

- Update `TestFetchOIDCProfileUsesVerifiedIDTokenClaims`: add `"nonce": "nonce-123"` to `rawClaims`, call with `"nonce-123"`.
- Update `TestOIDCCallbackWithFakeSSOServerCreatesSessionAndConsumesInvite`: `newFakeOIDCServer(t, fakeOIDCOptions{Issuer: issuerURL, ClientID: clientID, Sub: "user-123", Email: "USER@Example.COM", EmailVerified: true, Nonce: "nonce-123"})`; cookie `s.makeOAuthFlowCookie("oidc", state, verifier, "nonce-123")`.
- `TestFetchOIDCProfileRejectsNonceMismatch`: subtests `wrong nonce` (token nonce `nonce-123`, call with `other`) and `missing claim` (no nonce in token, call with `nonce-123`) → `errors.Is(err, errOIDCNonceMismatch)`.
- `TestOIDCCallbackRejectsNonceMismatch`: callback with cookie nonce `other` → 502, no `hn_session` cookie, no account created.
- `TestFetchOIDCProfileRejectsUserInfoSubjectMismatch`: ID token unverified email; userinfo `{"sub":"someone-else","email":"user@example.com","email_verified":true}` → `errOIDCUserInfoSubject`. Subtest with userinfo lacking `sub` → same error.
- `TestFetchOIDCProfileTakesEmailAndVerifiedFromUserInfoTogether`: ID token `id@example.com` unverified; userinfo `{"sub":"user-123","email":"info@example.com","email_verified":true}` → `Email == "info@example.com"`, `EmailVerified`.
- `TestFetchOIDCProfileDoesNotMixIDEmailWithUserInfoVerified`: ID token `id@example.com` unverified; userinfo `{"sub":"user-123","email_verified":true}` (no email) → `Email == "id@example.com"`, `!EmailVerified`.
- `TestFetchOIDCProfileRequiresIDTokenSubject`: ID token with `sub` `""`, userinfo `{"sub":"user-123",…}` → error text `missing oidc subject`.
- `TestFetchGoogleProfileRequiresMatchingNonce`: `oidctest.Server` as in `TestFetchOIDCProfileUsesVerifiedIDTokenClaims`; new helper `restoreGoogleIssuerURL(t, ts.URL)` (same shape as `restoreGitHubURLs`); token claims `iss: ts.URL, aud: "client-id", sub, exp, email, email_verified: true, nonce: "nonce-123"`; `fetchGoogleProfile(ctx, &oauthProviderConfig{authProvider: {Key: "google"}, ClientID: "client-id"}, tok, "nonce-123")` succeeds; with `"other"` → `errOIDCNonceMismatch`.
- `TestOAuthStartSendsNonceAndStoresItInFlowCookie`: OIDC settings as in the callback test; request `GET /oauth/oidc/start` with `oidc.ClientContext(ctx, fake.client())` and `SetPathValue("provider","oidc")`; 302; `Location` query has a non-empty `nonce`; the response cookie, re-added to a new request, parses with `parseOAuthFlowCookie(req, "oidc")` to the same nonce; state and `code_challenge` present.
- `TestOAuthStartOmitsNonceForGitHub`: enable GitHub settings; `Location` query has no `nonce`.
- `TestParseOAuthFlowCookie` (table): round trip ok; provider mismatch → !ok; tampered value (flip one char of the signature) → !ok; legacy 3-part payload `makeWebSession(s.secret, base64.RawURLEncoding.EncodeToString([]byte("oidc|s|v")), time.Minute)` → !ok; empty nonce part → !ok.

##### Stop conditions

- go-oidc's `UserInfo` needs an endpoint the fake does not serve, or `oidc.ClientContext` is not honoured by `UserInfo` → stop and report (do not switch libraries).
- A real provider configuration in tests depends on the userinfo `sub` fallback → stop.
- If the "purpose prefix per token type" Info item (other note) changes `makeWebSession`/`parseSignedSubject` in `security.go`, P4 must rebase; it does not edit `security.go` itself.

#### 4. L4: login timing reveals which accounts exist

##### Current state

`loginWithPassword` (`internal/server/web_login.go:62-85`) returns early without bcrypt for: unknown email or empty `PasswordHash` (`:69-71`), disabled (`:72-74`), off-domain (`:75-77`), OAuth required for non-admin (`:78-80`). Only an existing, enabled, in-policy account with a hash pays the bcrypt cost (`:81`). `loginWithToken` (`:87-106`) does a SHA-256 hash lookup; no timing difference worth fixing there. Callers: `handleLogin` (`:45-52`) and tests `TestLoginWithPasswordRejectsDisallowedDomain` / `TestLoginWithTokenRejectsDisallowedDomain` (`auth_domain_test.go:165-208`, both use `_, _, err = …`).

##### Design (in `web_login.go`)

```go
// passwordCompare is bcrypt.CompareHashAndPassword; tests swap it to count calls.
var passwordCompare = bcrypt.CompareHashAndPassword

// dummyPasswordHash is a bcrypt hash of a random-looking constant at
// bcrypt.DefaultCost, made once on first use. Failed logins compare against it
// so they take as long as a real comparison.
var dummyPasswordHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("peek-dummy-password-for-timing"), bcrypt.DefaultCost)
	if err != nil {
		panic("generate dummy password hash: " + err.Error())
	}
	return h
})

// checkPassword runs exactly one bcrypt comparison: against hash when it is set,
// otherwise against dummyPasswordHash (and then always fails).
func checkPassword(hash, password string) bool {
	if hash == "" {
		_ = passwordCompare(dummyPasswordHash(), []byte(password))
		return false
	}
	return passwordCompare([]byte(hash), []byte(password)) == nil
}
```
Decision: lazy `sync.OnceValue` instead of package-init generation, so `peekd` start-up and every test binary do not pay ~50-100 ms of bcrypt; the hash is still generated once per process with `bcrypt.DefaultCost` (same cost as real account hashes, `web_setup.go:62`). Go is 1.26 (`go.mod:3`), `sync.OnceValue` is available.

`loginWithPassword` new order (signature change belongs to L5, see below; here the body): empty email or password → `fmt.Errorf("missing credentials")` (no bcrypt; nothing about accounts is revealed); `owner, err := GetAccountByEmail`; `hash := ""` and `if err == nil { hash = owner.PasswordHash }`; `if !checkPassword(hash, password) { return nil, fmt.Errorf("invalid credentials") }`; then, in the existing order, disabled → `fmt.Errorf("account disabled")`, off-domain → `errAccountNotEligible`, OAuth required and not admin → `fmt.Errorf("oauth required")`. Every path past the empty-field check performs exactly one bcrypt comparison, and policy errors are only reachable with the correct password. The user-facing message stays "Invalid credentials." for all of them (`handleLogin:53-55`).

##### Files touched

P5: `internal/server/web_login.go`; test `internal/server/web_login_test.go`.

##### Tests to add (`internal/server/web_login_test.go`)

- `TestLoginWithPasswordRunsOneBcryptCompareOnEveryFailure`: swap `passwordCompare` with a counting wrapper around `bcrypt.CompareHashAndPassword` (restore in `t.Cleanup`); use `newTestServer(t)` (from `oauth_test.go`) and accounts made with a real `bcrypt.GenerateFromPassword(…, bcrypt.MinCost)` hash. Subtests, each asserting count == 1 and an error: `unknown email`; `account without password` (`CreateAccount`); `wrong password`; `disabled account, right password` (expects `account disabled`); `off-domain, right password` (expects `errors.Is(err, errAccountNotEligible)`); `oauth required non-admin, right password` (GitHub OAuth settings enabled; expects `oauth required`). One more subtest `missing password` asserts count == 0.
- `TestDummyPasswordHashIsDefaultCost`: `bcrypt.Cost(dummyPasswordHash()) == bcrypt.DefaultCost`.

##### Stop conditions

- S2 (other note) adds a per-account login limiter in `web_login.go`; if it lands first, keep its check before `checkPassword` and rebase; do not share the phase.

#### 5. L5: sessions cannot be revoked server-side

##### Current state

- Session cookie `hn_session` (`web_helpers.go:8`): `setWebSession(w, accountID)` (`oauth_session.go:45-54`) signs subject `strconv.FormatInt(accountID, 10)` with `makeWebSession(s.secret, …, sessionTTL)` (7 days). `parseSignedSubject` (`security.go`, `signToken` format `subject.exp.sig`, split on `.`) so a subject must not contain `.`; `:` is safe.
- `webAuth` (`web_auth.go:13-29`) parses the subject with `strconv.ParseInt`.
- `setWebSession` callers: `web_login.go:57` (after `loginWithPassword`/`loginWithToken`, which return `(int64, string, error)`), `oauth_flow.go:91` (`account` is `*models.Account` from `resolveOAuthAccount`), `web_setup.go:73` (`account` from `CreateAccountWithPassword`).
- Logout (`web_login.go:139-157`) only clears the cookie.
- There is **no password-change feature** (`grep password_hash=` finds only uploads), so "increment on password change" has no hook today; a future change-password handler must call `BumpSessionEpoch`.
- Disable: `handleDashboardUserDisabled` (`admin.go:125-150`) → `SetAccountDisabledChecked` (`internal/db/accounts.go:136-166`); also `SetAccountDisabled` (`:128-134`, tests only). `webAuth` already rejects disabled accounts, but re-enabling revives every old cookie.
- Accounts are read through `getAccountWhere` (`accounts.go:47-62`) and `ListAccounts` (`:64-86`), both with explicit column lists.
- About 20 test sites build `makeWebSession(s.secret, strconv.FormatInt(id, 10), sessionTTL)` directly, plus `asSession` (`handler_helpers_test.go:64-68`) and `TestHandlerHarnessAuthHelpers` asserts `sub == strconv.FormatInt(owner.ID, 10)` (`:118-121`).

##### Design

**Storage (P1).**
- `schema.go` `accounts`: after `disabled INTEGER NOT NULL DEFAULT 0,` add `session_epoch INTEGER NOT NULL DEFAULT 0,`.
- `migrations.go`: append `{12, "account_session_epoch", `-- ALTER TABLE handled idempotently below`},`; branch `} else if m.id == 12 {` → `s.migrateAccountSessionEpoch()`, placed after the `m.id == 11` branch and before `m.sql != ""`.

```go
// migrateAccountSessionEpoch adds the counter that signs an account out of
// every dashboard session when it changes. Existing accounts start at 0, which
// keeps their current sessions valid.
func (s *Store) migrateAccountSessionEpoch() error {
	_, err := s.Exec(`ALTER TABLE accounts ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0`)
	if err != nil && !isDuplicateColumnError(err) {
		return err
	}
	return nil
}
```
- `models.Account` gains `SessionEpoch int64 // bumped to end every dashboard session of the account` (after `Disabled`).
- `accounts.go`: both SELECTs read `…,disabled,session_epoch,created_at,updated_at` and scan into `&a.SessionEpoch`.

```go
// BumpSessionEpoch ends every dashboard session of account id and returns the
// new epoch. sql.ErrNoRows when the account does not exist.
func (s *Store) BumpSessionEpoch(ctx context.Context, id int64) (int64, error)
// tx: UPDATE accounts SET session_epoch=session_epoch+1, updated_at=? WHERE id=?; requireRowsAffected;
//     SELECT session_epoch FROM accounts WHERE id=?; commit.
```
- `SetAccountDisabled` and `SetAccountDisabledChecked`: UPDATE becomes `UPDATE accounts SET disabled=?, session_epoch=session_epoch+?, updated_at=? WHERE id=?` with args `boolToInt(disabled), boolToInt(disabled), now, id`. Disabling bumps the epoch; enabling does not.

**Cookie subject (P5, `oauth_session.go`).**

```go
// sessionSubject is the signed subject of a dashboard session cookie.
func sessionSubject(accountID, epoch int64) string {
	return strconv.FormatInt(accountID, 10) + ":" + strconv.FormatInt(epoch, 10)
}

// parseSessionSubject accepts "<id>:<epoch>" and the older "<id>", which
// counts as epoch 0 so sessions from before migration 12 stay valid until the
// account's epoch first changes. id must be > 0 and epoch >= 0.
func parseSessionSubject(sub string) (accountID, epoch int64, ok bool)

func (s *Server) setWebSession(w http.ResponseWriter, account *models.Account)
// Value: makeWebSession(s.secret, sessionSubject(account.ID, account.SessionEpoch), sessionTTL); other cookie fields unchanged.
```
`webAuth`: `id, epoch, ok := parseSessionSubject(sub)`; after `GetAccountByID`, `if a.SessionEpoch != epoch { return nil, false }`; then the `accountActive` check from P2.

Callers:
- `oauth_flow.go:91` → `s.setWebSession(w, account)`.
- `web_setup.go:73` → `s.setWebSession(w, account)`.
- `web_login.go`: `loginWithPassword(r) (*models.Account, error)` returns `owner`; `loginWithToken(r) (*models.Account, error)` keeps its checks, then `account, err := s.store.GetAccountByID(r.Context(), owner.AccountID)` and returns it. `handleLogin` holds `var account *models.Account`, then `s.setWebSession(w, account)` and `s.auditRequest(r, account.Name, "login.success", "")`.
- Logout unchanged (one browser only).

**Sign out other sessions (P5).** Decision: the button keeps the current browser signed in (it gets a fresh cookie with the new epoch) and ends all others, so it can report a flash on the dashboard. Its text is therefore "Sign out other sessions" rather than "Sign out everywhere"; the existing "Sign out" ends this browser.

New file `internal/server/web_sessions.go`:

```go
// handleDashboardSessionsRevoke ends every other dashboard session of the
// signed-in account: it bumps the account's session epoch, which invalidates
// all earlier session cookies, and gives this browser a new cookie.
func (s *Server) handleDashboardSessionsRevoke(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseDashboardForm(w, r) {
		return
	}
	epoch, err := s.store.BumpSessionEpoch(r.Context(), owner.ID)
	if err != nil {
		slog.Error("session revoke failed", "account_id", owner.ID, "err", err)
		dashboardError(w, r, "sign out failed")
		return
	}
	owner.SessionEpoch = epoch
	s.setWebSession(w, owner)
	s.auditRequest(r, owner.Name, "session.revoke_others", "")
	dashboardOK(w, r, "other sessions signed out")
}
```
Route (`routes.go`, after the api-keys routes): `mux.HandleFunc("POST /dashboard/sessions/revoke", s.handleDashboardSessionsRevoke)`. Redirects: `/dashboard?ok=other+sessions+signed+out` and `/dashboard?err=sign+out+failed`.

Template (`internal/web/templates/dashboard.gohtml`, header `<nav>`, immediately before the existing `<form method="POST" action="/logout" …>`):

```html
<form method="POST" action="/dashboard/sessions/revoke" data-confirm="Sign out of Peek in every other browser? This browser stays signed in and API keys keep working." x-on:submit="confirm($event, $el.dataset.confirm)" class="m-0">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <button type="submit" class="rounded-lg border border-input px-3.5 py-1.5 text-sm text-muted-foreground transition hover:border-border hover:text-secondary-foreground hover:bg-secondary">Sign out other sessions</button>
</form>
```
(Same classes as the Sign out button, so `pines.css` does not change; `confirm` comes from `dashboard-alpine.js` and the header is inside the `<body x-data="dashboard(…)">`.)

##### Files touched

- P1: `internal/db/schema.go`, `internal/db/migrations.go`, `internal/db/accounts.go`, `internal/models/models.go`; tests `internal/db/accounts_test.go` (new).
- P5: `internal/server/oauth_session.go`, `internal/server/web_auth.go`, `internal/server/web_login.go`, `internal/server/oauth_flow.go` (one line), `internal/server/web_setup.go` (one line), `internal/server/routes.go` (one line), `internal/server/web_sessions.go` (new), `internal/web/templates/dashboard.gohtml`; tests `internal/server/web_sessions_test.go` (new), `internal/server/web_login_test.go`, `internal/server/auth_domain_test.go` (two call sites `_, _, err = s.loginWith…` → `_, err = …`).

##### Tests to add

`internal/db/accounts_test.go` (new, use `openTokenTestStore`):
- `TestBumpSessionEpoch`: new account epoch 0; bump → 1, bump → 2; `GetAccountByID` and `ListAccounts` show 2; unknown id → `errors.Is(err, sql.ErrNoRows)`.
- `TestSetAccountDisabledBumpsSessionEpoch`: `SetAccountDisabledChecked(true)` → 1; `(false)` → still 1; `SetAccountDisabled(true)` → 2.
- `TestMigrationAddsCLILoginContextAndSessionEpoch` (covers migrations 11 and 12, pattern of `TestMigrationAddsTokenHintLastUsed`, `tokens_test.go:218`): open, create an account and a CLI device (old `CreateCLILoginDevice`), run `ALTER TABLE accounts DROP COLUMN session_epoch`, `ALTER TABLE cli_login_devices DROP COLUMN request_ip`, `ALTER TABLE cli_login_devices DROP COLUMN request_user_agent`, `DELETE FROM schema_migrations WHERE id IN (11,12)`; close; reopen; `columnInfo` finds all three columns; the account's `SessionEpoch == 0`; the device's `RequestIP == ""`; `isMigrationApplied(11)` and `(12)` are true.

`internal/server/web_sessions_test.go` (new):
- `TestParseSessionSubject` (table): `"42"`→(42,0,true); `"42:3"`→(42,3,true); `"42:"`, `":3"`, `"a:1"`, `"42:-1"`, `"42:1:2"`, `"0:1"`, `""` → false. Round trip with `sessionSubject`.
- `TestWebAuthRejectsStaleSessionEpoch`: `newHandlerTestServer`; account via `s.store.CreateAccount(ctx, "u@example.test", "U", false)`; `BumpSessionEpoch` → 1; request with legacy cookie (`asSession`) → `webAuth` false; cookie `makeWebSession(s.secret, sessionSubject(id, 0), sessionTTL)` → false; `sessionSubject(id, 1)` → true.
- `TestSetWebSessionIncludesEpoch`: account with epoch 2; `s.setWebSession(rec, account)`; parsed subject of the `hn_session` cookie equals `sessionSubject(id, 2)`.
- `TestDashboardSessionsRevokeSignsOutOtherSessions`: `rec := dashboardPost(t, s, id, "/dashboard/sessions/revoke", url.Values{}, true)`; `assertDashboardRedirect(t, rec, "/dashboard?ok=other+sessions+signed+out")`; response `hn_session` subject is `sessionSubject(id, 1)`; `GET /dashboard` with `asSession(s, id)` (old cookie) → 303 `/login`; with the new cookie → 200; `s.store.ListAuditLog(ctx, 10)` contains an entry with `Action == "session.revoke_others"`.
- `TestDashboardSessionsRevokeRequiresCSRF`: `withCSRF=false` → `assertDashboardRedirect(t, rec, "/dashboard?err=invalid+session")`; epoch still 0.
- `TestDashboardSessionsRevokeRequiresSession`: no cookie → 303 `/login`.
- `TestReEnabledAccountDoesNotReviveSessions`: `SetAccountDisabledChecked(true)`, then `(false)`; legacy cookie → `webAuth` false.
- `TestDashboardShowsSignOutOtherSessions`: `GET /dashboard` with a session → body contains `action="/dashboard/sessions/revoke"` and `Sign out other sessions`.
- `TestLoginSetsEpochSessionCookie` (in `web_login_test.go`): password login through `handleLogin` for an account whose epoch was bumped to 1 → cookie subject `sessionSubject(id, 1)`.

Existing tests stay valid: `asSession` and the ~20 direct `makeWebSession(…, strconv.FormatInt(id, 10), …)` sites produce the legacy subject, accepted while the epoch is 0; `TestHandlerHarnessAuthHelpers` still sees `sub == "<id>"`.

##### Stop conditions

- An existing test bumps the epoch indirectly (disables then re-enables an account) and then expects its old cookie to work → fix the test to build a cookie with `sessionSubject(id, epoch)`; if the test is about session lifetime, stop and report.
- L9 (other note) replaces free-text `?ok=`/`?err=` flashes with fixed codes: if it lands first, register `other sessions signed out` and `sign out failed` as codes in its table instead of free text.
- The "purpose prefix per token type" Info item changes the session cookie format in `security.go`: rebase; keep `parseSessionSubject` operating on the subject after the prefix is removed.

#### 6. Docs (P6)

`docs/operations.md`:
- "First Run And Access" (after the sentence ending "…Dashboard → API keys**."): add "API tokens follow the same account rules as dashboard sign-in: a token is refused with 403 when its account is disabled, when its email does not match the allowed email domain, or, while OAuth login is enabled, when a non-admin account has no linked OAuth identity. Tokens from `peek token create` / `POST /api/tokens` belong to accounts without an email, so they stop working once an allowed email domain is set, and non-admin ones also stop while OAuth is enabled; under SSO, create CI and agent keys from the dashboard of an account that signs in with SSO. Tokens from `peek login` expire 90 days after approval; dashboard keys and admin tokens do not expire unless created with `expires_hours`."
- "Upgrades And Rollbacks", after the migration 10 paragraph: "Migration 11 (`cli_login_request_context`) adds `request_ip` and `request_user_agent` to `cli_login_devices`, shown on the CLI login approval page. Migration 12 (`account_session_epoch`) adds `session_epoch` to `accounts`; dashboard sessions from before the upgrade stay valid until the account uses **Sign out other sessions** or is disabled. Sessions created by the new binary are not accepted by older binaries, so after a rollback everyone signs in again. This release also applies the allowed email domain and OAuth-required rules to API tokens (see First Run And Access); check which automation tokens that affects before upgrading."
- "Recommended Topology" or "Startup Configuration": no change.

`docs/src/content/docs/auth-access.md`:
- "Allowed Email Domain" (line 60): replace "It does not block direct API bearer tokens, so existing automation tokens keep working." with "It also applies to API bearer tokens: a token whose account email is outside the domain is refused with 403. Tokens created with `peek token create` have no email and are refused too once a domain is set."
- After line 78 ("When OAuth is enabled, non-admin password and token web login are disabled…") add: "The same rule applies to API tokens: while OAuth is enabled, a non-admin account's token works only if the account has signed in with OAuth at least once."
- "CLI Login" first paragraph becomes: "`peek login` starts a browser approval flow when the server supports it. The CLI prints a code such as `ABCD-EFGH` and opens `<host>/cli-login`. Sign in, type the code from your own terminal, check the request details (the IP address and client that started the login, and when), and approve. Peek then issues an API token to the CLI that expires after 90 days; run `peek login` again after that. Never type a code that someone else sent you: approving gives whoever ran `peek login` a token that acts as you. Old links of the form `/cli-login/<code>` open the empty code form. Code entry is limited to 10 attempts per minute per client IP."
- New section after "Invites And Users": "## Sessions" — "Dashboard sessions last 7 days. **Sign out other sessions** in the dashboard header ends every other browser session of your account and keeps this one. Disabling an account ends all of its sessions, and enabling it again does not bring them back. **Sign out** ends only the current browser's session. API keys are not affected; revoke them under **Dashboard → API keys**."

`docs/src/content/docs/using-peek.md:114`: append "Keys from `peek login` expire 90 days after approval."

`README.md` security table (`:181`): replace the "Long-lived tokens" row with `| Long-lived tokens | \`peek login\` tokens expire after 90 days; admin tokens can include an expiry; expired tokens are rejected. |`; add after the "Token leaking via terminal" row `| Phished CLI login | The approval link carries no code: the user types it from their own terminal and sees the requesting IP, client and time before approving. |` and `| Offboarding | API tokens follow the allowed email domain and OAuth-required rules; disabling an account or **Sign out other sessions** ends dashboard sessions server-side. |`. Change the "Session-cookie theft" row text "signed, revocable reference" → "signed reference that the server can revoke per account".

`skills/peek/SKILL.md` near line 48: add one sentence "The browser asks for the code that `peek login` prints; type it yourself, never use a code someone sent you."

Stop: if `pages.yml` (Astro docs build, dispatchable CI) fails on the new heading, report.

#### 7. Phases

Rules: each phase ≤8 source files and ≤~400 changed lines; no file is edited by two phases that can run at the same time.

| Phase | Findings | Source files | Test files | Depends on | Est. lines |
| --- | --- | --- | --- | --- | --- |
| P1 storage | S3, S4, L5 storage | `internal/db/schema.go`, `internal/db/migrations.go`, `internal/db/cli_login.go`, `internal/db/accounts.go`, `internal/db/tokens.go`, `internal/models/models.go` | `internal/db/cli_login_test.go` (new), `internal/db/accounts_test.go` (new), `internal/db/tokens_test.go` | — | ~280 |
| P2 token policy | S4 | `internal/server/account_policy.go` (new), `internal/server/web_auth.go`, `internal/server/middleware.go`, `internal/server/comments.go` | `internal/server/account_policy_test.go` (new), `internal/server/auth_domain_test.go` | user confirmation (section 0) | ~260 |
| P3b CLI | S3 (CLI side) | `internal/cli/login_oauth.go` | `internal/cli/login_oauth_test.go` | — | ~90 |
| P4 OIDC | L2, L3 | `internal/server/oauth_flow.go`, `internal/server/oauth_profile.go`, `internal/server/oauth_session.go` | `internal/server/oauth_test.go` | — | ~380 |
| P3a CLI login pages | S3 (server), S4 (90-day TTL, poll policy) | `internal/server/cli_login.go`, `internal/server/routes.go`, `internal/web/templates/cli_login.gohtml`, `internal/web/renderer.go` | `internal/server/cli_login_test.go` (new), `internal/web/renderer_test.go` | P1, P2 | ~400 |
| P5 login timing + sessions | L4, L5 (server) | `internal/server/web_login.go`, `internal/server/oauth_session.go`, `internal/server/oauth_flow.go`, `internal/server/web_setup.go`, `internal/server/web_auth.go`, `internal/server/routes.go`, `internal/server/web_sessions.go` (new), `internal/web/templates/dashboard.gohtml` | `internal/server/web_sessions_test.go` (new), `internal/server/web_login_test.go`, `internal/server/auth_domain_test.go` | P1, P2, P3a, P4 | ~380 |
| P6 docs | all six | `docs/operations.md`, `docs/src/content/docs/auth-access.md`, `docs/src/content/docs/using-peek.md`, `README.md`, `skills/peek/SKILL.md` | — | P1–P5 | ~60 |

Waves: **wave 1** P1, P2, P3b, P4 in parallel (disjoint files); **wave 2** P3a; **wave 3** P5; **wave 4** P6. Each phase runs `mise run check`; P1, P2, P3a, P4 and P5 also run `mise run check-full` (they touch `internal/server` / `internal/db`, per `.claude/toolkit.yaml` `dod_conditional`). P3a and P5 also run the manual smoke test (`mise run run`, then `./bin/peek login --host http://localhost:7700`, type the code in the browser, check the approval page details, approve, `./bin/peek list`; then **Sign out other sessions** in a second browser profile).

Acceptance greps (in addition to the tests):
- P1: `grep -n '{11, "cli_login_request_context"' internal/db/migrations.go` and `grep -n '{12, "account_session_epoch"' internal/db/migrations.go` each match once; `grep -c 'session_epoch' internal/db/schema.go` = 1.
- P2: `grep -n 'TestDirectAPITokenAuthIgnoresAllowedEmailDomain' -r internal` matches nothing; `grep -n 'accountActive' internal/server/middleware.go internal/server/comments.go internal/server/web_auth.go` matches in all three.
- P3a: `grep -n '"/cli-login/" + userCode' internal/server/cli_login.go` matches nothing; `grep -n 'cliTokenTTL = 90 \* 24 \* time.Hour' internal/server/cli_login.go` matches once.
- P4: `grep -n 'oidc.Nonce(' internal/server/oauth_flow.go` matches once.
- P5: `grep -n 'dummyPasswordHash' internal/server/web_login.go` matches; `grep -n 'POST /dashboard/sessions/revoke' internal/server/routes.go` matches once.

##### Overlap with other design notes (orchestrator to sequence)

- `internal/server/middleware.go`: L1 body limit in `withMiddleware` (P2 edits only `authToken`/`authAdmin`).
- `internal/server/web_login.go`: S2 per-account login limiter (P5).
- `internal/server/analytics.go` `clientIP` (S2): used by P3a; no edit here.
- `internal/server/comments.go`: L8 comment author (P2 edits only the bearer branch of `handleListComments`).
- `internal/cli/login_oauth.go`: S6 `verification_url` validation (P3b). S6 must allow the new `<host>/cli-login` URL (same origin as the host, so its planned rule already does).
- `internal/server/routes.go`: any other note adding routes (P3a, P5).
- `internal/web/templates/dashboard.gohtml` and dashboard flashes: L9 (P5).
- `internal/server/security.go` session/flow token format: Info "purpose prefix" item (P4, P5 read it).
- `internal/db/migrations.go` / `schema.go`: any other migration must be 13+ and run after P1.
- `docs/operations.md`, `auth-access.md`, `README.md`: other notes' doc phases.


### Design C — supply chain, file modes, metrics, S3 guard, CLI host checks and paths, secrets (S5, S6, S7, L10–L14)


Repo: `/home/user/peek` (module `github.com/andras-tkcs/peek`, remote `andras-tkcs/peek`, branch `plan/security-hardening-coverage` at `6380c6b`). Source: `docs/audits/2026-10-security-and-coverage-audit.md`.

User decisions that are already made: every `puemos/peek` reference goes to `andras-tkcs/peek`. `install.sh` must verify a `checksums.txt` that the release workflow publishes.

Facts checked on 2026-10-11 through the proxy:
- The Tailwind `sha256sums.txt` for v4.3.1 can be downloaded. The hashes are copied below.
- `git ls-remote` reaches GitHub. Every action SHA below was resolved live; for annotated tags the peeled `^{}` commit is used.
- `honnef.co/go/tools v0.8.1` is staticcheck **2026.2.1**: `lintcmd/version/version.go` has `Version = "2026.2.1"` and `MachineVersion = "0.8.1"`, and the tag `2026.2.1` is at commit `1285a6a5…`.
- `golang.org/x/vuln v1.9.0` exists. It was tagged on 2026-10-11T03:39Z, so it is brand new. If it fails in CI, use `v1.8.0`.
- SQLite file modes were tested with the repo's modernc sqlite v1.52.0 and Go 1.26.9, umask 022:
  - If `peek.db` is pre-created at 0600 and then opened in WAL mode, `-wal` and `-shm` are also created at 0600 (SQLite copies the main database file's mode).
  - Without pre-creating, the database and `-wal` are 0644.
  - `VACUUM INTO` a pre-created **empty** 0600 file works and keeps 0600. Without pre-creating, the backup is 0644.
- `andras-tkcs/peek` is public (the API returns 200) and has tags up to `v0.8.1`. Those older releases have no `checksums.txt`, so the new `install.sh` can only install releases made after this change.

General rules for every phase:
- Go tests that assert POSIX modes start with `if runtime.GOOS == "windows" { t.Skip("POSIX file modes") }`.
- Mode assertions use `info.Mode().Perm()`.
- Run `mise run check` after each phase. Run `mise run check-full` after P2, P3 and P5 (they touch storage, database, server and auth).

---

#### Phase plan (file lists do not overlap)

| Phase | Findings | Source files (≤8) | Test files | Depends on |
|---|---|---|---|---|
| P1 Supply chain & CI | S5 (code/CI), L14 | `install.sh`, `mise.toml`, `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `.github/workflows/docker-main.yml`, `.github/workflows/pages.yml`, `docs/astro.config.mjs`, `docs/src/components/SiteChrome.astro` | none (shell/YAML checks only) | none |
| P2 Storage & DB hardening | S7 (db, objectstore, backup), L11 (objectstore) | `internal/db/store.go`, `internal/objectstore/file.go`, `internal/objectstore/s3_endpoint.go`, `internal/objectstore/s3.go`, `internal/peekd/backup.go` | `internal/db/store_test.go`, `internal/objectstore/storage_test.go`, **new** `internal/peekd/backup_test.go` | none |
| P3 Server runtime | S7 (server dirs, secret.key), L10, L11 (settings + startup), L13 (peekd `_FILE`) | `internal/server/server.go`, `internal/server/bootstrap.go`, `internal/server/metrics.go`, `internal/server/health.go`, `internal/server/settings.go`, `internal/peekd/run.go`, `internal/peekd/env.go` | **new** `internal/server/metrics_test.go`, **new** `internal/server/file_modes_test.go`, `internal/server/bootstrap_test.go`, `internal/server/settings_test.go`, `internal/peekd/run_test.go` | P2 (uses `objectstore.ValidateS3Bucket`) |
| P4 CLI login/host | S6, L13 (SaveConfig, config set host change, plain-http warning) | `internal/cli/login_oauth.go`, `internal/cli/browser.go`, `internal/cli/login_command.go`, `internal/cli/config_command.go`, `internal/cli/client.go`, **new** `internal/cli/hostcheck.go` | `internal/cli/login_oauth_test.go`, **new** `internal/cli/hostcheck_test.go`, `internal/cli/test_helpers_test.go`, `internal/cli/client_test.go`, **new** `internal/cli/config_command_test.go` | none (but see the S3 conflict in its stop conditions) |
| P5 CLI path segments | L12, L13 (`--password` warning) | **new** `internal/cli/path_segments.go`, `internal/cli/uploads_command.go`, `internal/cli/stats_comments_command.go`, `internal/cli/gdpr_command.go`, `internal/cli/grants_command.go`, `internal/cli/token_command.go`, `internal/cli/upload_command.go` | **new** `internal/cli/path_segments_test.go`, `internal/cli/uploads_command_requests_test.go`, `internal/cli/upload_command_test.go` | P4 (uses `captureStderr` added to `test_helpers_test.go`) |
| P6 Docs | docs for every finding above | `README.md`, `skills/peek/SKILL.md`, `skills/peek-server/SKILL.md`, `docs/operations.md`, `docs/src/content/docs/server-setup.md`, `docs/src/content/docs/reference.md`, `docs/src/content/docs/deployment-platforms.md` | none | P1–P5 (it documents their behaviour) |

Docs are collected in P6 because `README.md` and `skills/peek-server/SKILL.md` need changes from S5 (repo references) and also from L10/L13 (new env vars). Giving them to one phase keeps the file lists from overlapping.

`LICENSE:3` (`Copyright (c) 2026 puemos`) is **not** changed. The MIT notice must be kept for the upstream author. `docker-compose.yml` has no `puemos` reference: it uses `build: .` and `image: peek:local`, so it needs no change.

---

#### S5: supply chain (repo references, release checksums, install.sh verification, Tailwind pin)

##### Current state: every `puemos` occurrence (`grep -rn puemos --exclude-dir=.git --exclude-dir=node_modules .`)

| path:line | text | Change | Phase |
|---|---|---|---|
| `install.sh:4` | `#   curl -fsSL https://raw.githubusercontent.com/puemos/peek/main/install.sh \| sh` | `puemos` → `andras-tkcs` | P1 |
| `install.sh:14` | `REPO="puemos/peek"` | `REPO="andras-tkcs/peek"` | P1 |
| `docs/astro.config.mjs:4` | `site: 'https://puemos.github.io',` | `site: 'https://andras-tkcs.github.io',` (keep `base: '/peek/'`) | P1 |
| `docs/src/components/SiteChrome.astro:12` | `const githubUrl = 'https://github.com/puemos/peek';` | `andras-tkcs` | P1 |
| `README.md:5` | CI badge, CI link, Release shield, releases link (4× `puemos/peek`) | all → `andras-tkcs/peek` | P6 |
| `README.md:52` | `[releases page](https://github.com/puemos/peek/releases)` | `andras-tkcs` | P6 |
| `README.md:56` | `curl -fsSL https://raw.githubusercontent.com/puemos/peek/main/install.sh \| sh` | `andras-tkcs` | P6 |
| `README.md:71` | `ghcr.io/puemos/peek:latest` | `ghcr.io/andras-tkcs/peek:latest` (+ pin note, see Docs) | P6 |
| `README.md:237` | `npx skills add puemos/peek@peek -g -y` | `npx skills add andras-tkcs/peek@peek -g -y` | P6 |
| `skills/peek/SKILL.md:30` | install.sh curl | `andras-tkcs` | P6 |
| `skills/peek-server/SKILL.md:28` | `curl -sSL https://github.com/puemos/peek/releases/latest/download/peek_<version>_linux_amd64.tar.gz \| tar xz` | replace the block with the verified download below | P6 |
| `skills/peek-server/SKILL.md:35` | `git clone https://github.com/puemos/peek && cd peek` | `andras-tkcs` | P6 |
| `skills/peek-server/SKILL.md:56` | `ghcr.io/puemos/peek:latest` | `ghcr.io/andras-tkcs/peek:latest` | P6 |
| `docs/src/content/docs/server-setup.md:12` | install.sh curl | `andras-tkcs` | P6 |
| `docs/src/content/docs/server-setup.md:83` | `ghcr.io/puemos/peek:latest` | `ghcr.io/andras-tkcs/peek:latest` | P6 |
| `LICENSE:3` | copyright line | **no change** (see above) | none |

The workflows already use `ghcr.io/${{ github.repository }}` (`release.yml:100`, `docker-main.yml:37`), so images are published at `ghcr.io/andras-tkcs/peek`.

`.github/workflows/release.yml` (126 lines, read in full) uses no goreleaser. The current flow:
- A matrix `build` job (5 targets: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, `max-parallel: 1`) runs `go build` twice, then `tar -czf peek_${VERSION}_${GOOS}_${GOARCH}.tar.gz`, or `zip` on Windows.
- Each matrix leg uploads one archive with `softprops/action-gh-release@v2` (`generate_release_notes: true`).
- The `sbom` job uploads `peek-sbom.spdx.json`.
- The `docker` job pushes a multi-arch image.
- Top-level `permissions: contents: write, packages: write` (lines 7–9).

`install.sh:63-65` downloads and extracts with no verification:
```sh
echo "Downloading $name ..."
download "$url" "$tmp/peek.tar.gz" || err "download failed: $url"
tar -xzf "$tmp/peek.tar.gz" -C "$tmp" || err "extract failed"
```
`install.sh:48` takes `version="${PEEK_VERSION:-}"` from the environment unchecked and puts it into the URL.

`mise.toml:19-32` (tailwind task) has these problems:
- It downloads with `curl -sL` (no `-f`) and has no hash.
- It maps arch with `if [ "$ARCH" = "arm64" ]; then ARCH="arm64"; else ARCH="x64"; fi`. **Linux arm64 reports `aarch64`, so it is mapped to x64 by mistake.**
- It only checks `[ ! -x "$TW" ]`, so an existing unverified binary is reused forever.

##### Design

**1. `release.yml`: new job `checksums`.** Insert it after the `build` job, before `sbom`. It uses `gh`, which is preinstalled on `ubuntu-latest`, so no new action is needed. There is no `${{ }}` inside `run:`.
```yaml
  checksums:
    name: checksums
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: Publish checksums.txt
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          mkdir dist
          cd dist
          gh release download "$GITHUB_REF_NAME" --pattern 'peek_*.tar.gz' --pattern 'peek_*.zip'
          # Must equal the number of build matrix entries above.
          expected=5
          count=$(find . -maxdepth 1 -type f -name 'peek_*' | wc -l)
          if [ "$count" -ne "$expected" ]; then
            echo "expected $expected release archives, found $count" >&2
            ls -l >&2
            exit 1
          fi
          sha256sum peek_* > checksums.txt
          cat checksums.txt
          gh release upload "$GITHUB_REF_NAME" checksums.txt --clobber
```
The output is standard `sha256sum` format: `<64 hex>  peek_vX.Y.Z_linux_amd64.tar.gz`, one line per archive, with two spaces between hash and name. The SBOM (`peek-sbom.spdx.json`) does not match `peek_*` and is not included.

No provenance attestation is added. That would need `id-token: write` and `attestations: write`, and the user only asked for checksums. List it as a follow-up in the PR body.

**2. `install.sh` changes** (complete replacements; everything else stays the same):

a) Line 14: `REPO="andras-tkcs/peek"`. Line 4: comment URL `andras-tkcs`.

b) Add a version sanity check right after the `version` is resolved (after line 54):
```sh
case "$version" in
  v[0-9]*) ;;
  *) err "invalid version '$version' (expected a release tag like v1.2.3)" ;;
esac
case "$version" in
  *[!A-Za-z0-9._-]*) err "invalid version '$version'" ;;
esac
```

c) Replace lines 59–65 (the `# --- download & extract` block, up to and including `tar -xzf`) with:
```sh
# --- download, verify & extract ------------------------------------------------
sums_url="https://github.com/$REPO/releases/download/${version}/checksums.txt"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t peek)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $name ..."
download "$url" "$tmp/${name}.tar.gz" || err "download failed: $url"
download "$sums_url" "$tmp/checksums.txt" \
  || err "download failed: $sums_url (releases published before checksums.txt existed cannot be verified; pick a newer PEEK_VERSION)"

awk -v f="${name}.tar.gz" '$2 == f || $2 == "*" f' "$tmp/checksums.txt" > "$tmp/expected.sha256"
[ "$(wc -l < "$tmp/expected.sha256" | tr -d ' ')" = "1" ] \
  || err "checksums.txt has no single entry for ${name}.tar.gz"

if have sha256sum; then
  (cd "$tmp" && sha256sum -c expected.sha256 >/dev/null 2>&1) \
    || err "checksum mismatch for ${name}.tar.gz; refusing to install"
elif have shasum; then
  (cd "$tmp" && shasum -a 256 -c expected.sha256 >/dev/null 2>&1) \
    || err "checksum mismatch for ${name}.tar.gz; refusing to install"
else
  err "need sha256sum or shasum to verify the download"
fi
echo "Verified SHA-256 checksum."

tar -xzf "$tmp/${name}.tar.gz" -C "$tmp" || err "extract failed"
```
The rest stays the same (`src="$tmp/$name/$BIN"` and so on). Do not add a skip-verification escape hatch.

**3. `mise.toml` tailwind task:** replace the whole `run = """ … """` of `[tasks.tailwind]` with:
```toml
run = """
set -eu
TW_VERSION=v4.3.1
case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=macos ;;
  *) echo "tailwind: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=x64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "tailwind: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
# SHA-256 from https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.1/sha256sums.txt
case "$OS-$ARCH" in
  linux-x64)   TW_SHA256=2526d063ba03b71f9a3ea7d5cee14f0aec147f117f222d5adc97b1d736d45999 ;;
  linux-arm64) TW_SHA256=3d662377a86d71c43b549dc06b90db4586b4acd412bf827a3268e951661e5adf ;;
  macos-x64)   TW_SHA256=e9e830ceb3e70b7e0775a3dd79eee8ec82c6b31270f08f2fa2857d0077045ac3 ;;
  macos-arm64) TW_SHA256=a27c43626185953ee19bdace1939c7601e55da654e0b2fc4461e3e29957aa739 ;;
esac
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
TW=bin/tailwindcss
if [ ! -x "$TW" ] || [ "$(sha256_of "$TW")" != "$TW_SHA256" ]; then
  echo "Downloading Tailwind CSS standalone CLI ${TW_VERSION}..."
  mkdir -p bin
  curl -fsSL -o "$TW.tmp" "https://github.com/tailwindlabs/tailwindcss/releases/download/${TW_VERSION}/tailwindcss-${OS}-${ARCH}"
  GOT=$(sha256_of "$TW.tmp")
  if [ "$GOT" != "$TW_SHA256" ]; then
    rm -f "$TW.tmp"
    echo "tailwind: checksum mismatch (expected $TW_SHA256, got $GOT)" >&2
    exit 1
  fi
  chmod +x "$TW.tmp"
  mv "$TW.tmp" "$TW"
fi
"$TW" -i internal/web/tailwind-input.css -o internal/web/assets/pines.css --minify
"""
```
Upstream `sha256sums.txt` for v4.3.1 (full, for the record; musl and windows are not used):
```
3d662377a86d71c43b549dc06b90db4586b4acd412bf827a3268e951661e5adf  ./tailwindcss-linux-arm64
7ed72712429166d869dc8472e0cd8c61cd46e565a5bc1ba8810612bedfe61e7b  ./tailwindcss-linux-arm64-musl
2526d063ba03b71f9a3ea7d5cee14f0aec147f117f222d5adc97b1d736d45999  ./tailwindcss-linux-x64
daeabe94235912b3773273053d5c8a16325af3fa513aa03b7295d6f445093cf2  ./tailwindcss-linux-x64-musl
a27c43626185953ee19bdace1939c7601e55da654e0b2fc4461e3e29957aa739  ./tailwindcss-macos-arm64
e9e830ceb3e70b7e0775a3dd79eee8ec82c6b31270f08f2fa2857d0077045ac3  ./tailwindcss-macos-x64
dc4fd46acd354d976df2a31b6425fbe865a38229a06bc005a4c59f2b3d24ab4a  ./tailwindcss-windows-x64.exe
```
The worker should re-download `sha256sums.txt` and `diff` it against these four values before committing. Any difference is a stop condition.

##### Files touched
- P1: `install.sh`, `mise.toml`, `.github/workflows/release.yml`, `docs/astro.config.mjs`, `docs/src/components/SiteChrome.astro`.
- P6: `README.md`, `skills/peek/SKILL.md`, `skills/peek-server/SKILL.md`, `docs/src/content/docs/server-setup.md`.

##### Tests / verification (P1, no Go tests)
- `sh -n install.sh`. Also run `shellcheck install.sh` if `shellcheck` is installed; skip it otherwise.
- `grep -rn puemos --exclude-dir=.git --exclude-dir=node_modules .` after P1 must list only P6 files and `LICENSE`. After P6 it must list only `LICENSE:3`.
- Delete `bin/tailwindcss`, run `mise run tailwind`: it must download and pass. Put a garbage `bin/tailwindcss` (`printf x > bin/tailwindcss; chmod +x bin/tailwindcss`) and run again: it must re-download. Then `git diff --exit-code internal/web/assets/pines.css` must be unchanged.
- Run `install.sh` against a local fake release, offline:
  - Copy `install.sh` to the scratchpad.
  - Point `REPO` at a `file://` path; `curl -fsSL file://…` works.
  - Build `peek_v9.9.9_linux_amd64.tar.gz` and `checksums.txt` with `sha256sum`, then run with `PEEK_VERSION=v9.9.9 PEEK_INSTALL_DIR=$scratch/bin`. It must succeed.
  - Corrupt one hash: it must fail with `checksum mismatch`.
  - Do this only in the scratchpad. Do not commit the test copy.
- YAML: `python3 -c 'import yaml,sys;[yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml`, plus `actionlint` if available.

##### Docs (P6)
- README "Prebuilt binaries" section: add one sentence: "`install.sh` verifies the archive against the release's `checksums.txt` and refuses to install on mismatch; releases before vX.Y (the first release cut after this change) have no checksums file."
- README/server-setup/skill Docker snippets: keep `:latest`. After the snippet add "For production, pin a release tag (`ghcr.io/andras-tkcs/peek:<version>`) or an image digest (`ghcr.io/andras-tkcs/peek@sha256:…`)."
- `skills/peek-server/SKILL.md:28` block becomes:
```sh
VERSION=vX.Y.Z   # pick from https://github.com/andras-tkcs/peek/releases
curl -fsSLO "https://github.com/andras-tkcs/peek/releases/download/${VERSION}/peek_${VERSION}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/andras-tkcs/peek/releases/download/${VERSION}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt
tar xzf "peek_${VERSION}_linux_amd64.tar.gz"
```

##### Stop conditions
- The upstream `sha256sums.txt` differs from the four hashes above.
- `gh` turns out to be missing on the runner. That cannot be tested locally, so state the assumption in the PR.
- Someone asks to change `LICENSE`.
- An existing release asset naming pattern other than `peek_<tag>_<os>_<arch>.{tar.gz,zip}` is found.

---

#### L14: CI hardening (SHA pins, tool versions, per-job permissions)

##### Current state: every `uses:` (`grep -n "uses:" .github/workflows/*.yml`) and its resolved SHA

| Action @ current tag | Used at | Pin to (commit SHA) | Exact version for comment |
|---|---|---|---|
| `actions/checkout@v4` | ci.yml:23, docker-main.yml:21, pages.yml:20, release.yml:26,69,84 | `11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `actions/setup-go@v5` | ci.yml:24, release.yml:27 | `40f1582b2485089dde7abd97c1529aa768e1baff` | v5.6.0 |
| `dominikh/staticcheck-action@v1` | ci.yml:47 | `9716614d4101e79b4340dd97b10e54d68234e431` (peeled; tag object `e986ce0b…`) | v1.4.1 |
| `docker/setup-qemu-action@v3` | docker-main.yml:23, release.yml:86 | `c7c53464625b32c7a7e944ae62b3e17d2b600130` | v3.7.0 |
| `docker/setup-buildx-action@v3` | docker-main.yml:24, release.yml:87 | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` | v3.12.0 |
| `docker/login-action@v3` | docker-main.yml:27, release.yml:90 | `c94ce9fb468520275223c153574b00df6fe4bcc9` | v3.7.0 |
| `docker/metadata-action@v5` | docker-main.yml:35, release.yml:98 | `c299e40c65443455700f0fdfc63efafe5b349051` | v5.10.0 |
| `docker/build-push-action@v6` | docker-main.yml:43, release.yml:107 | `10e90e3645eae34f1e60eeb005ba3a3d33f178e8` | v6.19.2 |
| `softprops/action-gh-release@v2` | release.yml:60,76 | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` | v2.6.2 |
| `anchore/sbom-action@v0` | release.yml:71 | `e22c389904149dbc22b58101806040fa8d37a610` | v0.24.0 |
| `pnpm/action-setup@v4` | pages.yml:22 | `b906affcce14559ad1aafd4ab0e942779e9f58b1` (peeled; tag object `f40ffcd9…`) | v4.3.0 |
| `actions/setup-node@v4` | pages.yml:26 | `49933ea5288caeca8642d1e84afbd3f7d6820020` | v4.4.0 |
| `actions/configure-pages@v5` | pages.yml:32 | `983d7736d9b0ae728b81ab479565c72886d7745b` | v5.0.0 |
| `actions/upload-pages-artifact@v3` | pages.yml:42 | `56afc609e74202658d3ffba0e8f6dda462b719fa` | v3.0.1 |
| `actions/deploy-pages@v4` | pages.yml:55 | `d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e` | v4.0.5 |

Format for every line: `uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0`. The "exact version" is the highest `vX.Y.Z` tag that points at the same commit as the moving major tag on 2026-10-11. Majors are not upgraded.

Tools:
- `ci.yml:43-44`: `go install golang.org/x/vuln/cmd/govulncheck@latest`.
- `ci.yml:47-50`: `staticcheck-action` with `version: "latest"`.
- `mise.toml:60`: `govulncheck@latest`.
- `mise.toml:64`: `staticcheck@latest`.

Permissions:
- `release.yml:7-9`: top-level `contents: write`, `packages: write`.
- `docker-main.yml:8-10`: top-level `contents: read`, `packages: write`.
- `pages.yml:6-9`: top-level `contents: read`, `pages: write`, `id-token: write`.
- `ci.yml` already has `contents: read` only.

No `pull_request_target` and no `${{ }}` in `run:`.

##### Design
- Replace every `uses:` in the table with the SHA plus the version comment.
- `ci.yml`:
  - Vulnerability step: `go install golang.org/x/vuln/cmd/govulncheck@v1.9.0`.
  - Staticcheck step: `version: "2026.2.1"`.
- `mise.toml`:
  - `run = "go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./..."`
  - `run = "go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./..."`, with comment line above `# v0.8.1 == staticcheck 2026.2.1`.
- `release.yml` permissions: top-level becomes `permissions:\n  contents: read`. Add job-level permissions:
  - `build`: `contents: write`
  - `checksums` (new, see S5): `contents: write`
  - `sbom`: `contents: write`
  - `docker`: `contents: read` + `packages: write`
- `docker-main.yml`: top-level `contents: read` only. Job `docker` gets `contents: read` + `packages: write`.
- `pages.yml`: top-level `contents: read` only. Job `build` gets `contents: read`. Job `deploy` gets `pages: write` + `id-token: write`.
- Do not add Dependabot in this phase. Mention it as a follow-up in the PR body.

##### Files touched
P1 only: the four workflow files and `mise.toml` (shared with S5 in the same phase).

##### Tests / verification
- `grep -nE "uses: [^@]+@v[0-9]" .github/workflows/*.yml` must return nothing.
- `grep -n "@latest\|\"latest\"" .github/workflows/*.yml mise.toml` must return nothing.
- `mise run govulncheck` and `mise run staticcheck` must pass locally.
- YAML parse check as in S5.

##### Stop conditions
- `mise run govulncheck` fails because of v1.9.0 itself, not because of findings. Then fall back to `v1.8.0` and say so in the PR.
- staticcheck 2026.2.1 reports new findings. Fix only if trivial and in files of this phase, otherwise stop and report.

---

#### S7: data directory, database, uploads and backups are world-readable

##### Current state (all `MkdirAll`/`WriteFile`/`OpenFile`/`Create`/modes in non-test code)

| path:line | code | mode now |
|---|---|---|
| `internal/server/server.go:78` | `os.MkdirAll(cfg.DataDir, 0o755)` | dir 0755 |
| `internal/server/server.go:149` | `os.MkdirAll(uploadsDir, 0o755)` | dir 0755 |
| `internal/objectstore/file.go:27` | `os.MkdirAll(filepath.Dir(path), 0o755)` (also creates `versions/<slug>/`) | dir 0755 |
| `internal/objectstore/file.go:31` | `os.WriteFile(tmp, data, 0o644)` then `os.Rename` | file 0644 |
| `internal/server/bootstrap.go:49` | `os.WriteFile(path, []byte(s), 0o600)` (secret.key) | 0600 only on creation; an existing file is read at `:37` and never tightened |
| `internal/server/bootstrap.go:85` | `os.WriteFile(path, []byte(code+"\n"), 0o600)` (setup.key) | 0600 OK |
| `internal/db/store.go:14` | `dsn := "file:" + path + "?_pragma=journal_mode(WAL)&..."`; `sql.Open("sqlite", dsn)` | SQLite creates `peek.db`, `-wal`, `-shm` at 0644 (verified) |
| `internal/peekd/backup.go:61-62` | `destURI := "file:" + destPath`; `db.Exec("VACUUM INTO ?", destURI)` | backup 0644 (verified) |
| `internal/cli/client.go:27,61` | config dir 0700, `WriteFile(p, b, 0o600)` | handled in L13 |

Docker (`Dockerfile`):
- `/data` is created and `chown 65532:65532`, then `USER 65532:65532`.
- `HEALTHCHECK` uses HTTP (`/peekd healthcheck`), not file access.
- `docker exec … peekd backup` runs as 65532 by default.

So no group or other read is needed in the image. Owner-only modes work. Under Kubernetes `fsGroup`, files the process creates are owned by the process uid, so 0600 still works for peekd itself. The only thing that breaks is a backup sidecar running as a different uid that reads `/data` directly. Document it.

##### Design
Use explicit modes, not `umask` (umask is process-wide and racy in tests): dirs **0o700**, files **0o600**.

1. `internal/server/server.go:78` → `os.MkdirAll(cfg.DataDir, 0o700)`. Right after it (P3), add a warning:
```go
if runtime.GOOS != "windows" {
	if info, err := os.Stat(cfg.DataDir); err == nil && info.Mode().Perm()&0o077 != 0 {
		slog.Warn("data directory is accessible to other users; run chmod 700 on it", "dir", cfg.DataDir, "mode", fmt.Sprintf("%#o", info.Mode().Perm()))
	}
}
```
Do **not** chmod an existing data directory. Operators may manage it.

2. `internal/server/server.go:149` → `os.MkdirAll(uploadsDir, 0o700)` (P3).

3. `internal/objectstore/file.go:27` → `0o700`, `:31` → `0o600` (P2). Existing objects keep their mode; the 0700 data dir is the boundary.

4. `internal/server/bootstrap.go` `loadOrCreateSecret` (P3): in the existing-secret branch, when `len(b) >= 32`, before `return string(b), nil`:
```go
if err := os.Chmod(path, 0o600); err != nil {
	slog.Warn("could not restrict secret file permissions", "path", path, "err", err)
}
```

5. `internal/db/store.go` (P2): new unexported helper. Call it as the first statement of `Open`:
```go
// preparePrivateDBFile creates the database file owner-only before SQLite opens it,
// so SQLite also creates -wal/-shm owner-only, and tightens files left by older versions.
func preparePrivateDBFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("restrict database file permissions: %w", err)
		}
	}
	return nil
}
```
In `Open`: `if err := preparePrivateDBFile(path); err != nil { return nil, err }`. A chmod failure is fatal: the process normally owns the file, and the error message says what to fix. All callers pass a real file path (`server.go:97`, tests).

6. `internal/peekd/backup.go` `backupDatabase` (P2): before `VACUUM INTO`:
```go
out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
if err != nil {
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("backup destination %s already exists", destPath)
	}
	return fmt.Errorf("create backup file: %w", err)
}
if err := out.Close(); err != nil {
	return fmt.Errorf("create backup file: %w", err)
}
```
On `VACUUM INTO` error: `_ = os.Remove(destPath)` before returning the existing wrapped error. Behaviour change: an existing **empty** destination file is now refused. A non-empty one was already refused by SQLite.

##### Files touched
- P2: `internal/db/store.go`, `internal/objectstore/file.go`, `internal/peekd/backup.go`.
- P3: `internal/server/server.go`, `internal/server/bootstrap.go`.

##### Tests to add
- `internal/db/store_test.go` (P2):
  - `TestOpenCreatesDatabaseOwnerOnly`: `Open(filepath.Join(t.TempDir(),"peek.db"))`. Assert `peek.db` is 0600. If `peek.db-wal` exists, assert it is 0600; same for `-shm`.
  - `TestOpenTightensExistingDatabaseMode`: open, close, `os.Chmod(path, 0o644)`, open again, assert 0600.
- `internal/objectstore/storage_test.go` (P2): `TestFileStorageWritesOwnerOnlyFilesAndDirs`:
  - `fs := &FileStorage{Dir: t.TempDir()}`.
  - `Save` key `"page"` and key `"versions/page/0123456789abcdef"`.
  - Assert `page.html` is 0600, `versions/page/0123456789abcdef.html` is 0600, and dirs `versions` and `versions/page` are 0700.
  - Reuse the key format from the existing `TestFileStorageSavesVersionKeyInSubdirectory`.
- **new** `internal/peekd/backup_test.go` (P2, `package peekd`):
  - `TestBackupDatabaseWritesOwnerOnlyFile`: seed with `db.Open` as in `run_test.go:102-115`, run `backupDatabase`, assert the backup is 0600.
  - `TestBackupDatabaseRefusesExistingDestination`: pre-create the destination, assert the error contains `already exists` and the file is unchanged.
  - `TestBackupDatabaseRemovesFileOnFailure`: data dir without `peek.db`. `sql.Open` succeeds lazily and VACUUM fails on the empty fresh database, or use a dataDir that is a file. Assert the destination does not exist afterwards. If no reliable failure can be produced, drop this test and note it.
- **new** `internal/server/file_modes_test.go` (P3, `package server_test`): `TestNewCreatesOwnerOnlyDataFiles`:
  - `dir := filepath.Join(t.TempDir(), "data")` (does not exist yet).
  - `server.New(server.Config{DataDir: dir, BaseURL: "http://localhost:7700", MaxUpload: 1<<20})` with **no** Secret, so `secret.key` is generated; `t.Cleanup(srv.Close)`.
  - Assert `dir` is 0700, `dir/uploads` is 0700, and `dir/peek.db`, `dir/secret.key`, `dir/setup.key` are 0600.
- `internal/server/bootstrap_test.go` (P3): `TestLoadOrCreateSecretTightensExistingFileMode`: write a 64-char secret with 0644, `os.Chmod(…, 0o644)`, call `loadOrCreateSecret`, assert 0600 and the same value is returned.

##### Docs (P6)
- `docs/operations.md` "Persistent State": add a paragraph:

  > Peek creates the data directory and `uploads/` as `0700` and `peek.db` (with its `-wal`/`-shm`), `secret.key`, `setup.key`, uploaded objects and `peekd backup` output as `0600`. On start it tightens `peek.db` and `secret.key` but does not change an existing directory's mode; it logs a warning if the data directory is accessible to other users. After upgrading a non-Docker install, run `chmod -R go-rwx /var/lib/peek`. Backup agents must run as the peekd user (uid 65532 in the container image) or as root.

- `docs/operations.md`, the backup paragraph: "`peekd backup` refuses to overwrite an existing destination file."

##### Stop conditions
- Any existing test fails because of `O_EXCL` on the backup destination. In particular, check that `TestBackupArgs` only computes paths.
- `db.Open` is called anywhere with `:memory:` or a `file:` URI. Today it is not.

---

#### L10: `/metrics` optional bearer token; `/readyz` generic error

##### Current state
- `internal/server/routes.go:61-62`:
  ```go
  // Prometheus metrics (unauthenticated, for monitoring).
  mux.HandleFunc("GET /metrics", s.handleMetrics)
  ```
- `internal/server/metrics.go:19` `handleMetrics` writes runtime metrics and runs `CountUploads`, `SumUploadSizes` and `CountTokens` per request.
- `internal/server/health.go:13-18`:
  ```go
  if err := s.store.Ping(); err != nil {
      ...
      _, _ = w.Write([]byte("not ready: " + err.Error()))
  ```
- `internal/server/server.go:25-46` defines `Config` (no metrics field). `internal/peekd/run.go:21-44` defines `serveConfig`. Flags are at `run.go:101-122` and the mapping at `run.go:184-203`.

##### Design
- **Flag/env:**
  - `--metrics-token` with env `PEEK_METRICS_TOKEN`, or `PEEK_METRICS_TOKEN_FILE` via `getenvSecret` (see L13).
  - Help text: `"bearer token required on /metrics (empty = unauthenticated)"`.
  - Validation in `parseServeConfig` after the other checks: `if *metricsToken != "" && len(*metricsToken) < 16 { return …, fmt.Errorf("metrics-token must be at least 16 characters") }`.
- **Wiring:**
  - `serveConfig.MetricsToken string`, `server.Config.MetricsToken string`, `Server.metricsToken string`.
  - In `server.New`, set it in the `&Server{…}` literal: `metricsToken: cfg.MetricsToken`.
  - `runServe` passes `MetricsToken: cfg.MetricsToken`.
  - Add `"metrics_auth", cfg.MetricsToken != ""` to the `slog.Info("peek starting", …)` line.
- **`metrics.go`:**
  ```go
  // metricsAuthorized reports whether r may read /metrics. With no metrics token
  // configured, /metrics stays open (protect it at the proxy).
  func (s *Server) metricsAuthorized(r *http.Request) bool {
  	if s.metricsToken == "" {
  		return true
  	}
  	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
  	if !ok {
  		return false
  	}
  	return subtle.ConstantTimeCompare([]byte(got), []byte(s.metricsToken)) == 1
  }
  ```
  The first statement of `handleMetrics`:
  ```go
  if !s.metricsAuthorized(r) {
  	w.Header().Set("WWW-Authenticate", `Bearer realm="peek-metrics"`)
  	http.Error(w, "unauthorized", http.StatusUnauthorized)
  	return
  }
  ```
  The body is exactly `unauthorized\n` (from `http.Error`). API tokens are **not** accepted for `/metrics`.
- **`routes.go` comment:** leave `routes.go` untouched to keep the phase small. The handler comment documents the behaviour.
- **`health.go`:** replace the error branch with:
  ```go
  if err := s.store.Ping(); err != nil {
  	slog.Error("readiness check failed", "err", err)
  	w.Header().Set("Content-Type", "text/plain")
  	w.WriteHeader(http.StatusServiceUnavailable)
  	_, _ = w.Write([]byte("not ready"))
  	return
  }
  ```

##### Files touched (P3)
`internal/server/server.go`, `internal/server/metrics.go`, `internal/server/health.go`, `internal/peekd/run.go`, `internal/peekd/env.go`.

##### Tests to add
- **new** `internal/server/metrics_test.go` (`package server`; it uses `doRequest`/`asBearer` from `handler_helpers_test.go`).
  - Helper `newMetricsTestServer(t, metricsToken string) (*Server, string)`: a copy of `newHandlerTestServer` with `MetricsToken: metricsToken` in `Config`.
  - `TestMetricsOpenWithoutConfiguredToken`: `newHandlerTestServer`, `GET /metrics` → 200, body contains `peek_requests_total`.
  - `TestMetricsRequiresConfiguredBearerToken`: token `strings.Repeat("m", 32)`.
    - No auth → 401, body `unauthorized\n`, header `WWW-Authenticate` = `Bearer realm="peek-metrics"`.
    - `asBearer("wrong")` → 401.
    - `asBearer(token)` → 200.
  - `TestMetricsRejectsAPITokenWhenMetricsTokenConfigured`: `asBearer(adminToken)` → 401.
  - `TestReadyzHidesDatabaseError`: `s, _ := newHandlerTestServer(t)`, `_ = s.store.Close()`, `GET /readyz` → 503, body exactly `not ready`.
- `internal/peekd/run_test.go`:
  - `TestParseServeConfigMetricsTokenFromEnv`: `t.Setenv("PEEK_METRICS_TOKEN", strings.Repeat("x",16))` → `cfg.MetricsToken` is set.
  - `TestParseServeConfigRejectsShortMetricsToken`: `--metrics-token short` → error contains `at least 16 characters`.
  - Extend nothing else.

##### Docs (P6)
- `docs/operations.md` "Observability", replace the `/metrics` paragraph with:

  > `/metrics` exposes Prometheus text metrics. Set `PEEK_METRICS_TOKEN` (or `PEEK_METRICS_TOKEN_FILE`, at least 16 characters) to require `Authorization: Bearer <token>`; configure Prometheus with `authorization: { credentials_file: … }`. Without a token, protect `/metrics` at the proxy or network layer. `/readyz` returns `not ready` without details; the cause is logged as `readiness check failed`.

- Add a `--metrics-token | PEEK_METRICS_TOKEN | (empty) | …` row to the README flag table, `skills/peek-server/SKILL.md`, and `docs/src/content/docs/reference.md`.
- Update the `/metrics` lines in `README.md:219`, `reference.md:134`, `skills/peek-server/SKILL.md:164-166` and `deployment-platforms.md:84` to mention the token option.

##### Stop conditions
- `withMiddleware` or the request counter turns out to need `/metrics` to bypass something.
- Another design (S1–S4) also changes `server.Config`/`server.go` in a conflicting phase. Then sequence them.

---

#### L11: S3 SSRF block list and bucket validation

##### Current state
`internal/objectstore/s3_endpoint.go:55-69`:
```go
func isPrivateOrMetadataIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	cloudMetadata := []string{"169.254.169.254", "fd00:ec2::254"}
	...
```
- Used by `ValidateS3Endpoint` (`:38-48`) and the dial guard `safeS3DialContext` (`:89-93`).
- The bucket is read in `internal/objectstore/s3.go:28` (`bucket()`) and concatenated into the path at `s3.go:46-48` (`objectURL`) without validation.
- Callers of `objectURL`: `putObject` (`:85`), `getObject` (`:104`), `deleteObject` (`:127`).
- Settings save path: `internal/server/settings.go:106` `normalizeSettingValue`, used by the API (`:84`) and the dashboard (`:220`, `:239`). It has a `case "s3_endpoint":` at `:136-141` and no `s3_bucket` case.
- Startup: `internal/server/server.go:137-145` validates only the endpoint.

##### Design (P2 for objectstore, P3 for server)

1. `s3_endpoint.go`: add `"net/netip"`. Replace `isPrivateOrMetadataIP` with:
```go
// blockedS3Prefixes are ranges never valid for a public S3 endpoint, beyond what
// netip's IsLoopback/IsPrivate/IsLinkLocal*/IsMulticast/IsUnspecified cover.
var blockedS3Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT, incl. Alibaba Cloud metadata 100.100.100.200
	netip.MustParsePrefix("169.254.169.254/32"), // cloud metadata (also link-local)
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("224.0.0.0/4"),        // IPv4 multicast
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved, incl. 255.255.255.255
	netip.MustParsePrefix("::/96"),              // IPv4-compatible IPv6 (deprecated)
	netip.MustParsePrefix("64:ff9b::/96"),       // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),     // NAT64 local-use prefix
	netip.MustParsePrefix("2001::/32"),          // Teredo
	netip.MustParsePrefix("2002::/16"),          // 6to4
	netip.MustParsePrefix("fc00::/7"),           // unique local (incl. AWS fd00:ec2::254)
	netip.MustParsePrefix("fec0::/10"),          // deprecated site-local
	netip.MustParsePrefix("ff00::/8"),           // IPv6 multicast
}

// isPrivateOrMetadataIP reports whether ip must not be used as an S3 endpoint
// address unless private endpoints are explicitly allowed.
func isPrivateOrMetadataIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range blockedS3Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
```
Keep the signature (`net.IP`) so both callers stay unchanged. `Unmap()` covers `::ffff:a.b.c.d`.

2. `s3_endpoint.go`: add the bucket validator:
```go
var s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// ValidateS3Bucket accepts DNS-compatible bucket names (AWS, R2 and MinIO rules),
// so a bucket can never inject path segments, queries or fragments into object URLs.
func ValidateS3Bucket(bucket string) error {
	if !s3BucketPattern.MatchString(bucket) || strings.Contains(bucket, "..") || net.ParseIP(bucket) != nil {
		return errors.New("S3 bucket must be 3-63 lowercase letters, digits, dots or hyphens, start and end with a letter or digit, and not be an IP address")
	}
	return nil
}
```

3. `s3.go`: change `objectURL` to return `(string, error)`:
```go
func (s *S3Storage) objectURL(key string) (string, error) {
	bucket := s.bucket()
	if err := ValidateS3Bucket(bucket); err != nil {
		return "", err
	}
	return strings.TrimRight(s.endpoint(), "/") + "/" + bucket + "/" + key, nil
}
```
In `putObject`, `getObject` and `deleteObject`: `url, err := s.objectURL(key); if err != nil { return err }` (or `return nil, err` in `getObject`).

4. `settings.go` `normalizeSettingValue` (P3): add after the `s3_endpoint` case:
```go
case "s3_bucket":
	if value != "" {
		if err := objectstore.ValidateS3Bucket(value); err != nil {
			return "", fmt.Errorf("invalid s3 bucket: %w", err)
		}
	}
```

5. `server.go` startup (P3): inside `if storageBackend == "s3" {`, after the endpoint check:
```go
if bucket, err := store.GetSetting(startupCtx, "s3_bucket"); err == nil && bucket != "" {
	if err := objectstore.ValidateS3Bucket(bucket); err != nil {
		return nil, fmt.Errorf("invalid s3 bucket: %w", err)
	}
}
```

##### Files touched
- P2: `internal/objectstore/s3_endpoint.go`, `internal/objectstore/s3.go`.
- P3: `internal/server/settings.go`, `internal/server/server.go`.

##### Tests to add
- `internal/objectstore/storage_test.go` (P2):
  - `TestIsPrivateOrMetadataIPBlocksReservedRanges`: a table of addresses that must all return `true` via `net.ParseIP`:
    `127.0.0.1`, `10.1.2.3`, `172.16.0.1`, `192.168.1.1`, `169.254.169.254`, `0.1.2.3`, `100.64.0.1`, `100.100.100.200`, `100.127.255.255`, `192.0.0.1`, `198.18.0.1`, `198.19.255.255`, `224.0.0.1`, `239.255.255.250`, `240.0.0.1`, `255.255.255.255`, `::`, `::1`, `::a00:1`, `::ffff:10.0.0.1`, `::ffff:169.254.169.254`, `64:ff9b::a00:1`, `64:ff9b::808:808`, `64:ff9b:1::1`, `2001::1`, `2002:a00:1::1`, `fd00:ec2::254`, `fe80::1`, `fec0::1`, `ff02::1`.
  - `TestIsPrivateOrMetadataIPAllowsPublicAddresses`, all `false`: `8.8.8.8`, `1.1.1.1`, `100.63.255.255`, `100.128.0.0`, `198.17.255.255`, `198.20.0.0`, `223.255.255.255`, `::ffff:8.8.8.8`, `2606:4700:4700::1111`.
  - `TestValidateS3BucketRejectsUnsafeNames`, all error: `""`, `"ab"`, `"a/b"`, `"bucket/../x"`, `"bucket?x=1"`, `"bucket#x"`, `"Bucket"`, `"my_bucket"`, `"-bucket"`, `"bucket-"`, `"a..b"`, `"192.168.1.1"`, `strings.Repeat("a",64)`, `"bucket%2f"`.
  - `TestValidateS3BucketAcceptsValidNames`: `"peek"`, `"my-bucket.v2"`, `"abc"`, `strings.Repeat("a",63)`.
  - `TestS3StorageRefusesInvalidBucketBeforeRequest`:
    - Start an `httptest.NewServer` that does `t.Fatal`s if hit.
    - Use `NewS3Storage(true, settings)` with endpoint = ts.URL, `s3_bucket` = `"x/../y"`.
    - `Save(ctx,"page",[]byte("x"))` must return an error containing `S3 bucket must be`.
- `internal/server/settings_test.go` (P3):
  - Add `{key: "s3_bucket", value: " peek ", want: "peek"}` to the `TestNormalizeSettingsValues` table.
  - New `TestNormalizeSettingRejectsInvalidS3Bucket`: `s.normalizeSettingValue("s3_bucket","a/b")` error contains `invalid s3 bucket`.

##### Docs (P6)
- `docs/operations.md` "Quotas, Retention, And Storage" S3 paragraph:

  > The SSRF guard also blocks CGNAT (`100.64.0.0/10`), NAT64/6to4/Teredo, benchmarking, multicast and reserved ranges. Bucket names must be DNS-compatible (3–63 lowercase letters, digits, dots, hyphens); a stored bucket that does not match stops startup with `invalid s3 bucket`.

- Same sentence in `docs/src/content/docs/reference.md` next to `--s3-bucket`.

##### Stop conditions
- An existing test relies on a bucket with uppercase or `_`. Check with `grep -rn s3_bucket internal`.
- `docker-compose.yml` uses bucket `peek`, which is valid.

---

#### S6: CLI opens a server-supplied URL without validation

##### Current state
`internal/cli/login_oauth.go:38-41`:
```go
fmt.Fprintf(os.Stderr, "Opening browser for Peek login.\nCode: %s\nURL:  %s\n", start.UserCode, start.VerificationURL)
if err := oauthOpenBrowser(start.VerificationURL); err != nil {
	fmt.Fprintln(os.Stderr, "Open the URL above to continue.")
}
```
`internal/cli/browser.go:8-19`: `openBrowser(url string)` → `open` / `rundll32 url.dll,FileProtocolHandler` / `xdg-open`, with no checks.

The server sends `verification_url: s.baseURL + "/cli-login/" + userCode` (`internal/server/cli_login.go:46`). The test fixtures in `login_oauth_test.go` (lines ~36, ~116, ~168) use the cross-origin `http://auth.example.test/device`.

##### Design (P4)
**New file `internal/cli/hostcheck.go`:**
```go
// validateBrowserURL reports whether raw may be passed to the OS URL opener:
// an absolute http(s) URL on the same scheme, host and port as the configured
// Peek host, with no credentials, no leading '-', and no whitespace/control bytes.
func validateBrowserURL(host, raw string) error
```
Rules, in this order, with exact error texts:
1. `raw == ""` → `errors.New("empty verification URL")`
2. `strings.HasPrefix(raw, "-")` → `errors.New("verification URL must not start with '-'")`
3. any byte `<= 0x20` or `== 0x7f` → `errors.New("verification URL contains whitespace or control characters")`
4. `u, err := url.Parse(raw)`; on err → `fmt.Errorf("invalid verification URL: %w", err)`
5. `u.Scheme != "http" && u.Scheme != "https"` → `errors.New("verification URL must use http or https")`
6. `u.Opaque != "" || u.Host == ""` → `errors.New("verification URL must be absolute")`
7. `u.User != nil` → `errors.New("verification URL must not contain credentials")`
8. `h, err := url.Parse(strings.TrimRight(host, "/"))`. If err, or `originOf(u) != originOf(h)` → `fmt.Errorf("verification URL is not on the configured host %s", originOf(h))`.

Here `originOf(u *url.URL) string` returns `strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port`, where `port = u.Port()`, or `"80"`/`"443"` by scheme when empty.

Also in `hostcheck.go`:
```go
// plainHTTPWarning returns a warning for http:// hosts that are not loopback, or "".
func plainHTTPWarning(host string) string
```
- Parse `host`. Return `""` on error, or when the scheme is not `http`.
- Return `""` when `hostname == "localhost"`, or hostname ends with `.localhost`, or `net.ParseIP(hostname)` is a loopback address.
- Otherwise return exactly:
  `fmt.Sprintf("warning: %s uses plain http://; your token and page passwords are sent unencrypted. Use https:// unless this host is only reachable on a trusted network.", host)`

**`login_oauth.go`:** replace lines 38–41 with:
```go
if err := validateBrowserURL(host, start.VerificationURL); err != nil {
	fmt.Fprintf(os.Stderr, "Peek login.\nCode: %s\nURL:  %q\n", start.UserCode, start.VerificationURL)
	fmt.Fprintf(os.Stderr, "Not opening the browser automatically: %v\nOpen the URL above yourself only if you trust it.\n", err)
} else {
	fmt.Fprintf(os.Stderr, "Opening browser for Peek login.\nCode: %s\nURL:  %s\n", start.UserCode, start.VerificationURL)
	if err := oauthOpenBrowser(start.VerificationURL); err != nil {
		fmt.Fprintln(os.Stderr, "Open the URL above to continue.")
	}
}
```
Polling continues in both cases. The login is not aborted.

**`browser.go`:** defence in depth. Rename the parameter to `rawURL` and add at the top:
```go
if strings.HasPrefix(rawURL, "-") {
	return errors.New("refusing to open URL starting with '-'")
}
if u, err := url.Parse(rawURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
	return errors.New("refusing to open non-http(s) URL")
}
```

**Plain-http warning call sites (stderr):**
- `login_command.go` `cmdLogin`: right after `if host == "" { return fmt.Errorf("host is required") }`:
  `if w := plainHTTPWarning(host); w != "" { fmt.Fprintln(os.Stderr, w) }`
- `config_command.go` `configSet`: right after `if host == "" { return fmt.Errorf("--host is required") }`: the same two lines.

##### Files touched (P4)
`internal/cli/hostcheck.go` (new), `internal/cli/login_oauth.go`, `internal/cli/browser.go`, `internal/cli/login_command.go`, `internal/cli/config_command.go`.

##### Tests to add
- **new** `internal/cli/hostcheck_test.go`:
  - `TestValidateBrowserURL`: a table with host `https://peek.example.com`.
    - OK: `https://peek.example.com/cli-login/ABCD`, `https://PEEK.example.com:443/cli-login/x`.
    - Errors:
      - `""`
      - `-https://peek.example.com/x`
      - `file:///etc/passwd`
      - `smb://peek.example.com/share`
      - `javascript:alert(1)`
      - `http://peek.example.com/x` (scheme differs)
      - `https://peek.example.com:8443/x`
      - `https://evil.example/x`
      - `https://user:pw@peek.example.com/x`
      - `https://peek.example.com/a b`
      - `"https://peek.example.com/\nx"`
      - `https:peek.example.com`
    - Plus host `http://127.0.0.1:7700` with `http://127.0.0.1:7700/cli-login/x`, which is OK.
  - `TestPlainHTTPWarning`:
    - Warns for: `http://peek.internal:7700`, `http://10.0.0.5`.
    - Does not warn for: `https://peek.example.com`, `http://localhost:7700`, `http://127.0.0.1:7700`, `http://[::1]:7700`, `http://app.localhost`.
  - `TestOpenBrowserRefusesNonHTTPURLs`: `openBrowser("file:///etc/passwd")` and `openBrowser("-x")` return errors. This never execs: the check happens before `exec.Command`.
- `internal/cli/login_oauth_test.go`:
  - In all three existing handlers change `"verification_url": "http://auth.example.test/device"` to `"verification_url": "http://" + r.Host + "/cli-login/USER-123"`.
  - In `TestLoginOAuthPollsUntilApproved` change the assertion to `openedURL != ts.URL+"/cli-login/USER-123"`.
  - New `TestLoginOAuthDoesNotOpenUntrustedVerificationURL`:
    - Table of `file:///etc/passwd`, `http://evil.example/cli-login/X`, `-x`.
    - The server returns the value, then `approved` on the first poll.
    - The `restoreOAuthTestHooks` open hook does `t.Fatalf("opened %q", url)`.
    - Assert `loginOAuth` returns nil and the token is saved.
- `internal/cli/test_helpers_test.go`:
  - Add `captureStderr(t *testing.T, fn func() error) (string, error)`, a copy of `captureStdout` that swaps `os.Stderr`.
  - Optionally refactor both into one `captureFile(t, **os.File, fn)` helper. Keep the public helper names.

##### Docs (P6)
None required beyond a mention in `docs/src/content/docs/reference.md` CLI section: "`peek login` only opens the browser for a verification URL on the configured host; it warns when the host uses plain `http://` and is not loopback."

##### Stop conditions
- **Overlap with S3 ("CLI device login is one-click phishable"):** that fix may also edit the `login_oauth.go` print/open block or the `verification_url` format. If the S3 phase changes `login_oauth.go`, P4 must run after it and keep its text. If S3 makes the server URL point to a different origin than `--host` (for example, an always-`base-url` origin), the cross-origin "not opening" path is expected, not a bug.

---

#### L12: CLI path segments not escaped

##### Current state: every API path built from user input

| path:line | code | today |
|---|---|---|
| `internal/cli/uploads_command.go:71` | `c.getJSON("/api/uploads/"+args[0]+"/versions", &items)` | raw |
| `internal/cli/uploads_command.go:95` | `c.del("/api/uploads/"+args[0], nil)` | raw |
| `internal/cli/uploads_command.go:171` | `c.postJSON("/api/uploads/"+slug+"/visibility", body, &out)` | raw |
| `internal/cli/uploads_command.go:200` | `"/api/uploads/"+url.PathEscape(slug)+"/name"` | escaped, not validated |
| `internal/cli/stats_comments_command.go:37` | `c.getJSON("/api/uploads/"+args[0]+"/stats", &st)` | raw |
| `internal/cli/stats_comments_command.go:104` | `path := "/api/uploads/" + slug + "/comments"` | raw |
| `internal/cli/gdpr_command.go:22` | `c.req("GET", "/api/uploads/"+args[0]+"/export", nil, "")` | raw |
| `internal/cli/grants_command.go:53` | `"/api/uploads/"+url.PathEscape(g.slug)+"/grants"` | escaped, not validated |
| `internal/cli/grants_command.go:77` | same, DELETE | escaped, not validated |
| `internal/cli/grants_command.go:106` | `"/api/uploads/"+url.PathEscape(args[0])+"/grants"` | escaped, not validated |
| `internal/cli/token_command.go:96` | `c.del("/api/tokens/"+id, nil)` | raw, id not checked |
| `internal/cli/upload_command.go:53` | `--slug` goes into a multipart form field, not the path | not validated |

Server slug charset:
- `internal/objectstore/slug.go:40-55` (`validObjectSlug`): `[A-Za-z0-9_-]`, non-empty.
- `internal/uploads/slug.go`: `slugify` gives `[a-z0-9-]`, and random IDs are base64url, so `[A-Za-z0-9_-]`.

These match.

##### Design (P5)
**New file `internal/cli/path_segments.go`:**
```go
var slugPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// slugPath validates a page slug against the server's slug charset and returns it
// escaped for use as one URL path segment.
func slugPath(slug string) (string, error) {
	if !slugPattern.MatchString(slug) {
		return "", fmt.Errorf("invalid slug %q: use only letters, digits, '-' and '_'", slug)
	}
	return url.PathEscape(slug), nil
}

// tokenIDPath validates a token id (positive integer) for use as a path segment.
func tokenIDPath(id string) (string, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return "", fmt.Errorf("invalid token id %q: must be a positive integer", id)
	}
	return strconv.FormatInt(n, 10), nil
}
```

**Call-site change.** Validate right after argument parsing, **before** `LoadConfig()`, so bad input fails without network or config:
```go
seg, err := slugPath(args[0]) // or slug / g.slug
if err != nil {
	return err
}
...
c.getJSON("/api/uploads/"+seg+"/versions", &items)
```
- Apply to every row in the table: `uploads_command.go` versions/delete/visibility/rename, `stats_comments_command.go` stats/comments, `gdpr_command.go` export, `grants_command.go` grant/revoke/grants.
- In `grants_command.go`, replace `url.PathEscape(...)` with the validated `seg`, and remove the `net/url` import if it becomes unused (same in `uploads_command.go`).
- `token_command.go:96`: `idSeg, err := tokenIDPath(id)` inside parsing, before `run` is built.
- `upload_command.go`: after `slug = strings.TrimSpace(args[i+1])` validation block (`if slug != "" {` at line 67), add `if _, err := slugPath(slug); err != nil { return err }` as the first statement inside that block.

**L13 `--password` warning (in the same files, P5).** In `cmdUpload` (`upload_command.go`) and `cmdVisibility` (`uploads_command.go`):
- Track `usedPasswordFlag bool`, set where `--password` is parsed.
- After all argument validation and before `LoadConfig()`:
```go
if usedPasswordFlag {
	fmt.Fprintln(os.Stderr, "warning: --password is exposed in your shell history and process list (ps). Prefer --password-stdin.")
}
```

##### Files touched (P5)
`internal/cli/path_segments.go` (new), `internal/cli/uploads_command.go`, `internal/cli/stats_comments_command.go`, `internal/cli/gdpr_command.go`, `internal/cli/grants_command.go`, `internal/cli/token_command.go`, `internal/cli/upload_command.go`.

##### Tests to add
- **new** `internal/cli/path_segments_test.go`:
  - `TestSlugPathAcceptsServerSlugs`: `page`, `q3-reorg-plan`, `AbC_12-x`; the result equals the input.
  - `TestSlugPathRejectsUnsafeSlugs`: `""`, `x/../../tokens/5`, `..`, `a b`, `a%2f`, `a?b`, `a#b`, `ü`; the error contains `invalid slug`.
  - `TestTokenIDPath`: `"42"` → `"42"`. Errors for `"0"`, `"-1"`, `"5/../x"`, `"abc"`, `""`.
  - `TestCommandsRejectTraversalSlugBeforeRequest`:
    - `configureTestClient(t, ts.URL)` with an `httptest` server whose handler does `t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)`.
    - For each of `cmdDelete`, `cmdVersions`, `cmdStats`, `cmdComments`, `cmdExport`, `cmdGrants`, `cmdGrant`, `cmdRevoke`, `cmdRename`, `cmdVisibility` (args `x/../../tokens/5` plus the required extra args), assert the error contains `invalid slug`.
    - `cmdToken([]string{"revoke","5/../x"})` → `invalid token id`.
- `internal/cli/uploads_command_requests_test.go`:
  - `TestCmdVisibilityWarnsAboutPasswordFlag`: wrap the existing `TestCmdVisibilitySendsSetVisibilityRequest` flow with `captureStderr` and assert stderr contains `--password is exposed`.
- `internal/cli/upload_command_test.go`:
  - `TestCmdUploadWarnsAboutPasswordFlag`: same idea around the existing `TestCmdUploadStreamsPasswordMultipart` call.
  - `TestUploadWithSlugRejectsInvalidSlug`: `cmdUpload([]string{"page.html","--slug","../x"})` → `invalid slug`.

##### Docs (P6)
None (no user-visible behaviour beyond the error text). Optionally add to `reference.md`: "`--password` prints a warning; prefer `--password-stdin`."

##### Stop conditions
- The server accepts slugs outside `[A-Za-z0-9_-]`. Re-check `internal/db/slug_aliases.go` and the `uploads.Rename` alias slugs. If any alias can hold other characters, stop.
- A test in `automation_commands_test.go` passes a non-integer token id.

---

#### L13: CLI and daemon credential hygiene

##### Current state
- `internal/cli/upload_command.go:28-33` and `internal/cli/uploads_command.go:113-118`: `--password <pw>` is accepted silently. `config_command.go:90-92` and `login_command.go:126-128` already warn for `--token`, so that is the precedent for the text style.
- `internal/cli/client.go:61`: `return os.WriteFile(p, b, 0o600)`. `WriteFile` does not change the mode of an existing file, so a `0644` config keeps its mode.
- `internal/cli/config_command.go:43`: `host, token := cfg.Host, cfg.Token`. `--host` alone keeps the old token, which is then sent to the new host. Save is at `:102-103`.
- `internal/peekd/run.go:105`: `secret := fs.String("secret", getenv("PEEK_SECRET", ""), …)`. `run.go:112`: `s3SecretKey := fs.String("s3-secret-key", getenv("PEEK_S3_SECRET_KEY", ""), …)`. Values given as flags are visible in `ps`. There is no `_FILE` support.
- `env.go` conventions:
  - `getenv(k, d)`.
  - `getenvInt64`, `getenvInt` and `getenvBool` return `(value, error)` with an error text `"%s must be …"` naming the env var.
  - They are called at the top of `parseServeConfig` and used as flag defaults.

##### Design
**a) `--password` warning:** in P5 (see L12).

**b) `SaveConfig` (P4, `client.go`):** replace the last line:
```go
if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
	return err
}
return os.WriteFile(p, b, 0o600)
```
Chmod comes **before** the write so the new token never lands in a group- or world-readable file. Add the `io/fs` import.

**c) `config set --host` clears the token on host change (P4, `config_command.go`):**
- After line 43 add `oldHost := strings.TrimRight(cfg.Host, "/")`.
- After the `host == ""` check and the plain-http warning, insert:
```go
tokenProvided := usedTokenFlag || tokenFile != "" || tokenStdin
if oldHost != "" && strings.TrimRight(host, "/") != oldHost && !tokenProvided && token != "" {
	token = ""
	fmt.Fprintf(os.Stderr, "note: host changed from %s to %s; the saved token was cleared. Run `peek login --host %s` to sign in.\n", oldHost, host, host)
}
```
`cmdLogin` already replaces the token on success, so it is not changed.

**d) peekd `_FILE` env vars (P3, `env.go` + `run.go`):** add to `env.go`:
```go
// getenvSecret returns the value of name, or the trimmed contents of the file
// named by name+"_FILE" (for Docker/Kubernetes secrets). Setting both is an error.
func getenvSecret(name string) (string, error) {
	fileVar := name + "_FILE"
	direct := os.Getenv(name)
	path := strings.TrimSpace(os.Getenv(fileVar))
	if path == "" {
		return direct, nil
	}
	if direct != "" {
		return "", fmt.Errorf("set only one of %s and %s", name, fileVar)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileVar, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s points to an empty file", fileVar)
	}
	return v, nil
}

// secretFlagWarnings lists warnings for secrets passed as command-line flags.
func secretFlagWarnings(fs *flag.FlagSet) []string {
	envFor := map[string]string{
		"secret":        "PEEK_SECRET_FILE",
		"s3-secret-key": "PEEK_S3_SECRET_KEY_FILE",
		"metrics-token": "PEEK_METRICS_TOKEN_FILE",
	}
	var out []string
	fs.Visit(func(f *flag.Flag) {
		if env, ok := envFor[f.Name]; ok {
			out = append(out, fmt.Sprintf("peekd: warning: --%s is visible to other users in the process list; prefer %s", f.Name, env))
		}
	})
	return out
}
```
In `run.go` `parseServeConfig`:
- Next to the other `getenv*` calls at the top, add:
  - `secretDefault, err := getenvSecret("PEEK_SECRET")`
  - `s3SecretKeyDefault, err := getenvSecret("PEEK_S3_SECRET_KEY")`
  - `metricsTokenDefault, err := getenvSecret("PEEK_METRICS_TOKEN")`

  Each returns `serveConfig{}, false, err` on error.
- Use them as flag defaults (lines 105, 112, and the new `metrics-token` flag).
- After `fs.Parse` (and after the `showVersion` early return): `for _, w := range secretFlagWarnings(fs) { fmt.Fprintln(os.Stderr, w) }`.

##### Files touched
- P4: `internal/cli/client.go`, `internal/cli/config_command.go`.
- P5: `internal/cli/upload_command.go`, `internal/cli/uploads_command.go`.
- P3: `internal/peekd/env.go`, `internal/peekd/run.go`.

##### Tests to add
- `internal/cli/client_test.go` (P4): `TestSaveConfigTightensExistingFileMode`:
  - `setTestConfigHome`; `p, _ := configPath()`.
  - `os.WriteFile(p, []byte("{}"), 0o644)`; `os.Chmod(p, 0o644)`.
  - `SaveConfig(&Config{Host: "https://h", Token: "t"})`.
  - Assert the mode is 0600 and `LoadConfig` round-trips.
- **new** `internal/cli/config_command_test.go` (P4):
  - `TestConfigSetHostChangeClearsSavedToken`:
    - `setTestConfigHome`; `SaveConfig(&Config{Host: "https://old.example.test", Token: "tok"})`.
    - `stderr, err := captureStderr(t, func() error { _, err := captureStdout(t, func() error { return configSet([]string{"--host", "https://new.example.test"}) }); return err })`.
    - Assert `LoadConfig().Token == ""`, `Host == "https://new.example.test"`, and stderr contains `the saved token was cleared`.
  - `TestConfigSetSameHostKeepsToken`: `--host https://old.example.test/` (trailing slash) keeps `tok`, with no note.
  - `TestConfigSetWarnsForPlainHTTPHost`: `--host http://peek.internal:7700`; stderr contains `uses plain http://`.
  - None of these pass a token, so `discoverAuth` is never called and no network is used.
- `internal/peekd/run_test.go` (P3):
  - `TestGetenvSecretReadsFile`: write `"s3cr3t\n"` to a temp file, `t.Setenv("PEEK_SECRET_FILE", path)`, then `parseServeConfig(nil)` → `cfg.Secret == "s3cr3t"`.
  - `TestGetenvSecretRejectsBothVarAndFile`: set both; the error contains `set only one of PEEK_SECRET and PEEK_SECRET_FILE`.
  - `TestGetenvSecretRejectsEmptyFile`: the error contains `points to an empty file`.
  - `TestParseServeConfigS3SecretKeyFromFile`: `PEEK_S3_SECRET_KEY_FILE` → `cfg.S3SecretKey`.
  - `TestSecretFlagWarnings`:
    - Build `fs := flag.NewFlagSet("t", flag.ContinueOnError)` with `secret`, `s3-secret-key` and `addr` string flags.
    - Parse `--secret x --addr :1`.
    - Expect exactly one warning, containing `--secret` and `PEEK_SECRET_FILE`.

##### Docs (P6)
- README, `skills/peek-server/SKILL.md` and `reference.md` flag tables: in the `--secret` and `--s3-secret-key` rows, append "Or `PEEK_SECRET_FILE` / `PEEK_S3_SECRET_KEY_FILE` with the path to a file (Docker/Kubernetes secrets); setting both the variable and `_FILE` is an error."
- `docs/operations.md` "Startup Configuration": add "Prefer `_FILE` variables or plain environment variables over `--secret`, `--s3-secret-key` and `--metrics-token` on the command line; flags are visible in `ps` and peekd prints a warning."
- `reference.md` CLI section: "`peek config set --host <new>` clears the saved token when the host changes; run `peek login` afterwards."

##### Stop conditions
- `parseServeConfig` tests run with a `PEEK_SECRET` already set in the environment. Use `t.Setenv("PEEK_SECRET", "")` where needed. `getenvSecret` treats empty as unset.

---

#### Cross-design coordination (for the plan author)
- `internal/server/server.go`, `internal/peekd/run.go` and `internal/server/settings.go` are likely also touched by S1–S4 or other Low findings (for example S4 token policy and L1 body limits in middleware). If another design's phase also lists them, P3 must be ordered after it, or the edits merged into one phase.
- `internal/cli/login_oauth.go` may be touched by S3. See the S6 stop condition.
- `docs/operations.md`, `README.md` and `docs/src/content/docs/reference.md` are probably touched by other designs. P6 should be the last docs phase, or merged with the other designs' docs phase.
- The release that first carries `checksums.txt` must be cut before anyone relies on the new `install.sh`. Mention this in the PR body. `main`'s `install.sh` fails for v0.8.1 and older.


### Design D — slugs, names and audit detail, flash codes, comment authors (L15, L7, L9, L8)


Base: `main` at 6380c6b (after PR #11, migration 10 present). All line numbers are from that commit. Audit line numbers in docs/audits/2026-10-security-and-coverage-audit.md are slightly stale (e.g. audit says `api_uploads.go:117`, actual is `:113`; `web_dashboard.go:166` is actually `:170`).

Experiment already run (scratch copy, not the repo): applying the L15 slug change alone breaks exactly 4 tests: `TestGenerateSlugFromName`, `TestRenameDerivesNewSlug` (internal/uploads), `TestDashboardRenameChangesLinkAndAudits`, `TestRenameE2E` (internal/server). Nothing in internal/cli breaks.

#### Proposed phases (order matters)

| Phase | Findings | Source files (non-test) | Est. changed lines | Depends on |
| --- | --- | --- | --- | --- |
| P1 | L15 + L7 (name limit on create) | internal/uploads/slug.go, internal/uploads/service.go, internal/uploads/rename.go, README.md, skills/peek/SKILL.md, docs/src/content/docs/using-peek.md, docs/operations.md | ~120 source + ~120 test | none |
| P2 | L7 (audit detail quoting) | internal/server/lifecycle.go, api_tokens.go, api_rename.go, api_uploads.go, api_grants.go, admin.go, web_api_keys.go, web_grants.go | ~60 source + ~80 test | none (P1 recommended first, see tests) |
| P3 | L9 (flash codes) + the two remaining L7 audit lines in web_dashboard.go | internal/server/web_helpers.go, web_dashboard.go, settings.go, web_rename.go, upload_service.go, admin.go, web_grants.go, web_api_keys.go | ~330 source + ~250 test | P1 and P2 (same files / same tests) |
| P4 | L8 (comment author) | internal/db/migrations.go, internal/db/schema.go, internal/db/comments.go, internal/models/models.go, internal/server/comments.go, internal/server/api_stats.go, internal/web/assets/app.js, internal/web/templates/page.gohtml | ~120 source + ~150 test | none of P1-P3; migration id 13 (see below) |

Docs files are listed with their phase but do not count toward the 8 source files.

Sequencing: P1 -> P2 -> P3 strictly serial (P2 and P3 both edit admin.go, web_api_keys.go, web_grants.go and web_api_keys_test.go; P1 and P3 both edit web_rename_test.go). P4 can run in parallel with P1-P3.

##### Overlap with other plan phases
- `internal/server/comments.go`: P4 edits `commentOut` (lines 23-32), the two list-building loops (90-97, 158-165), the name block in `handleAddComment` (131-148), the `AddComment` call in `handleAddAccountComment` (231-242). The token-policy phase edits the bearer path in `handleListComments` (61-75) and possibly `requireAPIToken` usage at 199. Different hunks, but same file: merge P4 after or before that phase, not concurrently in the same branch without a rebase.
- `internal/server/pages.go`: none of P1-P4 touch it. `pages.go:107` (`"slug="+slug` audit detail) is deliberately left unchanged (slug is the DB-resolved slug, charset `[a-z0-9-]` or legacy base64url, cannot contain space/`=`/quote).
- `internal/server/web_login.go`, `middleware.go`: not touched.
- `internal/server/cli_login.go`, `oauth_flow.go`: not touched. Their audit calls (`cli_login.go:107`, `:174`, `oauth_flow.go:92`) already `%q`-quote the email; `account=%d`, `provider=%s` (fixed key) and `code=%s` (server-validated device code) cannot carry separators. Left unchanged so the cli_logins-metadata phase owns cli_login.go.
- Migrations: other phases add 11 (`cli_logins` metadata) and 12 (`accounts.session_epoch`). P4 uses **13** (`comment_account_id`). Keep the `migrations` slice sorted by id; if P4 lands first the slice is temporarily `..., 10, 13` which works (the runner iterates the slice and records ids individually). Whoever lands last must place their entry in id order.

---

#### L15 - guessable slugs (Phase P1)

##### Current state
- `internal/uploads/slug.go:13-17`:
  ```go
  const (
  	slugRetries   = 5
  	maxSlugLength = 60
  	clashSuffix   = 4
  )
  ```
- `slug.go:48-75` `generateSlugFromName`: returns bare `slugify(name)` if free; only on clash appends `"-" + randID(clashSuffix)` (base64url of 4 bytes = 6 chars incl. upper case and `_`), up to 5 retries, then `generateRandomSlug`.
- `slug.go:77-91` `generateRandomSlug`: `randID(10)` = 14 base64url chars (upper case, `-`, `_`).
- `slug.go:98-104` `randID(nBytes)` base64.RawURLEncoding; only used by the two functions above (`grep randID internal/uploads` -> slug.go:61, :79, :98).
- Callers: `service.go:127` (`Create`) and `rename.go:60` (`Rename`, when the new name's slug form differs and is not the page's own alias).
- `objectstore/slug.go` `validObjectSlug` accepts lowercase alnum and `-` (new alphabet passes).
- No server-side slug regex exists elsewhere.

##### Design
Every slug generated from a name (all visibilities, create and rename) gets `"-" + 6 random chars`. Random fallback slugs use the same alphabet (16 chars). Existing slugs are untouched.

Replace the const block and `generateSlugFromName`, `generateRandomSlug`, `randID` in `internal/uploads/slug.go` with:

```go
const (
	slugRetries      = 5
	maxSlugLength    = 60
	slugSuffixLength = 6
	randomSlugLength = 16
	// slugAlphabet has 32 lowercase letters and digits without 0, 1, l and o,
	// so one random byte maps to one character without bias (b & 31).
	slugAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"
)

// generateSlugFromName derives a link from name plus a random suffix, so a page
// cannot be found by guessing its name. Names with no slug characters get a
// fully random slug.
func generateSlugFromName(ctx context.Context, name string, store slugChecker) (string, error) {
	base := slugify(name)
	if base == "" {
		return generateRandomSlug(ctx, store)
	}
	if limit := maxSlugLength - 1 - slugSuffixLength; len(base) > limit {
		base = strings.TrimRight(base[:limit], "-")
	}
	for range slugRetries {
		suffix, err := randomSlugString(slugSuffixLength)
		if err != nil {
			return "", err
		}
		candidate := base + "-" + suffix
		exists, err := store.UploadSlugExists(ctx, candidate)
		if err != nil {
			return "", fmt.Errorf("check slug availability: %w", err)
		}
		if !exists {
			return candidate, nil
		}
	}
	return generateRandomSlug(ctx, store)
}

func generateRandomSlug(ctx context.Context, store slugChecker) (string, error) {
	for range slugRetries {
		s, err := randomSlugString(randomSlugLength)
		if err != nil {
			return "", err
		}
		exists, err := store.UploadSlugExists(ctx, s)
		if err != nil {
			return "", fmt.Errorf("check slug availability: %w", err)
		}
		if !exists {
			return s, nil
		}
	}
	return "", errors.New("slug collision after retries")
}

// randomSlugString returns n characters from slugAlphabet using crypto/rand.
func randomSlugString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = slugAlphabet[b[i]&31]
	}
	return string(b), nil
}
```
Remove the `encoding/base64` import (keep `crypto/rand`, `encoding/hex` for `versionObjectKey`). `slugify` stays unchanged (60-char cap still applies to its output; the 53-char cap is applied in `generateSlugFromName`).

Rename behaviour (`rename.go`, no logic change): it calls `generateSlugFromName`, so renamed links also get a suffix. The "keep link" rules still hold: new name slug form == current slug, == old name slug form, or empty -> link kept. The own-alias reclaim (`ResolveSlugAlias(base)`) only matches unsuffixed legacy aliases; renaming back to an earlier name now mints a new suffixed link (the old one still redirects). Update the doc comment on `Rename` (rename.go:38-41) to:
```go
// Rename changes an upload's display name and derives its link from the new name
// the same way upload does (name slug plus a random suffix). The link is kept when
// the new name's slug form is empty, equals the current slug, or equals the old
// name's slug form; a page's own unsuffixed old link is taken back instead of
// minting a new one.
```

Entropy: 32^6 = 2^30 per name guess. Random fallback: 32^16 = 2^80 (same as the old 10 random bytes).

##### Tests to update / add
- `internal/uploads/validate_test.go` `TestGenerateSlugFromName`:
  - subtest "first upload": expect `strings.HasPrefix(slug, "my-cool-page-")`, `len(slug) == len("my-cool-page-")+6`, and every suffix char in `slugAlphabet`.
  - replace subtest "clash appends suffix" with "taken suffix is retried": `mock := &mockSlugChecker{returnErrorAfter: 3}`; expect prefix `my-cool-page-`, suffix length 6, `mock.counter == 3`.
  - keep "empty name falls back to random", "all special chars falls back to random", "exhausted retries falls back to random" (len >= 8 still holds; random slugs are now 16 chars).
  - add subtest "long name is truncated before suffix": name `strings.Repeat("a", 80)`; expect `len(slug) <= maxSlugLength` and `strings.HasPrefix(slug, strings.Repeat("a", 53)+"-")`.
- `validate_test.go` add `TestRandomSlugString`: `randomSlugString(16)` twice; each length 16, all chars in `slugAlphabet` (`strings.ContainsRune`), the two differ.
- `validate_test.go` `TestGenerateSlugUniqueness` "always free": additionally assert `len(slug) == randomSlugLength` and chars in `slugAlphabet`.
- `internal/uploads/rename_test.go` `TestRenameDerivesNewSlug`: expect `strings.HasPrefix(res.Slug, "new-page-")`, `len(res.Slug) == len("new-page-")+6`, `res.URL == "http://h/p/"+res.Slug`, `res.SlugChanged`. Other rename tests pass unchanged.
- `internal/server/web_rename_test.go` `TestDashboardRenameChangesLinkAndAudits`: replace the `wantLocation` and the `GetUpload("quarterly-report")` lines with:
  ```go
  loc, err := url.Parse(rec.Header().Get("Location"))
  if err != nil { t.Fatal(err) }
  newSlug := loc.Query().Get("manage")
  if !strings.HasPrefix(newSlug, "quarterly-report-") || len(newSlug) != len("quarterly-report-")+6 {
  	t.Fatalf("new slug = %q", newSlug)
  }
  if got := loc.Query().Get("ok"); got != "Renamed to /p/"+newSlug {
  	t.Fatalf("ok = %q", got)
  }
  got, err := s.store.GetUpload(context.Background(), newSlug)
  ```
  (P3 later changes the `ok` assertion; see L9.)
- `internal/server/rename_e2e_test.go` `TestRenameE2E`: decode the rename response (`decodeResponseJSON[struct{ Slug, Name string }](t, resp)`), assert `Slug` has prefix `second-report-` and length `len("second-report-")+6`, `Name == "Second Report"`; replace every literal `second-report` / `/p/second-report` with the decoded slug (`"/p/"+out.Slug`, `rename(out.Slug, ...)`).

##### Docs
- `README.md`: replace all 11 occurrences of `PhiUs-lMbZE_Sw` with `mypage-html-k7m2xq`. Line 194 table row: `| Path traversal / SQLi | Random base64url slugs; all queries parameterized. |` -> `| Path traversal / SQLi / link guessing | Slugs are the page name plus a random 6-character suffix (fully random when the name has no letters or digits); all queries parameterized. |`
- `skills/peek/SKILL.md`: replace both `PhiUs-lMbZE_Sw` with `page-html-k7m2xq`.
- `docs/src/content/docs/using-peek.md` after line 15 add: `Links are made from the page name plus a random six-character suffix, for example /p/q3-plan-k7m2xq, so a page cannot be found by guessing its name. Renaming a page gives it a new suffixed link; old links keep redirecting.`
- `docs/operations.md` "Page Access" paragraph: append `Page links are the page name plus a random six-character suffix; links created before this release keep their old form.`

##### Stop conditions
- Any test outside the 4 listed (plus the L7 tests below) fails because it expects a name-derived slug: stop and report the test name.
- `objectstore` rejects a generated slug: stop.

---

#### L7 - audit detail injection and unbounded names

##### L7a - name length on create (Phase P1)

Current state:
- `internal/uploads/rename.go:15` `const maxNameLength = 200`; `rename.go:47-49`:
  ```go
  if utf8.RuneCountInString(name) > maxNameLength {
  	return nil, newError(KindNameTooLong, "name must be 200 characters or fewer")
  }
  ```
- `internal/uploads/service.go:107-111` `Create` trims and defaults the name, no length check.
- HTTP mapping already exists: `internal/server/upload_service.go:31` maps `uploads.KindNameTooLong` to `400` with the error message, so `POST /api/upload` answers `400 {"error":"name must be 200 characters or fewer"}` (via `jsonError`). Dashboard upload (`web_dashboard.go:165-168`) flashes `uploadErrorMessage(err)` = `name must be 200 characters or fewer` (P3 turns this into code `upload_name_too_long`, same text).

Design:
- `rename.go`: add `const nameTooLongMessage = "name must be 200 characters or fewer"` next to `maxNameLength`; `Rename` uses `newError(KindNameTooLong, nameTooLongMessage)`.
- `service.go` `Create`, immediately after the `if in.Name == "" { in.Name = "page" }` block:
  ```go
  if utf8.RuneCountInString(in.Name) > maxNameLength {
  	return nil, newError(KindNameTooLong, nameTooLongMessage)
  }
  ```
  Add import `unicode/utf8`. Check runs before HTML sniffing and before any storage write.
- `AddVersion` has no name: unchanged.

Tests:
- `internal/uploads/service_test.go` add `TestCreateRejectsNameOver200Characters`: name `strings.Repeat("a", 201)` -> `*Error` with `Kind == KindNameTooLong`, `Message == "name must be 200 characters or fewer"`, `len(st.saved) == 0`. Add `TestCreateAcceptsNameOf200Characters`: `strings.Repeat("é", 200)` (200 runes, 400 bytes) succeeds.
- `internal/server/upload_service_test.go` add `TestAPIUploadRejectsLongName` (package server, `newHandlerTestServer`): `doRequest(t, s, http.MethodPost, "/api/upload?visibility=public&filename="+strings.Repeat("a", 201), strings.NewReader("<!doctype html><html></html>"), asBearer(tok), func(r *http.Request) { r.Header.Set("Content-Type", "text/html") })` -> `400`, body contains `name must be 200 characters or fewer`.

Docs: `docs/src/content/docs/reference.md` line 84 area (CLI reference): after the upload usage paragraph add `Page names (the --name value or the file name) are limited to 200 characters.`

##### L7b - audit detail quoting (Phase P2, plus two lines in P3)

Current state - every audit call and its detail (path:line at 6380c6b):

| Site | Action | Detail today | User-controlled values |
| --- | --- | --- | --- |
| api_tokens.go:41 | token.create | `"name="+body.Name` | name (unbounded, raw) |
| api_tokens.go:88 | token.revoke | `"id="+id+" name="+t.Name` | name |
| api_rename.go:9-11 `renameAuditDetail` (used at api_rename.go:41, web_rename.go:20) | upload.rename | `"slug="+old+" new_slug="+new+" name="+name` | name |
| api_uploads.go:113 | upload.create | `"slug="+up.Slug+" name="+up.Name+" size="+size` | name |
| api_uploads.go:149 | upload.version.create | `"slug="+slug+" version="+v+" size="+n` | none (slug DB-resolved) |
| api_uploads.go:228 | upload.delete | `"slug="+slug+" name="+u.Name` | name |
| api_uploads.go:269-275 `visibilityAuditDetail` (used at :265, web_dashboard.go:232) | upload.visibility.set | `slug=.. visibility=..[ password=updated]` | none (visibility validated) |
| api_uploads.go:295 | upload.delete_all | `"count="+n` | none |
| api_grants.go:111, :132 | upload.grant.add/remove | `"slug="+u.Slug+" kind="+body.Kind+" email="+body.Email` | email/kind (validated) |
| web_grants.go:52, :77 | upload.grant.add/remove | same shape | email/kind (validated) |
| web_api_keys.go:38-40 `apiKeyAuditDetail` (used at :131, :167, :195) | token.create/regenerate/revoke | `"id="+id+" name="+name` | name (<=100 runes, no control chars) |
| web_dashboard.go:170 | upload.create | same as api_uploads.go:113 | name |
| web_dashboard.go:199 | upload.delete | same as api_uploads.go:228 | name |
| admin.go:68 | (system) | `s.audit("invite created email=%q by=%s", email, owner.Name)` | owner.Name unquoted |
| admin.go:94 | (system) | `s.audit("invite revoked id=%d by=%s", id, owner.Name)` | owner.Name |
| admin.go:121 | (system) | `s.audit("account admin=%t id=%d by=%s", ...)` | owner.Name |
| admin.go:148 | (system) | `s.audit("account disabled=%t id=%d by=%s", ...)` | owner.Name |
| pages.go:107 | page.access.denied | `"slug="+slug` | none -- left unchanged (other phase owns pages.go) |
| comments.go:237 | comment.create | `"slug="+slug` | none -- left unchanged |
| settings.go:102 | settings.update | `strings.Join(keys, ",")` | none (keys from settingsMeta) -- unchanged |
| settings.go:256 | settings.update | `"via dashboard"` | none -- unchanged |
| web_login.go:58, web_setup.go:74 | login.success, setup.admin_created | `""` | -- unchanged |
| cli_login.go:107, :174, oauth_flow.go:92 | (system) | `%q` email, ints, fixed keys | -- unchanged (see overlap) |

Consumers of the detail string: only `GET /api/audit` (`api_audit.go:24,32`) which passes it through as JSON `detail`; slog `detail` attribute (`lifecycle.go:34`, `:43`); no CLI `peek audit` command (`grep -rn audit internal/cli` -> nothing); no dashboard rendering. Nothing parses it.

Tests that assert exact detail strings:
- `internal/server/api_grants_test.go:132` `"slug=g-audit kind=user email=bob@example.com"` -- unchanged by the design (no value needs quoting).
- `internal/server/web_dashboard_test.go:454` `"slug=page visibility=password password=updated"` -- unchanged.
- `internal/server/web_api_keys_test.go:331` `"id=" + kid + " name=QA runner"` -- **changes** to `"id=" + kid + ` + "` name=\"QA runner\"`" i.e. Go: `want := "id=" + strconv.FormatInt(kid, 10) + ` name="QA runner"``.
- Substring checks that stay valid: `pages_test.go:259`, `upload_service_test.go:77` (`slug=page` in logs), `lifecycle_test.go:141`, `db/store_test.go:232`.

Decision: quote only when needed (logfmt style), not always. Always-quoting would change every existing detail and the two exact-string tests above for no security gain.

Design - add to `internal/server/lifecycle.go` (imports `strconv`, `strings`, `unicode`):
```go
// auditDetail formats key/value pairs as space-separated key=value fields. A
// value that is empty or contains a space, '=', '"', '\\' or a non-printable
// rune is written with strconv.Quote, so user-supplied text (page names, token
// names, account names) cannot forge or hide another field. Keys must be fixed
// identifiers. An odd trailing key gets an empty value.
func auditDetail(kv ...string) string {
	var b strings.Builder
	for i := 0; i < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(kv[i])
		b.WriteByte('=')
		v := ""
		if i+1 < len(kv) {
			v = kv[i+1]
		}
		b.WriteString(auditValue(v))
	}
	return b.String()
}

func auditValue(v string) string {
	if v == "" || strings.ContainsAny(v, " =\"\\") || strings.IndexFunc(v, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return strconv.Quote(v)
	}
	return v
}
```
(`unicode.IsPrint` is false for control chars, U+2028, NBSP and other non-ASCII spaces, and invalid UTF-8 decodes to U+FFFD which is printable but `strconv.Quote` is not reached; acceptable.)

Exact replacements (P2):
- api_tokens.go:41 -> `auditDetail("name", body.Name)`
- api_tokens.go:88 -> `auditDetail("id", strconv.FormatInt(id, 10), "name", t.Name)`
- api_rename.go:10 -> `return auditDetail("slug", oldSlug, "new_slug", res.Slug, "name", res.Name)`
- api_uploads.go:113 -> `auditDetail("slug", up.Slug, "name", up.Name, "size", strconv.Itoa(up.Size))`
- api_uploads.go:149 -> `auditDetail("slug", slug, "version", strconv.Itoa(res.Version), "size", strconv.Itoa(res.Size))`
- api_uploads.go:228 -> `auditDetail("slug", slug, "name", u.Name)`
- api_uploads.go:269-275 `visibilityAuditDetail` body ->
  ```go
  if visibility == models.UploadVisibilityPassword {
  	return auditDetail("slug", slug, "visibility", visibility, "password", "updated")
  }
  return auditDetail("slug", slug, "visibility", visibility)
  ```
- api_uploads.go:295 -> `auditDetail("count", strconv.Itoa(deleted))`
- api_grants.go:111, :132 -> `auditDetail("slug", u.Slug, "kind", body.Kind, "email", body.Email)`
- web_grants.go:52, :77 -> `auditDetail("slug", u.Slug, "kind", kind, "email", email)`
- web_api_keys.go:39 -> `return auditDetail("id", strconv.FormatInt(id, 10), "name", name)`
- admin.go:68 -> `s.audit("invite created %s", auditDetail("email", email, "by", owner.Name))`
- admin.go:94 -> `s.audit("invite revoked %s", auditDetail("id", strconv.FormatInt(id, 10), "by", owner.Name))`
- admin.go:121 -> `s.audit("account %s", auditDetail("admin", strconv.FormatBool(makeAdmin), "id", strconv.FormatInt(id, 10), "by", owner.Name))`
- admin.go:148 -> `s.audit("account %s", auditDetail("disabled", strconv.FormatBool(disabled), "id", strconv.FormatInt(id, 10), "by", owner.Name))`
  (note: invite email changes from always-quoted `email="a@b"` to `email=a@b`; no test asserts it.)

P3 (same phase as L9 because web_dashboard.go is a P3 file):
- web_dashboard.go:170 -> `auditDetail("slug", up.Slug, "name", up.Name, "size", strconv.Itoa(up.Size))`
- web_dashboard.go:199 -> `auditDetail("slug", slug, "name", u.Name)`

Check after P2+P3: `grep -n '"[a-z_]*="+' internal/server/*.go | grep -v _test` must only list pages.go:107 and comments.go:237.

Tests (P2):
- `internal/server/lifecycle_test.go` add `TestAuditDetailQuotesUnsafeValues` table:
  | input | want |
  | `("slug","page","name","Q3 plan","size","42")` | `slug=page name="Q3 plan" size=42` |
  | `("name","x size=999 slug=evil")` | `name="x size=999 slug=evil"` |
  | `("name","a\nb")` | `name="a\nb"` (Go literal `` `name="a\nb"` ``) |
  | `("name",`say "hi"`)` | `` `name="say \"hi\""` `` |
  | `("name",`back\slash`)` | `` `name="back\\slash"` `` |
  | `("name","")` | `name=""` |
  | `("name","café")` | `name=café` |
  | `("name","a b")` | `` `name="a b"` `` |
  | `("slug")` | `slug=""` |
- `lifecycle_test.go` add `TestAPIUploadAuditQuotesName`: `newHandlerTestServer`; raw upload `POST /api/upload?visibility=public&filename=` + `url.QueryEscape("x size=1 slug=evil.html")` with `asBearer(tok)` and `Content-Type: text/html`; decode `slug` from JSON; `s.store.ListAuditLog` entry with action `upload.create` must have `Detail == "slug="+slug+` name="x size=1 slug=evil.html" size=`+strconv.Itoa(len(body))`.
- `web_api_keys_test.go:331` update `want` as above.

Docs (P2): `docs/operations.md` "Observability" paragraph, append: `Audit details are space-separated key=value fields; a value containing a space, =, a quote, a backslash or a control character is written as a Go-quoted string.`

Stop conditions (L7): a test other than web_api_keys_test.go:331 asserts an exact detail and changes; `go vet` flags the `s.audit("... %s", ...)` calls (it should not).

Out of scope, noted: `POST /api/tokens` token names are unbounded (`api_tokens.go`); quoting removes the injection, a length cap is a separate change.

---

#### L9 - flash message spoofing (Phase P3)

##### Current state
- `internal/server/web_dashboard.go:87-96`:
  ```go
  // carry over flash messages from query params
  if e := r.URL.Query().Get("err"); e != "" { dashData_.UploadError = e }
  if msg := r.URL.Query().Get("ok"); msg != "" { dashData_.FlashSuccess = msg }
  if url := r.URL.Query().Get("uploaded"); url != "" { dashData_.UploadSuccessURL = url }
  ```
  Rendered in `internal/web/templates/dashboard.gohtml:13-15` as toast `data-toast-message` / `data-toast-description` attributes (toast.js reads attributes, textContent; not XSS, but arbitrary text/URL on the real dashboard). `?uploaded=` shows toast "Uploaded! Share link:" with the URL as description (8 s).
- Redirect helpers `internal/server/web_helpers.go:15-41`: `dashboardError(w,r,msg)`, `dashboardOK(w,r,msg)`, `dashboardUploaded(w,r,shareURL)`, `dashboardFlash(w,r,key,msg)`, `dashboardFlashManage(w,r,key,msg,slug)` (adds `manage=slug`, which reopens the Access dialog via `ManageSlug`).
- Every flash producer (exact current text):

| Site | key | Current text |
| --- | --- | --- |
| web_helpers.go:45, :54 | err | `invalid session` |
| web_dashboard.go:111 | err | `file too large or invalid form` |
| web_dashboard.go:120 | err | `invalid session` |
| web_dashboard.go:133 | err | `no html pasted` |
| web_dashboard.go:143 | err | `no file selected` |
| web_dashboard.go:149 | err | `file too large` |
| web_dashboard.go:167 | err | `uploadErrorMessage(err)` (upload error kinds) |
| web_dashboard.go:172 | uploaded | `up.URL` |
| web_dashboard.go:187, :215; web_grants.go:25 | err | `not found` |
| web_dashboard.go:191, :219; web_grants.go:29 | err | `not owner` |
| web_dashboard.go:196 | err | `delete failed` |
| web_dashboard.go:224 | err | `uploadErrorMessage(err)` (visibility kinds) |
| web_dashboard.go:229 | err | `visibility update failed` |
| web_dashboard.go:234 | ok | `Password updated for /p/<slug>` |
| web_dashboard.go:238 | ok+manage | `/p/<slug> is now restricted` |
| web_dashboard.go:241 | ok | `/p/<slug> is now <visibility>` |
| web_dashboard.go:200 | (none) | `dashboardHome` plain redirect after delete |
| web_grants.go:44, :65 | err+manage | `normalizeGrantInput` msg: `kind must be user or group` / `invalid email address` / `group grants need Google group lookup; set PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL on the server` (api_grants.go:52,57,60) |
| web_grants.go:49, :74 | err+manage | `grant update failed` |
| web_grants.go:53 | ok+manage | `Shared /p/<slug> with <email>` |
| web_grants.go:70 | err+manage | `grant not found` |
| web_grants.go:78 | ok+manage | `Removed <email> from /p/<slug>` |
| web_rename.go:17 | err+manage | `uploadErrorMessage(err)` (`name is required`, `name must be 200 characters or fewer`, `slug generation failed`, `rename failed`) |
| web_rename.go:21 | ok+manage | `Renamed to /p/<newslug>` |
| admin.go:47 | err | `email required` |
| admin.go:51 | err | `email must match allowed domain` |
| admin.go:56, :61, :65 | err | `invite failed` |
| admin.go:69 | ok | `invite created` |
| admin.go:83, :88 | err | `bad invite` |
| admin.go:91 | err | `invite revoke failed` |
| admin.go:95 | ok | `invite revoked` |
| admin.go:109, :136 | err | `bad user` |
| admin.go:115 | err | `cannot remove last admin` |
| admin.go:118, :145 | err | `user update failed` |
| admin.go:122, :149 | ok | `user updated` |
| admin.go:142 | err | `cannot disable last admin` |
| settings.go:222, :230, :241, :247 | err | `err.Error()` (dynamic: `<key> must be a boolean`, `... must be an integer`, `... must be a positive integer`, `... must be a non-negative integer`, `... is too large`, `storage must be file or s3`, `invalid s3 endpoint: ...`, OIDC issuer errors incl. host names, `auth_allowed_email_domain must ...`, `account lookup failed`) |
| settings.go:252 | err | `settings update failed` |
| settings.go:257 | ok | `settings saved` |
| web_api_keys.go:118 | err | `API key name must be 1 to 100 characters` (`apiKeyNameError`) |
| web_api_keys.go:128 | err | `API key could not be created` |
| web_api_keys.go:164 | err | `API key could not be regenerated` |
| web_api_keys.go:192 | err | `API key could not be revoked` |
| web_api_keys.go:196 | ok | `API key revoked` |

Upload error texts reachable through `uploadErrorMessage` (internal/uploads): `empty file`, `file does not look like HTML`, `visibility must be public, password, private, or restricted`, `password visibility requires a password`, `password is only allowed with password visibility`, `password must be 72 characters or fewer`, `hash failed`, `slug generation failed`, `storage failed`, `total storage quota exceeded`, `per-token upload count quota exceeded`, `per-token storage quota exceeded`, `db failed` (Create) / `rename failed` (Rename) for `KindPersistenceFailure`, `name is required`, `name must be 200 characters or fewer`; non-`*uploads.Error` -> `upload failed`.

No other handler renders query text (`oauth_flow.go:50` only tests presence of `error`).

##### Design
Principle: query parameters carry only codes and identifiers. The dashboard renders text only from a fixed server-side map; placeholders are filled only from server data (the viewer's own visible uploads and their grants). Unknown codes, and codes whose referenced upload/grant is not visible to the viewer, render nothing. Settings validation errors (whose texts are dynamic and admin-relevant) are rendered inline in the POST response with status 400 instead of a redirect, so no text travels in a URL.

All of this goes in the existing `internal/server/web_helpers.go` (no new file; keeps P3 at 8 source files).

###### Codes and messages (exact)
Constants (type `string`), and `var flashMessages = map[string]string{...}`:

Error codes (`?err=`):
| const | code | message |
| --- | --- | --- |
| flashInvalidSession | `invalid_session` | `invalid session` |
| flashFormInvalid | `form_invalid` | `file too large or invalid form` |
| flashNoHTML | `no_html` | `no html pasted` |
| flashNoFile | `no_file` | `no file selected` |
| flashFileTooLarge | `file_too_large` | `file too large` |
| flashNotFound | `not_found` | `not found` |
| flashNotOwner | `not_owner` | `not owner` |
| flashDeleteFailed | `delete_failed` | `delete failed` |
| flashVisibilityFailed | `visibility_failed` | `visibility update failed` |
| flashRenameFailed | `rename_failed` | `rename failed` |
| flashGrantKind | `grant_kind` | `kind must be user or group` |
| flashGrantEmail | `grant_email` | `invalid email address` |
| flashGrantGroupLookup | `grant_group_lookup` | `group grants need Google group lookup; set PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL on the server` |
| flashGrantFailed | `grant_failed` | `grant update failed` |
| flashGrantNotFound | `grant_not_found` | `grant not found` |
| flashInviteEmailRequired | `invite_email_required` | `email required` |
| flashInviteDomain | `invite_domain` | `email must match allowed domain` |
| flashInviteFailed | `invite_failed` | `invite failed` |
| flashBadInvite | `bad_invite` | `bad invite` |
| flashInviteRevokeFailed | `invite_revoke_failed` | `invite revoke failed` |
| flashBadUser | `bad_user` | `bad user` |
| flashLastAdminRemove | `last_admin_remove` | `cannot remove last admin` |
| flashLastAdminDisable | `last_admin_disable` | `cannot disable last admin` |
| flashUserUpdateFailed | `user_update_failed` | `user update failed` |
| flashSettingsFailed | `settings_failed` | `settings update failed` |
| flashAPIKeyName | `api_key_name` | `apiKeyNameError` (the existing const, `API key name must be 1 to 100 characters`) |
| flashAPIKeyCreateFailed | `api_key_create_failed` | `API key could not be created` |
| flashAPIKeyRegenerateFailed | `api_key_regenerate_failed` | `API key could not be regenerated` |
| flashAPIKeyRevokeFailed | `api_key_revoke_failed` | `API key could not be revoked` |
| flashUploadFailed | `upload_failed` | `upload failed` |
| flashUploadPersistenceFailure | `upload_persistence_failure` | `db failed` |
| (no const) | `upload_empty_file` | `empty file` |
| | `upload_invalid_html` | `file does not look like HTML` |
| | `upload_invalid_visibility` | `visibility must be public, password, private, or restricted` |
| | `upload_password_required` | `password visibility requires a password` |
| | `upload_password_not_allowed` | `password is only allowed with password visibility` |
| | `upload_password_too_long` | `password must be 72 characters or fewer` |
| | `upload_password_hash` | `hash failed` |
| | `upload_slug_generation` | `slug generation failed` |
| | `upload_storage_write` | `storage failed` |
| | `upload_total_quota_exceeded` | `total storage quota exceeded` |
| | `upload_owner_count_exceeded` | `per-token upload count quota exceeded` |
| | `upload_owner_storage_exceeded` | `per-token storage quota exceeded` |
| | `upload_name_required` | `name is required` |
| | `upload_name_too_long` | `name must be 200 characters or fewer` |

Success codes (`?ok=`); `{slug}`, `{visibility}`, `{email}` are placeholders:
| const | code | message |
| --- | --- | --- |
| flashInviteCreated | `invite_created` | `invite created` |
| flashInviteRevoked | `invite_revoked` | `invite revoked` |
| flashUserUpdated | `user_updated` | `user updated` |
| flashSettingsSaved | `settings_saved` | `settings saved` |
| flashAPIKeyRevoked | `api_key_revoked` | `API key revoked` |
| flashPasswordUpdated | `password_updated` | `Password updated for /p/{slug}` |
| flashVisibilitySet | `visibility_set` | `/p/{slug} is now {visibility}` |
| flashGrantAdded | `grant_added` | `Shared /p/{slug} with {email}` |
| flashGrantRemoved | `grant_removed` | `Removed access from /p/{slug}` (TEXT CHANGE: the removed email cannot be verified server-side because the grant no longer exists, so it is dropped) |
| flashRenamed | `renamed` | `Renamed to /p/{slug}` |

`?uploaded=<slug>` (was a full URL).

###### Helper code (web_helpers.go)
Replace lines 15-41 with:
```go
func dashboardError(w http.ResponseWriter, r *http.Request, code string) {
	dashboardFlash(w, r, url.Values{"err": {code}})
}

func dashboardOK(w http.ResponseWriter, r *http.Request, code string) {
	dashboardFlash(w, r, url.Values{"ok": {code}})
}

// dashboardOKSlug flashes a success code whose message names /p/<slug>.
func dashboardOKSlug(w http.ResponseWriter, r *http.Request, code, slug string) {
	dashboardFlash(w, r, url.Values{"ok": {code}, "slug": {slug}})
}

// dashboardUploaded flashes the share link of the upload with this slug.
func dashboardUploaded(w http.ResponseWriter, r *http.Request, slug string) {
	dashboardFlash(w, r, url.Values{"uploaded": {slug}})
}

func dashboardHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, dashboardPath, http.StatusSeeOther)
}

// dashboardFlash redirects to the dashboard with flash codes and parameters.
// Only codes from flashMessages are ever rendered.
func dashboardFlash(w http.ResponseWriter, r *http.Request, q url.Values) {
	http.Redirect(w, r, dashboardPath+"?"+q.Encode(), http.StatusSeeOther)
}

// dashboardFlashManage redirects to the dashboard with a flash code about slug
// and reopens its access dialog.
func dashboardFlashManage(w http.ResponseWriter, r *http.Request, key, code, slug string) {
	dashboardFlash(w, r, url.Values{key: {code}, "manage": {slug}, "slug": {slug}})
}
```
`parseDashboardForm` (lines 45, 54): `dashboardError(w, r, flashInvalidSession)`.

Add:
```go
// dashboardFlashView is the resolved toast text for one dashboard render.
type dashboardFlashView struct {
	Error       string
	Success     string
	UploadedURL string
}

// resolveFlash turns the flash codes in q into text. Placeholders are filled
// only from uploads the viewer can see on this dashboard; a code that is unknown,
// or that names an upload or grant the viewer cannot see, renders nothing.
func resolveFlash(q url.Values, list []dashUpload, baseURL string) dashboardFlashView {
	var out dashboardFlashView
	if code := q.Get("err"); code != "" {
		out.Error = flashText(code, q, list)
	}
	if code := q.Get("ok"); code != "" {
		out.Success = flashText(code, q, list)
	}
	if slug := q.Get("uploaded"); slug != "" {
		if u := findDashUpload(list, slug); u != nil {
			out.UploadedURL = baseURL + "/p/" + u.Slug
		}
	}
	return out
}

func flashText(code string, q url.Values, list []dashUpload) string {
	text, ok := flashMessages[code]
	if !ok {
		return ""
	}
	if !strings.Contains(text, "{") {
		return text
	}
	u := findDashUpload(list, q.Get("slug"))
	if u == nil {
		return ""
	}
	email := ""
	if strings.Contains(text, "{email}") {
		email = q.Get("email")
		if !dashUploadHasGrant(u, email) {
			return ""
		}
	}
	return strings.NewReplacer("{slug}", u.Slug, "{visibility}", u.Visibility, "{email}", email).Replace(text)
}

func findDashUpload(list []dashUpload, slug string) *dashUpload {
	if slug == "" {
		return nil
	}
	for i := range list {
		if list[i].Slug == slug {
			return &list[i]
		}
	}
	return nil
}

func dashUploadHasGrant(u *dashUpload, email string) bool {
	for _, g := range u.Grants {
		if email != "" && g.Email == email {
			return true
		}
	}
	return false
}

// grantFlashCode maps a normalizeGrantInput message to its flash code.
func grantFlashCode(msg string) string {
	switch msg {
	case "kind must be user or group":
		return flashGrantKind
	case "invalid email address":
		return flashGrantEmail
	case "group grants need Google group lookup; set PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL on the server":
		return flashGrantGroupLookup
	default:
		return flashGrantFailed
	}
}
```
Imports: add `strings`.

`internal/server/upload_service.go`: delete `uploadErrorMessage` (lines 41-44) and add:
```go
// uploadFlashCode maps an upload error to a dashboard flash code.
func uploadFlashCode(err error) string {
	var uploadErr *uploads.Error
	if errors.As(err, &uploadErr) {
		code := "upload_" + string(uploadErr.Kind)
		if _, ok := flashMessages[code]; ok {
			return code
		}
	}
	return flashUploadFailed
}
```

###### Dashboard render (web_dashboard.go)
Split `handleDashboard` (lines 17-98):
```go
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	if s.setupRequired(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderDashboard(w, r, owner, http.StatusOK, r.URL.Query(), "")
}

// renderDashboard renders owner's dashboard. Flash codes come from q; when
// inlineError is set it is shown as the error toast instead (used by handlers
// that answer a POST with the page rather than a redirect).
func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, owner *models.Account, status int, q url.Values, inlineError string) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	// ... current lines 29-86 unchanged, except ManageSlug: q.Get("manage") ...
	flash := resolveFlash(q, uploads, s.baseURL)
	if flash.Error != "" {
		dashData_.UploadError = flash.Error
	}
	if inlineError != "" {
		dashData_.UploadError = inlineError
	}
	dashData_.FlashSuccess = flash.Success
	dashData_.UploadSuccessURL = flash.UploadedURL
	s.renderHTML(w, status, webui.TemplateDashboard, dashData_)
}
```
(remove the old lines 87-96; add import `net/url`; `q` may be nil, `url.Values(nil).Get` is safe.)

Call-site edits in web_dashboard.go:
- :111 `dashboardError(w, r, flashFormInvalid)`; :120 `flashInvalidSession`; :133 `flashNoHTML`; :143 `flashNoFile`; :149 `flashFileTooLarge`; :167 `dashboardError(w, r, uploadFlashCode(err))`; :170 audit -> `auditDetail(...)` (L7); :171-172 -> `dashboardUploaded(w, r, up.Slug)` (drop `shareURL`).
- :187, :215 `flashNotFound`; :191, :219 `flashNotOwner`; :196 `flashDeleteFailed`; :199 audit -> `auditDetail(...)` (L7); :224 `uploadFlashCode(err)`; :229 `flashVisibilityFailed`.
- :233-241 ->
  ```go
  if change.Visibility == models.UploadVisibilityPassword {
  	dashboardOKSlug(w, r, flashPasswordUpdated, slug)
  	return
  }
  if change.Visibility == models.UploadVisibilityRestricted {
  	dashboardFlashManage(w, r, "ok", flashVisibilitySet, slug)
  	return
  }
  dashboardOKSlug(w, r, flashVisibilitySet, slug)
  ```

settings.go `handleDashboardSettings`:
- :222, :230, :241, :247 -> `s.renderDashboard(w, r, owner, http.StatusBadRequest, nil, err.Error())` then `return`.
- :252 `dashboardError(w, r, flashSettingsFailed)`; :257 `dashboardOK(w, r, flashSettingsSaved)`.

web_rename.go:
- :17 ->
  ```go
  code := uploadFlashCode(err)
  if code == flashUploadPersistenceFailure {
  	code = flashRenameFailed
  }
  dashboardFlashManage(w, r, "err", code, slug)
  ```
- :21 `dashboardFlashManage(w, r, "ok", flashRenamed, res.Slug)`.

web_grants.go:
- :25 `flashNotFound`; :29 `flashNotOwner`; :44, :65 `dashboardFlashManage(w, r, "err", grantFlashCode(msg), slug)`; :49, :74 `flashGrantFailed`; :70 `flashGrantNotFound`.
- :53 `dashboardFlash(w, r, url.Values{"ok": {flashGrantAdded}, "manage": {slug}, "slug": {slug}, "email": {email}})` (add import `net/url`).
- :78 `dashboardFlashManage(w, r, "ok", flashGrantRemoved, slug)`.

admin.go: :47 `flashInviteEmailRequired`; :51 `flashInviteDomain`; :56, :61, :65 `flashInviteFailed`; :69 `dashboardOK(w, r, flashInviteCreated)`; :83, :88 `flashBadInvite`; :91 `flashInviteRevokeFailed`; :95 `flashInviteRevoked`; :109, :136 `flashBadUser`; :115 `flashLastAdminRemove`; :118, :145 `flashUserUpdateFailed`; :122, :149 `flashUserUpdated`; :142 `flashLastAdminDisable`.

web_api_keys.go: :118 `flashAPIKeyName`; :128 `flashAPIKeyCreateFailed`; :164 `flashAPIKeyRegenerateFailed`; :192 `flashAPIKeyRevokeFailed`; :196 `flashAPIKeyRevoked`.

After P3: `grep -n 'dashboardError(w, r, "' internal/server/*.go` and `grep -n 'dashboardOK(w, r, "'` and `dashboardFlashManage(w, r, "\(ok\|err\)", "` return nothing.

###### Resulting Location strings (url.Values.Encode sorts keys)
- invalid session: `/dashboard?err=invalid_session`
- not owner: `/dashboard?err=not_owner`
- password set: `/dashboard?ok=password_updated&slug=page`
- public: `/dashboard?ok=visibility_set&slug=page`
- restricted: `/dashboard?manage=page&ok=visibility_set&slug=page`
- visibility error: `/dashboard?err=upload_password_required`
- grant added: `/dashboard?email=alice%40example.com&manage=page&ok=grant_added&slug=page`
- grant removed: `/dashboard?manage=page&ok=grant_removed&slug=page`
- grant invalid email: `/dashboard?err=grant_email&manage=page&slug=page`
- group without lookup: `/dashboard?err=grant_group_lookup&manage=page&slug=page`
- grant missing: `/dashboard?err=grant_not_found&manage=page&slug=page`
- rename ok: `/dashboard?manage=<new>&ok=renamed&slug=<new>`
- rename empty name: `/dashboard?err=upload_name_required&manage=page&slug=page`
- invite revoked: `/dashboard?ok=invite_revoked`
- API key revoked: `/dashboard?ok=api_key_revoked`; bad name: `/dashboard?err=api_key_name`
- dashboard upload: `/dashboard?uploaded=<slug>`

##### Tests to update (P3)
- `web_helpers_test.go` `TestDashboardFlashRedirectEscapesQuery` -> rename to `TestDashboardUploadedRedirectCarriesSlug`: `dashboardUploaded(rec, req, "page")`, Location `== "/dashboard?uploaded=page"`.
- `web_dashboard_test.go`: :94 request `/dashboard?ok=settings_saved` (body still contains `settings saved`); :437 `/dashboard?ok=password_updated&slug=page`; :467 `/dashboard?ok=visibility_set&slug=page`; :481 `/dashboard?err=upload_password_required`; :493 `/dashboard?err=not_owner`; :501 `/dashboard?err=invalid_session`; :520 `/dashboard?manage=page&ok=visibility_set&slug=page`; :304 and :331 `u.Query().Get("err") == "delete_failed"`. `TestDashboardUploadPassesVisibility` additionally assert Location == `"/dashboard?uploaded="+list[0].Slug`.
- `web_grants_test.go`: :41 and :86 -> `/dashboard?email=alice%40example.com&manage=page&ok=grant_added&slug=page` / `...team%40example.com...`; :50 and :98 -> `/dashboard?manage=page&ok=grant_removed&slug=page`; :63 -> `/dashboard?err=grant_email&manage=page&slug=page`; :73 -> exact `wantLocation(t, loc, "/dashboard?err=grant_group_lookup&manage=page&slug=page")`; :108 -> `/dashboard?err=grant_not_found&manage=page&slug=page`; :119 `/dashboard?err=not_owner`; :129 `/dashboard?err=invalid_session`.
- `web_rename_test.go`: in `TestDashboardRenameChangesLinkAndAudits` (as rewritten in P1) change the `ok` assertion to `loc.Query().Get("ok") != "renamed" || loc.Query().Get("slug") != newSlug`; :32 `/dashboard?err=upload_name_required&manage=page&slug=page`; :43 `/dashboard?err=not_owner`; :50 `/dashboard?err=invalid_session`.
- `web_api_keys_test.go`: :133, :148, :301 `/dashboard?ok=api_key_revoked`; :185 `/dashboard?err=invalid_session`; :242 `/dashboard?err=api_key_name`.
- `admin_test.go`: :54 `got != "bad_invite"`; :71 `/dashboard?ok=invite_revoked`.
- `settings_test.go`:
  - `TestDashboardSettingsInvalidS3EndpointRedirectEscapesQuery` -> rename `TestDashboardSettingsInvalidS3EndpointRendersInlineError`; give the Server a renderer (`renderer, err := webui.NewRenderer()` as in web_dashboard_test.go:88-92, field `renderer: renderer`); expect `rec.Code == http.StatusBadRequest`, `rec.Header().Get("Location") == ""`, body contains `invalid s3 endpoint: `.
  - `TestDashboardSettingsRejectsInvalidValuesBeforeWriting`: same renderer addition; expect 400 and body contains `max_upload must be a positive integer`; keep the "settings unchanged" assertions.
  - :428 (`TestDashboardSettingsRejectsMalformedForm`) -> `"invalid_session"`.

##### Tests to add (P3, in web_helpers_test.go unless noted)
- `TestFlashMessagesCoverAllCodes`: slice of every `flash*` constant; each is a key of `flashMessages` with non-empty text.
- `TestUploadFlashCodeMatchesUploadErrors`: real errors -> `flashMessages[uploadFlashCode(err)] == err.Error()` for: `uploads.PrepareVisibility("bogus", "")`, `PrepareVisibility("password", "")`, `PrepareVisibility("public", "x")`, `PrepareVisibility("password", strings.Repeat("a", 73))`; `uploads.Rename(ctx, nil-safe fake, "", RenameInput{Name: " "})` -> name_required and `Name: strings.Repeat("a", 201)` -> name_too_long (Rename returns before touching repo; pass a zero-method fake implementing `uploads.RenameRepository`); constructed `&uploads.Error{Kind: k, Message: m}` for `empty_file`/`empty file`, `invalid_html`, `password_hash`, `slug_generation`, `storage_write`, the three quota kinds, `persistence_failure`/`db failed`; `errors.New("x")` -> `upload_failed`.
- `TestGrantFlashCodeMatchesGrantErrors`: for `(kind, email)` = `("bogus","a@b.c")`, `("user","not-an-email")`, `("group","g@example.com")` on a Server with `groups == nil` and `requireGroupLookup=true`: `msg` from `s.normalizeGrantInput`, `code := grantFlashCode(msg)`, `code != flashGrantFailed`, `flashMessages[code] == msg`.
- `TestResolveFlash` table, list = `[]dashUpload{{Slug: "page", Visibility: "public", Grants: []dashGrant{{Kind: "user", Email: "alice@example.com"}}}}`, baseURL `http://h`:
  - `err=not_owner` -> Error `not owner`
  - `err=Call IT on 555-0100` -> all empty
  - `ok=visibility_set&slug=page` -> `/p/page is now public`
  - `ok=visibility_set&slug=other` -> empty
  - `ok=password_updated` (no slug) -> empty
  - `ok=grant_added&slug=page&email=alice@example.com` -> `Shared /p/page with alice@example.com`
  - `ok=grant_added&slug=page&email=mallory@evil.example` -> empty
  - `ok=grant_removed&slug=page` -> `Removed access from /p/page`
  - `ok=renamed&slug=page` -> `Renamed to /p/page`
  - `uploaded=page` -> UploadedURL `http://h/p/page`
  - `uploaded=https://evil.example/x` -> empty
- `web_dashboard_test.go` `TestDashboardIgnoresFreeTextFlash`: `newHandlerTestServer`, viewer session; GET `/dashboard?err=Your+session+expired.+Call+IT&ok=Pay+now&uploaded=https%3A%2F%2Fevil.example%2Fx`; 200; body does not contain `Call IT`, `Pay now`, `evil.example`, `Uploaded! Share link:`.
- `web_dashboard_test.go` `TestDashboardUploadedFlashShowsOwnUploadLink`: seed upload `page` owned by viewer; GET `/dashboard?uploaded=page`; body contains `Uploaded! Share link:` and `http://localhost:7700/p/page`. Same request as a different non-admin account -> no `Uploaded! Share link:`.

##### Docs
None user-facing (flash mechanics are internal). Optionally mention in the PR body that bookmarked `?ok=...` dashboard URLs no longer show text.

##### Stop conditions (L9)
- P3 would exceed 8 source files (e.g. a flash producer outside the list above appears): stop and report the site.
- `renderDashboard` on the settings path needs data the settings handler does not have: stop (do not fall back to `?err=<text>`).
- Any `staticcheck` U1000 for removed helpers (`uploadErrorMessage`, old `dashboardFlash` signature): delete the dead code, do not keep shims.

---

#### L8 - comment author spoofing (Phase P4)

##### Current state
- `internal/server/comments.go:101-167` `handleAddComment` (browser route `POST /api/uploads/{slug}/comments`): access via `viewerCanAccessUpload` (public, password cookie, or `webAuth` for private/restricted); author is the submitted `name` (`:131-138`, trimmed, <=100 bytes, default `anonymous`); `UpsertVisitor` + `setNameCookie` when not anonymous (`:140-146`); `AddComment(..., in.Name, s.commentVisitorHash(vid), in.Body)` (`:148`). Nothing marks a comment as coming from a signed-in account, so any viewer can type `Alice (owner)`.
- `comments.go:195-243` `handleAddAccountComment` (bearer route `.../account-comments`): author = `owner.Name` (token account), cookie hash `"account:"+id`; response `commentOut` without `Version`.
- `commentOut` (`comments.go:23-32`): `id, selector, element_text, anchor_kind, author, body, created_at, version`; built in three places (`:92-96`, `:160-164`, `:238-242`).
- `webAuth` (`web_auth.go:13-43`) returns `(*models.Account, bool)`; rejects disabled accounts, wrong email domain, and non-OAuth non-admins when OAuth is required.
- DB: `internal/db/schema.go:50-61` comments table has no account column; `internal/db/comments.go:10-27` `AddComment(ctx, uploadID int64, version int, selector, text, anchorKind, author, cookie, body string)`; `ListComments` (`:30-55`) selects 10 columns. `models.Comment` (`internal/models/models.go:120-131`) has no account field. Accounts are never deleted (no `DELETE FROM accounts`).
- Other readers of comments: `internal/server/api_stats.go:85-93,126-131` (export JSON `exportComment`), `internal/cli/stats_comments_command.go:99` (reads `author` only), `db/versions.go:126` (delete).
- Frontend: comments panel is Alpine markup in `internal/web/templates/page.gohtml:106-119` (`x-text="c.name"` at :113); data normalized in `internal/web/assets/app.js:34-60` (`colorizeComments` keys colors by `comment.author`; `normalizeComment` sets `name`); markdown export at `app.js:502`. Name prompt modal: `page.gohtml:144-160`, `app.js:157-175, 436-445, 511-557`.
- AddComment callers: server `comments.go:148`, `:231`; tests `internal/server/api_test.go:101`, `internal/db/store_test.go:174, :177, :207, :675, :678`.

##### Design
- Signed-in browser comments: if `s.webAuth(r)` succeeds, the submitted `name` is ignored; author = account display name (`Name`, or `Email` when `Name` is blank), and `account_id` = account id. Otherwise unchanged (typed name, `account_id` NULL).
- Account (bearer) comments also store `account_id = owner.AccountID`.
- `commentOut` and the export gain `verified bool` (`json:"verified"`), true iff `account_id` is set.
- UI shows a marker next to verified authors, and colors verified and unverified authors with the same name separately.
- Migration 13 adds nullable `comments.account_id INTEGER` (no FK: accounts are never deleted, and a FK column cannot be dropped in the migration test).

###### DB / models
- `internal/models/models.go` `Comment`: add field `AccountID int64 // 0 when the author name was typed, not a signed-in account` after `AuthorCookie`.
- `internal/db/schema.go` comments table: add line `account_id INTEGER,` after `version INTEGER NOT NULL DEFAULT 1,`.
- `internal/db/migrations.go`:
  - slice entry after 10 (and after 11/12 when present): `{13, "comment_account_id", `-- ALTER TABLE handled idempotently below`},`
  - runner branch next to `m.id == 10`: `} else if m.id == 13 { if err := s.migrateCommentAccountID(); err != nil { return fmt.Errorf("migration %d (%s): %w", m.id, m.desc, err) } }`
  - ```go
    // migrateCommentAccountID records which signed-in account wrote a comment.
    // NULL means the author name was typed by the viewer.
    func (s *Store) migrateCommentAccountID() error {
    	if _, err := s.Exec(`ALTER TABLE comments ADD COLUMN account_id INTEGER`); err != nil && !isDuplicateColumnError(err) {
    		return err
    	}
    	return nil
    }
    ```
- `internal/db/comments.go`:
  - signature `func (s *Store) AddComment(ctx context.Context, uploadID int64, version int, selector, text, anchorKind, author, cookie, body string, accountID int64) (models.Comment, error)`; insert `account_id` with `var accountArg any; if accountID > 0 { accountArg = accountID }` (pattern of `grants.go:21-24`); returned struct sets `AccountID: accountID` (0 when <= 0).
  - `ListComments`: select `...,body,created_at,account_id`; scan into `var account sql.NullInt64`; `c.AccountID = account.Int64`. Add import `database/sql`.

###### Server (comments.go)
- `commentOut`: add `Verified bool `json:"verified"`` after `Author`.
- Add helper and use it at all three construction sites (also gives the account-comment response its `version`, previously 0):
  ```go
  func commentOutFrom(c models.Comment) commentOut {
  	return commentOut{
  		ID: c.ID, Selector: c.ElementSelector, Text: c.ElementText,
  		AnchorKind: commentAnchorKind(c.ElementSelector, c.ElementText, c.AnchorKind),
  		Author:     c.AuthorName, Verified: c.AccountID != 0,
  		Body: c.Body, CreatedAt: c.CreatedAt.Unix(), Version: c.Version,
  	}
  }

  // commentAccountName is the author name shown for a signed-in account.
  func commentAccountName(a *models.Account) string {
  	if name := strings.TrimSpace(a.Name); name != "" {
  		return name
  	}
  	return a.Email
  }
  ```
- `handleAddComment`, replace lines 131-148 with:
  ```go
  var accountID int64
  if a, ok := s.webAuth(r); ok {
  	// A signed-in viewer always comments as their account; a typed name is ignored.
  	in.Name = commentAccountName(a)
  	accountID = a.ID
  } else {
  	in.Name = strings.TrimSpace(in.Name)
  	if len(in.Name) > 100 {
  		jsonError(w, http.StatusRequestEntityTooLarge, "field too long")
  		return
  	}
  	if in.Name == "" {
  		in.Name = "anonymous"
  	}
  }

  vid := s.visitorID(w, r)
  if in.Name != "anonymous" {
  	if err := s.store.UpsertVisitor(r.Context(), vid, in.Name); err != nil {
  		slog.Warn("comment visitor upsert failed", "upload_id", u.ID, "err", err)
  	}
  	s.setNameCookie(w, in.Name)
  }

  if _, err := s.store.AddComment(r.Context(), u.ID, version, in.Selector, in.Text, in.AnchorKind, in.Name, s.commentVisitorHash(vid), in.Body, accountID); err != nil {
  ```
- `handleAddAccountComment` `AddComment` call (:231-232): append `, owner.AccountID`; response `jsonOK(w, commentOutFrom(c))`.
- Do not change `viewerCanAccessUpload`, the rate limiter, or the bearer path in `handleListComments` (other phase).

###### Export (api_stats.go)
- `exportComment`: add `Verified bool `json:"verified"`` after `Author`; set `Verified: c.AccountID != 0` at :129.

###### Frontend
- `internal/web/assets/app.js`:
  - `colorizeComments` (:38): `const author = (comment.verified === true ? "verified:" : "guest:") + (comment.author || "anonymous");`
  - `normalizeComment` (:50-52): add `verified: comment.verified === true,` after `name`.
  - markdown export (:502): `text += "## " + (c.name || "anonymous") + (c.verified ? " (signed in)" : "") + " (" + c.created_human + ")\n";`
  - No HTML string APIs; no other JS change. The name modal is unchanged (a signed-in viewer may still be asked for a name once; it is ignored server-side). Hiding the prompt for signed-in viewers needs a `PageData` field set in pages.go, which another phase owns -> follow-up, not in P4.
- `internal/web/templates/page.gohtml:113`: after `<strong class="font-semibold" :style="{ color: c.authorText }" x-text="c.name"></strong>` insert
  ```html
  <span x-show="c.verified" class="hn-comment-verified text-[11px] font-medium text-muted-foreground whitespace-nowrap" title="Posted by a signed-in Peek account">&#x2713; signed in</span>
  ```
  (static text, no binding of user data; all utility classes already exist in pines.css; `hn-comment-verified` is a hook class with no CSS.)

##### Tests (P4)
- `internal/db/store_test.go`: update the 5 `AddComment` calls (:174, :177, :207, :675, :678) to pass trailing `0`. Add `TestCommentAccountIDRoundTrip`: one comment with `accountID` = a created account's id, one with `0`; `ListComments` returns `AccountID` equal to the id and `0` respectively; `AddComment`'s returned struct matches.
- `store_test.go` add `TestMigrationAddsCommentAccountID` (pattern of `tokens_test.go:218-262`): open, create account/upload/comment, `ALTER TABLE comments DROP COLUMN account_id`, `DELETE FROM schema_migrations WHERE id=13`, close, reopen; `s.columnInfo("comments", "account_id")` exists; `ListComments` returns the old comment with `AccountID == 0`.
- `internal/server/api_test.go:101`: append `0` to `AddComment`.
- `internal/server/comments_test.go` add:
  - `TestAddCommentSignedInViewerUsesAccountName`: `newHandlerTestServer`; public upload; `viewer := newViewer(t, s, "ada@example.com", "Ada Lovelace", false)`; POST `/api/uploads/<slug>/comments` body `{"name":"Alice (owner)","body":"hi"}` with `asSession(s, viewer.ID)` and `withJSON()`; 200; body contains `"author":"Ada Lovelace"` and `"verified":true`, not `Alice (owner)`; `s.store.ListComments` -> `AccountID == viewer.ID`.
  - `TestAddCommentAnonymousViewerIsUnverified`: same without session; body contains `"author":"Alice (owner)"` and `"verified":false`.
  - `TestAddCommentDisabledSessionIsUnverified`: viewer disabled with `s.store.SetAccountDisabled(ctx, viewer.ID, true)` with session on a public page; author is the typed name, `"verified":false`.
  - `TestAddCommentSignedInBlankNameUsesEmail`: account with Name `""` (create via store with empty name) -> author is the email.
  - `TestAccountCommentIsVerified`: `postAccountComment` -> body contains `"verified":true`; listing via browser GET shows `"verified":true`.
- `internal/server/api_stats_test.go` add `TestExportMarksVerifiedComments` (no existing export test covers comments): via `GET /api/uploads/<slug>/export` with the owner's bearer token, assert `"verified":true` for an account comment and `"verified":false` for a typed one.
- `internal/web/renderer_test.go` add `TestPageTemplateShowsVerifiedCommentMarker`: render `TemplatePage`; body contains `hn-comment-verified` and `x-show="c.verified"`.
- `internal/web/assets_test.go` add `TestParentAppMarksVerifiedComments`: app.js source contains `verified: comment.verified === true` and `"verified:"`.

##### Docs (P4)
- `docs/src/content/docs/reference.md:119`: field list becomes `id`, `selector`, `element_text`, `anchor_kind`, `author`, `verified`, `body`, `created_at` (Unix seconds) and `version`; add sentence: `verified is true for comments written by a signed-in account or through this API, false when the author name was typed by a viewer.`
- `docs/src/content/docs/using-peek.md:82`: append `Comments from signed-in Peek accounts show the account name with a "signed in" marker; a signed-in viewer cannot choose another name. Names without the marker were typed by the viewer and are not verified.`
- `docs/operations.md` "Upgrades And Rollbacks": add `Migration 13 (comment_account_id) adds a nullable account_id to comments. Comments written before it are shown as unverified. Older binaries ignore the column, so a rollback keeps comments readable but new comments lose the verified marker.`
- `docs/src/content/docs/auth-access.md` table rows public/password (:109-110): no change needed.

##### Stop conditions (L8)
- Migration id 13 is already taken when P4 starts: use the next free id and update the docs/tests accordingly; report it.
- The token-policy phase has changed `handleAddAccountComment`'s auth (e.g. `requireAPIToken` replaced): keep their auth code, only apply the `AddComment` argument and `commentOutFrom` changes; if the owner variable no longer has `AccountID`, stop.
- `webAuth` signature changed by the session-epoch phase: adapt the call only if it still returns `(*models.Account, bool)`; otherwise stop.
- Any need to touch pages.go or PageData: stop (out of scope).


### Design E — coverage to 90% (inventory, seams, per-phase scope, gate)


Scope: a plan only. Nothing in the repo was changed. Source data: `scratchpad/cover.out` (mode `set`, HEAD `6380c6b`), parsed block by block (blocks with count 0, mapped back to source lines). Line numbers below come from HEAD and **will shift** after the security phases merge. Each coverage phase therefore begins by re-profiling and re-listing its own uncovered blocks (command in §6).

#### 1. Key facts that shape the plan

1. **Coverage is measured per package.** `go test -coverprofile=coverage.out ./...` without `-coverpkg` only credits a package's own tests. This is why `internal/db` shows `oauth.go` 0/14, `visits.go` 28/41 uncovered and so on: server tests run that code, but it does not count toward db. The db package needs its own direct tests. Switching the metric to `-coverpkg=./...` would raise the number without any new tests, but it changes the agreed metric, so it is **not** recommended. It is noted here only so nobody "discovers" it as a shortcut mid-plan.
2. Totals: 5336 statements, 3675 covered. Uncovered by package: server 873/2916 (70.1%), db 264/936 (71.8%), cli 290/807 (64.1%), peekd 93/212 (56.1%), objectstore 88/218 (59.6%), uploads 27/151 (82.1%), web 16/46 (65.2%), groups 7/47 (85.1%), cmd/peek 1/1, cmd/peekd 1/1, internal/version 1/1. `models` and `uploadquota` have no statements.
3. The external test package `server_test` (`api_test.go`, `setup_test.go`, `http_test_helpers_test.go`, `rename_e2e_test.go`, `visibility_e2e_test.go`, `account_comments_route_test.go`) **does** count toward server coverage.

#### 2. Existing fault-injection seams (verified)

| Seam | Where | How it is used today |
|---|---|---|
| `var secureRandomRead = rand.Read` | `internal/server/security.go:17` | `stubSecureRandomRead(t, func([]byte)(int,error))` in `internal/server/web_csrf_test.go:109`. It drives every `randID`, `newCSRFToken`, `encryptSecret` nonce, `loadOrCreateSecret` and `randomUserCode` failure in package server. So "rand failure" in server is **reachable**, not class (c). |
| `DROP TABLE` through the embedded `*sql.DB` | `db.Store` embeds `*sql.DB` (`internal/db/store.go:9`) | `store.Exec("DROP TABLE uploads")` in `web_dashboard_test.go:55`, and also for `visits`, `audit_log` and `visitors` (`api_stats_test.go:34`, `lifecycle_test.go:130`, `comments_test.go:27`). This is the established way to force "db error" 500s. |
| SQLite trigger `RAISE(ABORT, …)` | new; nothing uses it yet | Verified with modernc sqlite v1.52.0: `CREATE TRIGGER f BEFORE INSERT ON t BEGIN SELECT RAISE(ABORT,'injected'); END` makes that one statement fail with `constraint failed: injected`. This is the way to fail **one** write (an INSERT/UPDATE/DELETE inside a tx, or CreateAccount during setup) while reads keep working. The store uses `SetMaxOpenConns(1)`, so even TEMP triggers would work, but use plain triggers. |
| Corrupt row data | new | Verified: `INSERT … VALUES(1,'abc')` into an INTEGER column, then `Scan(&int64)` returns `converting driver.Value type string ("abc") to a int64`. This reaches the `rows.Scan` error branches in db. |
| Closed store | not used mid-test today; only in `t.Cleanup` | Verified: `(*sql.DB).Close()` is idempotent (a second close returns nil), and calls afterwards return `sql: database is closed`. Use it for `/readyz` Ping failure, metrics error branches, and the db "every method on a closed store" table test. Existing `t.Cleanup(func(){ _ = store.Close() })` stays safe. |
| Failing / fake Storage | `rawPageStorage` (pages_test.go:21, Open returns body), `retentionCleanupStorage` (lifecycle_test.go:22, Delete err), `dashboardDeleteStorage` (web_dashboard_test.go:27, Delete err), `memoryStorage` (uploads/service_test.go:17) | **No fake whose Save or Open fails exists in package server.** Phase S1 adds one (§5). |
| Hand-built `&Server{store, renderer, secret, storage, baseURL}` | `newAdminTestServer` (admin_test.go:100), `newWebLoginTestServer` (web_login_test.go:59), `newDashboardDeleteTestServer` (web_dashboard_test.go:363), `newRetentionCleanupTestServer` (lifecycle_test.go) | Lets a test call a handler directly with a nil limiter or a zero renderer. A zero-value `&webui.Renderer{}` makes `Execute` return "renderer is not initialized", which covers `render.go:12-16`. |
| Full server harness | `newHandlerTestServer(t) (*Server, adminToken string)`, `doRequest(t, s, method, path, body, opts...)`, `asBearer(tok)`, `asSession(s, accountID)`, `withJSON()`, `newAccountWithToken(t, s, email, token, isAdmin) *models.Account` (handler_helpers_test.go); `dashboardPost(t, s, accountID, path, form url.Values, withCSRF bool)`, `assertDashboardRedirect(t, rec, want)` (web_dashboard_test.go:408/423); `dashboardInviteRequest(s, accountID, id)` (admin_test.go:118) | Used for routed handler tests (internal package). External package: `newTestApp(t) testApp` with `.request/.requestJSON/.requestString`, `withAuth`, `withCookies`, `assertStatus`, `decodeResponseJSON[T]` (http_test_helpers_test.go). |
| OAuth fakes | `newFakeOIDCServer(t, issuer, clientID, sub, email) *fakeOIDCServer` with `.client()` (rewriteHostTransport), `restoreGitHubURLs(t, base)` (package vars `githubUserURL` and `githubEmailsURL`), `testGitHubProviderConfig()`, `oidctest.Server` / `oidctest.SignIDToken`, `oidc.ClientContext(ctx, client)` (oauth_test.go) | Callback tests inject the HTTP client through `req.WithContext(oidc.ClientContext(...))`. `fetchGoogleProfile` hard-codes `https://accounts.google.com`, but the same `rewriteHostTransport` plus a discovery doc served at `/.well-known/openid-configuration` with `issuer: https://accounts.google.com` reaches it **without a production seam**. |
| CLI | `setTestConfigHome(t)`, `configureTestClient(t, host)` (sets `PEEK_HOST` and `PEEK_TOKEN`), `captureStdout(t, fn) (string, error)` (cli/test_helpers_test.go); package vars `oauthSleep = time.Sleep` and `oauthOpenBrowser = openBrowser` (login_oauth.go:16-17); `httpClient` (client.go:70) | Stdin has no seam. Tests swap `os.Stdin` for an `*os.File` (temp file or `os.Pipe`). A non-terminal stdin makes `term.IsTerminal` false, which reaches the non-TTY path. |
| groups | `newDirectoryWithClient(client, baseURL, ttl, now)`, `newTestDirectory(t, status, body)` (groups/directory_test.go:18) | httptest fake Directory API. |
| objectstore | `NewS3Storage(allowPrivateEndpoint bool, getSetting func(string) string)` | With `allowPrivateEndpoint=true`, the safe dialer allows 127.0.0.1, so an `httptest.NewServer` fake S3 works directly. `TestS3HTTPClientAllowsPrivateDialWithOptIn` already does this. |
| peekd | `Run(args []string) int`, `runServe(cfg serveConfig) int`, `parseServeConfig(args)`, `runBackup`, `runHealthcheck` | `runServe` blocks on `signal.Notify(stop, SIGINT, SIGTERM)`. It can be driven with **no seam**: the test first calls its own `signal.Notify(guard, syscall.SIGTERM)`, which disables the default kill action. It then picks a free port (listen on `127.0.0.1:0`, take the addr, close), starts `runServe` in a goroutine, polls `/healthz`, and sends `syscall.Kill(os.Getpid(), syscall.SIGTERM)`. Both channels receive the signal, and `runServe` returns 0. The error branch comes from passing the addr of a listener that is still open (address in use), which returns 1. |

There is no production seam to add. All class-(b) branches listed below are reachable through the seams above. The plan explicitly **forbids new production seams** unless a phase proves a block is unreachable otherwise. In that case the only allowed form is a package-level `var` of a func type, defaulting to the real func (for example `var notifyShutdown = signal.Notify` in `internal/peekd/run.go`). This is listed as a fallback, not as part of the plan.

#### 3. Classification of the 1661 uncovered statements

Method: a heuristic split of each count-0 block (an `err != nil`, `Err()` or `err == nil` guard counts as (b), a Commit/rand guard as (c)), then a manual correction for seams that make (c) reachable. "(a)" means reachable through normal HTTP/CLI/API calls. "(b)" means it needs fault injection through the seams in §2. "(c)" means effectively unreachable in a unit test.

| Package | Uncovered | (a) normal | (b) fault-inj. | (c) unreachable (est.) | Max achievable |
|---|---|---|---|---|---|
| server | 873 | ~485 | ~375 | ~12 (AES `NewCipher`/`NewGCM` errors with a validated 32-byte key: security.go:150-156, 183-189 = 4; bcrypt failure after length validation: web_setup.go:63-66 = 2; `hs.Shutdown`-style timing and `ctx.Done` races in analytics/lifecycle ≈ 3; misc ≈ 3) | ~99.5% |
| db | 264 | ~109 | ~115 | ~40 (`tx.Commit()` errors: 6; `sql.Open` err: 1; deep `migrations.go` mid-migration failures that need an almost-migrated legacy DB plus a precise failure point: ~25; `rows.Err()` after iteration: ~5; misc ≈ 3) | ~95.7% |
| cli | 290 | ~193 | ~85 | ~12 (`readTokenInteractive` TTY branch login_command.go:18-25 = 6; `openBrowser` darwin/windows cases = 2; multipart `WriteField` after pipe close and `json.Encode` failure ≈ 4) | ~98.5% |
| peekd | 93 | ~80 | ~9 | ~4 (`filepath.Abs` err, `hs.Shutdown` err, `srv.Close` err, `case <-ctx.Done()` has 0 statements) | ~98% |
| objectstore | 88 | ~70 | ~15 | ~3 (`readS3ErrorBody` read error, `http.NewRequest` error with a sane URL, file.go rename-cleanup race) | ~98.6% |
| uploads | 27 | ~18 | ~5 | ~4 (`crypto/rand` failure in slug.go:100,108 has no seam in uploads; bcrypt failure visibility.go:43) | ~97% |
| web | 16 | ~13 | ~1 | ~2 (`init` ReadDir error assets.go:37; `NewRenderer` parse error of embedded templates renderer.go:55) | ~95% |
| groups | 7 | ~7 | 0 | 0 | 100% |
| cmd/peek, cmd/peekd | 2 | 0 | 0 | 2 (`main()`) | 0% |
| internal/version | 1 | 1 | 0 | 0 | 100% |
| **Total** | **1661** | | | **~79** | **~98.5%** |

Conclusion: ≥90% is comfortably achievable in principle. The binding constraint is test-writing volume (about 1300 statements of the ~1590 reachable ones would be covered by the phases below), not reachability.

##### Server split by security-touched vs untouched files

Security-touched files hold 516 uncovered statements: pages 40, web_dashboard 63, cli_login 82, api_uploads 54, oauth_profile 49, metrics 44, oauth_flow 37, comments 30, web_login 25, oauth_config 19, oauth_accounts 18, middleware 12, security 12, lifecycle 10, analytics 6, web_auth 6, oauth_session 5, health 4.

Untouched files hold 357: admin 85, api_stats 43, settings 41, api_tokens 29, server.go 23, web_api_keys 22, web_setup 20, runtime_settings 17, web_grants 13, bootstrap 12, assets 10, api_grants 9, api_rename 7, api_versions 5, api_audit 4, render 4, access 3, auth_domain 2, upload_delete 2, web_format 2, web_helpers 2, json_decode 1, upload_service 1.

Untouched files alone cannot reach 91% (357 − ~10 unreachable = 347, but 611 are needed), so coverage phases must also fill the gaps that remain in security-touched files after those phases merge. Those files will probably gain tests from the security work, so the S3–S6 scopes below are "whatever is still count-0 after re-profiling".

#### 4. Targets: validation and adjustment

The proposed targets are server ≥91, db ≥92, cli ≥91, objectstore ≥92, peekd ≥85, uploads ≥92, web ≥90, groups ≥90.

- **db 92% is tight.** It allows at most 75 uncovered, so 189 of 264 must be covered, while ~40 are effectively unreachable and the cheap closed-store and trigger patterns reach ~150–170. It is achievable only if D2 (migrations and legacy fixtures) succeeds fully. **Adjusted: db ≥90%** (≤93 uncovered).
- **peekd 85% is too low** given that runServe is fully drivable. **Adjusted: peekd ≥90%** (≤21 uncovered).
- **groups 90% is too low** because everything is reachable. **Adjusted: groups ≥95%.**
- The others are realistic as proposed: server ≥91, cli ≥91, objectstore ≥92, uploads ≥92, web ≥90.

Arithmetic at the adjusted floors, with denominators at HEAD:

| Pkg | Stmts | Floor | Max uncovered | Must cover (of uncovered) |
|---|---|---|---|---|
| server | 2916 | 91% | 262 | 611 / 873 |
| db | 936 | 90% | 93 | 171 / 264 |
| cli | 807 | 91% | 72 | 218 / 290 |
| objectstore | 218 | 92% | 17 | 71 / 88 |
| peekd | 212 | 90% | 21 | 72 / 93 |
| uploads | 151 | 92% | 12 | 15 / 27 |
| web | 46 | 90% | 4 | 12 / 16 |
| groups | 47 | 95% | 2 | 5 / 7 |
| cmd + version | 3 | – | 2 | 1 / 3 |
| **Total** | **5336** | | **485** | **1176** |

At the floors the total is (5336 − 485) / 5336 = **90.91%**, which is ≥ 90.5% with about 21 statements of slack above 90.5 and about 48 above the 90.0 gate. The expected outcome when phases hit their estimates (§5) is about **92.5–93%**. Code added by the security phases (with its own tests, assumed ≥85% covered) moves the total by under 0.1 pp per 100 new statements. The final gate phase G re-verifies the total before it turns the gate on.

#### 5. Work breakdown (coverage-only phases)

General rules for every phase:

- **Order.** All coverage phases run after the security phases have merged. S1 runs first among the server phases, because it creates the shared server fault helpers. S2–S6 then run in parallel. D1 runs before D2, and C1 before C2. O1, P1 and X1 are independent. G runs last.
- **Step 0 of every phase.** Re-profile with `go test -coverprofile=/tmp/c.out ./internal/<pkg>/` and list the count-0 blocks for the phase's files (§6). Write tests **only for blocks still at 0**. Never duplicate or re-assert security behaviour (CSRF, SSRF, auth, rate-limits, cookie flags) that security phases already test. Reaching a branch is the goal, and assertions should be the minimal status, Location or body check that proves the branch ran.
- **Files.** Extend the existing `<source>_test.go` when it exists. Create `<source>_test.go` when it does not, and check first whether a security phase already created it. Each phase owns only the test files listed for it, so file sets are disjoint across phases.
- **Helper name collisions.** All server phases compile into one package. New top-level helpers outside `fault_helpers_test.go` must carry a phase-unique prefix: `adm…` (S1), `apiCov…` (S2), `dash…Cov` (S3), `oauthCov…` (S4), `cliLoginCov…` (S5), `pageCov…` (S6). Alternatively, keep them as closures inside the test function. Grep for the identifier before adding it.
- **Test style.** Prefer table-driven tests. Do not use `t.Parallel()` in tests that stub package vars (`secureRandomRead`, `githubUserURL`, `oauthSleep`, `os.Stdin`, `os.Stdout`, signals), because CI runs `-race`.
- **Budget.** Each phase has about 600 lines of new test code or less. Acceptance for each phase is that `mise run check` passes and the package coverage meets the expected figure.

##### Phase S1: server admin, setup, bootstrap, construction, render, assets, plus the shared fault helpers

New file `internal/server/fault_helpers_test.go` (package server, about 90 lines). Phases S2–S6 depend on it.

- `type faultStorage struct{ mu sync.Mutex; objects map[string][]byte; saveErr, openErr, deleteErr error }` implements `objectstore.Storage` (Save, Open, Delete). Grep first for collisions with the security phases.
- `type failingWriter struct{ httptest.ResponseRecorder }` whose `Write([]byte) (int, error)` returns `errors.New("write failed")`. It is used for render.go:19 and pages.go:273/282.
- `func addFailTrigger(t *testing.T, store *db.Store, table, op string)` runs `CREATE TRIGGER cov_fail_<table>_<op> BEFORE <op> ON <table> BEGIN SELECT RAISE(ABORT,'injected failure'); END`, where `op` is INSERT, UPDATE or DELETE.
- `func dropTable(t *testing.T, store *db.Store, name string)`.
- `func newFaultServer(t *testing.T) (s *Server, store *db.Store, storage *faultStorage, adminID int64)` returns an `&Server{store, renderer: webui.NewRenderer(), secret: strings.Repeat("0",64), storage, baseURL: "http://localhost:7700", <all limiters via newLimiter(1000, time.Minute)>}` plus a seeded admin account.

Blocks to cover (line:count at HEAD):

- `admin.go` (85 uncovered, target ≥95% file), in `admin_test.go` (extend). Uses `newAdminTestServer`, `dashboardInviteRequest`, `dashboardPost` and `asSession`.
  - `handleInviteLink` 25-33 (2): a valid pending invite sets the cookie.
  - `handleDashboardCreateInvite` 38-69 (19): non-admin redirect; bad form (`parseDashboardForm` false via missing CSRF); empty or no-@ email; `randID` failure via `stubSecureRandomRead`; `encryptSecret` failure via `s.secret = "zz"` (invalid hex); `CreateInvite` failure via `addFailTrigger(store,"invites","INSERT")`; success.
  - `handleDashboardRevokeInvite` 74-92 (7): non-admin, bad form, store failure via `addFailTrigger(...,"invites","UPDATE")`.
  - `handleDashboardUserAdmin` 98-122 and `handleDashboardUserDisabled` 125-149 (34): non-admin, bad form, non-numeric id, `db.ErrLastAdmin` (demote the only admin), generic failure via `addFailTrigger(...,"accounts","UPDATE")`, success.
  - `dashboardInviteRows` 154-182 (12): list failure via `dropTable("invites")`; used, revoked and expired invites, using `store.ConsumeInvite`, the revoke API, and an `expiresAt` in the past.
  - `dashboardAccountRows` 195-212 (8): call directly; the failure path uses `dropTable("accounts")` on a separate store.
- `web_setup.go` (20, target ≥90%): new `internal/server/web_setup_test.go`. Use `newHandlerTestServer` (fresh install, so setup is required) or `New(Config{DataDir})` with no accounts. Cover the GET redirect when setup is already done (16-19), a missing code (26-28), POST bad form (33-36), CSRF token generation failure via `stubSecureRandomRead` (39-42), an invalid code (43-46), empty email (50-53), empty password (54-57), a password over 72 characters (58-61), and the CreateAccount failure via `addFailTrigger(...,"accounts","INSERT")` (68-71). 63-66 (bcrypt) is class (c).
- `bootstrap.go` (12): new `internal/server/bootstrap_test.go`, or extend `setup_test.go` only if the external package is needed. Direct calls: `loadOrCreateSecret` with `stubSecureRandomRead` failing (45-47) and with a path whose parent is a regular file (49-51); `bootstrapSetup` with an existing code file (74-79), with the rand failure (82-84), and with a write failure where the data dir is a file (85-87); `readSetupCode` missing (107-109); `validSetupCode` when not required or wrong (114-120).
- `server.go New` (23, target ≥90%): new `internal/server/server_test.go`. Table over `Config`: `DataDir` is an existing regular file (78-80); `Storage:"s3"` with an empty bucket (81-84); `Secret:""` creating `secret.key` (90-95); `Storage:"s3"` plus `S3Bucket`, `S3Endpoint:"https://8.8.8.8"` and `S3AllowPrivateEndpoint:false` succeeds (137-146); the s3_endpoint setting pre-seeded to `http://127.0.0.1:9` without the private opt-in gives a ValidateS3Endpoint error (139-141); a non-local `BaseURL` (`https://peek.example.com`) with `TrustedProxy:false` (157-159, 189-191); `Groups:` a stub `GroupChecker` (185-187). Each successful case calls `t.Cleanup(s.Close)`. 98-105, 110-112, 122-129 and 149-151 are db or open failures; cover the ones reachable by pre-creating `uploads` as a regular file in DataDir (149-151) and skip the rest.
- `render.go` (4): new `internal/server/render_test.go`. Use `&Server{renderer:&webui.Renderer{}}` with `renderHTML` to get a 500 (12-16), and a real renderer with `failingWriter` (19-21).
- `assets.go` (10): new `internal/server/assets_test.go`. A table of `doRequest(GET /bridge.js, /app.js, /dashboard-alpine.js, /alpine.min.js, /pines.css, /favicon.svg|png|ico, /logo.svg|png)` that asserts 200.
- `web_format.go` (2): new `web_format_test.go` with `humanSize(2048)` and `humanSize(3<<20)`.
- `json_decode.go` (1): extend `json_decode_test.go` with `decodeJSON(..., limit 0)`.

New code is about 580 lines. Expected server after S1: about 74.5%. The listed files should each reach ≥90%.

##### Phase S2: server token, stats, grants, rename, versions, audit APIs, settings, runtime settings, small helpers

Files: `api_stats_test.go` (extend), new `api_tokens_test.go`, `api_grants_test.go` (extend), new `api_rename_test.go`, new `api_versions_test.go`, new `api_audit_test.go`, `settings_test.go` (extend), `runtime_settings_test.go` (extend), `access_test.go` (extend), `auth_domain_test.go` (extend), new `upload_delete_test.go`, `upload_service_test.go` (extend), `web_helpers_test.go` (extend). Use `newHandlerTestServer`, `doRequest`, `asBearer`, `newAccountWithToken`, and from S1 `dropTable`, `addFailTrigger`, `faultStorage` and `stubSecureRandomRead`.

- `api_stats.go` (43): `handleStats` 10-51 is **entirely uncovered** (route `GET /api/uploads/{slug}/stats`). Cover 404, non-owner 403, owner 200 with one recorded visit (`s.store.RecordVisit` or `app.flushVisits`), `CountVisits` failure via `dropTable("visits")`, and the `RecentVisits` failure. `handleExportUpload` 56-146: 404, 403, and db failures via `dropTable` of `comments`, `visits` and `upload_versions`, in that order. `handleViews` 166-186: 404 and the two db failures.
- `api_tokens.go` (29): `handleCreateToken` bad JSON or empty name (24-27), `randID` failure (29-32), store failure via `addFailTrigger("tokens","INSERT")` (37-40); `handleListTokens` failure (47-50); `handleDeleteToken` 65-89 (all of it: bad id, 404, last-admin 400, generic failure via `addFailTrigger("tokens","DELETE")`, success); `actorName(nil)` (96).
- `api_grants.go` (9), `api_rename.go` (7), `api_versions.go` (5), `api_audit.go` (4): 404/403/bad-JSON paths and `dropTable("upload_grants" | "upload_versions" | "audit_log")`; `?limit=5` on `/api/audit`.
- `settings.go` (41): `handleGetSettings` failure (48-51), the unknown-key label (55-57), the secret mask (59-61); `handleUpdateSettings` bad JSON (78-81) and the `encryptedSetSetting` failure via `addFailTrigger("settings","INSERT")` (97-100); the normalize helpers' error branches as direct table tests against `normalizeSettingValue`, `normalizeBoolSetting`, `normalizeNonNegativeInt64Setting`, `normalizeNonNegativeIntSetting`, `parseInt64Setting` and `dashboardMegabytesToBytes` (125-194, 276-293); `handleDashboardSettings` non-admin (210-213), the normalize error path (221-232), a blank secret skip (236), and the write failure (251-254); the `dashboardSettingsMap` nil map (308), `dashboardSettingMegabytes` rounding (432), `dashboardSettingInt64` bad value (444), `settingValueBool("yes")` (452), the `maxInt64` second branch (463), and the `dashboardSettingsRows` unknown key (492).
- `runtime_settings.go` (17): `initDefaultSettings` on an existing key (13-15), a secret key with an invalid secret (18-20), `upsert` failure via `addFailTrigger("settings","INSERT")` (33-41); `settingInt64` and `settingInt` with a non-numeric value (53, 65); `decryptedStoreSetting` missing or bad (84-93); `encryptedSetSetting` encrypt error with a bad secret (100); `encryptedGetAllSettings` with `dropTable("settings")` (110) and with secret-key decrypt success and failure (114-120).
- Small helpers:
  - `access.go:27-30, 38-39`: grant lookup with `dropTable("upload_grants")`, and a user-kind grant skipped in the group loop.
  - `auth_domain.go:35, 68`.
  - `upload_delete.go:12-21`: `deleteUpload` with `dropTable("upload_versions")`, and with no versions, which falls back to the slug key.
  - `upload_service.go:37`: an unknown `uploads.ErrorKind`.
  - `web_helpers.go:49-52`: `parseDashboardForm` CSRF generation error via `stubSecureRandomRead`.

New code is about 600 lines; split `settings` into its own follow-up phase S2b if it exceeds that. Expected server after S2: about 79.5%.

##### Phase S3: server web dashboard, API keys, web grants, web login, web auth (security-touched files: re-profile first)

Files: `web_dashboard_test.go` (extend), `web_api_keys_test.go` (extend), `web_grants_test.go` (extend), `web_login_test.go` (extend), new `web_auth_test.go` (unless a security phase created it). Use `dashboardPost`, `assertDashboardRedirect`, `newDashboardDeleteTestServer`, `newWebLoginTestServer`, and `newFaultServer`, `faultStorage`, `addFailTrigger` and `dropTable` from S1.

Remaining count-0 blocks at HEAD:

- `web_dashboard.go` (63): `handleDashboard` setup redirect (20-23), unauthenticated redirect (25-28), admin `ListAllUploads` (31-33), grants list failure (52-54), admin invites and accounts (83-86), the `?err=` and `?uploaded=` flashes (88-96). `handleDashboardUpload` 100-169: unauthenticated, multipart parse error, CSRF error, invalid CSRF, pasted-HTML empty or unnamed, missing file, oversized file, filename default, and the service error via `faultStorage{saveErr}`. `handleDashboardDelete` and `handleDashboardVisibility` unauthenticated, not found, non-owner, and the visibility store failure via `addFailTrigger("uploads","UPDATE")`. `handleDashboardStats` unauthenticated, non-owner, and the buckets failure. `statsSparkline` with all-zero buckets (323, 344), and `visitCountLabel(1)` (358).
- `web_api_keys.go` (22): `newAPIKey` rand failure (28); `dashboardAPIKeyRow` with LastUsedAt and an expired key (67-74); the list failure via `dropTable("tokens")` (81-84); create failure (126-130); regenerate not found or rate-limited, by building the server with `apiKeyLimiter: newLimiter(0, time.Minute)` (145-152); regenerate failure (162-166); revoke unauthenticated (173-176); revoke failure (190-194).
- `web_grants.go` (13): unauthenticated (16-19), not found (24-27), the add failure via `addFailTrigger("upload_grants","INSERT")` (47-51), the remove-path flash (64-67), the remove failure (73-75).
- `web_login.go` (25): setup redirect (17-20), CSRF error and invalid (31-38), `method=password` paths in `loginWithPassword` 65-84 (missing, unknown email, disabled, oauth-required non-admin, wrong password, success), the unsupported method (50-51), `loginWithToken` missing, invalid and disabled (89-98), and logout bad form, CSRF error and success (140-156).
- `web_auth.go` (6): a bad cookie, an unknown account, the db error, and oauth-required without an identity (19-40).

Budget: at most 600 lines. Expected server after S3: about 83%.

##### Phase S4: server OAuth (oauth_flow, oauth_profile, oauth_config, oauth_accounts, oauth_session; re-profile first)

Files: `oauth_test.go` (extend, which holds the existing fakes), or new `oauth_flow_test.go`, `oauth_profile_test.go`, `oauth_config_test.go`, `oauth_accounts_test.go` and `oauth_session_test.go`, whichever do not already exist after the security phases. Prefer new files and reuse the fakes from `oauth_test.go`.

- `oauth_flow.go` (37): `handleOAuthStart` with the `randID` failure (19-24) and the success path that sets the cookie and redirects (25-35); `handleOAuthCallback` with an unknown provider (40-43), a state mismatch (45-49), `?error=` (50-54), a missing code (56-60), a token exchange failure where the fake token endpoint returns 400 (63-68), a profile failure where the fake id_token is missing (70-75), account resolution failure with no invite (77-82), and the `UpsertOAuthIdentity` failure via `addFailTrigger("oauth_identities","INSERT")` (83-88); `oauthAccountErrorMessage(nil)` (103).
- `oauth_profile.go` (49):
  - `fetchOAuthProfile` dispatch for google, github and default (29-36).
  - `fetchGoogleProfile` 40-68: build a Google variant of `newFakeOIDCServer` that serves `/.well-known/openid-configuration` and `/keys` with issuer `https://accounts.google.com`. Pass `oidc.ClientContext(ctx, fake.client())`. Cover the missing id_token, a bad signature, and success.
  - `fetchGitHubProfile`: emails failure (87), no primary but a verified one (97-101), none verified (105).
  - `fetchOIDCProfile`: nil `OIDCProvider` with discovery through the fake (119-124), missing id_token (127), verify failure (131), the userinfo fallback for empty email, `"user"` name or unverified email (144-160; add a `/oidc/userinfo` handler to the fake), and a missing subject (165).
  - `flexibleBool.UnmarshalJSON` `"false"` and invalid (191-194).
  - `fetchOAuthJSON` with a bad URL, a transport error, a status ≥400, and bad JSON (201-222).
- `oauth_config.go` (19): `GET /api/auth/providers` (39-46); the `oauthProviderMetadata` invalid OIDC issuer and unknown key (73-78); `oauthProviderConfig` google, github, oidc-unconfigured, discovery failure and unknown (91-130); `normalizeOIDCIssuerURL` with a bad URL, a non-http scheme and an empty host (145-156); a hostname resolving to private, using `http://localhost/` (168-174); the metadata IP check (186-188).
- `oauth_accounts.go` (18): `resolveOAuthAccount` covering a linked identity → missing account, disabled, or domain not allowed; a direct email match that is disabled or not allowed; the lookup error via `dropTable("oauth_identities")`; and the invite flow with no invite, not found, mismatch, create failure and consume failure (20-68). Also `displayName()` falling back to `"user"` (87).
- `oauth_session.go` (5): `parseOAuthFlowCookie` with a missing cookie, bad signature, expired cookie, or wrong provider (27-41), and `setNextPath` with an unsafe path (57).

Budget: at most 600 lines. Expected server after S4: about 87%.

##### Phase S5: server CLI login, metrics, health, middleware, security helpers (re-profile first)

Files: new `cli_login_test.go` (CLI-login tests currently live in `oauth_test.go`; put new ones in `cli_login_test.go` unless a security phase created it), new `metrics_test.go`, new `health_test.go`, new `middleware_test.go`, `security_test.go` (extend).

- `cli_login.go` (82):
  - `handleCLILoginStart` with setup required (18-21), and with the rand failures for the device code, user code and the store insert failure via `addFailTrigger("cli_login_devices","INSERT")` (23-42). Check the table name in `internal/db/schema.go`.
  - `handleCLILoginPoll` with bad JSON, an empty code, an invalid code, expired+pending (expire it by updating `expires_at` with `store.Exec`), pending, denied, consume failure, token-generation failure and default (56-110).
  - `handleCLILoginPage` and `handleCLILoginApprove`, both entirely uncovered (114-175): not logged in, which redirects and sets next; expired or unknown code; bad form; CSRF error and invalid; deny success and failure; approve success and failure via `addFailTrigger("cli_login_devices","UPDATE")`.
  - `renderCLILoginForm` CSRF failure (180-182) and `randomUserCode` rand failure (190).
- `metrics.go` (44): `GET /metrics` on a healthy server (19-85), plus the same after `s.store.Close()` to take each `err == nil` false branch. Adapt to whatever auth the security phase adds to `/metrics`, and do not re-test that auth.
- `health.go` (4): `GET /readyz` after `s.store.Close()` returns 503.
- `middleware.go` (12): HSTS when `s.secure` (23-25); `authToken` with a disabled account (64-67) and the `TouchTokenLastUsed` failure via `addFailTrigger("tokens","UPDATE")` (80-82); `authAdmin` missing, invalid, disabled and non-admin (88-104).
- `security.go` (12): the remaining parse branches of `verifyWebSession` and `parseSignedSubject` (malformed, expired, bad HMAC: 53, 93, 127-138); `encryptSecret` nonce failure (158); `decryptSecret` short ciphertext (191-194). Lines 150-156 and 183-189 are class (c).

Budget: at most 600 lines. Expected server after S5: about 91.5%.

##### Phase S6: server api_uploads, pages, comments, lifecycle, analytics (re-profile first)

Files: new `api_uploads_test.go` (unless it already exists), `pages_test.go` (extend), `comments_test.go` (extend), `lifecycle_test.go` (extend), `analytics_test.go` (extend). Use `faultStorage`, `failingWriter`, `rawPageStorage`, `retentionCleanupStorage`, `dropTable` and `addFailTrigger`.

- `api_uploads.go` (54): multipart parse error (55-58); missing file (63-66); file too large (69-72, 87-90); raw-body password visibility (76-79); create and add-version service errors via `faultStorage{saveErr}` (107-112, 143-148); unknown body type (155-157); the list failure via `dropTable("uploads")` (182-185); delete 404/403/storage failure (210-227); visibility 404/403/bad JSON/store failure (234-264); and `handleDeleteAllByOwner` in full (277-296, route `DELETE /api/uploads-by-owner`), with one delete failure via `faultStorage{deleteErr}`.
- `pages.go` (40):
  - The missing version (52), clearing the stale session cookie (87, 97), the password POST for a missing upload, a bad version, non-password visibility and a bad form (130-150), and the visitor cookie (176).
  - `handleRaw`, `handleRawVersion` and `serveRawObject` with not-found paths, an `openErr` via `faultStorage` (188-252), and a scan-close error (245).
  - `writeRawHTML` with `failingWriter` (273-284).
  - `handleIndex` for a non-root path and for success (288-296).
  - `injectBridge` without a marker (303), the `bridgeInsertOffset` tail rollover (339; use a body longer than the scan buffer with the marker split across chunks) and a reader error (346), and `lastMarkerOffset` (372).
- `comments.go` (30): list 404, invalid token, non-owner, db failure (54-89); add rate-limited, using `commentLimiter: newLimiter(0, …)` (102-105); 404, bad JSON, name too long, anonymous default, and the store failure via `addFailTrigger("comments","INSERT")` (108-157); account-comment rate-limit, bad JSON and failure (200-236); `normalizeCommentAnchorKind("page")` (253); `viewerCanAccessUpload` with an unknown visibility (290).
- `lifecycle.go` (10): `Close` on a nil-cancel server (22), `runRetentionCleanup` with an interval ≤0 (52), the list and versions failures via `dropTable` (81-104), and the version delete failures via `faultStorage{deleteErr}` and `addFailTrigger("upload_versions","DELETE")` (107-113).
- `analytics.go` (6): `visitorID` rand failure (32), an empty IP (56), the upsert visitor failure (86), `FlushVisits` with a cancelled ctx (100, 106), and an XFF single value (117).

Budget: at most 600 lines. Expected server after S6: **about 94% (floor 91%)**. If S1–S5 already put server at ≥92.5%, S6 may be descoped to the api_uploads part only.

##### Phase D1: db, every non-migration file

New files: `internal/db/accounts_test.go`, `invites_test.go`, `oauth_test.go`, `visits_test.go`, `uploads_test.go`, `audit_test.go`, `settings_test.go`, `comments_test.go`, `cli_login_test.go`, `faults_test.go` (shared helpers and the closed-store table). Extend: `tokens_test.go`, `versions_test.go`, `grants_test.go`, `slug_aliases_test.go`. Existing helpers: `openTestStore(t) *Store` (store_test.go:17), `openTokenTestStore`, `seedVersionUpload(t, s, email, slug, size) (accountID, uploadID)`, `seedVersionTestUpload`.

1. **Happy-path coverage of functions never called from db tests** (about 105 statements):
   - `ListAccounts`, `GetAccountByEmail`, `CountAdminAccounts`, `CountAccounts`, and `CreateAccount` with an empty name.
   - `ListInvites` with used and revoked rows, `GetInvite*` with used and revoked.
   - `GetOAuthIdentity`, `UpsertOAuthIdentity` (insert and update), `AccountHasOAuthIdentity`.
   - `CountVisits`, `VisitBuckets`, `RecentVisits`, `UpsertVisitor`, `GetVisitor`.
   - `GetUploadByID`, `ListAllUploads`, `CountUploads`, `SumUploadSizes`, `CreateUploadChecked` with an empty visibility (default password) and with the per-owner storage quota (50).
   - `GetTokenByID`, `CountAdminTokens`, `CountTokens`, `CreateAccountToken` with an empty name.
   - `ListAuditLog` with limit 0 and 1000.
   - `GetCLILoginByUserCode` and a consumed device.
   - `HashToken`-style validation with non-hex input (tokens.go:25).
2. **`TestStoreMethodsFailOnClosedStore`** in `faults_test.go`: open a store, `Close()` it, then run a table of `func(*Store) error` closures, one line per exported method (about 60 methods). Assert `err != nil`. This covers the first `if err != nil { return … }` after `QueryContext`, `ExecContext`, `BeginTx` or `QueryRowContext.Scan` in every method, about 80 statements.
3. **Mid-transaction failures** via a local helper `failOn(t, s, table, op)` (the same trigger SQL as S1, duplicated because db is a different package): `SetAccountAdminChecked` and `SetAccountDisabledChecked` multi-step tx (accounts.go:90-161), `RegenerateAccountToken` and `DeleteAccountToken` (tokens.go:131-175, 257-276), `CreateVersionChecked` (versions.go:46-62), `DeleteUploadVersion` (versions.go:122-132), `RenameUpload` (slug_aliases.go:26-47), `CreateUploadChecked` (uploads.go:62-72), `AddUploadGrant` (grants.go:47-53). About 35 statements.
4. **Scan errors**: insert a TEXT value into an INTEGER column with raw `s.Exec`, then call the List/Get function. This covers `rows.Scan` error branches in accounts.go:75, invites.go:62, grants.go:77, comments.go:47, audit.go:36, settings.go:33 (a NULL into a NOT NULL column is impossible; use a type mismatch on `v` only if declared as such, otherwise skip), visits.go:36/56, tokens.go:306. About 10 statements.

Class (c), left alone: `tx.Commit()` errors (accounts.go:165, tokens.go:143/173/274, versions.go:60, uploads.go commit) and `rows.Err()`.

Budget: at most 600 lines (the closed-store table is about 120 lines). Expected db after D1: about 89%.

##### Phase D2: db migrations and store open (re-profile first; migrations.go, schema.go and accounts.go are security-touched)

New file `internal/db/migrations_test.go`. Extend `store_test.go` (already has `TestLegacyAuthMigrationPreservesTokenAndUploadOwnership` and `TestIsMigrationAppliedReportsMetadataReadFailure` as models).

- `Open` failure branches: `Open(t.TempDir())` (a directory, so schema exec fails, covering store.go:26-28 and closeOnError 21-23); a pre-created DB where `uploads` is a VIEW or has an incompatible definition, making `migrateUploadsOwner` or the index create fail (store.go:30-44).
- `runMigrations` per-migration error wrapping (migrations.go:71-108): pre-create a DB, mark migrations up to N−1 applied, and plant an object whose name collides with what migration N creates (for example a VIEW named `upload_grants` makes migration 8's `CREATE INDEX … ON upload_grants` fail), then call `Open`. One table-driven test over N ∈ {2, 4, 5, 6, 7, 8, 9, 10}, each with a minimal fixture. About 12 statements.
- Legacy fixtures: `migrateTokenHashes` with an unhashed legacy token row (230-255); `migrateAccounts` with the legacy `tokens` without `account_id` (262-307); `migrateUploadsOwner` with the legacy `uploads` table, with and without `owner_account_id` (325-372, including 356-360 `hasOwnerAccount`); `migrateInviteTokenCipher` on an invites table without `token_cipher` (378-385); `tableColumns` pragma failure (390, 399). About 20 statements.

The deeper error branches inside those migrators (each `if err != nil` after a successful earlier statement) are class (c); leave them.

Budget: about 400 lines. Expected db after D2: **about 91.5% (floor 90%)**.

##### Phase C1: CLI dispatcher, config, login, OAuth login, discovery, browser, client

Files: new `internal/cli/commands_test.go`? It already exists (`commands_test.go`), so extend it. New `config_command_test.go`, `login_command_test.go` (extend), `login_oauth_test.go` (extend), new `login_discovery_test.go`, new `browser_test.go`, `client_test.go` (extend). Add one helper to `test_helpers_test.go`: `func withStdin(t *testing.T, input string)`, which writes a temp file, opens it, swaps `os.Stdin`, and restores it in `t.Cleanup`. C2 depends on this helper.

- `commands.go Run` (34): a table over every subcommand with `setTestConfigHome(t)` and no host. Each `cmdX` then fails at `LoadConfig`/`newClient`, so Run returns 1. Add `help` and `version` (0), empty args (1) and unknown (1). Also cover the `usage()` body. Capture stdout with `captureStdout`; stderr can be left alone or redirected the same way.
- `config_command.go` (36): `config` with no args or an unknown subcommand; `config set` with each flag's missing value; `--token-file` success and read error; `--token-stdin` via `withStdin`; the `--token` warning; a missing host; discovery reporting OAuth providers (httptest `/api/auth/providers` returning `{"providers":[{"key":"oidc"}]}`); success. `config show` is covered already.
- `login_command.go` (39): `readTokenInteractive` with non-TTY stdin through `withStdin` (16-17, 27-31; the TTY branch 18-25 is class (c)); flag errors; `--oauth` with a discovery error and with browser login unavailable; the host prompt from stdin; `--token-stdin`; an empty token; the `--token` warning.
- `login_oauth.go` (13): poll statuses denied, expired, consumed and unknown; start or poll HTTP errors; interval and expiry defaults (32-37); the timeout loop exit (77) with `oauthSleep` stubbed to a no-op and `expires_in:1`. Use the existing `oauthOpenBrowser` stub.
- `login_discovery.go` (4): an unreachable host, a 404, and bad JSON.
- `browser.go` (6): `t.Setenv("PATH", t.TempDir())` and call `openBrowser("http://x")`, expecting an error because no `xdg-open` exists. This covers 8-10, 15-18; darwin and windows are class (c). This **must** set PATH, so that a dev machine never launches a real browser.
- `client.go` (13): `configPath` with `HOME` and `XDG_CONFIG_HOME` unset (23-25) and with a config dir under a regular file (27-29); `LoadConfig` with bad JSON (46); `SaveConfig` write failure (54-60); `newClient` with no host or token (75-80); request-build errors via a host with a control character (86); `getJSON`/`postJSON`/`del` transport errors against a closed httptest server (98-126).

Budget: at most 600 lines. Expected cli after C1: about 79%.

##### Phase C2: CLI upload, list, delete, visibility, rename, versions, grants, gdpr, stats, comments, token

Files: `upload_command_test.go` (extend), new `uploads_command_test.go` (`uploads_command_requests_test.go` exists; add the new file so the two stay disjoint), `grants_command_test.go` (extend), `gdpr_command_test.go` (extend), new `stats_comments_command_test.go`, new `token_command_test.go`. Uses `configureTestClient(t, ts.URL)`, `captureStdout`, and `withStdin` from C1. Use one generic fake: an `httptest.NewServer` with a `map[string]string` from path to JSON body and a per-path status override for error cases.

- `upload_command.go` (32): flag errors (29-66), invalid visibility, `--password` together with `--password-stdin`, stdin password empty or ok, password/visibility mismatches (77-98), a missing file (101-112), an HTTP error response (120-134), and the default base name `page` (194).
- `uploads_command.go` (42): `cmdList` empty and with rows (20-48), plus `cmdVersions`, `cmdDelete`, `cmdVisibility` and `cmdRename`, each with usage errors, config errors and HTTP errors (54-202).
- `grants_command.go` (30): an unknown flag, wrong arity, all error returns, and `cmdGrants` with an empty list and with a populated one (89-117).
- `gdpr_command.go` (16): `cmdExport` usage and errors; `cmdDeleteAll` success and error (44-59).
- `stats_comments_command.go` (13): stats usage and HTTP error; comments `--version` missing value, a duplicate slug, a missing slug, the kind and context variants (125-139).
- `token_command.go` (12): usage, create and list HTTP errors, revoke argument variants (79-98).

Budget: at most 600 lines. Expected cli after C2: **about 94% (floor 91%)**.

##### Phase O1: objectstore S3 client against a fake S3, plus file storage error paths

Files: new `internal/objectstore/s3_test.go`, new `internal/objectstore/file_test.go`. Extend `storage_test.go` only for `s3_endpoint` dial cases, or create `s3_endpoint_test.go` if a security phase has not already.

Fake S3 (in `s3_test.go`, about 60 lines): `httptest.NewServer` holding a `map[string][]byte` keyed by `/bucket/uploads/<name>`. It handles PUT, GET and DELETE, records that an `Authorization` header starting `AWS4-HMAC-SHA256` was present, and returns 404 for missing keys. It also takes a configurable `failPath` that returns 500 with an XML body. Storage: `NewS3Storage(true, func(k string) string { return map[string]string{"s3_endpoint": ts.URL, "s3_bucket": "bucket", "s3_access_key": "AK", "s3_secret_key": "SK"}[k] })`. With no `s3_region`, the "us-east-1" default (33) is covered.

- `s3.go` (68): a Save, Open, read, Delete round trip; Open on a missing key returns `os.ErrNotExist`; Delete on a missing key returns nil; Save, Open and Delete against `failPath` give errors carrying the body text (98, 119-123, 142); invalid slugs return early (52, 60, 72); a transport error after `ts.Close()` (94, 112, 135); `http.NewRequest` errors via an endpoint containing a control character (88, 107, 130); `httpClient()` with `client == nil` on a struct-literal `&S3Storage{getSetting: …, allowPrivateEndpoint: true}` (82).
- `s3_signing.go:57` (1): sign a request that already carries an `Authorization` header.
- `s3_endpoint.go` (14; security-touched, re-profile first): `ValidateS3Endpoint` with an unparsable URL and a missing host (18-24), a hostname resolving to private (`http://localhost:9000`, 42-48), and the metadata IP (64). Call `safeS3DialContext(true)` directly with a bad address (82), an unresolvable host (`nonexistent.invalid`, 86), `network "tcp6"` with `127.0.0.1:1` (103-108) and `"tcp4"` with `[::1]:1` (100-101).
- `file.go` (5): a Save where `fs.Dir` is a regular file, so MkdirAll fails (27); a Save where `<path>.tmp` exists as a directory, so WriteFile fails (31); a Save where `<path>` exists as a non-empty directory, so Rename fails (34-37); Delete of a missing object returns nil (55). Do not rely on chmod: the container runs as root.

Budget: about 400 lines. Expected objectstore after O1: **about 96% (floor 92%)**.

##### Phase P1: peekd Run, runServe, runBackup, env

Files: `internal/peekd/run_test.go` (extend), new `internal/peekd/serve_test.go` with `//go:build unix` for the signal-driven test, new `backup_test.go`, new `env_test.go`.

- `Run` (9): `Run([]string{"--version"})` returns 0 (capture stdout via `os.Pipe`); `Run([]string{"--nope"})` returns 2; `Run([]string{"healthcheck","--addr",<httptest addr>})`; `Run([]string{"backup", …})`.
- `parseServeConfig` (6): env parse errors for each `getenvInt` and `getenvBool` site (77-91), a flag parse error (123), `--version` (126), and the abs error (140, class (c)).
- `runServe` (about 60):
  - (i) `GoogleSAKeyFile` missing returns 1 (198-201).
  - (ii) The key file contains `{}`, so `groups.NewDirectory` errors and returns 1 (203-206).
  - (iii) `DataDir` is a regular file, so `server.New` errors and returns 1 (232-235).
  - (iv) Addr already in use: hold a `net.Listen("tcp","127.0.0.1:0")` and pass its addr. The serverErr path returns 1 (260-265).
  - (v) The happy path with a valid generated service-account JSON (RSA key via `x509.MarshalPKCS8PrivateKey` and PEM, `"type":"service_account"`, `client_email`, `token_uri`), so 207-208 are covered too. Add `PEEK_LOG_LEVEL=debug` (and a second run with `warn`) for configureLogging 295-302. Signal-guard first, then a free port, start runServe in a goroutine, poll `GET /healthz` until 200, `syscall.Kill(os.Getpid(), syscall.SIGTERM)`, and expect 0 within 20 s (268-286).
  - Restore `slog.Default()` in `t.Cleanup`, because configureLogging replaces it.
  - `closeServer` with an error is class (c).
- `backup.go` (13): `runBackup` with bad flags (2), with a missing data dir (VACUUM INTO fails, 1), and success (0) (13-24); `backupArgs` flag parse error (31).
- `env.go` (6): valid int (26), invalid int (34-38), false-y bool (47).
- `healthcheck.go:20`: the request-build error via an addr with a control character, or a connection refused on a closed port.

Budget: about 450 lines. Expected peekd after P1: **about 95% (floor 90%)**.

##### Phase X1: uploads, web, groups, version (small gaps)

Files: `internal/uploads/service_test.go` (extend), new `internal/uploads/slug_test.go` (slug.go is security-touched; re-profile), `rename_test.go` (extend), `validate_test.go` (extend), `internal/web/renderer_test.go` (extend), `internal/web/assets_test.go` (extend), `internal/groups/directory_test.go` (extend), new `internal/version/version_test.go`.

- `uploads/service.go` (15): `(*Error).Error` and `(*CleanupError).Error` strings (84, 93); `Create` with an empty name (107), empty data (116), non-HTML data (119), slug generation failure via a repo whose `UploadSlugExists` errors (128), and `memoryStorage` with a save error (131); `AddVersion` with empty or non-HTML data (153-158) and save or cleanup failures (163-171); `storeError` for owner-count, owner-storage and default (188-193). Use the existing `memoryStorage` (extend it with `saveErr`) and `failingVersionRepo`.
- `uploads/slug.go` (9): a name over `maxSlugLength` (41-44); checker errors at 54, 62, 67 and 80 via a fake `slugChecker`; the collision loop falling through to random (74). The rand failures at 100/108 are class (c).
- `uploads/rename.go:61`, `validate.go:40` (`min` with a > b), `visibility.go:43` (class (c)).
- `web/renderer.go` (12): `newRenderer(nil)` (49-50); `(*Renderer)(nil).Execute` and `(&Renderer{}).Execute` (62); an unknown template name (66); `RenderHTML` success and error (72-80).
- `web/assets.go` (4): `ServeAsset` for an unknown name gives 404 (61-64); the non-hashed asset Cache-Control branch (68-70).
- `groups/directory.go` (7): `NewDirectory` with a generated valid SA JSON, built as in P1 (51-54); `newDirectoryWithClient` with a base URL containing a control character, so `NewRequest` errors (84); `client.Do` against a closed server (88); 200 with an invalid JSON body (98); cache pruning of an expired entry for a different key by advancing the `clock` (121-123).
- `version/version.go` (1): `String()` contains `Version`.

Budget: about 350 lines. Expected: uploads about 96%, web about 93%, groups 100%, version 100%.

##### Phase G: CI coverage gate (last)

Files: new `scripts/coverage-gate.sh`, `mise.toml` (`[tasks.coverage]`), `.github/workflows/ci.yml` (Coverage step). `scripts/` exists and currently holds only asset and screenshot generators (`gen-assets.sh`, `gen-assets.mjs`, `gen-screenshots.sh`, `gen-screenshots.mjs`, `demo-report.html`), so a shared script fits there and keeps CI and local runs identical. `*.out` is already in `.gitignore`.

`scripts/coverage-gate.sh` (mark it executable; it must be POSIX sh):

```sh
#!/bin/sh
# Run the test suite with coverage and fail if total statement coverage is below the minimum.
# Usage: scripts/coverage-gate.sh [profile]   (env COVERAGE_MIN, default 90.0)
set -eu
min="${COVERAGE_MIN:-90.0}"
profile="${1:-coverage.out}"
go test -coverprofile="$profile" ./...
go tool cover -func="$profile" | tail -1
total=$(go tool cover -func="$profile" | awk '$1 == "total:" { sub(/%$/, "", $NF); print $NF }')
if [ -z "$total" ]; then
  echo "coverage gate: could not read total from $profile" >&2
  exit 1
fi
awk -v t="$total" -v min="$min" 'BEGIN {
  if (t + 0 < min + 0) { printf "coverage gate: FAIL total %.1f%% < %.1f%%\n", t, min; exit 1 }
  printf "coverage gate: OK total %.1f%% >= %.1f%%\n", t, min
}'
```

`mise.toml`:

```toml
[tasks.coverage]
description = "Run tests with coverage and fail below the 90% total-statement gate"
run = "sh scripts/coverage-gate.sh"
```

`check-full` already depends on `coverage`, so the local CI-equivalent gate gains the threshold automatically.

`.github/workflows/ci.yml` replaces the existing Coverage step:

```yaml
      - name: Coverage (gate >= 90.0%)
        run: sh scripts/coverage-gate.sh coverage.out
```

If the script is not wanted, the equivalent inline step is:

```yaml
      - name: Coverage (gate >= 90.0%)
        run: |
          go test -coverprofile=coverage.out ./...
          go tool cover -func=coverage.out | tail -1
          go tool cover -func=coverage.out | awk '$1 == "total:" { sub(/%$/, "", $NF); if ($NF + 0 < 90.0) { printf "coverage %s%% is below 90.0%%\n", $NF; exit 1 } }'
```

Optional, non-gating: append `go tool cover -func=coverage.out | sort -k3 -n | head -30` to the step for a "least covered functions" list in the CI log.

Acceptance for G:
- `sh scripts/coverage-gate.sh` exits 0 locally at ≥90.0.
- `COVERAGE_MIN=99 sh scripts/coverage-gate.sh` exits 1, which proves the gate can fail.
- `mise run check-full` passes.
- CI is green.
- Recommended: record the per-package figures from the final run in the PR description, so later regressions are easy to localize.

Optional ratchet, not required: per-package floors could be enforced by extending the script with `go test -cover ./... | awk` parsing `coverage: NN.N% of statements`. This was left out to keep the gate simple and in line with the "boring operational reliability" direction. The total gate is the contract.

#### 6. Tooling for phase step 0 (no Python needed)

```sh
go test -coverprofile=/tmp/c.out ./internal/server/
go tool cover -func=/tmp/c.out | tail -1
# count-0 blocks for one file, as file:start-end stmts
awk -F'[:, ]' 'NR>1 && $5==0 { split($2,a,"."); split($3,b,"."); print $1":"a[1]"-"b[1]" stmts="$4 }' /tmp/c.out | grep '/admin.go:'
# uncovered statements per file
awk -F'[:, ]' 'NR>1 && $5==0 { n[$1]+=$4 } END { for (f in n) print n[f], f }' /tmp/c.out | sort -rn | head -30
```

(The profile lines have the shape `path/file.go:25.3,33.5 2 0`, so with `-F'[:, ]'` the fields are `$1` path, `$2` start, `$3` end, `$4` statements, `$5` count.)

#### 7. Expected trajectory (HEAD denominators; security work shifts these slightly)

| After | server | db | cli | objstore | peekd | uploads | web | groups | Total (est.) |
|---|---|---|---|---|---|---|---|---|---|
| HEAD | 70.1 | 71.8 | 64.1 | 59.6 | 56.1 | 82.1 | 65.2 | 85.1 | 68.9 |
| S1+S2 | ~79.5 | | | | | | | | ~74.0 |
| S3+S4 | ~87 | | | | | | | | ~78.1 |
| S5+S6 | ~93–94 | | | | | | | | ~81.8 |
| D1+D2 | | ~91.5 | | | | | | | ~85.2 |
| C1+C2 | | | ~94 | | | | | | ~89.4 |
| O1, P1, X1 | | | | ~96 | ~95 | ~96 | ~93 | 100 | ~92.5–93 |
| **Floors** | 91 | 90 | 91 | 92 | 90 | 92 | 90 | 95 | **90.9** |

The phases are independent across packages, so the total reaches 90% only once most phases have landed. G must therefore be the last merge. If a schedule slip leaves one package short, the cheapest top-ups are S6 (server, about 115 statements) and C2 (cli, about 135 statements).

#### 8. Risks and notes

- **Line drift.** All line numbers are from HEAD. The security phases rewrite many of the listed files, so every phase re-lists count-0 blocks first (§6) and covers only what is still missing.
- **The signal-based runServe test** is Unix-only (`//go:build unix`). CI runs ubuntu-latest and local dev is Linux or macOS, so this is fine. The guard `signal.Notify` must be registered **before** the goroutine starts, or a SIGTERM delivered before runServe's own Notify would kill the test binary.
- **The browser test must override PATH**, or it may open a real browser on a developer machine.
- **Root in container.** Permission-based failure tricks (chmod 000) do not work as root. Use path-type collisions (file where a dir is expected, and vice versa) instead.
- **Race detector.** Tests that swap globals (`secureRandomRead`, `githubUserURL`, `oauthSleep`, `os.Stdin`, `os.Stdout`, `slog.Default`) must not call `t.Parallel()`.
- **Triggers persist** in the test DB. Each test uses its own `t.TempDir()` store, so this is harmless. Never add triggers to a shared fixture.
- **No production seams are planned.** The only contingency is `var notifyShutdown = signal.Notify` in `internal/peekd/run.go`, used if the signal test proves flaky in CI. Do not add a rand seam to `internal/uploads/slug.go`; those 2 statements are budgeted as class (c).

## Manual steps


There is nothing to do before implementation. After the last phase merges, the user runs three checks in a real browser and terminal that CI cannot do; the step-by-step page is https://claude.ai/artifact/9vu1vXxYG3f5BWpMhGJxHv (source: `docs/plans/security-hardening-coverage-plan-manual-steps.html`):

- `ma1-browser-smoke`: uploaded HTML still renders in the frame under the new CSP `sandbox` and `frame-ancestors 'self'` (Design A › S1 stop condition), the raw URL opened in a tab is refused, a private page's frame loads, signed-in comments show the "signed in" marker, dashboard flashes read correctly, and **Sign out other sessions** ends a second browser's session.
- `ma2-cli-login`: `peek login` against the local server prints a code and opens `/cli-login`; typing the code shows the request details and approving issues a working token.
- `ma3-oauth-login`: if the user has Google, GitHub or OIDC configured somewhere, one sign-in per provider still works (nonce, userinfo `sub` check).

Releasing (which first publishes `checksums.txt`) is the maintainer's decision after the PR merges; the PR body lists it as a follow-up, together with setting `PEEK_TRUSTED_PROXY_CIDRS` on deployments whose proxy is not on the same host.

## Risks and open questions


- **`frame-ancestors 'self'` inside a sandboxed document.** Browsers should match `'self'` against the response URL's origin, not the opaque sandbox origin. If a frame shows blank with a `frame-ancestors` console error in `ma1`, the fallback (explicit origin from `--base-url`) needs a follow-up; it is not implemented here.
- **Loopback-only trusted proxy default** changes behaviour for deployments with `--trusted-proxy` whose proxy is in another container: all clients share the proxy's rate-limit bucket until `PEEK_TRUSTED_PROXY_CIDRS` is set. Peek logs one warning naming the peer. Documented in `p20`.
- **Session cookie format** changes to `<id>:<epoch>`; older binaries reject the new cookies, so a rollback signs everyone out (documented).
- **Old `install.sh` releases.** The new `install.sh` refuses releases without `checksums.txt` (v0.8.1 and older) until a new release is cut.
- **Line drift.** Design line numbers are from 6380c6b/d7242f9. Workers locate code by symbol; a symbol that no longer exists or has a different shape than the design describes is a stop condition (`status=blocked`), not something to redesign.
- **Coverage arithmetic.** The floors give about 90.9%. If the security phases add more untested code than expected, `g01` tops up; if the total is still below 90.0% after 300 lines of top-up, `g01` stops with `status=blocked` and lists the packages below their floors.
- **Parallel server coverage phases** (`c02`–`c07`) share one Go package; identifier clashes are avoided by the prefixes in §0.9. A compile error after a merge from a duplicate identifier is fixed by renaming in the later phase.
- **Docs site build.** `p20`/`p21` build the docs locally (`cd docs && pnpm install --frozen-lockfile && pnpm build`). If that cannot run in the container, they dispatch `pages.yml` against the feature branch and judge its "Build docs" job; `p04` restricts the deploy job to `main`, so a dispatch from the feature branch only builds.

## Implementation manifest

Every brief's step 1 is the same: read `AGENTS.md`, `CONTRIBUTING.md`, `docs/architecture.md`, `docs/operations.md`, `docs/audits/2026-10-security-and-coverage-audit.md` (the finding) and Design §0 of this plan, then the Design subsections the brief names. Design §0 overrides Design A–E. "Design A › S1" means the subsection "S1 — …" under "Design A".

```yaml
plan_slug: security-hardening-coverage
feature_branch: fix/security-hardening-coverage
max_parallel: 3
manual_steps_artifact: https://claude.ai/artifact/9vu1vXxYG3f5BWpMhGJxHv
manual_steps_source: docs/plans/security-hardening-coverage-plan-manual-steps.html
manual_before: []
manual_after:
  - id: ma1-browser-smoke
    title: Browser smoke test of the sandboxed frame, raw URL refusal, comment marker, flashes and "Sign out other sessions"
    why: CI cannot check how a real browser applies the CSP sandbox with frame-ancestors 'self', sends cookies on the iframe request, or renders toasts.
  - id: ma2-cli-login
    title: End-to-end `peek login` with a typed code against a local server
    why: The device flow spans the CLI, the browser and the approval page; tests cover each side separately.
  - id: ma3-oauth-login
    title: One real sign-in per configured OAuth provider (Google, GitHub, OIDC), if any
    why: The nonce and userinfo `sub` checks are tested against fakes only; a real IdP confirms they do not reject valid logins.
verify_after_merge:
  - mise run race
  - mise run staticcheck
  - sh -c 'go test -coverprofile=/tmp/peek-cover.out ./... >/dev/null && go tool cover -func=/tmp/peek-cover.out | tail -1'
final_checks:
  - docs/plans/security-hardening-coverage-plan.md and docs/plans/security-hardening-coverage-plan-manual-steps.html are deleted and `grep -rn "security-hardening-coverage-plan" --exclude-dir=.git .` prints nothing
  - '`grep -rn puemos --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=audits .` prints only LICENSE:3'
  - '`sh scripts/coverage-gate.sh` prints "coverage gate: OK" with a total of at least 90.0%'
  - '`grep -nE "uses: [^@]+@v[0-9]" .github/workflows/*.yml` prints nothing'
  - The audit report docs/audits/2026-10-security-and-coverage-audit.md starts with a status line naming this change
phases:
  # ---------------------------------------------------------------- wave A: independent security phases
  - id: p01-raw-sandbox
    title: Sandbox uploaded HTML on /raw, bind view tokens to the visitor cookie, re-check access per load (S1, L6)
    depends_on: []
    complexity: M
    touches:
      - internal/server/pages.go
      - internal/server/security.go
      - internal/server/routes.go
      - internal/server/web_csrf.go
      - internal/server/page_versions_test.go
      - internal/server/pages_test.go
      - internal/server/visibility_e2e_test.go
      - internal/server/web_csrf_test.go
    brief: |
      1. Read the must-read docs and Design §0 (see the note above the manifest), then Design A › S1 and Design A › L6 in full.
      2. Check the HttpOnly precondition first: `grep -rn "document.cookie\|hn_csrf" internal/web/assets/*.js` must print nothing. If it prints anything, stop with status=blocked.
      3. In internal/server/pages.go add the `rawSandbox` and `rawContentCSP` constants and `rawFetchAllowed` exactly as Design A › S1 Design items 1 and 5; make `writeRawHTML` set `rawContentCSP`.
      4. Make `rawViewerID` cookie-only (item 2), drop `"&v=" + vid` from the raw URL in the page handler (item 3), and in internal/server/security.go make `verifyViewToken` reject an empty visitor id (item 4).
      5. Rewrite `handleRawVersion` in the order a–f of item 6, including the L6 access re-check with `s.viewerCanAccessUpload(r, u)` (Design A › L6).
      6. Delete `handleRaw` and its route `GET /raw/{slug}` in internal/server/routes.go (item 7).
      7. In internal/server/web_csrf.go set `HttpOnly: true` on the `hn_csrf` cookie (item 8). Do not touch internal/web/templates/page.gohtml (item 9).
      8. Update the existing tests listed under "Existing tests to update" and add every test under "Tests to add" (Design A › S1), including the helpers `rawSrcFromPage`, `withCookieList`, `withFetchDest` and the three L6 tests.
      9. Do not edit internal/server/security_test.go (Design A lists it as conditional; nothing there needs to change). Run `mise run check-full` (Design §0.8). Do not edit docs; p20/p21 apply Design A's docs items.
    acceptance:
      - go test ./internal/server -count=1 -run 'TestRawSetsSandboxCSP|TestRawRejectsNonIframeFetchDest|TestRawTokenRequiresVisitorCookie|TestRawSandboxMatchesIframeAttribute|TestRawRefusedAfterVisibilityChange|TestRawRefusedAfterGrantRemoved|TestRawRefusedAfterPasswordChange|TestLegacyRawRouteRemoved|TestRawHTMLE2ERejectsLeakedURL|TestCSRFTokenSetsCookie' passes
      - '`grep -n "GET /raw/{slug}\"" internal/server/routes.go` prints nothing'
      - '`grep -n "sandbox allow-scripts allow-popups" internal/server/pages.go` matches'
      - mise run check passes

  - id: p02-db-auth-storage
    title: Storage for CLI-login request context, expiring account tokens and session epochs (migrations 11, 12)
    depends_on: []
    complexity: M
    touches:
      - internal/db/schema.go
      - internal/db/migrations.go
      - internal/db/cli_login.go
      - internal/db/accounts.go
      - internal/db/tokens.go
      - internal/models/models.go
      - internal/db/cli_login_test.go
      - internal/db/accounts_test.go
      - internal/db/tokens_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design B §0, §1 "Storage (P1)", §2 (the `CreateAccountTokenExpiring` part) and §5 "Storage (P1)".
      2. Migration 11: add the two `cli_login_devices` columns to internal/db/schema.go, the `{11, "cli_login_request_context", …}` entry, the `m.id == 11` branch and `migrateCLILoginRequestContext` in internal/db/migrations.go.
      3. Add `RequestIP` and `UserAgent` to `models.CLILoginDevice`; add `CreateCLILoginDeviceWithContext`, make `CreateCLILoginDevice` call it with empty strings, and extend the `getCLILoginWhere` SELECT and scan (internal/db/cli_login.go).
      4. Add `CreateAccountTokenExpiring` to internal/db/tokens.go and make `CreateAccountToken` call it with 0.
      5. Migration 12: `session_epoch` in the `accounts` schema, `{12, "account_session_epoch", …}`, the `m.id == 12` branch and `migrateAccountSessionEpoch`; `models.Account.SessionEpoch`; read it in both account SELECTs; add `BumpSessionEpoch`; make `SetAccountDisabled` and `SetAccountDisabledChecked` bump the epoch when disabling (internal/db/accounts.go).
      6. Add the tests in Design B §1 "internal/db/cli_login_test.go", §2 `TestCreateAccountTokenExpiringStoresExpiry`, and §5 "internal/db/accounts_test.go" (including `TestMigrationAddsCLILoginContextAndSessionEpoch`). The helper is `openTokenTestStore` from internal/db/tokens_test.go.
      7. Do not change any existing function signature in internal/db. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/db -count=1 -run 'TestCreateCLILoginDeviceWithContextStoresRequestContext|TestCreateCLILoginDeviceLeavesRequestContextEmpty|TestCreateAccountTokenExpiringStoresExpiry|TestBumpSessionEpoch|TestSetAccountDisabledBumpsSessionEpoch|TestMigrationAddsCLILoginContextAndSessionEpoch' passes
      - '`grep -c "{11, \"cli_login_request_context\"" internal/db/migrations.go` prints 1 and `grep -c "{12, \"account_session_epoch\"" internal/db/migrations.go` prints 1'
      - mise run check passes

  - id: p03-file-modes-s3-guard
    title: Owner-only database, objects and backups; wider S3 SSRF block list and bucket validation (S7, L11 storage side)
    depends_on: []
    complexity: M
    touches:
      - internal/db/store.go
      - internal/objectstore/file.go
      - internal/objectstore/s3_endpoint.go
      - internal/objectstore/s3.go
      - internal/peekd/backup.go
      - internal/db/store_test.go
      - internal/objectstore/storage_test.go
      - internal/peekd/backup_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design C "General rules for every phase", Design C › S7 and Design C › L11.
      2. internal/db/store.go: add `preparePrivateDBFile` and call it first in `Open` (S7 Design item 5).
      3. internal/objectstore/file.go: directories 0o700, files 0o600 (S7 item 3).
      4. internal/peekd/backup.go: pre-create the destination with O_EXCL 0o600, refuse an existing file, remove it when VACUUM INTO fails (S7 item 6).
      5. internal/objectstore/s3_endpoint.go: replace `isPrivateOrMetadataIP` with the netip version and `blockedS3Prefixes`; add `s3BucketPattern` and `ValidateS3Bucket` (L11 items 1–2).
      6. internal/objectstore/s3.go: `objectURL` returns `(string, error)` and validates the bucket; update `putObject`, `getObject`, `deleteObject` (L11 item 3).
      7. Add the tests listed for P2 in Design C › S7 and › L11 "Tests to add" (store_test.go, storage_test.go, new internal/peekd/backup_test.go). Mode assertions skip on Windows.
      8. Do not touch internal/server (p12 does the server side). Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/db ./internal/objectstore ./internal/peekd -count=1 -run 'TestOpenCreatesDatabaseOwnerOnly|TestOpenTightensExistingDatabaseMode|TestFileStorageWritesOwnerOnlyFilesAndDirs|TestBackupDatabaseWritesOwnerOnlyFile|TestBackupDatabaseRefusesExistingDestination|TestIsPrivateOrMetadataIPBlocksReservedRanges|TestIsPrivateOrMetadataIPAllowsPublicAddresses|TestValidateS3BucketRejectsUnsafeNames|TestValidateS3BucketAcceptsValidNames|TestS3StorageRefusesInvalidBucketBeforeRequest' passes
      - mise run check passes

  - id: p04-supply-chain-ci
    title: Repoint to andras-tkcs/peek, publish and verify checksums.txt, pin Tailwind, pin actions and tools, per-job permissions (S5, L14)
    depends_on: []
    complexity: M
    touches:
      - install.sh
      - mise.toml
      - .github/workflows/release.yml
      - .github/workflows/ci.yml
      - .github/workflows/docker-main.yml
      - .github/workflows/pages.yml
      - docs/astro.config.mjs
      - docs/src/components/SiteChrome.astro
      - internal/web/tailwind-input.css
      - internal/web/assets/pines.css
    brief: |
      1. Read the must-read docs and Design §0, then Design C › S5 and Design C › L14 in full.
      2. release.yml: add the `checksums` job exactly as S5 Design item 1.
      3. install.sh: `REPO="andras-tkcs/peek"`, the comment URL, the version check and the download/verify/extract block (S5 item 2 a–c).
      4. mise.toml: replace the `[tasks.tailwind]` run script (S5 item 3). First re-download https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.1/sha256sums.txt and compare the four hashes; any difference is a stop condition.
      5. docs/astro.config.mjs and docs/src/components/SiteChrome.astro: `puemos` → `andras-tkcs` (S5 table rows marked P1).
      6. All four workflows: pin every `uses:` to the SHA with the version comment from the L14 table; ci.yml govulncheck `@v1.9.0` and staticcheck `version: "2026.2.1"`; mise.toml govulncheck `@v1.9.0` and staticcheck `@v0.8.1` with the comment line; permissions per L14 Design (release.yml top-level `contents: read` plus job-level, docker-main.yml and pages.yml job-level). Do not change the ci.yml Coverage step (g01 does).
      7. pages.yml: add `if: github.ref == 'refs/heads/main'` to the `deploy` job, so a dispatch against another branch only builds.
      8. internal/web/tailwind-input.css: directly after `@import "tailwindcss";` add the three lines `@source not "../../docs";`, `@source not "../../skills";` and `@source not "../../**/*.md";` (Tailwind v4 source exclusion; paths are relative to the CSS file). Run `mise run tailwind` and commit the regenerated internal/web/assets/pines.css once. Verify the exclusion: create an untracked `docs/tw-probe.md` containing the class `bg-[#123457]`, run `mise run tailwind`, check that `grep -c 123457 internal/web/assets/pines.css` prints 0, delete the probe and run `mise run tailwind` again so `git diff --exit-code internal/web/assets/pines.css` is clean. If Tailwind rejects the `@source not` syntax, stop with status=blocked.
      9. Run every check under S5 "Tests / verification" and L14 "Tests / verification", including the offline fake-release run of install.sh in your scratch directory (never commit the test copy) and the Tailwind re-download check. `mise run govulncheck` gets HTTP 403 from vuln.go.dev in a cloud container; that is expected (Design §0.8) and is not a reason to fall back to v1.8.0. Instead check that `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -version` builds and runs; fall back to v1.8.0 only if that fails.
      10. Run `mise run check`. Do not edit README.md, skills/ or docs/src/content (p21 does).
    acceptance:
      - '`sh -n install.sh` exits 0 and `grep -c "andras-tkcs/peek" install.sh` prints at least 2'
      - '`grep -nE "uses: [^@]+@v[0-9]" .github/workflows/*.yml` prints nothing'
      - '`grep -n "@latest\|\"latest\"" .github/workflows/*.yml mise.toml` prints nothing'
      - '`grep -n "checksums.txt" .github/workflows/release.yml` matches'
      - '`python3 -c "import yaml,sys;[yaml.safe_load(open(f)) for f in sys.argv[1:]]" .github/workflows/*.yml` exits 0'
      - '`grep -c "@source not" internal/web/tailwind-input.css` prints 3 and `grep -n "refs/heads/main" .github/workflows/pages.yml` matches'
      - '`mise run tailwind && git diff --exit-code internal/web/assets/pines.css` exits 0 on the committed tree'
      - mise run check passes

  - id: p05-cli-login-host
    title: CLI shows the typed-code login, validates the browser URL, warns on plain http, tightens and resets the config (S3 CLI side, S6, L13 CLI part)
    depends_on: []
    complexity: M
    touches:
      - internal/cli/login_oauth.go
      - internal/cli/browser.go
      - internal/cli/login_command.go
      - internal/cli/config_command.go
      - internal/cli/client.go
      - internal/cli/hostcheck.go
      - internal/cli/login_oauth_test.go
      - internal/cli/hostcheck_test.go
      - internal/cli/test_helpers_test.go
      - internal/cli/client_test.go
      - internal/cli/config_command_test.go
    brief: |
      1. Read the must-read docs and Design §0 (especially §0.3), then Design B §1 "CLI" and its CLI tests, Design C › S6 and Design C › L13 items b and c.
      2. Create internal/cli/hostcheck.go with `validateBrowserURL`, `originOf` and `plainHTTPWarning` exactly as Design C › S6.
      3. internal/cli/login_oauth.go: add `oauthStderr`, the validated/unvalidated print-and-open logic of §0.3, and the `User-Agent: peek-cli/<version>` header in `postJSONNoAuth`.
      4. internal/cli/browser.go: the defence-in-depth checks (S6 `browser.go`).
      5. internal/cli/login_command.go and internal/cli/config_command.go: print `plainHTTPWarning` (S6 call sites); config_command.go also clears the saved token on a host change (L13 c). internal/cli/client.go: chmod before write in `SaveConfig` (L13 b).
      6. Tests: add `captureStderr` to internal/cli/test_helpers_test.go; new internal/cli/hostcheck_test.go and internal/cli/config_command_test.go; update internal/cli/login_oauth_test.go fixtures per §0.3; add `TestLoginOAuthPrintsCodeAndURL`, `TestPostJSONNoAuthSendsUserAgent`, `TestLoginOAuthDoesNotOpenUntrustedVerificationURL`, `TestSaveConfigTightensExistingFileMode`, `TestOpenBrowserRefusesNonHTTPURLs` and the config tests.
      7. Run `mise run check`.
    acceptance:
      - go test ./internal/cli -count=1 -run 'TestValidateBrowserURL|TestPlainHTTPWarning|TestOpenBrowserRefusesNonHTTPURLs|TestLoginOAuthPrintsCodeAndURL|TestPostJSONNoAuthSendsUserAgent|TestLoginOAuthDoesNotOpenUntrustedVerificationURL|TestLoginOAuthPollsUntilApproved|TestSaveConfigTightensExistingFileMode|TestConfigSetHostChangeClearsSavedToken|TestConfigSetSameHostKeepsToken|TestConfigSetWarnsForPlainHTTPHost' passes
      - mise run check passes

  - id: p07-token-policy
    title: API tokens follow the account policy, with email-less automation accounts exempt (S4)
    depends_on: []
    complexity: M
    touches:
      - internal/server/account_policy.go
      - internal/server/web_auth.go
      - internal/server/middleware.go
      - internal/server/comments.go
      - internal/server/account_policy_test.go
      - internal/server/auth_domain_test.go
    brief: |
      1. Read the must-read docs and Design §0 (especially §0.2), then Design B §2.
      2. Create internal/server/account_policy.go with `errAccountDisabled`, `errOAuthRequired`, `accountActive`, `tokenAccount`, `writeTokenPolicyError` (Design B §2) and `tokenAccountActive` (§0.2).
      3. internal/server/web_auth.go: replace the disabled/domain/OAuth checks with `s.accountActive(...) != nil`; update the doc comment.
      4. internal/server/middleware.go `authToken` and `authAdmin`, and the bearer branch of `handleListComments` in internal/server/comments.go: call `s.tokenAccountActive(r.Context(), t)` and answer with `writeTokenPolicyError`, in the order Design B §2 gives. Touch nothing else in middleware.go or comments.go.
      5. internal/server/auth_domain_test.go: delete `TestDirectAPITokenAuthIgnoresAllowedEmailDomain`, add `TestDirectAPITokenAuthHonoursAllowedEmailDomain`.
      6. New internal/server/account_policy_test.go: every test in Design B §2 "Tests to add" plus `TestTokenAccountActiveExemptsEmailLessAccounts` (§0.2).
      7. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 -run 'TestAccountActive|TestTokenAccountActiveExemptsEmailLessAccounts|TestDirectAPITokenAuthHonoursAllowedEmailDomain|TestAuthTokenRequiresOAuthIdentityWhenOAuthEnabled|TestAuthAdminHonoursAllowedEmailDomain|TestAuthTokenDisabledAccountStillAnswersAccountDisabled|TestListCommentsBearerHonoursAccountPolicy' passes
      - '`grep -rn "TestDirectAPITokenAuthIgnoresAllowedEmailDomain" internal` prints nothing'
      - '`grep -n "tokenAccountActive" internal/server/middleware.go internal/server/comments.go` matches in both files'
      - mise run check passes

  - id: p08-oidc-nonce-claims
    title: OIDC nonce, userinfo subject check and same-source email claims (L2, L3)
    depends_on: []
    complexity: M
    touches:
      - internal/server/oauth_flow.go
      - internal/server/oauth_profile.go
      - internal/server/oauth_session.go
      - internal/server/oauth_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design B §3 in full.
      2. internal/server/oauth_session.go: 4-part flow cookie (`makeOAuthFlowCookie(provider, state, verifier, nonce)`, `parseOAuthFlowCookie` returning the nonce).
      3. internal/server/oauth_flow.go: generate the nonce in `handleOAuthStart`, send `oidc.Nonce` only when `oauthProviderUsesIDToken(p.Key)`, pass the nonce from the cookie to `fetchOAuthProfile` in the callback.
      4. internal/server/oauth_profile.go: `errOIDCNonceMismatch`, `errOIDCUserInfoSubject`, the `googleIssuerURL` variable, `oauthProviderUsesIDToken`, `verifyIDTokenNonce`, the new `fetchOAuthProfile`/`fetchGoogleProfile`/`fetchOIDCProfile` signatures and the new `fetchOIDCProfile` body.
      5. internal/server/oauth_test.go: convert `newFakeOIDCServer` to `fakeOIDCOptions` with the `/oidc/userinfo` handler, add `fakeOIDCProviderConfig` and `restoreGoogleIssuerURL`, update the two existing tests and add every test in Design B §3 "Tests to add / change".
      6. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 -run 'TestFetchOIDCProfile|TestOIDCCallback|TestFetchGoogleProfileRequiresMatchingNonce|TestOAuthStartSendsNonceAndStoresItInFlowCookie|TestOAuthStartOmitsNonceForGitHub|TestParseOAuthFlowCookie' passes
      - '`grep -c "oidc.Nonce(" internal/server/oauth_flow.go` prints 1'
      - mise run check passes

  - id: p14-slugs-names
    title: Random suffix on name-derived slugs and the 200-character name limit on create (L15, L7a)
    depends_on: []
    complexity: S
    touches:
      - internal/uploads/slug.go
      - internal/uploads/service.go
      - internal/uploads/rename.go
      - internal/uploads/validate_test.go
      - internal/uploads/rename_test.go
      - internal/uploads/service_test.go
      - internal/server/upload_service_test.go
      - internal/server/web_rename_test.go
      - internal/server/rename_e2e_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design D › L15 and Design D › L7 "L7a".
      2. internal/uploads/slug.go: replace the constants, `generateSlugFromName`, `generateRandomSlug` and `randID` with the Design D › L15 code (`randomSlugString`, `slugAlphabet`); drop the `encoding/base64` import.
      3. internal/uploads/rename.go: `nameTooLongMessage` constant, use it in `Rename`, new doc comment on `Rename`.
      4. internal/uploads/service.go `Create`: the rune-count check after the default-name block.
      5. Update the four breaking tests exactly as L15 "Tests to update / add" (`TestGenerateSlugFromName`, `TestRenameDerivesNewSlug`, `TestDashboardRenameChangesLinkAndAudits`, `TestRenameE2E`) and add `TestRandomSlugString`, the uniqueness assertion, `TestCreateRejectsNameOver200Characters`, `TestCreateAcceptsNameOf200Characters` and `TestAPIUploadRejectsLongName`.
      6. If any other test fails because it expects a name-derived slug, stop with status=blocked naming it. Do not edit docs (p20/p21). Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/uploads ./internal/server -count=1 -run 'TestGenerateSlugFromName|TestRandomSlugString|TestGenerateSlugUniqueness|TestRenameDerivesNewSlug|TestCreateRejectsNameOver200Characters|TestCreateAcceptsNameOf200Characters|TestAPIUploadRejectsLongName|TestDashboardRenameChangesLinkAndAudits|TestRenameE2E' passes
      - '`grep -n "encoding/base64" internal/uploads/slug.go` prints nothing'
      - mise run check passes

  # ---------------------------------------------------------------- wave B: dependent security phases
  - id: p06-cli-path-segments
    title: Validate and escape slugs and token ids in CLI paths; warn on --password (L12, L13 --password)
    depends_on: [p05-cli-login-host]
    complexity: M
    touches:
      - internal/cli/path_segments.go
      - internal/cli/uploads_command.go
      - internal/cli/stats_comments_command.go
      - internal/cli/gdpr_command.go
      - internal/cli/grants_command.go
      - internal/cli/token_command.go
      - internal/cli/upload_command.go
      - internal/cli/path_segments_test.go
      - internal/cli/uploads_command_requests_test.go
      - internal/cli/upload_command_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design C › L12 and Design C › L13 item a.
      2. New internal/cli/path_segments.go with `slugPattern`, `slugPath` and `tokenIDPath`.
      3. Apply `slugPath` at every call site in the L12 table, before `LoadConfig()`; replace the `url.PathEscape` calls in grants_command.go and uploads_command.go and drop unused `net/url` imports; `tokenIDPath` in token_command.go; the `--slug` check in upload_command.go.
      4. The `--password` warning in `cmdUpload` and `cmdVisibility` (L12 "L13 `--password` warning").
      5. Tests: new internal/cli/path_segments_test.go (four tests), `TestCmdVisibilityWarnsAboutPasswordFlag`, `TestCmdUploadWarnsAboutPasswordFlag`, `TestUploadWithSlugRejectsInvalidSlug`. Use `captureStderr` from p05.
      6. Run `mise run check`.
    acceptance:
      - go test ./internal/cli -count=1 -run 'TestSlugPathAcceptsServerSlugs|TestSlugPathRejectsUnsafeSlugs|TestTokenIDPath|TestCommandsRejectTraversalSlugBeforeRequest|TestCmdVisibilityWarnsAboutPasswordFlag|TestCmdUploadWarnsAboutPasswordFlag|TestUploadWithSlugRejectsInvalidSlug' passes
      - mise run check passes

  - id: p09a-client-ip-limiter
    title: Rightmost-untrusted client IP with --trusted-proxy-cidrs, IPv6 /64 keys, capped limiter maps (S2 part 1)
    depends_on: [p07-token-policy]
    complexity: M
    touches:
      - internal/server/client_ip.go
      - internal/server/analytics.go
      - internal/server/ratelimit.go
      - internal/server/middleware.go
      - internal/server/comments.go
      - internal/server/server.go
      - internal/peekd/run.go
      - internal/server/client_ip_test.go
      - internal/server/analytics_test.go
      - internal/server/ratelimit_test.go
      - internal/peekd/run_test.go
    brief: |
      1. Read the must-read docs and Design §0 (especially §0.6), then Design A › S2 "Config", "clientIP", "Limiter keys", "Limiter hard cap".
      2. New internal/server/client_ip.go: `DefaultTrustedProxyCIDRs`, `ParseTrustedProxyCIDRs`, `clientIP` (moved from analytics.go, which loses it), `parseRemoteAddr`, `parseForwardedHop`, `isTrustedProxy`, `warnUntrustedForwarder`, `rateLimitKeyForIP`, `rateLimitKey`.
      3. internal/server/server.go: `Config.TrustedProxyCIDRs`, `Server.trustedProxyCIDRs`, `Server.warnedUntrustedForwarder`, the defaulting and log line in `New`, and the `pagePasswordFailLimiter` / `accountLoginLimiter` fields constructed in `New` (§0.6).
      4. internal/server/ratelimit.go: the constants block, `maxKeys`/`nextPrune`, `hasRoom`, nil-safe `blocked` and `recordFailure`; remove the old 10000-key scan.
      5. Switch exactly the four limiter call sites to `s.rateLimitKey(r)`: ratelimit.go `rateLimit`, middleware.go global limiter, comments.go (two sites). Leave analytics and audit on `clientIP`.
      6. internal/peekd/run.go: `--trusted-proxy-cidrs` / `PEEK_TRUSTED_PROXY_CIDRS`, parse, the empty-list error, pass to `server.Config`.
      7. Tests: new internal/server/client_ip_test.go (with `mustPrefixes`), the ratelimit_test.go additions and the `TestLimiterCapacityCleanup` update, the analytics_test.go update, and the four internal/peekd/run_test.go changes.
      8. Do not touch pages.go or web_login.go (p09b). Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server ./internal/peekd -count=1 -run 'TestClientIPRightmostUntrustedHop|TestClientIPIgnoresForwardedForWithoutTrustedProxy|TestClientIPWarnsOnceForUntrustedForwarder|TestParseTrustedProxyCIDRs|TestRateLimitKeyForIP|TestLimiterFailsClosedWhenFull|TestLimiterBlockedDoesNotCountHits|TestLimiterNilIsNoop|TestRateLimitWrapperGroupsIPv6By64|TestLimiterCapacityCleanup|TestRecordVisitPersistsPrivacySafeAnalytics|TestParseServeConfig' passes
      - '`grep -n "func (s \*Server) clientIP" internal/server/analytics.go` prints nothing'
      - mise run check passes

  - id: p09b-failure-limiters
    title: Per-page password and per-email sign-in failure limits (S2 part 2)
    depends_on: [p01-raw-sandbox, p09a-client-ip-limiter]
    complexity: S
    touches:
      - internal/server/pages.go
      - internal/server/web_login.go
      - internal/server/pages_test.go
      - internal/server/web_login_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.6, §0.7), then Design A › S2 "Per-page password failure limiter" and "Per-account login failure limiter".
      2. internal/server/pages.go `handlePagePassword`: the `failKey` check before `ParseForm` and `recordFailure` on a wrong password.
      3. internal/server/web_login.go: `errLoginThrottled`, `loginFailureKey`, the throttle wrapper `loginWithPassword` around a new `checkPasswordLogin` holding today's body, and the 429 branch in `handleLogin`.
      4. Tests: `TestPagePasswordFailuresLockPageAfterLimit` (pages_test.go), `TestPasswordLoginFailuresLockAccountAfterLimit`, `TestPasswordLoginThrottlesUnknownEmails`, `TestHandleLoginReturns429WhenAccountThrottled` (web_login_test.go).
      5. If an existing test sends more than 10 password logins for one email or more than 20 failures for one page and now fails, stop with status=blocked naming it. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 -run 'TestPagePasswordFailuresLockPageAfterLimit|TestPasswordLoginFailuresLockAccountAfterLimit|TestPasswordLoginThrottlesUnknownEmails|TestHandleLoginReturns429WhenAccountThrottled' passes
      - mise run check passes

  - id: p10-cli-login-pages
    title: Typed-code CLI login pages with request context, rate limit and 90-day CLI tokens (S3 server side, S4 expiry)
    depends_on: [p01-raw-sandbox, p02-db-auth-storage, p04-supply-chain-ci, p07-token-policy]
    complexity: M
    touches:
      - internal/server/cli_login.go
      - internal/server/routes.go
      - internal/web/templates/cli_login.gohtml
      - internal/web/renderer.go
      - internal/web/assets/pines.css
      - internal/server/cli_login_test.go
      - internal/web/renderer_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design B §1 (server side) and the poll part of Design B §2.
      2. internal/server/cli_login.go: the constants (including `cliTokenTTL`), `formatUserCode`, `normalizeUserCode`, `cliLoginUserAgent`, the start handler changes, `handleCLILoginEntry`, `handleCLILoginLookup`, `handleCLILoginLegacyLink`, `cliLoginApprovalData`, `renderCLILoginEntry`, the new `handleCLILoginApprove` order with audits, and the poll using `accountActive` and `CreateAccountTokenExpiring`. Delete `handleCLILoginPage`.
      3. internal/server/routes.go: replace the two `/cli-login/{code}` routes with the four routes of Design B §1.
      4. internal/web/renderer.go: `TemplateCLILoginEntry`, the new `CLILoginData` fields and `CLILoginEntryData`. internal/web/templates/cli_login.gohtml: the new `cli-login-entry` template and the approval page changes.
      5. Run `mise run build`; if it changes internal/web/assets/pines.css, commit that change; if it removes classes, stop with status=blocked.
      6. Tests: new internal/server/cli_login_test.go with every test of Design B §1 "internal/server/cli_login_test.go"; the internal/web/renderer_test.go changes.
      7. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server ./internal/web -count=1 -run 'TestNormalizeUserCode|TestCLILoginStartReturnsCodeFreeVerificationURL|TestCLILoginLegacyLinkRedirectsWithoutCode|TestCLILoginEntryRequiresSession|TestCLILoginEntryRendersCodeForm|TestCLILoginLookupShowsRequestContext|TestCLILoginLookupRejectsUnknownExpiredOrMalformedCode|TestCLILoginLookupRequiresCSRF|TestCLILoginLookupIsRateLimited|TestCLILoginApproveIssuesNinetyDayToken|TestCLILoginApproveDeny|TestCLILoginApproveRequiresCSRF|TestCLILoginApproveRequiresSession|TestCLILoginApproveExpiredCode|TestCLILoginPollDeniesAccountFailingPolicy|TestRendererExecutesAllTemplates' passes
      - '`grep -n "\"/cli-login/\" + userCode" internal/server/cli_login.go` prints nothing and `grep -c "cliTokenTTL = 90 \* 24 \* time.Hour" internal/server/cli_login.go` prints 1'
      - mise run check passes

  - id: p11a-login-timing
    title: One bcrypt comparison on every password-login failure path (L4)
    depends_on: [p09b-failure-limiters]
    complexity: S
    touches:
      - internal/server/web_login.go
      - internal/server/web_login_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.7), then Design B §4.
      2. internal/server/web_login.go: `passwordCompare`, `dummyPasswordHash` (`sync.OnceValue`), `checkPassword`, and the new order inside `checkPasswordLogin` (p09b's throttle wrapper stays around it). `checkPasswordLogin` still returns `(int64, string, error)` in this phase, so Design B §4's `return nil, fmt.Errorf(...)` is written `return 0, "", fmt.Errorf(...)`; p11b changes the types.
      3. Tests in internal/server/web_login_test.go: `TestLoginWithPasswordRunsOneBcryptCompareOnEveryFailure` (fresh server per subtest) and `TestDummyPasswordHashIsDefaultCost`.
      4. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 -run 'TestLoginWithPasswordRunsOneBcryptCompareOnEveryFailure|TestDummyPasswordHashIsDefaultCost|TestPasswordLoginFailuresLockAccountAfterLimit' passes
      - '`grep -n "dummyPasswordHash" internal/server/web_login.go` matches'
      - mise run check passes

  - id: p11b-session-epoch
    title: Session cookies carry the account epoch; "Sign out other sessions" (L5)
    depends_on: [p02-db-auth-storage, p08-oidc-nonce-claims, p10-cli-login-pages, p11a-login-timing]
    complexity: M
    touches:
      - internal/server/oauth_session.go
      - internal/server/web_auth.go
      - internal/server/web_login.go
      - internal/server/oauth_flow.go
      - internal/server/web_setup.go
      - internal/server/routes.go
      - internal/server/web_sessions.go
      - internal/web/templates/dashboard.gohtml
      - internal/web/assets/pines.css
      - internal/server/web_sessions_test.go
      - internal/server/web_login_test.go
      - internal/server/auth_domain_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.5, §0.7), then Design B §5 (server parts).
      2. internal/server/oauth_session.go: `sessionSubject`, `parseSessionSubject`, `setWebSession(w, account *models.Account)`.
      3. internal/server/web_auth.go: parse the subject with `parseSessionSubject` and refuse a stale epoch before the `accountActive` check.
      4. Callers: oauth_flow.go and web_setup.go pass the account; web_login.go changes `loginWithPassword`, `checkPasswordLogin` and `loginWithToken` to return `(*models.Account, error)` and `handleLogin` uses the account (§0.7).
      5. New internal/server/web_sessions.go with `handleDashboardSessionsRevoke` and the two flash constants of §0.5; route `POST /dashboard/sessions/revoke` in routes.go; the button in internal/web/templates/dashboard.gohtml.
      6. Run `mise run build`; commit a pines.css change if any (pines.css is generated, so it is not counted as a ninth source file); stop if classes are removed.
      7. Tests: new internal/server/web_sessions_test.go (Design B §5 list, with the §0.5 Locations), `TestLoginSetsEpochSessionCookie` in web_login_test.go, arity updates in auth_domain_test.go and web_login_test.go.
      8. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 -run 'TestParseSessionSubject|TestWebAuthRejectsStaleSessionEpoch|TestSetWebSessionIncludesEpoch|TestDashboardSessionsRevokeSignsOutOtherSessions|TestDashboardSessionsRevokeRequiresCSRF|TestDashboardSessionsRevokeRequiresSession|TestReEnabledAccountDoesNotReviveSessions|TestDashboardShowsSignOutOtherSessions|TestLoginSetsEpochSessionCookie' passes
      - '`grep -c "POST /dashboard/sessions/revoke" internal/server/routes.go` prints 1'
      - mise run check passes

  - id: p12-server-runtime
    title: Owner-only data dir and secret, /metrics token, generic /readyz, S3 bucket checks, _FILE secrets (S7 server, L10, L11 server, L13 peekd)
    depends_on: [p03-file-modes-s3-guard, p09a-client-ip-limiter]
    complexity: M
    touches:
      - internal/server/server.go
      - internal/server/bootstrap.go
      - internal/server/metrics.go
      - internal/server/health.go
      - internal/server/settings.go
      - internal/peekd/run.go
      - internal/peekd/env.go
      - internal/server/metrics_test.go
      - internal/server/file_modes_test.go
      - internal/server/bootstrap_test.go
      - internal/server/settings_test.go
      - internal/peekd/run_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design C › S7 (server items 1, 2, 4), › L10, › L11 (items 4–5) and › L13 item d.
      2. internal/server/server.go: data dir and uploads 0o700 with the warning; `Config.MetricsToken` / `Server.metricsToken`; the S3 bucket startup check.
      3. internal/server/bootstrap.go: chmod an existing secret file to 0o600.
      4. internal/server/metrics.go: `metricsAuthorized` and the 401 branch. internal/server/health.go: generic `not ready` with the logged error.
      5. internal/server/settings.go: the `s3_bucket` case in `normalizeSettingValue`.
      6. internal/peekd/env.go: `getenvSecret`, `secretFlagWarnings`. internal/peekd/run.go: `_FILE` defaults for secret, S3 secret key and metrics token; the `--metrics-token` flag and its 16-character check; print the flag warnings; pass `MetricsToken`; add `metrics_auth` to the start log.
      7. Tests: new internal/server/metrics_test.go and internal/server/file_modes_test.go, `TestLoadOrCreateSecretTightensExistingFileMode` (bootstrap_test.go), the settings_test.go additions, and the run_test.go tests of L10 and L13 d.
      8. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server ./internal/peekd -count=1 -run 'TestMetricsOpenWithoutConfiguredToken|TestMetricsRequiresConfiguredBearerToken|TestMetricsRejectsAPITokenWhenMetricsTokenConfigured|TestReadyzHidesDatabaseError|TestNewCreatesOwnerOnlyDataFiles|TestLoadOrCreateSecretTightensExistingFileMode|TestNormalizeSettingsValues|TestNormalizeSettingRejectsInvalidS3Bucket|TestParseServeConfigMetricsTokenFromEnv|TestParseServeConfigRejectsShortMetricsToken|TestGetenvSecretReadsFile|TestGetenvSecretRejectsBothVarAndFile|TestGetenvSecretRejectsEmptyFile|TestParseServeConfigS3SecretKeyFromFile|TestSecretFlagWarnings' passes
      - mise run check passes

  - id: p13-body-cap
    title: 64 KiB request body cap outside the two upload routes (L1)
    depends_on: [p09a-client-ip-limiter]
    complexity: S
    touches:
      - internal/server/middleware.go
      - internal/server/web_security_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design A › L1.
      2. internal/server/middleware.go: `maxRequestBodyBytes`, `bodyLimitExempt`, `requestTooLargeError`, and the cap in `withMiddleware` after the global limiter.
      3. Tests in internal/server/web_security_test.go: the five tests of Design A › L1.
      4. If an existing test posts more than 64 KiB to a non-upload route, or the settings form needs more, stop with status=blocked. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 -run 'TestRequestBodyCapRejectsDeclaredOversizedForm|TestRequestBodyCapCutsChunkedForm|TestRequestBodyCapJSONAPI|TestRequestBodyCapExemptsUploads|TestRequestBodyCapAllowsSmallForms' passes
      - mise run check passes

  - id: p15-audit-detail
    title: Quote user-controlled audit detail values (L7b)
    depends_on: [p14-slugs-names]
    complexity: M
    touches:
      - internal/server/lifecycle.go
      - internal/server/api_tokens.go
      - internal/server/api_rename.go
      - internal/server/api_uploads.go
      - internal/server/api_grants.go
      - internal/server/admin.go
      - internal/server/web_api_keys.go
      - internal/server/web_grants.go
      - internal/server/lifecycle_test.go
      - internal/server/web_api_keys_test.go
    brief: |
      1. Read the must-read docs and Design §0, then Design D › L7 "L7b".
      2. internal/server/lifecycle.go: `auditDetail` and `auditValue`.
      3. Replace every detail string in the "Exact replacements (P2)" list (api_tokens.go, api_rename.go, api_uploads.go, api_grants.go, web_grants.go, web_api_keys.go, admin.go). The two web_dashboard.go lines belong to p16.
      4. Tests: `TestAuditDetailQuotesUnsafeValues` and `TestAPIUploadAuditQuotesName` in lifecycle_test.go; update the `want` at the `name=QA runner` assertion in web_api_keys_test.go.
      5. If any other exact-detail assertion changes, stop with status=blocked. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 -run 'TestAuditDetailQuotesUnsafeValues|TestAPIUploadAuditQuotesName' passes
      - mise run check passes

  - id: p16-flash-codes
    title: Dashboard flashes carry only codes; settings errors render inline (L9)
    depends_on: [p11b-session-epoch, p12-server-runtime, p15-audit-detail]
    complexity: M
    touches:
      - internal/server/web_helpers.go
      - internal/server/web_dashboard.go
      - internal/server/settings.go
      - internal/server/web_rename.go
      - internal/server/upload_service.go
      - internal/server/admin.go
      - internal/server/web_grants.go
      - internal/server/web_api_keys.go
      - internal/server/web_helpers_test.go
      - internal/server/web_dashboard_test.go
      - internal/server/web_grants_test.go
      - internal/server/web_rename_test.go
      - internal/server/web_api_keys_test.go
      - internal/server/admin_test.go
      - internal/server/settings_test.go
      - internal/server/web_sessions_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.5), then Design D › L9 in full and the two web_dashboard.go lines of Design D › L7 "P3".
      2. internal/server/web_helpers.go: the flash constants of the L9 tables and `flashMessages` (all L9 codes, plus entries for `flashSessionsRevoked` and `flashSessionsRevokeFailed`, which stay declared in web_sessions.go), the new redirect helpers, `dashboardFlashView`, `resolveFlash`, `flashText`, `findDashUpload`, `dashUploadHasGrant`, `grantFlashCode`.
      3. internal/server/upload_service.go: delete `uploadErrorMessage`, add `uploadFlashCode`.
      4. internal/server/web_dashboard.go: split `handleDashboard` into it plus `renderDashboard`; convert every call site; the two `auditDetail` lines.
      5. Convert the call sites in settings.go (inline 400 render for normalize errors), web_rename.go, web_grants.go, admin.go and web_api_keys.go exactly as listed.
      6. Update and add the tests in L9 "Tests to update (P3)" and "Tests to add (P3)"; include `flashSessionsRevoked` and `flashSessionsRevokeFailed` in `TestFlashMessagesCoverAllCodes`; in web_sessions_test.go change `TestDashboardSessionsRevokeRequiresCSRF` to expect `/dashboard?err=invalid_session` (§0.5).
      7. Check: `grep -n 'dashboardError(w, r, "' internal/server/*.go`, `grep -n 'dashboardOK(w, r, "' internal/server/*.go` and `grep -n '"[a-z_]*="+' internal/server/*.go | grep -v _test` (only pages.go and comments.go may remain).
      8. If a flash producer outside the listed files appears, stop with status=blocked. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 -run 'TestFlashMessagesCoverAllCodes|TestUploadFlashCodeMatchesUploadErrors|TestGrantFlashCodeMatchesGrantErrors|TestResolveFlash|TestDashboardIgnoresFreeTextFlash|TestDashboardUploadedFlashShowsOwnUploadLink|TestDashboardUploadedRedirectCarriesSlug|TestDashboardSettingsInvalidS3EndpointRendersInlineError|TestDashboardSettingsRejectsInvalidValuesBeforeWriting' passes
      - '`grep -n "dashboardError(w, r, \"" internal/server/*.go` and `grep -n "dashboardOK(w, r, \"" internal/server/*.go` print nothing'
      - mise run check passes

  - id: p17-comment-authors
    title: Signed-in comments use the account name and are marked verified (L8, migration 13)
    depends_on: [p02-db-auth-storage, p03-file-modes-s3-guard, p09a-client-ip-limiter, p10-cli-login-pages]
    complexity: M
    touches:
      - internal/db/migrations.go
      - internal/db/schema.go
      - internal/db/comments.go
      - internal/models/models.go
      - internal/server/comments.go
      - internal/server/api_stats.go
      - internal/web/assets/app.js
      - internal/web/templates/page.gohtml
      - internal/db/store_test.go
      - internal/server/api_test.go
      - internal/server/comments_test.go
      - internal/server/api_stats_test.go
      - internal/web/renderer_test.go
      - internal/web/assets_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.1), then Design D › L8 in full.
      2. DB: `comments.account_id` in schema.go; migration `{13, "comment_account_id", …}` after 12 with its `m.id == 13` branch and `migrateCommentAccountID`; `models.Comment.AccountID`; `AddComment` gains `accountID int64`; `ListComments` reads it.
      3. internal/server/comments.go: `Verified` in `commentOut`, `commentOutFrom`, `commentAccountName`, the signed-in branch in `handleAddComment`, `owner.AccountID` and `commentOutFrom` in `handleAddAccountComment`. Leave the bearer branch of `handleListComments` and the limiter keys as they are.
      4. internal/server/api_stats.go: `Verified` in `exportComment`.
      5. internal/web/assets/app.js and internal/web/templates/page.gohtml: the Frontend changes (textContent-only rules of CONTRIBUTING.md; no HTML string APIs).
      6. Tests: the five `AddComment` call updates and two new tests in internal/db/store_test.go; `AddComment` in internal/server/api_test.go; the five comments_test.go tests; `TestExportMarksVerifiedComments`; `TestPageTemplateShowsVerifiedCommentMarker`; `TestParentAppMarksVerifiedComments`.
      7. Run `mise run build`; if it changes internal/web/assets/pines.css, stop with status=blocked (the design uses only existing classes). If id 13 is taken, stop with status=blocked. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/db ./internal/server ./internal/web -count=1 -run 'TestCommentAccountIDRoundTrip|TestMigrationAddsCommentAccountID|TestAddCommentSignedInViewerUsesAccountName|TestAddCommentAnonymousViewerIsUnverified|TestAddCommentDisabledSessionIsUnverified|TestAddCommentSignedInBlankNameUsesEmail|TestAccountCommentIsVerified|TestExportMarksVerifiedComments|TestPageTemplateShowsVerifiedCommentMarker|TestParentAppMarksVerifiedComments' passes
      - '`grep -c "{13, \"comment_account_id\"" internal/db/migrations.go` prints 1'
      - mise run check passes

  # ---------------------------------------------------------------- docs
  - id: p20-docs-operations
    title: Operator and user docs for every security change (operations, auth-access, using-peek, reference)
    depends_on: [p04-supply-chain-ci, p06-cli-path-segments, p13-body-cap, p16-flash-codes, p17-comment-authors]
    complexity: S
    touches:
      - docs/operations.md
      - docs/src/content/docs/auth-access.md
      - docs/src/content/docs/using-peek.md
      - docs/src/content/docs/reference.md
    brief: |
      1. Read the must-read docs and Design §0 (§0.2, §0.4).
      2. For each of the four files, apply every docs item that names it in Design A (S1, S2, L1), Design B §6 (as amended by §0.2), Design C (S7, L10, L11, S6, L12, L13) and Design D (L15, L7a, L7b, L8). Use the code on the branch as the source of truth for flag names, defaults and texts; where a docs item disagrees with the merged code, follow the code and say so in the report.
      3. docs/operations.md "Upgrades And Rollbacks": one paragraph each for migrations 11, 12, 13 and the S1, S2 and token-policy notes, in that order, after the migration 10 paragraph.
      4. No manual line wrapping (AGENTS.md).
      5. Build the docs site: `cd docs && pnpm install --frozen-lockfile && pnpm build`. If that cannot run in the container, dispatch `pages.yml` against the feature branch with the GitHub MCP `actions_run_trigger` and judge its "Build docs" job (p04 made the deploy job run only on main; if the deploy job runs anyway, cancel the run and stop with status=blocked).
    acceptance:
      - '`grep -n "PEEK_TRUSTED_PROXY_CIDRS" docs/operations.md` matches, `grep -n "PEEK_METRICS_TOKEN" docs/operations.md` matches, `grep -n "Migration 13" docs/operations.md` matches'
      - '`grep -n "/cli-login" docs/src/content/docs/auth-access.md` matches and `grep -n "verified" docs/src/content/docs/reference.md` matches'
      - the docs site build passes (local `pnpm build`, or the pages.yml "Build docs" job)

  - id: p21-docs-readme-skills
    title: README, server setup, deployment platforms and skills (repo references, new flags, security table)
    depends_on: [p04-supply-chain-ci, p06-cli-path-segments, p13-body-cap, p16-flash-codes, p17-comment-authors]
    complexity: M
    touches:
      - README.md
      - docs/src/content/docs/server-setup.md
      - docs/src/content/docs/deployment-platforms.md
      - skills/peek/SKILL.md
      - skills/peek-server/SKILL.md
    brief: |
      1. Read the must-read docs and Design §0 (§0.4).
      2. Replace every `puemos` reference in these five files per the Design C › S5 table (rows marked P6), including the verified download block for skills/peek-server/SKILL.md and the image-pinning sentence.
      3. Apply every other docs item that names these files in Design A (S1, S2, L1), Design B §6, Design C (S5, L10, L13) and Design D (L15): security table rows, flag table rows (`--trusted-proxy-cidrs`, `--metrics-token`, `_FILE` variables), README slug examples (`PhiUs-lMbZE_Sw` → `mypage-html-k7m2xq`; skills → `page-html-k7m2xq`).
      4. Use the merged code as the source of truth for names and defaults. No manual line wrapping.
      5. Build the docs site as in p20 step 5.
    acceptance:
      - '`grep -rn puemos README.md skills docs/src/content/docs/server-setup.md docs/src/content/docs/deployment-platforms.md` prints nothing'
      - '`grep -n "PhiUs-lMbZE_Sw" README.md skills/peek/SKILL.md` prints nothing'
      - '`grep -n "trusted-proxy-cidrs" README.md` matches and `grep -n "checksums.txt" README.md` matches'
      - the docs site build passes (local `pnpm build`, or the pages.yml "Build docs" job)

  # ---------------------------------------------------------------- coverage
  - id: c01-cov-server-admin-setup
    title: Coverage for server admin, setup, bootstrap, New, render, assets; shared fault helpers
    depends_on: [p13-body-cap, p16-flash-codes, p17-comment-authors]
    complexity: M
    touches:
      - internal/server/fault_helpers_test.go
      - internal/server/admin_test.go
      - internal/server/web_setup_test.go
      - internal/server/bootstrap_test.go
      - internal/server/server_test.go
      - internal/server/render_test.go
      - internal/server/assets_test.go
      - internal/server/web_format_test.go
      - internal/server/json_decode_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E §1, §2, §6 and § "Phase S1".
      2. Step 0: re-profile internal/server and list count-0 blocks in admin.go, web_setup.go, bootstrap.go, server.go, render.go, assets.go, web_format.go, json_decode.go (Design E §6).
      3. Create internal/server/fault_helpers_test.go with `faultStorage`, `failingWriter`, `addFailTrigger`, `dropTable`, `newFaultServer` (Design E Phase S1). Grep for name clashes first.
      4. Cover the remaining blocks of those files with the techniques Design E Phase S1 lists, in the listed test files. Test files only; prefix new identifiers with `adm`.
      5. Measure with the per-file command of §0.9. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 passes
      - apart from files whose remaining count-0 blocks are all listed in the report as unreachable (§0.9), the §0.9 per-file command lists none of admin.go, web_setup.go (floor 85), bootstrap.go, server.go (floor 85), render.go, assets.go, web_format.go, json_decode.go below its floor
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c02-cov-server-api
    title: Coverage for server token, stats, grants, rename, versions and audit APIs
    depends_on: [c01-cov-server-admin-setup]
    complexity: M
    touches:
      - internal/server/api_stats_test.go
      - internal/server/api_tokens_test.go
      - internal/server/api_grants_test.go
      - internal/server/api_rename_test.go
      - internal/server/api_versions_test.go
      - internal/server/api_audit_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase S2" (the api_* bullets).
      2. Step 0: re-profile and list count-0 blocks in api_stats.go, api_tokens.go, api_grants.go, api_rename.go, api_versions.go, api_audit.go.
      3. Cover them in the listed test files using the fault helpers from c01. Test files only; prefix new identifiers with `apiCov`.
      4. Measure with the §0.9 command. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 passes
      - apart from files whose remaining count-0 blocks are all listed in the report as unreachable (§0.9), the §0.9 per-file command lists none of api_stats.go, api_tokens.go, api_grants.go, api_rename.go, api_versions.go, api_audit.go
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c03-cov-server-settings-helpers
    title: Coverage for server settings, runtime settings and small helpers
    depends_on: [c01-cov-server-admin-setup]
    complexity: M
    touches:
      - internal/server/settings_test.go
      - internal/server/runtime_settings_test.go
      - internal/server/access_test.go
      - internal/server/auth_domain_test.go
      - internal/server/upload_delete_test.go
      - internal/server/upload_service_test.go
      - internal/server/web_helpers_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase S2" (settings, runtime_settings and small-helper bullets).
      2. Step 0: re-profile and list count-0 blocks in settings.go, runtime_settings.go, access.go, auth_domain.go, upload_delete.go, upload_service.go, web_helpers.go, account_policy.go.
      3. Cover them in the listed test files (account_policy.go gaps go in auth_domain_test.go). Test files only; prefix new identifiers with `setCov`.
      4. Measure with the §0.9 command. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 passes
      - apart from files whose remaining count-0 blocks are all listed in the report as unreachable (§0.9), the §0.9 per-file command lists none of settings.go, runtime_settings.go, access.go, auth_domain.go, upload_delete.go, upload_service.go, web_helpers.go, account_policy.go
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c04-cov-server-dashboard-login
    title: Coverage for server dashboard, API keys, web grants, web login, web auth, sessions
    depends_on: [c01-cov-server-admin-setup]
    complexity: M
    touches:
      - internal/server/web_dashboard_test.go
      - internal/server/web_api_keys_test.go
      - internal/server/web_grants_test.go
      - internal/server/web_login_test.go
      - internal/server/web_auth_test.go
      - internal/server/web_sessions_test.go
      - internal/server/web_rename_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase S3".
      2. Step 0: re-profile and list count-0 blocks in web_dashboard.go, web_api_keys.go, web_grants.go, web_login.go, web_auth.go, web_sessions.go, web_rename.go.
      3. Cover them in the listed test files. Test files only; prefix new identifiers with `dashCov`.
      4. Measure with the §0.9 command. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 passes
      - apart from files whose remaining count-0 blocks are all listed in the report as unreachable (§0.9), the §0.9 per-file command lists none of web_dashboard.go, web_api_keys.go, web_grants.go, web_login.go, web_auth.go, web_sessions.go, web_rename.go
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c05-cov-server-oauth
    title: Coverage for server OAuth flow, profile, config, accounts and session helpers
    depends_on: [c01-cov-server-admin-setup]
    complexity: M
    touches:
      - internal/server/oauth_flow_test.go
      - internal/server/oauth_profile_test.go
      - internal/server/oauth_config_test.go
      - internal/server/oauth_accounts_test.go
      - internal/server/oauth_session_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase S4". The fakes live in internal/server/oauth_test.go (after p08: `fakeOIDCOptions`, `fakeOIDCProviderConfig`, `restoreGoogleIssuerURL`); reuse them, do not edit oauth_test.go.
      2. Step 0: re-profile and list count-0 blocks in oauth_flow.go, oauth_profile.go, oauth_config.go, oauth_accounts.go, oauth_session.go.
      3. Cover them in the five new test files. Test files only; prefix new identifiers with `oauthCov`.
      4. Measure with the §0.9 command. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 passes
      - apart from files whose remaining count-0 blocks are all listed in the report as unreachable (§0.9), the §0.9 per-file command lists none of oauth_flow.go, oauth_profile.go, oauth_config.go, oauth_accounts.go, oauth_session.go
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c06-cov-server-cli-login-runtime
    title: Coverage for server CLI login, metrics, health, middleware, security, client IP, rate limits
    depends_on: [c01-cov-server-admin-setup]
    complexity: M
    touches:
      - internal/server/cli_login_test.go
      - internal/server/metrics_test.go
      - internal/server/health_test.go
      - internal/server/middleware_test.go
      - internal/server/security_test.go
      - internal/server/client_ip_test.go
      - internal/server/ratelimit_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase S5".
      2. Step 0: re-profile and list count-0 blocks in cli_login.go, metrics.go, health.go, middleware.go, security.go, client_ip.go, ratelimit.go.
      3. Cover them in the listed test files. Test files only; prefix new identifiers with `cliLoginCov`.
      4. Measure with the §0.9 command (security.go floor 85). Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 passes
      - apart from files whose remaining count-0 blocks are all listed in the report as unreachable (§0.9), the §0.9 per-file command lists none of cli_login.go, metrics.go, health.go, middleware.go, client_ip.go, ratelimit.go, and security.go not below 85%
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c07-cov-server-uploads-pages
    title: Coverage for server uploads API, pages, comments, lifecycle, analytics, account comments
    depends_on: [c01-cov-server-admin-setup]
    complexity: M
    touches:
      - internal/server/api_uploads_test.go
      - internal/server/pages_test.go
      - internal/server/comments_test.go
      - internal/server/lifecycle_test.go
      - internal/server/analytics_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase S6" (handleRaw no longer exists after p01).
      2. Step 0: re-profile and list count-0 blocks in api_uploads.go, pages.go, comments.go, lifecycle.go, analytics.go.
      3. Cover them in the listed test files. Test files only; prefix new identifiers with `pageCov`.
      4. Measure with the §0.9 command. Then measure the whole package: `go test -cover ./internal/server/`. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/server -count=1 passes
      - apart from files whose remaining count-0 blocks are all listed in the report as unreachable (§0.9), the §0.9 per-file command lists none of api_uploads.go, pages.go, comments.go, lifecycle.go, analytics.go
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c08-cov-db-store
    title: Coverage for every non-migration db file (closed-store table, triggers, scan errors)
    depends_on: [p17-comment-authors]
    complexity: M
    touches:
      - internal/db/faults_test.go
      - internal/db/accounts_test.go
      - internal/db/invites_test.go
      - internal/db/oauth_test.go
      - internal/db/visits_test.go
      - internal/db/uploads_test.go
      - internal/db/audit_test.go
      - internal/db/settings_test.go
      - internal/db/comments_test.go
      - internal/db/cli_login_test.go
      - internal/db/tokens_test.go
      - internal/db/versions_test.go
      - internal/db/grants_test.go
      - internal/db/slug_aliases_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase D1".
      2. Step 0: re-profile internal/db and list count-0 blocks in every file except migrations.go, schema.go, store.go.
      3. Implement D1 items 1–4 (happy paths, `TestStoreMethodsFailOnClosedStore` in faults_test.go, `failOn` trigger helper, scan errors) in the listed files; extend files p02 created rather than recreating them.
      4. Measure with the §0.9 command (floors for accounts.go, tokens.go, versions.go, uploads.go, slug_aliases.go are 85). Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/db -count=1 passes
      - the §0.9 per-file command for internal/db lists no non-migration file below its floor
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c09-cov-db-migrations
    title: Coverage for db migrations and store open
    depends_on: [c08-cov-db-store]
    complexity: M
    touches:
      - internal/db/migrations_test.go
      - internal/db/store_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase D2".
      2. Step 0: re-profile and list count-0 blocks in migrations.go and store.go.
      3. Cover the `Open` failure branches, the per-migration error wrapping (now including 11, 12, 13) and the legacy fixtures, in a new internal/db/migrations_test.go and store_test.go. Leave deep class-(c) branches.
      4. Measure: migrations.go ≥ 80%, store.go ≥ 85%, and `go test -cover ./internal/db/` ≥ 90.0%. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/db -count=1 passes
      - '`go test -cover ./internal/db/` reports at least 90.0% of statements'
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c10-cov-cli-core
    title: Coverage for the CLI dispatcher, config, login, OAuth login, discovery, browser and client
    depends_on: [p06-cli-path-segments]
    complexity: M
    touches:
      - internal/cli/commands_test.go
      - internal/cli/config_command_test.go
      - internal/cli/login_command_test.go
      - internal/cli/login_oauth_test.go
      - internal/cli/login_discovery_test.go
      - internal/cli/browser_test.go
      - internal/cli/client_test.go
      - internal/cli/hostcheck_test.go
      - internal/cli/test_helpers_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase C1".
      2. Step 0: re-profile internal/cli and list count-0 blocks in commands.go, config_command.go, login_command.go, login_oauth.go, login_discovery.go, browser.go, client.go, hostcheck.go.
      3. Add `withStdin(t, input)` to test_helpers_test.go, then cover the blocks in the listed files. The browser test must set `PATH` to an empty temp dir. Test files only.
      4. Measure with the §0.9 command (login_command.go floor 85, browser.go floor 50). Run `mise run check`.
    acceptance:
      - go test ./internal/cli -count=1 passes
      - apart from files whose remaining count-0 blocks are all listed in the report as unreachable (§0.9), the §0.9 per-file command lists none of commands.go, config_command.go, login_oauth.go, login_discovery.go, client.go, hostcheck.go, and login_command.go, browser.go not below their floors
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c11-cov-cli-commands
    title: Coverage for the CLI upload, uploads, grants, gdpr, stats/comments and token commands
    depends_on: [c10-cov-cli-core]
    complexity: M
    touches:
      - internal/cli/upload_command_test.go
      - internal/cli/uploads_command_test.go
      - internal/cli/grants_command_test.go
      - internal/cli/gdpr_command_test.go
      - internal/cli/stats_comments_command_test.go
      - internal/cli/token_command_test.go
      - internal/cli/path_segments_test.go
      - internal/cli/format_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase C2".
      2. Step 0: re-profile and list count-0 blocks in upload_command.go, uploads_command.go, grants_command.go, gdpr_command.go, stats_comments_command.go, token_command.go, path_segments.go, format.go.
      3. Cover them in the listed files with one generic httptest fake. Test files only.
      4. Measure with the §0.9 command and `go test -cover ./internal/cli/` (≥ 91.0%). Run `mise run check`.
    acceptance:
      - go test ./internal/cli -count=1 passes
      - '`go test -cover ./internal/cli/` reports at least 91.0% of statements'
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c12-cov-objectstore
    title: Coverage for the S3 client against a fake S3 and file storage error paths
    depends_on: [p03-file-modes-s3-guard]
    complexity: M
    touches:
      - internal/objectstore/s3_test.go
      - internal/objectstore/file_test.go
      - internal/objectstore/s3_endpoint_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase O1". After p03 the bucket must be a valid DNS name (`bucket` is fine).
      2. Step 0: re-profile and list count-0 blocks in s3.go, s3_signing.go, s3_endpoint.go, file.go, slug.go, storage.go.
      3. Build the fake S3 in a new s3_test.go and cover the blocks in the three new test files (do not edit storage_test.go). Use path-type collisions, not chmod.
      4. Measure: `go test -cover ./internal/objectstore/` ≥ 92.0%. Run `mise run check-full` (Design §0.8).
    acceptance:
      - go test ./internal/objectstore -count=1 passes
      - '`go test -cover ./internal/objectstore/` reports at least 92.0% of statements'
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: c13-cov-peekd
    title: Coverage for peekd Run, runServe (signal-driven), backup, env, healthcheck
    depends_on: [p12-server-runtime]
    complexity: M
    touches:
      - internal/peekd/serve_test.go
      - internal/peekd/env_test.go
      - internal/peekd/backup_test.go
      - internal/peekd/healthcheck_test.go
      - internal/peekd/run_test.go
      - internal/peekd/run.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase P1" and its risks in §8.
      2. Step 0: re-profile internal/peekd and list count-0 blocks.
      3. New serve_test.go (`//go:build unix`): register the guard `signal.Notify` before starting `runServe`, use a free port, poll `/healthz`, send SIGTERM; plus the error cases (i)–(iv). Restore `slog.Default()` in `t.Cleanup`. New env_test.go and healthcheck_test.go; extend backup_test.go and run_test.go (including the `_FILE` and metrics-token paths p12 added).
      4. Test files only, except the §0.9 fallback (`var notifyShutdown = signal.Notify` in run.go) if the signal test is flaky under `-race`; say so if used.
      5. Measure: `go test -cover ./internal/peekd/` ≥ 90.0%. Run `mise run check` and `mise run race`.
    acceptance:
      - go test -race ./internal/peekd -count=3 passes
      - '`go test -cover ./internal/peekd/` reports at least 90.0% of statements'

  - id: c14-cov-uploads-web-groups-version
    title: Coverage for uploads, web, groups and version
    depends_on: [p14-slugs-names, p17-comment-authors]
    complexity: S
    touches:
      - internal/uploads/service_test.go
      - internal/uploads/slug_test.go
      - internal/uploads/rename_test.go
      - internal/uploads/validate_test.go
      - internal/web/renderer_test.go
      - internal/web/assets_test.go
      - internal/groups/directory_test.go
      - internal/version/version_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase X1".
      2. Step 0: re-profile internal/uploads, internal/web, internal/groups and internal/version.
      3. Cover the remaining blocks in the listed files. Test files only.
      4. Measure: uploads ≥ 92.0%, web ≥ 90.0%, groups ≥ 95.0%, version 100% (`go test -cover ./internal/uploads/ ./internal/web/ ./internal/groups/ ./internal/version/`). Run `mise run check-full` (Design §0.8).
    acceptance:
      - '`go test -cover ./internal/uploads/ ./internal/web/ ./internal/groups/ ./internal/version/` reports at least 92.0%, 90.0%, 95.0% and 100.0% respectively'
      - '`git fetch -q origin fix/security-hardening-coverage && git diff --name-only FETCH_HEAD...HEAD | grep -v "_test.go$"` prints nothing'

  - id: g01-coverage-gate
    title: CI and local gate at 90.0% total coverage
    depends_on: [p04-supply-chain-ci, c02-cov-server-api, c03-cov-server-settings-helpers, c04-cov-server-dashboard-login, c05-cov-server-oauth, c06-cov-server-cli-login-runtime, c07-cov-server-uploads-pages, c09-cov-db-migrations, c11-cov-cli-commands, c12-cov-objectstore, c13-cov-peekd, c14-cov-uploads-web-groups-version]
    complexity: S
    touches:
      - scripts/coverage-gate.sh
      - mise.toml
      - .github/workflows/ci.yml
      - internal/**/*_test.go
    brief: |
      1. Read the must-read docs and Design §0 (§0.9), then Design E § "Phase G".
      2. Create scripts/coverage-gate.sh exactly as Design E (POSIX sh, executable), set `[tasks.coverage]` in mise.toml to `run = "sh scripts/coverage-gate.sh"` with the new description, and replace the ci.yml Coverage step with `Coverage (gate >= 90.0%)` running `sh scripts/coverage-gate.sh coverage.out`. Keep the SHA pins p04 added.
      3. Run `sh scripts/coverage-gate.sh` and `go test -cover ./...`; record the per-package figures against the §0.9 package floors.
      4. If the total is below 90.0%, add top-up tests (≤ 300 lines, `_test.go` only) in the packages furthest below their floors, then re-run. If it is still below 90.0%, stop with status=blocked and list each package with its coverage and floor.
      5. Run `COVERAGE_MIN=99 sh scripts/coverage-gate.sh` and confirm it exits 1. Run `mise run check-full` (Design §0.8).
    acceptance:
      - '`sh scripts/coverage-gate.sh` exits 0 and prints "coverage gate: OK"'
      - '`COVERAGE_MIN=99 sh scripts/coverage-gate.sh` exits 1'
      - '`grep -n "coverage-gate.sh" .github/workflows/ci.yml mise.toml` matches in both files'
      - mise run check passes

  # ---------------------------------------------------------------- retirement
  - id: z01-retire-plan
    title: Retire the plan and mark the audit addressed
    depends_on: [g01-coverage-gate, p20-docs-operations, p21-docs-readme-skills]
    complexity: S
    touches:
      - docs/plans/security-hardening-coverage-plan.md
      - docs/plans/security-hardening-coverage-plan-manual-steps.html
      - docs/audits/2026-10-security-and-coverage-audit.md
    brief: |
      1. Read the must-read docs.
      2. Delete docs/plans/security-hardening-coverage-plan.md and docs/plans/security-hardening-coverage-plan-manual-steps.html.
      3. In docs/audits/2026-10-security-and-coverage-audit.md, add directly under the title: "Status: the Critical, Medium and Low findings below are addressed by the `fix/security-hardening-coverage` change, which also raises total coverage to at least 90% with a CI gate. Info items remain open." Do not rewrite the findings.
      4. `grep -rn "security-hardening-coverage-plan" --exclude-dir=.git .` must print nothing. The profile has no ADR directory and no changelog, so there is nothing else to retire.
      5. Run `mise run check`.
    acceptance:
      - '`test ! -e docs/plans/security-hardening-coverage-plan.md && test ! -e docs/plans/security-hardening-coverage-plan-manual-steps.html` exits 0'
      - '`grep -rn "security-hardening-coverage-plan" --exclude-dir=.git .` prints nothing'
      - '`grep -n "^Status:" docs/audits/2026-10-security-and-coverage-audit.md` matches'
      - mise run check passes
```

