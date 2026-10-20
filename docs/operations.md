# Internal Operations

Peek is intended to be run by one company or trusted team as internal infrastructure. This guide is the operator checklist for that model.

## Recommended Topology

Run `peekd` behind a TLS-terminating reverse proxy such as Caddy, nginx, Traefik, or your platform ingress. Set `--base-url` / `PEEK_BASE_URL` to the externally visible `https://...` URL so generated links, secure cookies, and HSTS are correct.

Use one primary `peekd` process per data directory. Peek stores mutable state in SQLite plus uploaded objects. Horizontal scaling is not the default operating model; if the project ever needs that, the storage, session, and migration model should be revisited deliberately instead of hidden behind ad hoc process replication.

## Persistent State

The data directory contains:

- `peek.db`: SQLite database with accounts, tokens, comments, settings, visits, audit logs, and upload metadata.
- `secret.key`: the signing/encryption secret generated on first run when `PEEK_SECRET` is not provided.
- `uploads/`: file-backed upload objects when `PEEK_STORAGE=file`, including `uploads/versions/<slug>/` for versions after the first.

Peek creates the data directory and `uploads/` as `0700` and `peek.db` (with its `-wal`/`-shm`), `secret.key`, `setup.key`, uploaded objects and `peekd backup` output as `0600`. On start it tightens `peek.db` and `secret.key` but does not change an existing directory's mode; it logs a warning if the data directory is accessible to other users. After upgrading a non-Docker install, run `chmod -R go-rwx /var/lib/peek`. Backup agents must run as the peekd user (uid 65532 in the container image) or as root.

Back up the whole data directory for simple deployments. For database-consistent snapshots while the server may be running, use:

```sh
PEEK_DATA=/var/lib/peek peekd backup /backups/peek-$(date +%F).db
```

`peekd backup` refuses to overwrite an existing destination file.

If you use S3 storage, also back up or lifecycle-manage the bucket according to your internal retention policy. The SQLite backup contains object metadata, comments, auth state, settings, and analytics, not the remote object bytes themselves.

## Startup Configuration

Peek fails fast for invalid operational config: `base-url` must be an absolute `http` or `https` URL, `max-upload` must be greater than zero, storage must be `file` or `s3`, and total-size / retention limits cannot be negative.

Minimum production-like configuration:

```sh
peekd \
  --addr 127.0.0.1:7700 \
  --data /var/lib/peek \
  --base-url https://peek.example.com \
  --trusted-proxy
```

Set `--trusted-proxy` only when a reverse proxy you control appends to `X-Forwarded-For`. Peek then honours the header only on connections from `--trusted-proxy-cidrs` / `PEEK_TRUSTED_PROXY_CIDRS` (default `127.0.0.0/8,::1/128`, a proxy on the same host) and uses the rightmost address that is not one of those proxies. When the proxy runs in another container, pod or platform edge, set the CIDRs to the addresses it connects from; Peek logs one warning naming the peer when it ignores the header. Without `--trusted-proxy`, every request behind a proxy has the proxy's address, so the whole organisation shares one rate-limit bucket (for example 10 sign-in attempts per minute).

Besides per-IP limits, Peek locks password sign-in for an email address after 10 failed attempts for 15 minutes, and a password-protected page's gate after 20 failed attempts for 10 minutes. Anyone can trigger these locks, so a locked admin can still sign in with SSO or an API token, and viewers who already unlocked a page are not affected.

Prefer `_FILE` variables or plain environment variables over `--secret`, `--s3-secret-key` and `--metrics-token` on the command line; flags are visible in `ps` and peekd prints a warning.

## First Run And Access

On first run, Peek creates a one-time setup URL in the logs and stores the setup code in the data directory. Use it to create the first admin. After an account exists, the setup file is removed and the setup route is closed.

For company usage, prefer OAuth/SSO with invite-only signup. Google Workspace organizations can use `auth_google_org_signup` instead of invites. Admins can configure Google, GitHub, or generic OpenID Connect on the **Admin** page (the **Admin** button next to **Sign out**), create invite links, and promote or disable users later. Direct bearer tokens remain appropriate for internal automation, CI jobs, and agents. Users can create their own from **Dashboard → API keys**. API tokens follow the same account rules as dashboard sign-in: a token is refused with 403 when its account is disabled, when its email does not match the allowed email domain, or, while OAuth login is enabled, when a non-admin account has no linked OAuth identity. Tokens from `peek token create` / `POST /api/tokens` belong to automation accounts without an email; only disabling applies to them. Tokens from `peek login` expire 90 days after approval; dashboard keys and admin tokens do not expire unless created with `expires_hours`.

## Page Access

Each page has one of four visibilities: `public` (anyone with the link), `password` (link plus upload password), `private` (any signed-in Peek account), and `restricted` (only the owner, admins, and signed-in viewers matching a grant). Grants are user emails or Google group emails, managed with `peek grant`, `peek revoke` and `peek grants`, or the grants API, or the dashboard's **Access** dialog. Grants are stored for any visibility but only enforced while the page is `restricted`. They are read from the database on every view of `/p/...`, the comment API and the views API.

A signed-in viewer without a matching grant gets a 403 "Access denied" page naming the account they are signed in as, and the denial is written to the audit log as `page.access.denied`. Viewers who are not signed in are sent to the login page.

The uploaded HTML is served to the sandboxed iframe through a view token that is minted only after the access check. Every load of that view URL re-checks access, so revoking a grant, changing visibility, or setting a new password applies to the frame on its next load; a frame already displayed keeps what it has rendered. The view URL works only in the browser that opened the page (it is bound to the `hn_vid` cookie) and only inside the page's iframe. Renaming a page redirects its old links (302) to the new one; password-page viewers unlock once more after a rename. Pages already open under the old link must be reloaded before comments work again. Page links are the page name plus a random six-character suffix; links created before this release keep their old form.

## Google Group Grants

Group grants need Google Workspace lookups, configured at startup with a service account that has domain-wide delegation:

- `PEEK_GOOGLE_SA_KEY_FILE` (`--google-sa-key-file`): path to the service account JSON key file.
- `PEEK_GOOGLE_ADMIN_EMAIL` (`--google-admin-email`): the Workspace admin user the service account impersonates. Both settings must be set together.
- `PEEK_GOOGLE_GROUP_CACHE_TTL` (`--google-group-cache-ttl`, default `5m`, between `1s` and `1h`): how long a membership answer is cached in memory.

The only scope needed is the read-only `https://www.googleapis.com/auth/admin.directory.group.member.readonly`; authorize exactly that scope for the service account's client ID under domain-wide delegation in the Workspace admin console. Without these settings, adding a group grant is refused and user grants keep working.

The key file is not stored in SQLite, so it is not in `peekd backup` output. Back it up and rotate it separately; rotating means replacing the file and restarting `peekd`.

Membership changes take up to the cache TTL to apply. Group grants are checked one after another, and each lookup times out after 5 s, so a page with several group grants can take up to 5 s per group longer to open when the Directory API is slow. A lookup that fails denies access through that group.

## Quotas, Retention, And Storage

Use runtime settings for normal day-to-day limits: maximum upload size, total storage cap, per-token count/storage limits, retention days, auth options, and S3 credentials. Storage backend selection itself is a startup concern and requires restart because it changes where object bytes are read and written.

Re-uploading to an existing page with `peek upload --slug` adds a version. Every version counts toward the total storage cap and the per-owner storage cap (charged to the page owner, not the uploader), but versions do not count toward the per-owner upload count, which counts pages.

Retention cleanup runs in the background. It deletes a page when its newest version is older than the configured number of days, and prunes older versions individually together with the comments written on them. The newest version of a page is never pruned. Visits are kept. `0` disables automatic cleanup. A version uploaded while its page is being deleted can leave one orphaned object in storage. Keep retention aligned with your company’s data handling policy rather than treating Peek as an unlimited archive.

For S3-compatible storage, private/link-local endpoints are blocked by default to avoid SSRF. Set `PEEK_S3_ALLOW_PRIVATE_ENDPOINT=true` only for explicit private deployments such as local MinIO or controlled internal object stores. The SSRF guard also blocks CGNAT (`100.64.0.0/10`), NAT64/6to4/Teredo, benchmarking, multicast and reserved ranges. Bucket names must be DNS-compatible (3–63 lowercase letters, digits, dots, hyphens); a stored bucket that does not match stops startup with `invalid s3 bucket`.

Request bodies are limited to 64 KiB on every route except page uploads, which use the maximum upload size.

## Observability

Use `/healthz` for liveness and `/readyz` for readiness; readiness verifies the database is reachable. `peekd healthcheck` calls `/healthz` and can be used in container or service-manager probes.

Peek logs structured JSON to stderr. Set `PEEK_LOG_LEVEL=debug`, `info`, or `warn`. Audit events are persisted in SQLite and important operational failures are logged with structured fields. Audit details are space-separated key=value fields; a value containing a space, =, a quote, a backslash or a control character is written as a Go-quoted string.

`/metrics` exposes Prometheus text metrics. Set `PEEK_METRICS_TOKEN` (or `PEEK_METRICS_TOKEN_FILE`, at least 16 characters) to require `Authorization: Bearer <token>`; configure Prometheus with `authorization: { credentials_file: … }`. Without a token, protect `/metrics` at the proxy or network layer. `/readyz` returns `not ready` without details; the cause is logged as `readiness check failed`.

## Upgrades And Rollbacks

Before upgrading, take a SQLite backup and confirm you know where uploaded object bytes live. Run the new binary against a staging copy of the data directory when changing storage, auth, retention, or database-related code.

This release adds migrations 7 (`upload_versions`, which also adds a `version` column to comments and visits and backfills one version per existing page) and 8 (`upload_grants`). Existing objects are not moved and existing `private` pages keep their meaning.

Migration 9 (`upload_slug_aliases`) keeps the old links of renamed pages reserved. After upgrading, existing password-page unlock cookies stop working once; viewers re-enter the password. Do not roll back to an older binary once a page has been renamed: older binaries do not reserve old links, so a new upload could overwrite a renamed page's first version. Restore the pre-upgrade backup and object storage instead.

Migration 10 (`token_hint_last_used`) adds `hint` and `last_used_at` to `tokens`. Tokens created before it show `—` instead of their last four characters on the dashboard. Older binaries ignore both columns, so tokens keep working after a rollback, but older binaries still cannot revoke a token that uploaded a page.

Migration 11 (`cli_login_request_context`) adds `request_ip` and `request_user_agent` to `cli_login_devices`, shown on the CLI login approval page.

Migration 12 (`account_session_epoch`) adds `session_epoch` to `accounts`; dashboard sessions from before the upgrade stay valid until the account uses **Sign out other sessions** or is disabled. Sessions created by the new binary are not accepted by older binaries, so after a rollback everyone signs in again.

Migration 13 (`comment_account_id`) adds a nullable `account_id` to `comments`. Comments written before it are shown as unverified. Older binaries ignore the column, so a rollback keeps comments readable but new comments lose the verified marker.

This release removes the unversioned `/raw/<slug>` route and serves uploaded HTML with a CSP `sandbox`. Pages opened before the upgrade must be reloaded. The `hn_csrf` cookie is now HttpOnly.

With `--trusted-proxy`, `X-Forwarded-For` is now trusted only from `PEEK_TRUSTED_PROXY_CIDRS` (default loopback). Deployments whose proxy connects from another address must set it, or all clients share the proxy's rate-limit bucket.

This release also applies the allowed email domain and OAuth-required rules to API tokens (see First Run And Access); check which personal API keys that affects before upgrading.

Rollback is simplest when the database has not been migrated by a newer binary. If a release includes migrations, treat rollback as restoring the pre-upgrade backup plus object storage state.

## Local Operator Smoke Test

After deployment or upgrade:

```sh
peekd healthcheck --addr https://peek.example.com
peek login --host https://peek.example.com
printf '<!doctype html><h1>Peek smoke</h1>' > /tmp/peek-smoke.html
peek upload /tmp/peek-smoke.html --visibility public
peek list
```

Then open the uploaded page, add a comment, and verify the dashboard shows the upload and visit stats.
