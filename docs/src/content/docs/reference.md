---
title: Reference
description: Server flags, environment variables, runtime settings, CLI configuration, and operational endpoints.
kicker: peekd reference
---

## Server Parameters

| Flag | Env | Default | Notes |
| --- | --- | --- | --- |
| `--addr` | `PEEK_ADDR` | `:7700` | Listen address. |
| `--data` | `PEEK_DATA` | `./data` | Data directory for SQLite, generated secret, and file uploads. |
| `--base-url` | `PEEK_BASE_URL` | `http://localhost:7700` | Public absolute URL. Use HTTPS in production. |
| `--secret` | `PEEK_SECRET` | generated | HMAC/encryption secret. Provide one when multiple processes must share cookie/settings secrets. Or `PEEK_SECRET_FILE` with the path to a file (Docker/Kubernetes secrets); setting both the variable and `_FILE` is an error. |
| `--max-upload` | `PEEK_MAX_UPLOAD` | `2097152` | Maximum upload size in bytes. Must be greater than zero. |
| `--max-total-size` | `PEEK_MAX_TOTAL_SIZE` | `0` | Server-wide storage cap in bytes. `0` means unlimited. |
| `--retention-days` | `PEEK_RETENTION_DAYS` | `0` | Delete uploads older than N days. `0` disables. |
| `--trusted-proxy` | `PEEK_TRUSTED_PROXY` | `false` | Trust `X-Forwarded-For` for analytics and audit IP fields. |
| `--trusted-proxy-cidrs` | `PEEK_TRUSTED_PROXY_CIDRS` | `127.0.0.0/8,::1/128` | Proxies allowed to set `X-Forwarded-For` (with `--trusted-proxy`). |
| `--metrics-token` | `PEEK_METRICS_TOKEN` | empty | Bearer token required on `/metrics`, at least 16 characters. Or `PEEK_METRICS_TOKEN_FILE` with the path to a file; setting both is an error. When empty, `/metrics` requires an admin API token; it is never anonymous. |
| `--storage` | `PEEK_STORAGE` | `file` | Storage backend: `file` or `s3`. |
| `--s3-endpoint` | `PEEK_S3_ENDPOINT` | empty | S3-compatible endpoint URL. |
| `--s3-bucket` | `PEEK_S3_BUCKET` | empty | S3 bucket name. Must be DNS-compatible (3–63 lowercase letters, digits, dots, hyphens); the SSRF guard also blocks CGNAT, NAT64/6to4/Teredo, benchmarking, multicast and reserved ranges. |
| `--s3-region` | `PEEK_S3_REGION` | `us-east-1` | S3 signing region. |
| `--s3-access-key` | `PEEK_S3_ACCESS_KEY` | empty | S3 access key ID. |
| `--s3-secret-key` | `PEEK_S3_SECRET_KEY` | empty | S3 secret access key. Or `PEEK_S3_SECRET_KEY_FILE` with the path to a file; setting both the variable and `_FILE` is an error. |
| `--s3-allow-private-endpoint` | `PEEK_S3_ALLOW_PRIVATE_ENDPOINT` | `false` | Allows HTTP/private/link-local endpoints for controlled private deployments. |
| `--google-sa-key-file` | `PEEK_GOOGLE_SA_KEY_FILE` | empty | Path to a Google service account JSON key with domain-wide delegation, for Google group grants. Requires `--google-admin-email`. |
| `--google-admin-email` | `PEEK_GOOGLE_ADMIN_EMAIL` | empty | Workspace admin user the service account impersonates. Requires `--google-sa-key-file`. |
| `--google-group-cache-ttl` | `PEEK_GOOGLE_GROUP_CACHE_TTL` | `5m` | How long group membership answers are cached. Between `1s` and `1h`. |
| `--oidc-allow-private-issuer` | `PEEK_OIDC_ALLOW_PRIVATE_ISSUER` | `false` | Allows HTTP/private OIDC issuers for local SSO testing. |

`PEEK_LOG_LEVEL` accepts `debug`, `info`, or `warn`. Any other value falls back to info.

## Runtime Settings

Admins can change these from the **Admin** page (the **Admin** button next to **Sign out**) or the settings API:

| Key | Type | Notes |
| --- | --- | --- |
| `auth_token_login_enabled` | boolean | Allows web login with an access token when OAuth is not required. |
| `auth_allowed_email_domain` | email domain | Optional exact email domain for human sign-in, invites, and CLI browser approval. Empty allows any domain. |
| `auth_google_org_signup` | boolean | Google-only org sign-in: first sign-in of a Google Workspace user in the allowed domain creates the account, and invites are inactive. Requires Google login and `auth_allowed_email_domain`. |
| `oauth_google_enabled` | boolean | Enables Google login if credentials are configured. |
| `oauth_google_client_id` | string | Google OAuth web client ID. |
| `oauth_google_client_secret` | secret string | Google OAuth web client secret. |
| `oauth_github_enabled` | boolean | Enables GitHub login if credentials are configured. |
| `oauth_github_client_id` | string | GitHub OAuth app client ID. |
| `oauth_github_client_secret` | secret string | GitHub OAuth app client secret. |
| `oauth_oidc_enabled` | boolean | Enables generic OpenID Connect SSO if issuer and credentials are configured. |
| `oauth_oidc_issuer_url` | URL | OpenID Connect issuer URL. Must be HTTPS and publicly routable unless `PEEK_OIDC_ALLOW_PRIVATE_ISSUER=true`. |
| `oauth_oidc_client_id` | string | OpenID Connect client ID. |
| `oauth_oidc_client_secret` | secret string | OpenID Connect client secret. |
| `storage` | `file` or `s3` | Startup setting; restart to apply backend changes. |
| `s3_endpoint` | URL | Validated to block unsafe endpoints unless private endpoints are explicitly allowed. |
| `s3_bucket` | string | Bucket name for uploaded HTML bytes. |
| `s3_region` | string | S3 signing region. |
| `s3_access_key` | string | S3 access key ID. |
| `s3_secret_key` | secret string | S3 secret access key. |
| `max_upload` | bytes | Maximum individual upload size. |
| `max_total_size` | bytes | Server-wide storage cap; `0` means unlimited. |
| `max_uploads_per_token` | count | Per-owner upload count cap; `0` means unlimited. |
| `max_storage_per_token` | bytes | Per-owner storage cap; `0` means unlimited. |
| `retention_days` | days | Auto-delete threshold; `0` disables cleanup. |

## CLI Configuration

The CLI stores config under the user config directory in `peek/config.json`. Override per command with:

```sh
PEEK_HOST=https://peek.example.com
PEEK_TOKEN=...
```

Token input paths, from safest to least safe:

```text
peek login
peek login --token-stdin
peek login --token-file <path>
peek login --token <value>
```

`peek login` only opens the browser for a verification URL on the configured host; it warns when the host uses plain `http://` and is not loopback. `peek config set --host <new>` clears the saved token when the host changes; run `peek login` afterwards.

## CLI Commands

```text
peek upload <file.html> [--visibility public|password|signed-in|restricted] [--password <pw> | --password-stdin] [--name <filename>]
peek upload <file.html> --slug <slug>
peek visibility <slug> public|signed-in|password|restricted [--password <pw> | --password-stdin]
peek rename <slug> <new name>
peek grant <slug> <email> [--group]
peek revoke <slug> <email> [--group]
peek grants <slug>
peek versions <slug>
peek comments <slug> [--version <n>]
```

`--slug` uploads a new version of an existing page you own (admins can target any page). It cannot be combined with `--visibility`, `--password`, `--password-stdin` or `--name`. `grant` and `revoke` take a user email by default and a Google group email with `--group`; group grants need the `PEEK_GOOGLE_*` server settings. `grants` lists a page's grants. `versions` lists a page's versions with size, time and URL. `comments` shows the latest version's comments unless `--version` is given. Page names (the `--name` value or the file name) are limited to 200 characters. `--password` prints a warning; prefer `--password-stdin`.

## Page And API Routes

| Route | Purpose |
| --- | --- |
| `/p/<slug>` | Latest version of a page. |
| `/p/<slug>/v/<n>` | Version `n` of a page, with a banner when it is not the latest. |
| `POST /api/upload` | Upload a page. Add `slug=<slug>` (form field, or query parameter for raw HTML) to add a version. |
| `GET /api/uploads/<slug>/versions` | List versions (owner or admin). |
| `GET /api/uploads/<slug>/grants` | List grants (owner or admin). |
| `POST /api/uploads/<slug>/grants` | Add a grant. JSON body `{"kind":"user\|group","email":"..."}`. |
| `DELETE /api/uploads/<slug>/grants` | Remove a grant. Same JSON body. |
| `POST /api/uploads/<slug>/name` | Rename a page. JSON body `{"name":"..."}`; returns the new `slug`, `url` and `name`. The link follows the name; old links redirect. |
| `GET /api/uploads/<slug>/comments?v=<n>` | Comments for version `n`; defaults to the latest. |

## Account Comment API

`POST /api/uploads/{slug}/account-comments` posts a comment under the account name of the bearer token, so API clients do not appear as "anonymous". The comment lands on the page's latest version, or on version `n` when called with `?v=<n>` (404 `version not found` for an unknown version), the same as the browser comment route. It is separate from the browser comment route, so a server without it answers 404 or 405 instead of silently posting as "anonymous".

Authenticate with `Authorization: Bearer <token>`. The token's account must own the upload or be an admin, otherwise the answer is 403 `not owner`.

The request body is JSON. `body` is required and may be up to 4000 characters. Optional fields are `selector` (up to 500 characters), `element_text` (up to 200 characters) and `anchor_kind`. `anchor_kind` `text` needs both `selector` and `element_text`, `element` needs a `selector`, `page` needs no `selector`, and an empty value is inferred from the other fields. Any other value or an inconsistent combination gives 400 `invalid anchor kind`. A `name` field is accepted but ignored: the author is always the token's account name.

A successful call answers 200 with a single comment object with `id`, `selector`, `element_text`, `anchor_kind`, `author`, `verified`, `body`, `created_at` (Unix seconds) and `version`. `verified` is true for comments written by a signed-in account or through this API, false when the author name was typed by a viewer. Errors are 400 (bad JSON, missing body or invalid anchor), 401 (missing or invalid token), 403 (not the owner, or account disabled), 404 (unknown slug), 413 (a field is too long) and 429 (too many comments).

```sh
curl -s -X POST -H "Authorization: Bearer $PEEK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"body":"Looks good","selector":"#hero","element_text":"Hero copy"}' \
  "$PEEK_HOST/api/uploads/<slug>/account-comments"
```

## Operational Endpoints

| Endpoint | Purpose |
| --- | --- |
| `/healthz` | Liveness. |
| `/readyz` | Readiness, including database reachability. Failures answer `not ready` without details; the cause is logged. |
| `/metrics` | Prometheus text metrics. Requires `Authorization: Bearer <token>`: the `--metrics-token` value when set, otherwise an admin API token. |
| `/setup` | First-run setup only. Closes after the first account exists. |
| `/oauth/google/callback` | Google OAuth callback. |
| `/oauth/github/callback` | GitHub OAuth callback. |
| `/oauth/oidc/callback` | Generic OpenID Connect callback. |

## Operator Checks

Health:

```sh
peekd healthcheck --addr https://peek.example.com
curl -fsS https://peek.example.com/readyz
```

Backup:

```sh
PEEK_DATA=/var/lib/peek peekd backup /backups/peek-$(date +%F).db
```

Smoke upload:

```sh
peek login --host https://peek.example.com
printf '<!doctype html><h1>Peek smoke</h1>' > /tmp/peek-smoke.html
peek upload /tmp/peek-smoke.html --visibility public
peek list
```
