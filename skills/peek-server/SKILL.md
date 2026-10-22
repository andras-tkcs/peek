---
name: peek-server
description: Run and administer a self-hosted peek server — the HTML sharing service behind the peek CLI. Use when the user wants to install, start, deploy, or self-host a peek server, create or revoke access tokens, configure SMTP email, or configure peekd. Triggers on "run a peek server", "self-host peek", "deploy peek", "create a peek token", "peek admin", "set up peekd". For just uploading HTML and reading comments as a client, use the peek skill instead.
---

# peek-server — Run and administer a peek server

peek is a self-hosted HTML sharing server (`peekd`) with a companion CLI
(`peek`). This skill covers **running and administering** the server: starting
`peekd`, issuing access tokens, managing page access and share emails, configuring
runtime limits/storage, and deploying behind a reverse proxy.

> Just uploading HTML and reading comments as a client? Use the **peek** skill.

## When to use this skill

- The user wants to **install, run, deploy, or self-host** a peek server.
- The user needs to **create, list, or revoke access tokens** for users/agents.
- The user wants to **change who can open a page** or **set up share emails** as an admin/owner.
- The user mentions **peekd**, peek server setup, or peek deployment.

## Install the server binary

The server binary is `peekd`. Get it from a release or build from source.

```sh
# Download a release archive (contains both peekd and peek), then:
VERSION=vX.Y.Z   # pick from https://github.com/andras-tkcs/peek/releases
curl -fsSLO "https://github.com/andras-tkcs/peek/releases/download/${VERSION}/peek_${VERSION}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/andras-tkcs/peek/releases/download/${VERSION}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt
tar xzf "peek_${VERSION}_linux_amd64.tar.gz"
sudo mv peek_*/peekd peek_*/peek /usr/local/bin/
```

Or build from source (needs Go):

```sh
git clone https://github.com/andras-tkcs/peek && cd peek
go build -o bin/peekd ./cmd/peekd
go build -o bin/peek  ./cmd/peek
```

## Run the server

```sh
peekd --addr :7700 --data ./data --base-url https://peek.example.com
```

On first run, `peekd` prints a one-time setup URL. Open it to create the first
local admin account. After setup, use the dashboard or `peek login --host
https://peek.example.com`.

### Docker

```sh
docker run -d --name peek -p 7700:7700 \
  -v peek-data:/data \
  -e PEEK_BASE_URL=https://peek.example.com \
  ghcr.io/andras-tkcs/peek:latest
```

For production, pin a release tag (`ghcr.io/andras-tkcs/peek:<version>`) or an image digest (`ghcr.io/andras-tkcs/peek@sha256:…`).

The image runs as uid `65532` and stores the SQLite DB, uploads, and generated
secret under `/data`. If bind-mounting a host directory, make it writable by
uid `65532`.

### Configuration

| Flag | Env | Default | Description |
|---|---|---|---|
| `--addr` | `PEEK_ADDR` | `:7700` | Listen address |
| `--data` | `PEEK_DATA` | `./data` | Data dir (db + uploads + secret) |
| `--base-url` | `PEEK_BASE_URL` | `http://localhost:7700` | Public base URL in share links. **Use `https://…` in production** — it enables `Secure` cookies + HSTS. |
| `--max-upload` | `PEEK_MAX_UPLOAD` | `2097152` (2 MiB) | Max upload size in bytes |
| `--secret` | `PEEK_SECRET` | *(stored in data dir)* | HMAC/encryption secret. Set explicitly when multiple instances must share signed cookies/settings. Or `PEEK_SECRET_FILE` with the path to a file (Docker/Kubernetes secrets); setting both the variable and `_FILE` is an error. |
| `--max-total-size` | `PEEK_MAX_TOTAL_SIZE` | `0` | Total upload storage limit in bytes (`0` = unlimited) |
| `--retention-days` | `PEEK_RETENTION_DAYS` | `0` | Auto-delete uploads older than N days (`0` = off) |
| `--trusted-proxy` | `PEEK_TRUSTED_PROXY` | `false` | Trust `X-Forwarded-For` for analytics/audit IPs. Enable only behind your reverse proxy. |
| `--trusted-proxy-cidrs` | `PEEK_TRUSTED_PROXY_CIDRS` | `127.0.0.0/8,::1/128` | Proxies allowed to set `X-Forwarded-For` (with `--trusted-proxy`) |
| `--metrics-token` | `PEEK_METRICS_TOKEN` | *(empty)* | Bearer token (at least 16 characters) for `/metrics`; when empty an admin API token is required. Or `PEEK_METRICS_TOKEN_FILE` with the path to a file. |
| `--storage` | `PEEK_STORAGE` | `file` | Storage backend: `file` or `s3` |
| `--s3-endpoint` | `PEEK_S3_ENDPOINT` | *(empty)* | S3-compatible endpoint URL |
| `--s3-bucket` | `PEEK_S3_BUCKET` | *(empty)* | S3 bucket name |
| `--s3-region` | `PEEK_S3_REGION` | `us-east-1` | S3 region |
| `--s3-access-key` | `PEEK_S3_ACCESS_KEY` | *(empty)* | S3 access key |
| `--s3-secret-key` | `PEEK_S3_SECRET_KEY` | *(empty)* | S3 secret key, encrypted in settings after initialization. Or `PEEK_S3_SECRET_KEY_FILE` with the path to a file (Docker/Kubernetes secrets); setting both the variable and `_FILE` is an error. |
| `--google-sa-key-file` | `PEEK_GOOGLE_SA_KEY_FILE` | *(empty)* | Service account JSON key (domain-wide delegation) for Google group grants. Needs `--google-admin-email`. Not in the SQLite backup. |
| `--google-admin-email` | `PEEK_GOOGLE_ADMIN_EMAIL` | *(empty)* | Workspace admin user to impersonate |
| `--google-group-cache-ttl` | `PEEK_GOOGLE_GROUP_CACHE_TTL` | `5m` | Group membership cache lifetime (1s to 1h) |
| `--backends` | `PEEK_BACKENDS` | `off` | Page backends: `off` or `docker` |
| `--docker-host` | `PEEK_DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker or Podman API address (`unix://` or `tcp://`) |
| `--backend-network` | `PEEK_BACKEND_NETWORK` | `peek-backends` | Docker network for backend containers |

`PEEK_LOG_LEVEL` controls structured JSON log verbosity (`debug`, `info`,
`warn`). `peekd --version` prints the server version.

Admins can update these runtime settings from the dashboard: max upload size,
total storage limit, max uploads per token, max storage per token, retention
days, S3 credentials, and the page backend limits. Changing the storage backend itself requires a
restart.

## Administer with the CLI

Configure the CLI against the server with browser login (see the **peek** skill
for `peek login`), then:

### Manage access tokens (admin only)

```sh
peek token create --name "Alice"   # prints a new user token once
peek token list                    # list tokens (ids + names)
peek token revoke <id>             # revoke a token by id
```

Tokens are stored hashed and shown only once at creation. Non-admin tokens can
upload and manage only their own uploads.

Token expiry is available through the admin JSON API by sending
`{"name":"service","expires_hours":24}` to `POST /api/tokens`. The current CLI
creates non-expiring tokens.

### Manage OAuth and invitations

Admins can use the web dashboard Settings section to enable Google and/or GitHub
OAuth. Create web OAuth credentials with these callback URLs:

```text
https://peek.example.com/oauth/google/callback
https://peek.example.com/oauth/github/callback
```

For local GitHub testing, create a temporary OAuth App at
`https://github.com/settings/applications/new` with `Homepage URL` set to the
local base URL and `Authorization callback URL` set to
`http://127.0.0.1:<port>/oauth/github/callback`.

OAuth signups are invite-only. Create manual invite links in the dashboard and
send them to users. Admins can also set an allowed email domain in Settings to
restrict human login, CLI browser approval, and invites to one exact domain.
When OAuth is enabled, non-admin dashboard and CLI login must use OAuth; the
local password form remains available to admins if the admin email matches the
allowed domain. When OAuth is not enabled, token login remains available and can
be disabled from Settings. Direct bearer tokens still work for API/automation.
The same verified email maps to the same Peek account across Google and GitHub.
Admins can disable users or promote/demote admins in the dashboard later.

Google Workspace organizations can instead turn on `auth_google_org_signup` in Settings. It requires Google login with client credentials and an allowed email domain (not gmail.com or googlemail.com). While it is on, a Google Workspace account (Google's `hd` claim) with a verified email in the allowed domain gets a non-admin account on first sign-in, GitHub and OIDC sign-in are inactive, and invites are inactive (existing invites return when it is off). Non-admin password and token login stay disabled and admins keep the password form. Enable it in this order: make sure an active admin has an email in the allowed domain, set the domain, configure Google login, then turn the mode on.

### Manage page access

```sh
peek visibility <slug> restricted                    # the default for new pages
peek grant <slug> alice@example.com                  # let a person open it
peek visibility <slug> public                        # anyone with the link
```

Pages are restricted by default: only the owner, admins and grantees can open them. Page passwords were removed; migration 15 turned existing password pages into restricted pages. Owners and admins can also change visibility, manage grants and rename pages from the dashboard's **Access** row action; `peek rename <slug> <new name>` renames from the CLI (old links redirect).

### Share emails (SMTP)

Admins configure email on the **Email** tab of the Admin page: `smtp_host`, `smtp_port`, `smtp_tls` (`starttls` default, `tls`, or `none` for a local relay), `smtp_username`, `smtp_password` and `smtp_from`. Email is on when the host and From address are set; **Send test email** checks the saved settings. With email on, adding a grant to a restricted page, or switching a page to restricted, emails the grantees a link (only recipients in the allowed email domain, when one is set). A failed send is logged and audited as `upload.share.notify` and never blocks the share.

### Page backends

Page owners can attach a Docker image to a page version (`peek upload --backend`), which Peek runs as a container and the page calls with `peek.fetch`. To enable it:

1. Start `peekd --backends docker` (optionally `--docker-host`, `--backend-network`). peekd refuses to start when the engine is not reachable.
2. Give the peekd user access to the socket (the image runs as uid 65532; in Compose use `group_add` with `export DOCKER_GID=$(stat -c %g /var/run/docker.sock)`), and attach a containerised peekd to the backend network so it can reach the containers. Docker Desktop on macOS/Windows needs peekd in a container.
3. On the Admin page's **Backends** tab set the allowed images (`ghcr.io/acme/` prefixes or exact repositories; empty allows none), and optionally memory, CPU, idle stop, max running backends and registry credentials.

The Docker socket is root on the host: prefer rootless Docker/Podman or a dedicated VM, and keep the allowed list short. Containers get fixed limits, a read-only root filesystem, no capabilities and no published ports. Backend volumes (`peek-<instance>-data-u<id>`) are not in `peekd backup` and are deleted with the page. Backends do not use the Email tab's SMTP settings. Migration 16 (`upload_backends`) adds the backend tables. Details: `docs/operations.md`.

### Data export and deletion

```sh
peek export <slug>   # JSON export with upload metadata, visits, and comments
peek delete-all      # delete every upload owned by the configured token
```

### Health, metrics, and backups

```sh
curl -fsS http://127.0.0.1:7700/healthz
curl -fsS http://127.0.0.1:7700/readyz
curl -fsS -H "Authorization: Bearer $PEEK_METRICS_TOKEN" http://127.0.0.1:7700/metrics

PEEK_DATA=./data peekd backup ./peek-backup.db
```

`/healthz` is liveness, `/readyz` checks database reachability, and `/metrics`
emits Prometheus text metrics and always needs `Authorization: Bearer <token>`:
the `--metrics-token` (or `PEEK_METRICS_TOKEN_FILE`) value when set, otherwise
an admin API token.

## Deployment

peek speaks plain HTTP and expects a **TLS-terminating reverse proxy** in front
(this is what enables `Secure` cookies + HSTS). Example with Caddy:

```
peek.example.com {
    reverse_proxy 127.0.0.1:7700
}
```

Run `peekd` with `--base-url https://peek.example.com` so links and cookie flags
are correct. If your proxy forwards `X-Forwarded-For` and you want those client
IPs used for analytics/audit logs, also set `--trusted-proxy`, and `--trusted-proxy-cidrs` if the proxy does not connect from localhost; otherwise Peek
intentionally ignores forwarded IP headers. Back up the `data/` directory — it
holds the DB, uploads, and the signing secret.

For S3-compatible storage, set `--storage s3` plus endpoint, bucket, region, and
credentials. S3 endpoints must be HTTP(S), HTTPS unless localhost, and cannot
resolve to private/link-local IPs.

## Web dashboard

The server also serves a browser dashboard at `/login`. Sign in with a token or
an enabled OAuth provider to upload (file, paste HTML, or an empty page), list
and delete pages, see the restricted pages shared with them, manage access, and
view stats. Admins can also edit runtime limits, retention,
S3 and SMTP email settings, OAuth providers, invites, and users — no CLI required. Direct
non-technical users there.
