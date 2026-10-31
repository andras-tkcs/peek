---
title: Auth And Access
description: Configure local login, OAuth, invites, CLI login, tokens, and upload visibility.
kicker: Admin / Auth
---

## Auth Model

Peek has account authentication for the dashboard and API, plus upload-level visibility for each shared page. Keep those separate:

| Layer | Controls |
| --- | --- |
| Account auth | Who can sign in to the dashboard or approve CLI login. |
| API tokens | Which authenticated actor can upload, list, export, delete, or manage tokens. |
| Upload visibility | Who can open a particular `/p/<slug>` page. |

First-run setup creates the initial admin. Admins can invite users, disable users, promote or remove admin rights, enable OAuth providers, restrict human sign-in to an email domain, and control token-login behavior.

<figure>
  <img src="/peek/assets/screenshots/11-admin-users-invites.png" alt="Peek admin page showing invitations and users tables">
  <figcaption>Admins manage invitations and account status from the Admin page, opened with the Admin button next to Sign out.</figcaption>
</figure>

## OAuth Providers

Peek supports Google, GitHub, and one generic OpenID Connect provider for SSO systems such as Okta, Entra ID, Auth0, or Keycloak. A provider is active only when it is enabled and its required credentials are configured.

<figure>
  <img src="/peek/assets/screenshots/08-admin-auth.png" alt="Peek Admin page, Auth tab: Google client ID and secret, GitHub login toggle with client ID and secret, SSO login toggle with issuer URL, client ID and secret, and the Save settings button">
  <figcaption>The Auth tab holds the Google, GitHub and SSO provider settings: enable toggles, client IDs, client secrets and the SSO issuer URL. Token login and the allowed email domain are on the same tab, above what the screenshot shows.</figcaption>
</figure>

Use these callback URLs in the provider console:

```text
https://peek.example.com/oauth/google/callback
https://peek.example.com/oauth/github/callback
https://peek.example.com/oauth/oidc/callback
```

Provider scopes are intentionally small:

| Provider | Scopes |
| --- | --- |
| Google | OpenID, email, profile |
| GitHub | `read:user`, `user:email` |
| OpenID Connect | `openid`, `email`, `profile` |

Provider tokens are used for profile lookup and are not stored. Peek stores the provider identity, verified email, and display name needed to link future logins.

For Okta, use the issuer URL for the authorization server, for example `https://dev-123456.okta.com/oauth2/default`, and register the OIDC callback URL above. The issuer URL must be HTTPS and cannot point at private, link-local, loopback, or metadata endpoints unless the server is started with `PEEK_OIDC_ALLOW_PRIVATE_ISSUER=true` for explicit local SSO testing.

<figure>
  <img src="/peek/assets/screenshots/07-login-oauth.png" alt="Peek sign-in page with Google, GitHub, and SSO OAuth buttons">
  <figcaption>When OAuth is configured, users see provider buttons on the sign-in page.</figcaption>
</figure>

## Allowed Email Domain

Admins can set one allowed email domain on the Admin page. When configured, human sign-in must use an account email from that exact domain. The rule applies to OAuth login and signup, local password login, web token login, CLI browser approval, signed-in page sessions, and new invites. It also applies to API bearer tokens of accounts with an email: a token whose account email is outside the domain is refused with 403. Automation tokens from `peek token create` have no email and are not affected.

Use the bare domain, such as `example.com`. A leading `@` is accepted and normalized away. Subdomains are not implicit matches, so `person@team.example.com` does not match `example.com`.

Peek refuses to save a non-empty allowed domain unless at least one active admin account already has a matching email address. That keeps the setting from locking out all administrators.

## Invites And Users

OAuth signup is invite-only (a person whose account a [provisioning key](#provisioning-keys) already created or adopted can sign in with OAuth without an invite, because Peek matches the email). A new OAuth user can create an account only when:

1. The provider returns a verified email.
2. The browser has a pending Peek invite cookie.
3. The invite email matches the provider email.

If an account already exists with the verified email, Peek links the OAuth identity to that account without requiring another invite. Disabled accounts cannot sign in.

When OAuth is enabled, non-admin password and token web login are disabled. Admins keep password login as a recovery path, as long as the admin email also matches the allowed domain when one is configured.

The same rule applies to API tokens of accounts with an email: while OAuth is enabled, a non-admin account's token works only if the account has signed in with OAuth at least once. Automation tokens from `peek token create` have no email and are exempt; only disabling applies to them. The one other exception is the token a [provisioning key](#provisioning-keys) minted for an account, which skips only the OAuth rule.

Organizations that only use Google Workspace can skip invites entirely with [Google org sign-in](#google-org-sign-in).

## Configure sign-in from the environment

A server can start already set up, with no `/setup` code and no clicks on the Admin page, by setting variables (or the matching flags, see the [reference](/peek/docs/reference/#server-parameters)). A minimal example is in [First Run](/peek/docs/server-setup/#first-run).

**Locked settings.** Setting `PEEK_GOOGLE_CLIENT_ID`, `PEEK_GOOGLE_CLIENT_SECRET`, `PEEK_OIDC_ISSUER_URL`, `PEEK_OIDC_CLIENT_ID`, `PEEK_OIDC_CLIENT_SECRET` or `PEEK_ALLOWED_EMAIL_DOMAIN` locks the matching setting; `PEEK_GOOGLE_ORG_SIGNUP` and `PEEK_OIDC_SIGNUP` lock theirs only when true. A client ID or issuer also turns that provider on. Client and issuer variables come in pairs: Google needs its ID and secret, SSO needs issuer, ID and secret, and Peek refuses to start otherwise. Secrets can come from `PEEK_GOOGLE_CLIENT_SECRET_FILE` and `PEEK_OIDC_CLIENT_SECRET_FILE`. Peek writes the values to its settings at every start, so the environment always wins, and the settings are validated like Admin-page edits (for example, a sign-up needs an allowed domain). A locked setting is shown disabled on the Admin page with "Set by <variable> on the server", `GET /api/settings` reports `locked_by`, and `PUT /api/settings` refuses it with 400 `<key> is set by <variable> on the server`. The dashboard form ignores locked keys. Removing a variable does not clear anything: the last value stays in the database and becomes editable on the Admin page. For example, Google login stays enabled.

**SSO sign-up.** With `PEEK_OIDC_SIGNUP=true` (the `auth_oidc_signup` setting), the first SSO sign-in of anyone whose email is in the allowed domain creates a non-admin account, without an invite. It needs SSO login with issuer and client credentials and an allowed email domain. It cannot be combined with Google org sign-in: setting both fails at start with `PEEK_OIDC_SIGNUP: auth_oidc_signup cannot be used with auth_google_org_signup`. If one of the two is stored on the Admin page rather than set in the environment, the start fails too and the error names that setting, such as `auth_oidc_signup (set on the Admin page): …`; remove the variable that conflicts with it, start Peek once, turn the stored setting off on the Admin page, and set the variable again.

**Admins by email.** `PEEK_ADMIN_EMAILS` is a comma-separated list. Peek refuses to start on an invalid entry, on an entry outside a locked allowed domain, or without a Google or SSO sign-in set in the environment for the admins to use. At every Google or SSO sign-in with a verified email that is on the list, the account becomes an admin (and is created first if it does not exist); GitHub sign-in is never promoted. Because this runs at every sign-in, demoting someone on the Admin page does not last while they stay listed: remove them from the list first. A provisioned account that is promoted this way loses its provisioned token at once, and later provisioning of it answers 409. Promotion trusts the identity provider's `email_verified` claim, so list only addresses your provider verifies. An issuer over plain `http` sends the token exchange unencrypted and is acceptable only on `localhost`.

**When `/setup` is skipped.** Peek skips the first-run `/setup` page when `PEEK_ADMIN_EMAILS` is set, or when Google or SSO sign-in is set in the environment and accounts can come from a sign-up or from `PEEK_PROVISIONING_KEY_FILE`. It prints `Peek first-run setup is skipped: <reason>.` and writes no setup code. When Google or SSO sign-in is set in the environment but none of those is, Peek refuses to start with `with sign-in from the environment, set PEEK_ADMIN_EMAILS, a sign-up (PEEK_GOOGLE_ORG_SIGNUP or PEEK_OIDC_SIGNUP) or PEEK_PROVISIONING_KEY_FILE, or nobody can get in`. With neither, `/setup` works as before.

**Issuer on localhost.** Peek fetches `<issuer>/.well-known/openid-configuration` from its own process at every login, and the issuer in the tokens must match exactly. An issuer at `http://localhost:...` therefore works only when Peek shares the issuer's network namespace; the failure shows at login, not at start. A plain-http or private issuer also needs `PEEK_OIDC_ALLOW_PRIVATE_ISSUER=true`.

## Provisioning Keys

A provisioner is a named key holder, such as PrivacyFence running in organization mode, that may create accounts, adopt existing ones and mint one API token per account it manages, without each person doing a device sign-in. An admin creates its provisioning key on the command line:

```sh
peek provisioner create --name PrivacyFence
peek provisioner list
peek provisioner revoke <id>
```

The key starts with `peekprov_` and is shown once; store it in the key holder's secret store. The **Admin** page lists provisioners and their account counts, and can revoke a key. The routes are in the [reference](/peek/docs/reference/#provisioning-api).

**Trust.** A provisioning key is trusted to vouch for email addresses, as an OAuth provider is. Holding it is equivalent to being able to act as any non-admin Peek account whose email the holder asserts, including people who never used the key holder. It can never act as an admin: admin accounts are refused when linking, when minting and when a token is used, so a provisioned token stops working the moment its account is promoted to admin. It can never open a dashboard session. The allowed email domain still applies to every request.

**Created and adopted accounts.** If no account has the asserted email, Peek creates a normal non-admin account. If one exists, Peek adopts it and leaves its name, pages and own API keys alone. A disabled account is adopted too, but no token is minted for it. Either way the person signs in to Peek through OAuth like anyone else and keeps their pages when the key is revoked.

**Tokens.** The key holder mints one token per account (90 days by default, up to 365); minting again replaces the previous one. The token appears in the person's own API key list under the provisioner's name. Only the provisioner's own token is exempt from "must sign in with OAuth": the person's other keys follow the normal rule, and the disabled and allowed-domain checks still apply to the provisioned token. Provisioned tokens cannot open a dashboard session.

**Key from a file.** `PEEK_PROVISIONING_KEY_FILE` holds a key (starting with `peekprov_`, at least 40 characters) that Peek registers at every start under `PEEK_PROVISIONING_KEY_NAME` (default `PrivacyFence`), so nobody runs `peek provisioner create`; it works with no admin account. To rotate, replace the file's content and restart: Peek updates the key of that provisioner in place, and its tokens and links are kept. The Admin page shows no Revoke button for this provisioner, and revoking it from the Admin page, the API or the CLI is refused (the API answers 409); replace the file instead. If the name matches more than one provisioner, Peek refuses to start. The Admin page is not reachable then, so unset `PEEK_PROVISIONING_KEY_FILE`, start Peek, revoke the extra provisioners there, and set the variable again.

**Revoking and releasing.** Revoking a key deletes every token it minted and removes its links; the accounts and their pages stay. Releasing a single account does the same for that account alone. Peek never connects to the key holder: it only answers requests, so it keeps working when the key holder is down.

## Google Org Sign-In

The `auth_google_org_signup` setting turns Peek into a "Google sign-in for the whole organization" server. While it is on, anyone who signs in with a Google Workspace account whose verified email is in the allowed email domain gets a Peek account on their first sign-in. No invite link is needed and nothing is emailed. The first sign-in shows a short "Your Peek account is ready" page; Continue opens the dashboard.

Requirements: Google login must be enabled with a client ID and secret, and `auth_allowed_email_domain` must be set. Peek refuses to save the mode otherwise, and it refuses `gmail.com` and `googlemail.com` as the allowed domain. While the mode is on you also cannot clear the domain, disable Google, or blank the Google client ID.

What changes while the mode is on:

- Only Google Workspace accounts are provisioned. Peek requires Google's `hd` (hosted domain) claim, so a personal Google account that merely carries a work email address is refused, even if an account with that email already exists in Peek. The address itself must still be in the allowed domain.
- New accounts are created as non-admin users.
- The GitHub and generic OIDC providers are inactive: their buttons and endpoints are gone. Their settings are kept, so turning the mode off restores them.
- Invites are inactive: the Invitations card is hidden, creating an invite is refused, and invite links redirect to the login page. Existing invites are kept and work again when the mode is off.
- An existing account with the same verified email is linked as before.
- Non-admin password and token login stay disabled. Admins keep the local password form as the recovery path, as long as the admin email matches the allowed domain.

Things the mode does not do:

- Accounts that already linked a GitHub or SSO identity keep working while the mode is on.
- Deleting or suspending a user in Google Workspace does not disable their Peek account or API keys. An admin disables the account in Peek.

A wrong allowed domain locks out everyone except admins whose email matches it. To enable the mode safely:

1. Make sure an active admin has an email address in the allowed domain.
2. Set the allowed email domain.
3. Configure Google login with its client credentials and enable it.
4. Turn on Google org sign-in.

## Sessions

Dashboard sessions last 7 days. **Sign out other sessions** in the dashboard header ends every other browser session of your account and keeps this one. Disabling an account ends all of its sessions, and enabling it again does not bring them back. **Sign out** ends only the current browser's session. API keys are not affected; revoke them under **Dashboard → API keys**.

## CLI Login

`peek login` starts a browser approval flow when the server supports it. The CLI prints a code such as `ABCD-EFGH` and opens `<host>/cli-login`. Sign in, type the code from your own terminal, check the request details (the IP address and client that started the login, and when), and approve. Peek then issues an API token to the CLI that expires after 90 days; run `peek login` again after that. Never type a code that someone else sent you: approving gives whoever ran `peek login` a token that acts as you. Old links of the form `/cli-login/<code>` open the empty code form. Code entry is limited to 10 attempts per minute per client IP.

If browser login is unavailable or inappropriate for automation, use one of the safer token input paths:

```sh
peek login --token-stdin
peek login --token-file /path/to/token
```

Avoid `peek login --token <value>` unless you deliberately accept command history and process-list exposure.

Admins can create and revoke automation tokens:

```text
peek token create --name ci-reports
peek token list
peek token revoke <id>
```

Tokens are stored hashed and the plaintext token is shown only at creation time.

Any signed-in account can also create, regenerate and revoke its own keys under **Dashboard → API keys** without the CLI. The key is shown once. The tokens that `peek login` creates appear there as "CLI login" and can be revoked there. Admins keep `peek token` and `/api/tokens` for tokens of other accounts.

## Upload Visibility

Each upload chooses one of three access modes:

| Mode | Access |
| --- | --- |
| `public` | Anyone with the link can open and comment. |
| `signed-in` | Visitors must have an active Peek account session. Any account qualifies, not only the owner; use `restricted` to limit access to named people. The former name `private` is still accepted. |
| `restricted` (default) | Only the owner, admins, and signed-in visitors matching a grant. Others see a 403 page. |

Uploaded HTML itself remains sandboxed in all modes.

### Grants

A restricted page is opened up with grants. A user grant names one email address and matches the signed-in account with that email. A group grant names a Google Workspace group address and matches accounts that are direct or nested members of that group.

Owners and admins can change a page's name, mode and grants later from the dashboard's **Access** dialog or with `peek rename`, `peek visibility` and `peek grant`. Restricted pages that someone shared with you, directly or through a Google group, are listed on your dashboard with a view-only icon. When an admin has configured email, each new grantee is emailed the link, and switching a page to restricted emails everyone who already has a grant; only recipients in the allowed email domain, when one is set, are mailed. Page passwords were removed, and pages that had one became restricted.

```sh
peek upload report.html --visibility restricted
peek grant <slug> alice@example.com
peek grant <slug> team@example.com --group
peek grants <slug>
peek revoke <slug> alice@example.com
```

Grants apply to page views, comments, and view stats. Revoking a grant takes effect the next time the page or its frame loads. Group grants need the Google service account described in [Server setup](/peek/docs/server-setup/), and membership changes take up to the cache TTL (5 minutes by default) to apply.

## Audit Log

Peek records security-relevant events in an audit log stored in SQLite: sign-ins, token and provisioning key changes, grants and visibility changes, access denials on restricted pages, backend actions, settings changes and email test sends. Admins read it with `GET /api/audit` and an admin token. Details are space-separated key=value fields; a value containing a space, `=`, a quote, a backslash or a control character is written as a Go-quoted string. Log IP fields come from `X-Forwarded-For` only with `--trusted-proxy`. See the [operator guide](https://github.com/privacyfence/peek/blob/main/docs/operations.md#observability).

## Parameters

| Setting | Where | Meaning |
| --- | --- | --- |
| `auth_token_login_enabled` | Runtime setting | Allows dashboard login with access tokens when OAuth is not required. |
| `auth_allowed_email_domain` | Runtime setting | Optional exact email domain for human sign-in, invites, and CLI browser approval. |
| `auth_google_org_signup` | Runtime setting | Google-only sign-in that creates accounts on first sign-in for Google Workspace users in the allowed domain; invites are inactive. Requires Google login and an allowed domain. |
| `auth_oidc_signup` | Runtime setting | SSO sign-up: creates accounts on the first SSO sign-in of anyone in the allowed domain. Requires SSO login and an allowed domain; cannot be combined with Google org sign-in. |
| `oauth_google_enabled` | Runtime setting | Enables Google login when credentials are present. |
| `oauth_google_client_id` | Runtime setting | Google OAuth web client ID. |
| `oauth_google_client_secret` | Runtime setting | Google OAuth web client secret; leave blank in the dashboard to keep the current secret. |
| `oauth_github_enabled` | Runtime setting | Enables GitHub login when credentials are present. |
| `oauth_github_client_id` | Runtime setting | GitHub OAuth app client ID. |
| `oauth_github_client_secret` | Runtime setting | GitHub OAuth app client secret; leave blank in the dashboard to keep the current secret. |
| `oauth_oidc_enabled` | Runtime setting | Enables generic OpenID Connect SSO when issuer and credentials are present. |
| `oauth_oidc_issuer_url` | Runtime setting | OpenID Connect issuer URL. |
| `oauth_oidc_client_id` | Runtime setting | OpenID Connect client ID. |
| `oauth_oidc_client_secret` | Runtime setting | OpenID Connect client secret; leave blank in the dashboard to keep the current secret. |
