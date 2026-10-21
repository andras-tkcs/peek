---
title: Auth And Access
description: Configure local login, OAuth, invites, CLI login, tokens, and upload visibility.
kicker: Settings / Auth
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
  <img src="/peek/assets/screenshots/08-admin-auth.png" alt="Peek Settings Auth tab showing access-token login, allowed email domain, and OAuth provider configuration">
  <figcaption>The Auth tab controls token login, allowed email domain, and provider credentials.</figcaption>
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

Admins can set one allowed email domain on the Admin page. When configured, human sign-in must use an account email from that exact domain. The rule applies to OAuth login and signup, local password login, web token login, CLI browser approval, private-page sessions, and new invites. It also applies to API bearer tokens of accounts with an email: a token whose account email is outside the domain is refused with 403. Automation tokens from `peek token create` have no email and are not affected.

Use the bare domain, such as `example.com`. A leading `@` is accepted and normalized away. Subdomains are not implicit matches, so `person@team.example.com` does not match `example.com`.

Peek refuses to save a non-empty allowed domain unless at least one active admin account already has a matching email address. That keeps the setting from locking out all administrators.

## Invites And Users

OAuth signup is invite-only. A new OAuth user can create an account only when:

1. The provider returns a verified email.
2. The browser has a pending Peek invite cookie.
3. The invite email matches the provider email.

If an account already exists with the verified email, Peek links the OAuth identity to that account without requiring another invite. Disabled accounts cannot sign in.

When OAuth is enabled, non-admin password and token web login are disabled. Admins keep password login as a recovery path, as long as the admin email also matches the allowed domain when one is configured.

The same rule applies to API tokens: while OAuth is enabled, a non-admin account's token works only if the account has signed in with OAuth at least once.

Organizations that only use Google Workspace can skip invites entirely with [Google org sign-in](#google-org-sign-in).

## Google Org Sign-In

The `auth_google_org_signup` setting turns Peek into a "Google sign-in for the whole organization" server. While it is on, anyone who signs in with a Google Workspace account whose verified email is in the allowed email domain gets a Peek account on their first sign-in. No invite link is needed and nothing is emailed.

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

Each upload chooses one of four access modes:

| Mode | Access |
| --- | --- |
| `public` | Anyone with the link can open and comment. |
| `password` | Visitors must pass the upload password gate before opening and commenting. |
| `private` | Visitors must have an active Peek account session. |
| `restricted` | Only the owner, admins, and signed-in visitors matching a grant. Others see a 403 page. |

Uploaded HTML itself remains sandboxed in all modes.

### Grants

A restricted page is opened up with grants. A user grant names one email address and matches the signed-in account with that email. A group grant names a Google Workspace group address and matches accounts that are direct or nested members of that group.

Owners and admins can change a page's name, mode, password and grants later from the dashboard's **Access** dialog or with `peek rename`, `peek visibility` and `peek grant`. A new password revokes every earlier unlock of that page.

```sh
peek upload report.html --visibility restricted
peek grant <slug> alice@example.com
peek grant <slug> team@example.com --group
peek grants <slug>
peek revoke <slug> alice@example.com
```

Grants apply to page views, comments, and view stats. Revoking a grant takes effect the next time the page or its frame loads. Group grants need the Google service account described in [Server setup](/peek/docs/server-setup/), and membership changes take up to the cache TTL (5 minutes by default) to apply.

## Parameters

| Setting | Where | Meaning |
| --- | --- | --- |
| `auth_token_login_enabled` | Runtime setting | Allows dashboard login with access tokens when OAuth is not required. |
| `auth_allowed_email_domain` | Runtime setting | Optional exact email domain for human sign-in, invites, and CLI browser approval. |
| `auth_google_org_signup` | Runtime setting | Google-only sign-in that creates accounts on first sign-in for Google Workspace users in the allowed domain; invites are inactive. Requires Google login and an allowed domain. |
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
