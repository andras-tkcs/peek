---
title: Using Peek
description: Upload HTML, share review links, collect comments, and inspect activity.
kicker: peek upload
---

## Upload A Page

Use the CLI when a report or generated page already exists on disk:

```sh
peek upload demo.html --visibility public
```

The response includes a URL and a slug. Share the URL with reviewers; keep the slug for CLI commands such as `stats`, `comments`, `visibility`, and `export`.

Links are made from the page name plus a random six-character suffix, for example /p/q3-plan-k7m2xq, so a page cannot be found by guessing its name. Renaming a page gives it a new suffixed link; old links keep redirecting.

The dashboard is better when you want to paste HTML, choose visibility visually, copy links, or manage several uploads at once.

<figure>
  <img src="/peek/assets/screenshots/05-dashboard-uploads.png" alt="Peek dashboard with the upload form and uploads table">
  <figcaption>The dashboard combines upload, link copying, stats, and delete actions in one place.</figcaption>
</figure>

## Pick Visibility

Visibility is a review policy, not a storage location.

| Visibility | Who can open it | Good for |
| --- | --- | --- |
| `public` | Anyone with the link | Fast internal sharing where the URL itself is enough control. |
| `password` | Anyone with the link and upload password | Sharing outside the signed-in group without creating accounts. |
| `signed-in` | Any signed-in Peek user (the whole organisation when Google org sign-in is on; use `restricted` for named people only) | Internal reports that should stay behind the company login surface. |
| `restricted` | Owner, admins, and signed-in users matching a grant | Reports for a named person or Google group. |

Change visibility after upload when the audience changes:

```sh
peek visibility <slug> public
peek visibility <slug> password --password newpass
peek visibility <slug> signed-in
peek visibility <slug> restricted
peek rename <slug> "New name"
```

Restricted pages are opened up with grants: `peek grant <slug> alice@example.com` for one person, `peek grant <slug> team@example.com --group` for a Google group, `peek grants <slug>` to list, and `peek revoke <slug> <email>` to remove. Someone signed in without a grant sees a 403 page.

In the dashboard, the **Access** button on an upload's row renames the page, changes its visibility, sets a new password and, for restricted pages, adds or removes people and Google groups. Renaming changes the link to follow the new name; old links keep redirecting and are never given to another page. Setting a new password signs out everyone who unlocked the page with the previous one.

## Update A Page

Upload a new version of an existing page by slug:

```sh
peek upload demo.html --slug <slug>
peek versions <slug>
```

`/p/<slug>` always serves the latest version and `/p/<slug>/v/<n>` serves a specific one, with a banner linking to the latest. Visibility and name stay as they were. Comments belong to the version they were written on.

## Review In Context

Open `/p/<slug>`. Peek keeps the uploaded page full-screen and adds a small toolbar for comments, view count, and the comments panel. Use the chevron button at the end of the toolbar to hide it while reading; press Shift+H to bring it back (or hide it again). Reloading the page always shows the toolbar.

Select text when exact wording matters:

<figure>
  <img src="/peek/assets/screenshots/03-text-anchor.png" alt="Selected text inside a shared report with Peek's inline comment button visible">
  <figcaption>Text comments keep feedback attached to the sentence or phrase under review.</figcaption>
</figure>

Use element comments for sections, charts, cards, headings, or layout issues:

<figure>
  <img src="/peek/assets/screenshots/04-element-pin.png" alt="Peek element comment mode with a feedback composer open on a report section">
  <figcaption>Element comments pin feedback to a rendered part of the page.</figcaption>
</figure>

Use a page comment when the note is about the whole artifact rather than one target.

## Read Feedback

The comments panel shows author, timestamp, scope, target text, and body. Anchored comments are clickable, so owners can jump back to the relevant part of the page. Comments from signed-in Peek accounts show the account name with a "signed in" marker; a signed-in viewer cannot choose another name. Names without the marker were typed by the viewer and are not verified.

<figure>
  <img src="/peek/assets/screenshots/02-viewer-comments.png" alt="Peek shared-page viewer with the comments panel open">
  <figcaption>The panel is the review thread: every note carries enough context to act on it later.</figcaption>
</figure>

Owners can read comments from the CLI:

```sh
peek comments <slug>
peek comments <slug> --version 2
peek export <slug>
```

Use `comments` for quick terminal review. Use `export` when an agent, ticket, or audit trail needs the upload metadata, visits, and comments together.

## Stats

Stats answer a narrow question: did reviewers open the page?

<figure>
  <img src="/peek/assets/screenshots/06-upload-stats.png" alt="Peek stats page with visit totals and recent visits">
  <figcaption>Stats show total visits, unique visitors, and recent visits for one upload.</figcaption>
</figure>

Peek hashes analytics IPs. Treat stats as internal review activity, not a full web analytics product.

## API Keys

Every signed-in account has an **API keys** card on the dashboard. **Create key** takes a name (1 to 100 characters) and shows the full key once, starting with `peek_`, with a Copy button ("Copy it now. Peek stores only a hash and cannot show it again.").

The list shows each key's name, last four characters, created, last used (updated at most once a minute) and expiry, including the "CLI login" keys that `peek login` creates. Keys that were created before the hint was recorded show `—` instead of their last four characters.

**Regenerate** replaces the secret and keeps the name, and the old key stops working at once. **Revoke** deletes the key after a confirmation.

A key acts as your account with the same access, so an admin's key can use the admin API. It keeps working until it is revoked or the account is disabled, even if an allowed email domain is set later. Use it as `PEEK_TOKEN` or as `Authorization: Bearer <key>`. Keys from `peek login` expire 90 days after approval.

## CLI Workflow

Configure once:

```sh
peek login --host https://peek.example.com
```

Common user commands:

```text
peek upload <file.html> --visibility public|password|signed-in|restricted
peek upload <file.html> --slug <slug>
peek versions <slug>
peek grant|revoke <slug> <email> [--group]
peek grants <slug>
peek list
peek stats <slug>
peek comments <slug> [--version <n>]
peek export <slug>
peek visibility <slug> public|password|signed-in|restricted
peek rename <slug> <new name>
peek delete <slug>
peek delete-all
```

For automation, set `PEEK_HOST` and `PEEK_TOKEN`, with a key from **Dashboard → API keys** or from `peek login`. Prefer browser login, `--token-stdin`, or `--token-file` over passing a token directly in the command line.
