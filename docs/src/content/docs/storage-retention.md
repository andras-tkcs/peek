---
title: Storage, Limits, And Retention
description: Choose file or S3-compatible storage, set upload limits, and plan backups.
kicker: Admin / Storage
---

## Storage Model

Peek keeps metadata in SQLite and upload bytes in the configured object store.

SQLite contains accounts, sessions, tokens, upload metadata, comments, visits, settings, audit logs, and migrations. Object storage contains the uploaded HTML bytes.

Changing the storage backend between `file` and `s3` requires a restart because it changes where `peekd` reads and writes upload bytes.

## File Storage

File storage is the default. Uploaded HTML is stored under the data directory, next to `peek.db` and `secret.key`.

Use file storage when one VM or one container volume is the operational source of truth. Back up the whole data directory for the simplest recovery story.

```sh
peekd --data /var/lib/peek --storage file
```

## S3-Compatible Storage

S3 storage writes upload bytes to `uploads/<object-name>` inside the configured bucket. It works with S3-compatible services that support signed `PUT`, `GET`, and `DELETE` object requests.

<figure>
  <img src="/peek/assets/screenshots/09-admin-storage-s3.png" alt="Peek Admin page, Storage tab with S3 selected and endpoint, bucket, region, access key, and secret fields visible">
  <figcaption>The Admin page can update S3 connection settings, but backend selection takes effect after restart.</figcaption>
</figure>

Startup environment:

```sh
PEEK_STORAGE=s3
PEEK_S3_ENDPOINT=https://example-account.r2.cloudflarestorage.com
PEEK_S3_BUCKET=peek
PEEK_S3_REGION=auto
PEEK_S3_ACCESS_KEY=...
PEEK_S3_SECRET_KEY=...
```

Private, loopback, link-local, metadata, and plain HTTP endpoints are blocked by default to reduce SSRF risk. Use `PEEK_S3_ALLOW_PRIVATE_ENDPOINT=true` only for explicit private deployments such as local MinIO or a controlled internal object store.

After changing S3 credentials or endpoint settings, run a smoke upload and open the resulting page.

## Limits And Quotas

Limits protect the server from accidental growth and runaway automation.

<figure>
  <img src="/peek/assets/screenshots/10-admin-limits-retention.png" alt="Peek Admin page, Limits tab showing upload size, total storage, per-owner quotas, and retention controls">
  <figcaption>Limits are runtime settings: save them from the Admin page and they apply to future uploads and cleanup.</figcaption>
</figure>

| Limit | Meaning |
| --- | --- |
| Max upload size | Maximum size for one HTML upload. Must be greater than zero. |
| Total storage limit | Cumulative upload storage across the server. `0` means unlimited. |
| Max uploads per owner | Count limit per account or token owner. `0` means unlimited. |
| Storage per owner | Byte limit per account or token owner. `0` means unlimited. |

The Admin page shows byte-based limits in MB. The API stores the underlying runtime setting in bytes.

## Versions

Re-uploading with `peek upload <file.html> --slug <slug>` stores a new object per version. Version 1 is keyed `<slug>`; later versions are keyed `versions/<slug>/<hex>`. Every version counts toward the total storage limit and the page owner's storage limit, but not toward the per-owner upload count, which counts pages.

## Retention

Retention deletes a page when its newest version is older than the configured number of days. Older versions of a page that is kept are pruned individually, together with the comments written on them; the newest version is never pruned. `0` disables automatic cleanup. A version uploaded while its page is being deleted can leave one orphaned object.

Use retention for policy, not as a substitute for backups. If your company treats generated reports as temporary review artifacts, set retention to match that expectation.

## Backups

For SQLite consistency while the server is running:

```sh
PEEK_DATA=/var/lib/peek peekd backup /backups/peek-$(date +%F).db
```

With file storage, also back up the upload directory and `secret.key`. With S3 storage, the SQLite backup does not contain object bytes; back up or lifecycle-manage the bucket according to the same recovery policy.

Before upgrading storage, auth, retention, or database-sensitive releases, take a backup and test the new binary against a copy of the data directory.

## Restore

To restore from a backup:

1. Stop peekd.
2. Copy the backup over `<data>/peek.db` and delete `<data>/peek.db-wal` and `<data>/peek.db-shm` if present.
3. Restore `<data>/secret.key` and `<data>/uploads/` (or the S3 bucket) from the same point in time.
4. Start peekd.
5. Run the operator smoke test (`/healthz`, `/readyz`, `peek list`, open one page).

peekd refuses to start when `secret.key` exists but is shorter than 32 bytes, instead of replacing it: restore the file from the same backup as `peek.db`, or delete it only if losing every session, API token signature and encrypted setting (S3 keys, OAuth secret) is acceptable.

## Upgrades And Rollbacks

Before upgrading, take a SQLite backup with `peekd backup` and confirm you know where uploaded object bytes live. Try the new binary on a staging copy of the data directory when a release touches storage, auth, retention, or the database.

Rollback is simplest when the database has not been migrated by a newer binary. If a release includes migrations, roll back by restoring the pre-upgrade backup plus the object storage state (see Restore above). Migration notes per version:

- Unreleased: migration 17 adds the provisioning key tables; older binaries ignore them, so provisioning keys stop working after a rollback.
- v0.14.0: migration 16 adds the page backend tables; backends stop being served after a rollback and leftover containers labelled `peek.managed=true` need removing.
- v0.13.0: migrations 14 and 15 rewrite visibilities and convert password pages to restricted; roll back by restoring the backup.
- v0.10.0: migrations 11 to 13; sessions created by the new binary are not accepted by older ones, and the unversioned `/raw/<slug>` route is gone.
- v0.9.0: migration 10 adds token hint and last-used columns.
- v0.8.0: migrations 7 to 9; do not roll back once a page has been renamed, restore the backup instead.

The full notes are in the [operator guide](https://github.com/andras-tkcs/peek/blob/main/docs/operations.md#upgrades-and-rollbacks).
