# Backup and restore

A Kontainer registry keeps state in two places:

| What | Where | Contains |
| --- | --- | --- |
| **Database** | `auth.database_url` (PostgreSQL) | Users, organizations, teams, permissions, tokens, sessions, repository descriptions and READMEs, stars, quotas, retention policies, build/scan/webhook queues, upload sessions, background jobs |
| **Storage** | `storage.driver` (filesystem, S3, GCS or Azure) | Image layers and manifests (`blobs/`), tags and repository links (`repositories/`), scan reports (`scans/`), activity log (`logs/`) |

Back up both, and the configuration file. The search index is rebuilt from storage on start,
so it needs no backup.

## Taking a backup

```sh
kontainer --config /etc/kontainer/config.toml backup /backups/kontainer-2026-10-13 --storage
```

- The database is dumped with `pg_dump --format=custom` into `<output>/database.dump`, a
  consistent snapshot that is safe to take while the server runs. `pg_dump` must be on the
  `PATH` (it is in the image); on a managed service you can use its own snapshots instead.
- With `--storage`, every registry object is streamed into `<output>/storage`, whichever
  backend is configured, and the manifests, tags and links are exported as
  `<output>/metadata.jsonl` (they are in the database dump too; the JSON Lines file is the
  storage-independent copy that `kontainer migrate-metadata --from` can load).
- `backup.json` records when the backup was taken, the version, the storage driver, the file
  names and how many objects and bytes were copied.
- The output directory must not exist yet, so a backup never overwrites another one.

> The dump holds password hashes, session ids and, unless `auth.secret` is set, the token
> signing key. Keep backups as private as the database itself.

### Large registries and object storage

On S3, GCS or Azure, `--storage` downloads everything, which may not be what you want. Back
up the database with `kontainer backup` (without `--storage`), and use the provider's own tools for
storage:

- **S3:** bucket versioning plus replication, or `aws s3 sync s3://bucket/prefix /backups/...`.
- **GCS:** object versioning, or `gcloud storage rsync`.
- **Azure:** blob versioning and soft delete, or `azcopy sync`.

Take the database backup *after* the storage copy starts. A database that is slightly older
than storage is harmless, because it only describes repositories and permissions. Storage
that is older than the database can be missing images that the database expects to exist.

### Scheduling

A daily job with a retention window is enough for most installations, for example in cron:

```cron
15 3 * * * kontainer --config /etc/kontainer/config.toml backup /backups/kontainer-$(date +\%F) --storage && find /backups -maxdepth 1 -name 'kontainer-*' -mtime +14 -exec rm -rf {} +
```

## Restoring

1. Stop the registry.
2. Restore the database into an empty database at `auth.database_url`:
   `pg_restore --clean --if-exists --no-owner -d "$KONTAINER_DATABASE_URL" <backup>/database.dump`.
3. Restore storage. Copy `<backup>/storage/*` into the filesystem root, or sync it back into
   the bucket under `storage.prefix`.
4. Restore the configuration file. If it relies on `auth.secret` or OIDC client secrets, make
   sure those are set again. **A restore needs the same encryption key:** stored secrets
   (upstream passwords, webhook secrets, Git tokens, SSO client secrets) are encrypted with
   `auth.encryption_key` (or the key derived from `auth.secret`), and the registry refuses to
   start on a database whose secrets need a key it doesn't have. Back the key up separately
   from the dump; see [Secrets at rest](operations.md#secrets-at-rest).
5. Start the registry. Pending database migrations run automatically, and the search index is
   rebuilt from the database.

### Upgrading from a registry that kept metadata in storage

Versions before 0.3 kept manifests, tags and links as `repositories/...` keys in storage. After
upgrading, run `kontainer migrate-metadata` once against the same configuration: it imports
those keys into the database and deletes nothing. Garbage collection refuses to run until that
has happened. The old keys can be removed afterwards.

### Checking a restore

Restore into a scratch location first, start a second instance on another port, and check:

```sh
curl -s -u admin:<password> http://localhost:5599/v2/_catalog
docker pull localhost:5599/<namespace>/<image>:<tag>
```

Then run a dry-run garbage collection. If it reports manifests or blobs it would remove that
you expected to keep, storage and database come from different points in time:

```sh
kontainer --config restore.toml gc --dry-run
```

## What a restore does not bring back

- **Uploads in progress** (`storage.upload_dir`): clients retry their push.
- **Sessions** are restored with the database. To force everyone to sign in again, delete the
  rows in the `sessions` table.
- **Anything pushed after the backup.**
