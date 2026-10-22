# Architecture

Kontainer is one binary with three roles, one shared database and one or more object stores:
stateless application nodes in front of stateful PostgreSQL and object storage, background work
in queues that any node can drain, and per-region storage for a global registry.

```text
                 clients, CI, docker/podman/crane            browsers
                              │                                 │
                     ┌────────▼─────────────────────────────────▼────────┐
                     │        load balancer / CDN (region header)         │
                     └───────┬───────────────────────────────┬───────────┘
            region EU        │                               │       region US
   ┌─────────────────────────▼──────┐             ┌──────────▼──────────────────────┐
   │ kontainer serve  ×N            │             │ kontainer serve  ×N             │
   │  v2 API · UI · management API  │             │  (same config,                  │
   │  queue workers · schedulers    │             │   KONTAINER_STORAGE_LOCATION=us) │
   └───────┬──────────────┬─────────┘             └─────────┬───────────────┬───────┘
           │              │                                 │               │
   ┌───────▼───────┐  ┌───▼─────────────────────────────────▼───┐   ┌───────▼───────┐
   │ bucket "eu"   │◀─│              PostgreSQL                  │─▶│ bucket "us"   │
   │ blobs, scans, │  │ accounts · manifests · tags · placements │  │               │
   │ logs, chunks  │  │ queues · sessions · jobs · settings      │  │               │
   └───────────────┘  └──────────────────────────────────────────┘   └───────────────┘
                                          ▲
                       ┌──────────────────┴──────────────────┐
                       │ kontainer runner ×N (builds)         │
                       │ local · docker · kubernetes executor │
                       └──────────────────────────────────────┘
```

## Components

| Component | Runs where | Does |
| --- | --- | --- |
| **Registry node** (`kontainer serve`) | N per region, stateless | the OCI distribution API (`/v2`), the management API (`/api/v1`), the embedded UI, token issuing, and every worker and scheduler below |
| **PostgreSQL** | one, highly available on its own | all metadata and all coordination (see [State](#state)) |
| **Storage location** | one per region (S3, GCS, Azure, Ceph RGW, MinIO, R2; `filesystem` for one node) | blob bytes, scan reports, activity logs, in-flight upload chunks |
| **Runner** (`kontainer runner`) | anywhere that reaches the registry over HTTPS | claims queued builds from Git triggers and runs them with the `local`, `docker` or `kubernetes` executor; pushes the result |
| **Scanner** (trivy or grype) | a subprocess of each registry node | pulls an image with a per-scan pull-only token and reports vulnerabilities |
| **Upstreams** | elsewhere | registries used by pull-through caches, mirrors, imports and push replication |

There is no Redis and no separate worker deployment. Build logs, events, queues and the GC
lock are in PostgreSQL or in object storage.

## Workers and schedulers

Every registry node runs the same set. Queues are PostgreSQL tables claimed with
`FOR UPDATE SKIP LOCKED` and a lease, so a node that dies mid-job loses nothing: another node
reclaims the row when the lease expires. Periodic jobs take a PostgreSQL advisory lock first,
so only one node runs each at a time; the others skip the tick.

| Worker | Kind | Config | Does |
| --- | --- | --- | --- |
| Blob copy | queue, `replication_concurrency` per node | `storage.replication_concurrency` | copies a blob, scan report or log from a location that has it to one that does not; retries with backoff; keeps failures with their error |
| Scan | queue, `scanner.workers` per node | `[scanner]` | runs the scanner on a pushed manifest, three attempts, stores the report, fires the `scan` webhook |
| Webhook delivery | queue, 8 per node | `[[webhooks]]`, namespace hooks | signed HTTP deliveries with retries; history kept per hook |
| Build claim | queue, claimed by runners | `[builds]` | builds from Git triggers and manual starts, one claim per build |
| Push replication | per-rule task | replication rules | pushes tags to another registry when they change |
| Backfill | periodic, locked | `storage.replication_interval` | queues copies of every blob each location is missing |
| Garbage collection | periodic or `kontainer gc`, locked | `[maintenance]` | marks from the tables, sweeps unreferenced blobs from every location under a per-digest lock |
| Retention and tag expiry | periodic, locked | retention policies | prunes tags by count or age, expires tags with a deadline |
| Mirrors and Git polling | periodic, locked | mirrors, build triggers | syncs mirrored repositories, polls Git hosts without webhooks |
| Usage report | periodic, locked | | walks placements for the cluster-wide storage figures that `/metrics` and the admin UI show |
| Purge | periodic | | expired sessions, OIDC states, MFA setups, login counters, finished jobs, stale uploads |
| Cache watcher | per node | | applies `LISTEN/NOTIFY` events to the node's role, visibility, proxy and search caches |
| Build log fan-out | per node | | wakes the node's live build log streams when any node stores a log chunk (`NOTIFY kontainer_build_log`) |

## State

| State | Where | Why there |
| --- | --- | --- |
| Users, organizations, teams, roles, grants, robots, tokens, sessions, identities, MFA | PostgreSQL | shared, transactional |
| Manifests (bodies included), tags, blob links, referrers | PostgreSQL | a push anywhere is visible everywhere at once; manifest PUT is one transaction |
| Blob placements (which location holds which digest) and the copy queue | PostgreSQL | reads pick a location without a HEAD; GC knows every copy |
| Upload sessions | PostgreSQL, chunks in the node's location | any node can take the next chunk or finish the upload |
| Queues, background jobs, task runs, login throttling, usage report, settings | PostgreSQL | shared and durable |
| Token signing key | PostgreSQL (`auth.secret` if set) | created once with `ON CONFLICT DO NOTHING` |
| Blob bytes, scan reports, activity logs | object storage, every location eventually | large, immutable, content-addressed |
| Search index | each node, in memory | rebuilt from PostgreSQL on start, updated on notify |
| Role, visibility, proxy, upstream-client caches | each node, in memory | invalidated by notify, reloaded every 60 s anyway |
| Temp files, scanner caches | each node's disk | per request |

## Request paths

- **Push:** `POST /v2/<name>/blobs/uploads/` creates a session row; each `PATCH` writes a chunk
  object to the node's location and advances the offset with a compare-and-set; `PUT` seals the
  session, re-hashes the chunks into `blobs/<alg>/<hex>`, records the placement and queues
  copies; the manifest `PUT` checks every referenced blob has a link, then writes manifest, links
  and tag in one transaction. Quota is checked at upload time and again at manifest time.
- **Pull:** the manifest comes from PostgreSQL. A blob `GET` looks up the placements, orders the
  locations (client's region, this node's, any other), and either answers `307` to a presigned
  URL or streams, failing over to the next location on error. Authorization and the
  vulnerability block policy run before either.
- **Login:** password or LDAP, with optional TOTP, or OIDC (instance-wide or per organization),
  or workload federation from a CI provider's JWT. Docker gets a scoped bearer token from
  `/auth/token`; browsers get a session cookie.

## Geo-replication model

- Every region runs the same configuration with its own `KONTAINER_STORAGE_LOCATION`.
- Pushes land in the region's bucket. Copies to the other buckets are asynchronous.
- Pulls are served from the nearest bucket that has the blob, otherwise from the source bucket,
  so a blob is never unavailable while a copy is in flight.
- Every region's nodes need read and write access to every bucket: a node copies into the
  other regions' buckets and may stream from them.
- A region's bucket can be unreachable without stopping pushes elsewhere: reads fail over, and
  copies into it queue up and are retried. Nodes know each location's health
  (`/api/v1/health`, per-location gauges) and can be taken out of rotation for it
  (`server.ready_requires_all_locations`).
- Permanent loss of a bucket loses the blobs that were only placed there. The admin page and
  `kontainer_replication_pending_blobs{location}` show how much is still unreplicated at any
  moment; keep it near zero before any planned decommissioning.
- The database is shared, not replicated per region. Run it where write latency is acceptable
  for every region and make it highly available on its own.

**Geo-replication or mirroring?** Geo-replication is one registry with one namespace,
one set of accounts and one view of every tag, served close to each region. Mirroring
(pull-through caches, mirrors, push replication rules) connects independent registries that
share selected content and have their own accounts and policies. Prefer one registry with
organizations and roles over several registries, and use mirroring at the boundary to other
organizations.

## Sizing

Kontainer is a single Rust process; the numbers below are starting points for the parts that
matter. The database and object storage are the parts to size
carefully.

| | Proof of concept | Team | Large |
| --- | --- | --- | --- |
| Registry nodes | 1 (1 vCPU, 512 MB; 2 GB with scanning) | 2-3 (2 vCPU, 2 GB each) | 4-10 per region (4 vCPU, 4 GB each) |
| PostgreSQL | shared container, 1 GB | 2-4 cores, 8 GB, 50 GB | 8+ cores, 32 GB, 500 GB+, with a standby |
| Connections | `auth.database_pool` 16 | 16 per node + 1 listener | 32 per node + 1 listener; size `max_connections` to nodes × (pool + 4) |
| Object storage | the data volume | 1-10 TB | 10 TB+ per region |
| Runners | the registry host | 1-2 with the `docker` executor | a Kubernetes namespace per team |

Memory on a node scales with concurrent uploads (chunks stream through, bounded) and with the
scanner (trivy needs about 1 GB per concurrent scan). Manifest bodies are capped at
`server.max_manifest_size` and kept in the database, so the database grows with tags and
manifests, not with layers.

## Deployment shapes

| Shape | What | See |
| --- | --- | --- |
| Single node | one container, PostgreSQL alongside, blobs on a volume or a bucket | [deployment.md](deployment.md#docker-compose) |
| Highly available | 3+ nodes behind a balancer, managed PostgreSQL, object storage | [high-availability.md](high-availability.md) |
| Geo-replicated | the HA shape in every region, one database, a bucket per region | [operations.md](operations.md#geo-replication) |
| Kubernetes | the Helm chart with `replicaCount`, optional runner and build namespace | [deployment.md](deployment.md#kubernetes-helm) |
| Air-gapped | mirrors or `kontainer export`/layout import to move images; the scanner's database needs its own offline update | [operations.md](operations.md) |

## Design principles

- **PostgreSQL is the coordinator.** Queues, locks, leases, cache invalidation and the signing
  key all live there, so there is exactly one stateful dependency besides blob storage.
- **Nodes are interchangeable.** No sticky sessions, no node-local state that matters, the same
  configuration everywhere.
- **Blobs are content-addressed and immutable**, so copying them between regions needs no
  conflict handling; only metadata needs transactions, and that is in the database.
- **Verify what clients send.** Digests are recomputed on upload and on copy, manifests are
  validated against their linked blobs, tokens are scoped to the repositories they name, and
  the registry mints the scanner's and runners' credentials itself.
- **Prefer one registry.** Organizations, teams, roles and quotas separate tenants; mirroring is
  for crossing into other registries.
