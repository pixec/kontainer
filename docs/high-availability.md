# High availability

A highly available Kontainer is stateless registry nodes behind a load balancer, one
PostgreSQL and one object store. There is no Redis: queues, locks and cache invalidation run in
PostgreSQL. The configuration is shared by giving every node the same file, with at most one
environment variable per region.

## Topology

```text
                    ┌─────────────────┐
   clients ───────▶ │  load balancer  │  TLS, /readyz health check, no sticky sessions
                    └────────┬────────┘
             ┌───────────────┼───────────────┐
      ┌──────▼─────┐  ┌──────▼─────┐  ┌──────▼─────┐
      │ kontainer  │  │ kontainer  │  │ kontainer  │   3+ nodes, identical config
      └──┬──────┬──┘  └──┬──────┬──┘  └──┬──────┬──┘
         │      └────────┼──────┼────────┼──────┘
   ┌─────▼──────┐  ┌─────▼──────▼────────▼──────┐
   │ PostgreSQL │  │ object storage (S3, GCS,   │
   │ (HA pair)  │  │ Azure, Ceph RGW, MinIO...)  │
   └────────────┘  └────────────────────────────┘
```

Minimum for production: three registry nodes, a PostgreSQL with a standby, an object store
that is itself replicated, and a load balancer that is not a single machine. Component roles,
state placement and sizing are in [architecture.md](architecture.md).

## What lives where

| State | Where | Notes |
| --- | --- | --- |
| Accounts, roles, teams, tokens, sessions | PostgreSQL | |
| Manifests, tags, blob links, referrers | PostgreSQL | a push on any node is visible on every node at once |
| Blob placements, copy queue | PostgreSQL | which bucket holds which blob |
| Build, scan and webhook queues, background jobs | PostgreSQL | claimed with `FOR UPDATE SKIP LOCKED`; work survives a node dying |
| Upload sessions | PostgreSQL | chunks in object storage: any node can take the next chunk |
| Login throttling, OIDC state, TOTP replay guard | PostgreSQL | |
| Token signing key | PostgreSQL (`auth.secret` if you set it) | created once with `ON CONFLICT DO NOTHING`, so nodes booting together agree |
| Blobs, scan reports, activity logs | object storage | |
| Search index | each node, in memory | rebuilt from the database on start, kept current by `LISTEN/NOTIFY` |
| Role, visibility and proxy caches | each node, in memory | invalidated across nodes by `LISTEN/NOTIFY`, reloaded every 60 s regardless |
| Build logs | PostgreSQL, in chunks | a runner's check-in can reach any node; followers on every node hear of new chunks by `LISTEN/NOTIFY` and read them from the table |
| Upload temp files, scanner caches | each node's `upload_dir` and data directory | per request; never shared |

Periodic work (GC, retention, mirrors, backfill, Git polling) is guarded by PostgreSQL
advisory locks so only one node runs each job at a time. Every node runs queue workers.

## What must be identical on every node

- The configuration file. The only per-node difference is `KONTAINER_STORAGE_LOCATION`, and
  only with several regions (see [Geo-replication](operations.md#geo-replication)).
- `auth.database_url`. One database, not one per node.
- `server.public_url`: the external address, the same everywhere, since token realms, upload
  `Location` headers and OIDC redirect URIs are built from it.
- `auth.secret`, if set. Unset, the key is generated once and stored in the database, which
  is the same thing with less to manage.

`kontainer check-config` on each node before starting validates the configuration and prints
the effective values with secrets redacted.

## Load balancer

- **Health check:** `GET /readyz` on each node. It answers `200` when the node is up, the
  database answers and the node's own storage location can be listed, else `503` with the
  reason. `GET /livez` only says the process is alive; use it for restarts, not for routing.
  With `server.ready_requires_all_locations = true`, `/readyz` also probes every other
  storage location.
- **No sticky sessions.** Nothing is pinned to a node: chunked uploads, browser sessions and
  Docker tokens all work from any node.
- **Bodies and timeouts:** allow request bodies of any size and idle timeouts long enough for
  a multi-gigabyte layer; do not buffer.
- **Client address:** have the balancer set `X-Forwarded-For` and list it in
  `server.trusted_proxies`; otherwise every login counts against the balancer's IP.
- **TLS:** terminate at the balancer and set `server.public_url` to `https://...`, or pass TCP
  through and terminate on each node; either works. The session cookie is `Secure` whenever
  `public_url` is https.
- **Region routing** (several regions): the CDN or balancer sets the header named by
  `storage.region_header`, and pulls are redirected to the nearest bucket.

## Health endpoints

| Endpoint | Auth | Meaning |
| --- | --- | --- |
| `GET /livez` | none | process is up |
| `GET /readyz` | none | this node can serve: database and own storage reachable |
| `GET /api/v1/health` | `users:read` or `gc` | end to end: database, a write/read/delete probe of every storage location, replication backlog per location, search index, scanner, upstream registries, mirrors, failed jobs |

## Scaling

- **Registry nodes** are stateless. Add nodes to add request capacity, scan workers
  (`scanner.workers` per node), webhook and copy workers. Rolling restarts are safe: a node that
  dies mid-job leaves a lease that another node reclaims after two minutes.
- **PostgreSQL** is the one component that must be made highly available on its own: a managed
  service with a standby, Patroni, or CloudNativePG. Size the connection limit for
  `auth.database_pool` (default 16) plus a few per node.
- **Object storage** should be the provider's replicated service. With the `filesystem` driver,
  every node must mount the same volume, so prefer object storage for anything beyond one node.
- **Builds** run on runners, not on registry nodes; see [builds.md](builds.md).

## Upgrades

Nodes of the previous and the next version can run side by side while a rolling update is in
progress, except when a release changes the database schema; the release notes say so, and
then all nodes are stopped, the database is backed up, and the new version is started on one
node first so it runs the migration alone.

## Reference deployments

- **Compose:** `deploy/compose/compose.ha.yaml` runs three registry containers behind Caddy with
  PostgreSQL and RustFS on one host, for trying the topology; a real deployment spreads the
  nodes over machines.
- **Helm:** `replicaCount: 3` with `storage.driver` set to `s3`, `gcs`, `azure` or `locations`
  and `database.url` pointing at your PostgreSQL. See [deployment.md](deployment.md#kubernetes-helm).
