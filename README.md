# Kontainer

Kontainer is a container registry implementing the [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec),
written in Rust. It is a single binary with an embedded web UI and the operational features
a team registry needs: role-based access control, vulnerability scanning, immutable tags,
webhooks, activity logs and garbage collection.

## Features

**Distribution spec** (push/pull with `docker`, `podman`, `crane`, `oras`, `skopeo`, BuildKit...)

- Resumable, chunked and monolithic blob uploads; cross-repository blob mounts
- Blob `Range` requests; repository-scoped blob access
- Manifest validation (every referenced blob must exist), OCI image manifests and indexes,
  Docker schema 2 manifests and lists
- Tags with `n`/`last` pagination, `/v2/_catalog`, OCI 1.1 referrers API with
  `artifactType` filtering and `OCI-Subject`, and pushes by digest that set several tags at
  once (`?tag=1.2.3&tag=latest`, answered with `OCI-Tag` headers)
- Spec error codes and bodies throughout

**Storage** via [`object_store`](https://docs.rs/object_store)

- Local filesystem, S3 and S3-compatible (MinIO, R2, Ceph...), Google Cloud Storage, Azure Blob,
  in-memory
- Content-addressed blobs in object storage, with manifests, tags and links in PostgreSQL
- Uploads are staged as chunks in object storage and committed once their digest is verified
- Geo-replication: one shared database, one object storage per region, pushes
  written locally and copied to the other regions in the background, pulls redirected to
  the nearest bucket that has the blob with presigned URLs

**Accounts and access control** (PostgreSQL via sqlx)

- User accounts with Argon2id passwords, web sessions, TOTP two-factor authentication with
  recovery codes, OpenID Connect single sign-on and LDAP / Active Directory, both with
  group-to-role mapping
- Per-organization OIDC providers, and teams synced from LDAP or OIDC groups
- Keyless robot logins: CI jobs (GitHub Actions, GitLab CI, any OIDC issuer) sign in with
  their own short-lived token
- Docker-style bearer token flow for `docker login`; personal access tokens (scopable to
  repositories/actions) and robot accounts for CI. Accounts with MFA must use tokens on the CLI
- Fine-grained roles: repository rules (`pull`, `push`, `delete`, `delete_repository`, `scan`,
  `logs`, `metadata`, `visibility`, `permissions`, `state`, `builds`, `mirror`, `admin`) on
  glob patterns such as `team-a/**`, plus global permissions
  (`users:read`, `users:write`, `roles:write`, `gc`, `logs:all`, `catalog`, `system`).
  Nobody can grant more than they hold.
- Public repositories pullable without credentials; roles for anonymous users; catalog and UI
  filtered to what the caller may see
- Users and roles manageable from the UI, the API, the CLI, or seeded from the config file
- Organizations: an `org/` namespace with teams whose rules are scoped inside it,
  org admins, and org-owned robots (`org+ci`)
- Repository catalogue: description, Markdown README, topics, and public/private visibility;
  public repositories are pullable by anyone and listed on the Explore page

**Security scanning**

- Trivy or Grype run as a subprocess against the registry itself; reports normalised into one
  schema and stored next to the image
- Scan on push, or on demand from the UI/API; background queue with de-duplication
- Cluster-wide hourly budget for automatic scans and a queue cap, with a timed admin override
- Policy: refuse to serve manifests with vulnerabilities at or above a severity

**Operations**

- Immutable tag rules (`prod/**` + `v*`)
- Tag history with Time Machine restore, tag expiration (also via the `quay.expires-after`
  label), and read-only / mirror repository states
- Builds from Git (push webhooks or polling) in BuildKit, with live logs, run by self-hosted or
  shared runners on machines, Docker hosts or Kubernetes
- Webhooks for `push`, `delete`, `scan` events, filtered by repository
- Usage/audit log: pushes, deletes, mounts, GC, logins and failed logins, tokens, robots,
  role and user changes, MFA changes (and optionally pulls); export as CSV or JSON Lines
- Mark-and-sweep garbage collection with a grace window, optional untagged-manifest removal,
  dry run, via CLI or API
- Stale upload purging
- Pull-through caches (Docker Hub, GHCR, any registry) bound to a namespace, with
  stale-if-unreachable serving; usable as a containerd mirror (`hosts.toml`, `?ns=`)
- Scheduled mirroring of upstream repositories (tag globs, only changed digests copied)
- Import from another registry or an OCI layout archive; export any tag as a `.tar`
- Health: `/livez`, `/readyz` and a detailed report of storage, database, upstreams and mirrors

**Layer view UI** (React, TanStack Query/Form, React Router, shadcn/ui, Tailwind)

- Browse repositories, tags, multi-arch indexes and referrers
- Per-layer Dockerfile step, size, digest and diff ID; expand any layer to list the files
  inside it (gzip, zstd and plain tar) including whiteouts
- Image config: entrypoint, cmd, env, labels, ports
- Vulnerability reports with severity filtering, activity log
- Account settings (access tokens, robots, two-factor, sessions) and admin pages for users,
  roles (with a rule editor) and garbage collection

## Quick start

```sh
# build the UI once, then the registry
npm --prefix web install && npm --prefix web run build
cargo build --release

./target/release/kontainer serve          # http://0.0.0.0:5000, data in ./data, auth off
```

With authentication (the normal case):

```sh
cat > config.toml <<'EOF'
[auth]
mode = "token"
bootstrap_admin = { username = "admin", password = "change-me-now" }
EOF
./target/release/kontainer --config config.toml serve
# or create accounts from the shell:
./target/release/kontainer --config config.toml user create alice --role developers
```

Push something:

```sh
docker tag alpine localhost:5000/demo/alpine
docker push localhost:5000/demo/alpine
# or without a daemon:
crane copy --insecure alpine:3.20 localhost:5000/demo/alpine:3.20
```

Then open <http://localhost:5000/> for the UI.

### Docker Compose and Kubernetes

```sh
cp deploy/compose/.env.example deploy/compose/.env   # set KONTAINER_ADMIN_PASSWORD
docker compose up --build
docker login localhost:5000
```

[deploy/compose](./deploy/compose) adds RustFS object storage, builds from Git and automatic HTTPS
as add-ons, and [deploy/helm/kontainer](./deploy/helm/kontainer) is a Helm chart. See
[docs/deployment.md](./docs/deployment.md).

## Configuration

Configuration is a TOML file passed with `--config` or `KONTAINER_CONFIG`.
[`config.example.toml`](./config.example.toml) documents every option; the important ones:

```toml
[server]
bind = "0.0.0.0:5000"

[storage]
driver = "s3"                       # filesystem | s3 | gcs | azure | memory
upload_dir = "/var/lib/registry/_uploads"

[storage.s3]
bucket = "registry"
endpoint = "http://minio:9000"      # omit for AWS
region = "us-east-1"
allow_http = true                   # credentials: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or IAM

[auth]
mode = "token"                      # none | basic | token (docker login flow)
database_url = "postgres://kontainer:secret@postgres:5432/kontainer"
bootstrap_admin = { username = "admin", password = "change-me-now" }
public_repositories = ["public/**"]

[[auth.roles]]                      # config roles are read-only in the UI; more can be made there
name = "team-a-dev"
rules = [{ repositories = ["team-a/**"], actions = ["pull", "push", "scan", "logs"] }]

[[auth.roles]]
name = "team-a-ops"
rules = [{ repositories = ["team-a/**"], actions = ["admin"] }]
global = ["gc", "users:read"]

[[auth.users]]                      # optional: static accounts
username = "alice"
password_hash = "$argon2id$..."     # kontainer hash-password (prompts)
roles = ["team-a-dev"]

[auth.oidc]
enabled = true
display_name = "Okta"
issuer = "https://example.okta.com"
client_id = "..."
client_secret = "..."
groups_claim = "groups"
group_roles = { "registry-admins" = ["system"], "engineering" = ["team-a-dev"] }

[scanner]
kind = "trivy"                      # none | trivy | grype
scan_on_push = true
username = "scanner"                # a user with pull on everything
password = "..."
block_pull_at = "critical"          # optional policy

[policy]
immutable_tags = [{ repositories = ["prod/**"], tags = ["v*"] }]

[[webhooks]]
name = "ci"
url = "https://hooks.example.com/registry"
events = ["push", "scan"]
```

Environment overrides for containers: `KONTAINER_BIND`, `KONTAINER_PUBLIC_URL`,
`KONTAINER_STORAGE_DRIVER`, `KONTAINER_STORAGE_ROOT`, `KONTAINER_UPLOAD_DIR`, `KONTAINER_S3_BUCKET`,
`KONTAINER_S3_ENDPOINT`, `KONTAINER_LOG`, `KONTAINER_DATABASE_URL`, `KONTAINER_AUTH_SECRET`.

### Accounts, roles and permissions

Every request resolves to a principal: a user, a robot, or anonymous, authenticated through
one of

1. a **session cookie** (the web UI; password + optional TOTP code, or OIDC),
2. a **bearer token** from `/auth/token` (what `docker login` / `crane` / `podman` do in
   `mode = "token"`; tokens are scoped to the repositories the client asked for),
3. **HTTP Basic** with a password or a **personal access token** (`kontainer_...`),
4. nothing (anonymous).

Accounts with two-factor authentication cannot use their password outside the browser; they
create an access token in *Settings* instead, as on Docker Hub. Robot accounts are named
`owner+name`, have no password, and can only hold roles their owner holds.

A **role** is a list of rules plus global permissions. A rule grants actions on repositories
matching glob patterns (`*` within a path segment, `**` across segments).

| Repository action   | Allows                                                        |
|---------------------|---------------------------------------------------------------|
| `pull`              | GET/HEAD manifests and blobs, tags, referrers, scan reports   |
| `push`              | blob uploads, blob mounts, manifest PUT, moving tags          |
| `delete`            | DELETE manifests, tags, blobs                                 |
| `delete_repository` | remove a whole repository                                     |
| `scan`              | trigger scans                                                 |
| `logs`              | read the repository's activity log                            |
| `metadata`          | edit the description, README and topics                       |
| `visibility`        | make the repository public or private                         |
| `permissions`       | see and change who has access (the *Permissions* tab)         |
| `state`             | make the repository read-only or a mirror target              |
| `builds`            | create, edit and delete build triggers (running one needs `push`) |
| `mirror`            | set up mirrors into the repository                            |
| `admin`             | every repository action, including ones added later           |

The UI shows only the controls for actions you hold, and `docker login` tokens carry exactly
the `pull`, `push` and `delete` rights the same rules grant.

| Global permission | Allows                                                     |
|-------------------|------------------------------------------------------------|
| `users:read`      | list users, robots and roles                               |
| `users:write`     | create/edit/delete users, reset passwords and MFA          |
| `roles:write`     | create/edit/delete roles                                   |
| `gc`              | run garbage collection                                     |
| `logs:all`        | read every repository's activity log                          |
| `catalog`         | list every repository regardless of pull access            |
| `system`          | superuser                                                  |

Nobody can create a role or robot, or assign a role, that grants more than they hold
themselves. Roles and users from the config file are synced into the database on start and
are read-only in the UI; everything else is managed in the UI (`/admin`), the API or the
CLI (`kontainer user ...`, `kontainer roles`).

Unauthenticated callers get `anonymous_roles` plus `pull` on `public_repositories`. With
`mode = "none"` and no anonymous roles configured, everything is allowed, so `none` is refused
unless `server.bind` is a loopback address or `auth.allow_insecure_none = true` is set. The
default mode is `token`.

### Organizations, teams and repository permissions

An organization owns the `org/` namespace. Organization and user names share one namespace,
so `acme/api` is unambiguous. Access works as follows:

- **Repository permissions.** Every repository has a list of people, robots and teams, each
  with **Read** (pull), **Write** (also push, delete tags, scan), **Admin** (everything), or a
  **Custom** set of the actions above, such as `pull` + `metadata` for someone who maintains
  the README. Anyone with `permissions` on the repository manages the list on its
  *Permissions* tab, or with `PUT /api/v1/repository-permissions/{name}` and a `level` of
  `"read"`, `"write"`, `"admin"` or an array of actions.
- **Teams** have a role. *Member* teams get access through grants only. *Creator* teams can
  also push new repositories into the org, and become admin of what they create. *Admin*
  teams have full access and manage the org. A team can also have a **base permission**
  (Read/Write/Admin) on every repository in the org.
- **Robot accounts** (`org+ci`, `user+ci`) have no access until they are granted it on
  repositories in their own namespace, or added to a team.
- Everyone owns their personal namespace (`<username>/`). Global roles (above) still apply
  for instance-wide access.

Creating an organization needs the `orgs:create` permission; the creator lands in an `owners`
admin team. Namespaces can be renamed from the org's settings or your profile. This moves
every repository, robot, permission and star; image references using the old name stop
working.

### Storage, quotas, retention, upstreams and health

How the pieces fit together, what state lives where, and how to size them:
[docs/architecture.md](docs/architecture.md). Running several nodes:
[docs/high-availability.md](docs/high-availability.md).

See [docs/operations.md](docs/operations.md) for:

- the storage report (deduplication, reclaimable space, shared layers);
- namespace quotas;
- tag retention policies;
- the Prometheus metrics at `/metrics` (requires `metrics.token`);
- upstream registries, pull-through caches and mirrors;
- importing and exporting images;
- health endpoints (`/livez`, `/readyz`, `/api/v1/health`);
- tag history, the Time Machine, tag expiration and repository states;
- exporting the activity log;
- geo-replication.

Backups are covered in [docs/backup-restore.md](docs/backup-restore.md).

### LDAP, organization SSO and keyless robots

See [docs/authentication.md](docs/authentication.md).

### Builds

See [docs/builds.md](docs/builds.md).

### Single sign-on

Any OpenID Connect provider works (authorization code flow with PKCE). Users signing in for
the first time get an account named after `username_claim` (falling back to the email) with
`default_roles`; if `groups_claim` is set, provider groups are mapped to roles on every login
so revocations propagate. Set `auto_create_users = false` to allow only pre-created accounts.

### Scanning

The scanner CLI pulls the image back from the registry by digest (`registry_host` defaults to
`127.0.0.1:<port>`), so give it credentials if auth is enabled. Trivy and Grype are both
supported; results are normalised to:

```json
{ "status": "done", "scanner": "trivy", "total": 3,
  "summary": { "high": 1, "medium": 2 },
  "vulnerabilities": [{ "id": "CVE-...", "severity": "high", "package": "openssl",
                         "installed_version": "3.0.1", "fixed_version": "3.0.2",
                         "url": "...", "layer": "sha256:..." }] }
```

Index (multi-arch) manifests fan out to a scan per child image.

## CLI

```
kontainer serve                          run the server (default)
kontainer gc [--dry-run] [--delete-untagged] [--grace 1h]
kontainer hash-password                  Argon2id hash for the config (prompts)
kontainer check-config                   print the effective configuration
kontainer user create <name> [--system] [--role r]...   # also: list, delete, passwd,
                                                           #   set-roles, reset-mfa, disable
kontainer roles                          list roles and their grants
kontainer backup <dir> [--storage]       consistent database snapshot (+ all storage objects)
kontainer replicate                      queue copies of every blob a storage location is missing
kontainer migrate-metadata               import a pre-PostgreSQL repositories/ layout into the database
kontainer encryption-status | rotate-encryption-key   secrets at rest: which key each stored secret needs / re-encrypt under the current key
kontainer runner --server <url>          run builds for a registry (token in KONTAINER_RUNNER_TOKEN; docs/builds.md)
```

## HTTP API

Everything under `/v2/` is the distribution spec, including its error body
(`{"errors": [{"code", "message", "detail"}]}`). The UI uses `/api/v1`, whose errors are

```json
{ "code": "CONFLICT", "message": "team already exists", "details": {} }
```

with `code` one of `BAD_REQUEST`, `UNAUTHORIZED`, `DENIED`, `NOT_FOUND`, `CONFLICT`,
`UNSUPPORTED`, `TOOMANYREQUESTS`, `UNKNOWN` or a registry code such as `MANIFEST_UNKNOWN`.
Endpoints:

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/me` | caller identity, roles, enabled features |
| GET | `/api/v1/repositories` | repositories visible to the caller, with tag counts and allowed actions |
| POST | `/api/v1/repositories` | create an empty repository: `{name, description?, visibility?, topics?}`; 201 with the `repository-meta` view, 409 if it exists; allowed to whoever may push it into existence |
| GET | `/api/v1/repositories/{name}` | one repository's listing entry (`tags: 0` when created empty) |
| GET | `/api/v1/repositories/{name}/tags` | tags with digest, media type and scan summary |
| GET | `/api/v1/repositories/{name}/manifests/{ref}` | resolved manifest: layers joined to history, parsed config, index children, referrers, scan |
| GET | `/api/v1/repositories/{name}/manifests/{ref}/layers/{digest}/files?limit=` | files inside a layer |
| GET/POST | `/api/v1/repositories/{name}/manifests/{ref}/scan` | fetch / trigger a scan |
| GET | `/api/v1/repositories/{name}/delete-preview`, `.../tags/{tag}/delete-preview` | what a delete would remove: tags sharing the digest, index parents, referrers, sizes |
| POST | `/api/v1/repositories/{name}/delete-plan`, `/api/v1/delete-plans/{id}/execute` | delete a repository or up to 100 tags: a plan valid for five minutes, executed once with the repository name typed back |
| GET | `/api/v1/logs?repository=&limit=` | activity log, newest first |
| POST | `/api/v1/gc?dry_run=&delete_untagged=&grace_seconds=` | garbage collection (`gc`) |
| GET/POST | `/auth/token` | Docker token endpoint (`service`, `scope=repository:name:pull,push`) |
| POST | `/api/v1/auth/login`, `/logout`, `/password` | session login (JSON: `username`, `password`, `otp` or `recovery_code`) |
| POST | `/api/v1/auth/mfa/setup`, `/enable`, `/disable`, `/recovery-codes` | two-factor authentication |
| GET/POST/DELETE | `/api/v1/auth/tokens[/{id}]` | personal access tokens |
| GET/POST/DELETE | `/api/v1/auth/robots[/{id}]`, `POST .../rotate` | robot accounts |
| GET/DELETE | `/api/v1/auth/sessions[/{id}]` | browser sessions |
| GET | `/auth/oidc/login`, `/auth/oidc/callback` | single sign-on |
| GET/POST/PUT/DELETE | `/api/v1/roles[/{name}]`, `GET /api/v1/permissions` | role management |
| GET/POST/PATCH/DELETE | `/api/v1/users[/{id}]`, `POST .../password`, `DELETE .../mfa`, `DELETE .../sessions` | user management |
| GET/POST/PATCH/DELETE | `/api/v1/orgs[/{org}]` | organizations |
| POST/PUT/DELETE | `/api/v1/orgs/{org}/teams[/{team}]`, `.../members[/{user}]` | teams and memberships |
| POST/DELETE | `/api/v1/orgs/{org}/robots[/{id}]`, `POST .../rotate` | organization robots |
| GET/PATCH | `/api/v1/repository-meta/{name}` | description, README, visibility, topics |
| GET | `/api/v1/explore?q=&topic=` | public repositories |
| GET/POST/PUT/DELETE | `/api/v1/registries[/{id}]`, `POST .../test` | upstream registries |
| GET/POST/DELETE | `/api/v1/proxy-caches[/{namespace}]` | pull-through caches |
| GET/POST/PUT/DELETE | `/api/v1/mirrors[/{id}]`, `POST .../sync` | mirrors |
| POST | `/api/v1/import`, `/api/v1/import/archive/{name}?tag=` | import from a registry (job) or an OCI layout tar |
| GET | `/api/v1/repositories/{name}/manifests/{ref}/export` | OCI layout tar of a tag |
| GET | `/api/v1/jobs` | background imports and syncs, from every instance |
| POST | `/api/v1/jobs/{id}/cancel` | stop one; `204` when this instance runs it, `202` when another will |
| GET | `/api/v1/repositories/{name}/history?tag=` | tag history, with what the Time Machine can restore |
| POST | `/api/v1/repositories/{name}/tags/{tag}/restore` | point a tag back at an earlier digest |
| PUT | `/api/v1/repositories/{name}/tags/{tag}/expiration` | set or clear a tag's expiry |
| GET/PUT | `/api/v1/repositories/{name}/state` | `normal`, `read_only` or `mirror` |
| GET | `/api/v1/logs/export?format=csv\|json&since=&until=` | activity log download |
| GET/PUT | `/api/v1/robots/{id}/federation` | trusted OIDC issuers for a robot |
| GET/POST | `/api/v1/auth/federation/token` | exchange a CI OIDC token for a robot token |
| GET/PUT/DELETE | `/api/v1/orgs/{org}/sso` | an organization's OIDC provider |
| GET | `/auth/oidc/orgs/{org}/login`, `.../callback` | organization single sign-on |
| PUT/DELETE | `/api/v1/orgs/{org}/teams/{team}/sync` | sync a team from an LDAP or OIDC group |
| GET/POST/PUT/DELETE | `/api/v1/build-triggers[/{id}]`, `POST .../run`, `.../secret`, `.../webhook` | build triggers |
| GET | `/api/v1/builds?repository=`, `/api/v1/builds/{id}`, `POST .../cancel` | builds and their logs |
| GET | `/api/v1/builds/{id}/log/stream` | follow a build's log live (server-sent events, resumes with `Last-Event-ID`) |
| GET/POST/PUT/DELETE | `/api/v1/runners[/{id}]`, `POST .../token`, `GET /api/v1/namespaces/{ns}/runners` | build runners |
| GET | `/api/v1/admin/storage`, `POST .../sync` | storage locations and replication (`gc`) |
| GET | `/livez`, `/readyz`, `/api/v1/health` | probes and the detailed health report |

## Development

```sh
# The tests need a PostgreSQL they can create databases in (KONTAINER_TEST_DATABASE_URL,
# default postgres://kontainer:kontainer@127.0.0.1:55432/kontainer). Each test gets its own.
docker run -d --name kontainer-pg --shm-size=1g --tmpfs /var/lib/postgresql/data:size=8g -p 127.0.0.1:55432:5432 \
  -e POSTGRES_USER=kontainer -e POSTGRES_PASSWORD=kontainer -e POSTGRES_DB=kontainer \
  postgres:17-alpine -c max_connections=500
cargo test                                   # unit + end-to-end tests on the in-memory blob store
cargo clippy --all-targets
scripts/conformance.sh                       # OCI distribution-spec conformance suite against a local build (needs Go)
npm --prefix web run dev                      # Vite dev server proxying /api and /v2 to :5000
```

`web/dist` is embedded into the binary at compile time (`crates/kontainer-server/build.rs` writes a placeholder page if
the UI has not been built).

## Notes and limitations

- Several instances can run against one PostgreSQL and one object store: uploads, queues,
  sessions and periodic jobs are shared through the database. The `filesystem` storage driver
  needs a volume every instance can see.
- GC never touches blobs or links modified within the grace window (default:
  `storage.upload_ttl`), which protects in-flight pushes. `--delete-untagged` has no such
  protection; run it while the registry is quiet.
- Pull-through caches and mirrors pull from upstream. Push replication to other registries is
  not implemented.
- Geo-replication is eventually consistent for blob bytes only: a pull right after a push in
  another region is streamed from that region's bucket until the local copy lands.

## License

[GNU Affero General Public License v3.0](./LICENSE) (`AGPL-3.0-only`).

You can use, modify and self-host Kontainer freely. If you run a modified version as a network
service, you must offer its users the corresponding source code (section 13).
