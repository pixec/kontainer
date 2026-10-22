# Operating Kontainer

## Storage analytics

**Admin → Storage** shows where the bytes go, using `GET /api/v1/storage`. The figures:

- **Physical** is the total size of every blob actually stored.
- **Logical** is the sum of every repository's size. Layers are stored once but count towards
  every repository that uses them, so logical is usually larger than physical.
- **Deduplication savings** is logical minus what the referenced blobs physically take.
- **Reclaimable now** is blobs no manifest references. The next garbage collection frees them.
- **Untagged** is space held only by manifests no tag points at. It is freed by
  `kontainer gc --delete-untagged`.
- **Per repository:**
  - **Size** is what a full pull downloads.
  - **Unique** is what deleting only that repository (and then running GC) would free.
- **Shared layers** are the largest blobs used by more than one repository.

The report is a full scan of storage, so it is cached for `retention.report_ttl` (default
10 minutes). Add `?refresh=1` to recompute it. Namespace members see their own namespace in
**Settings → Storage** (`GET /api/v1/namespaces/<ns>/storage`).

## Quotas

Instance administrators (the `users:write` permission) can cap a namespace:

```sh
curl -X PUT -H 'content-type: application/json' -d '{"max_bytes": 50000000000}' \
  https://registry.example.com/api/v1/namespaces/acme/quota
```

A quota counts the distinct blobs that the namespace's repositories reference. Shared layers
count once per namespace. It is checked when a manifest is pushed. A push is refused with
`DENIED: storage quota exceeded for acme: ...` if it would add bytes beyond the quota. Pushing
content the namespace already holds (re-tagging, or pushing the same image again) always
succeeds.

Defaults cover every namespace without a quota of its own, new ones included:

```toml
[policy]
default_user_quota = "10g"
default_org_quota = "100g"
```

`{"max_bytes": null}` removes a namespace's own quota, so the default applies again.
`{"max_bytes": 0}` means no limit for that namespace, even when there is a default. In the UI,
the same choices are under a namespace's **Settings → Storage → Change quota**.

Checking a quota scans the namespace's manifests, so very large namespaces pay a small cost
on every push.

## Creating a repository

A push creates a repository with its first manifest. To set one up first (a build trigger,
permissions, a README), create it empty: **New repository** on the repositories page or an
organization's, or `POST /api/v1/repositories` with `{"name": "acme/app"}` and optionally
`description`, `visibility` (`private` by default) and `topics`. Whoever may push a repository
into existence may create it (their own namespace, a Creator team in the organization, org
admins and superusers), and a Creator team member becomes its admin, as after a first push.
It answers `201` with the `repository-meta` view, `409` if the repository already has a
catalogue entry or manifests, and is audited as `repository_created`. An empty repository is
listed (with no tags) on the repositories page, `/v2/_catalog`, Explore and search, and is
taken: other Creator team members can no longer push it into existence. Its OCI tag list
(`/v2/<name>/tags/list`) stays `NAME_UNKNOWN` until something is pushed or built. Delete it
like any other repository.

## Deleting images

Deleting is guarded. The UI shows what a delete would take with it before asking for the
repository name to be typed back:

- a tag's **delete preview** (`GET /api/v1/repositories/{name}/tags/{tag}/delete-preview`)
  lists every other tag pointing at the same manifest, the indexes it is part of and its
  referrers, since deleting one tag removes the manifest for all of them;
- a repository's preview (`.../delete-preview`) gives tag and manifest counts, bytes, immutable
  tags, and the replication rules and mirrors that reference it.

A repository, or more than one tag at a time, is deleted through a **plan**:
`POST /api/v1/repositories/{name}/delete-plan` with `{"repository": true}` or
`{"tags": [...]}` (up to 100) returns a plan id and the preview; `POST
/api/v1/delete-plans/{id}/execute` with `{"confirm": "<repository name>"}` runs it. A plan is
valid for five minutes, usable once, only by the user who made it, and permissions and
immutable tags are checked again when it runs. Both steps are audited. Single-tag deletes
through the OCI API (`DELETE /v2/<name>/manifests/<tag>`) are unchanged.

## Retention policies

Namespace admins (org admins, or the user for a personal namespace) define tag retention
under **Settings → Retention**, or `/api/v1/namespaces/<ns>/retention`. A policy has:

- **`repositories`:** a pattern relative to the namespace. `**` matches every repository,
  `api/*` matches one level under `api/`.
- **`keep_last`:** keep the N most recently pushed tags of each repository.
- **`max_age_days`:** delete tags pushed more than N days ago. With both rules set, a tag is
  deleted only if it is outside the newest N **and** older than the age limit, so a quiet
  repository is never emptied.
- **`protect`:** tag patterns that are never deleted, such as `latest`, `v*` or `release-*`.
  Protected tags don't count towards `keep_last`.

Immutable tags (`policy.immutable_tags`) are never deleted. A cosign signature, attestation
or SBOM tag (`sha256-<hex>.sig`, `.att`, `.sbom`) is deleted together with the image it
belongs to, once nothing tagged points at that image any more.

**Preview** shows what a policy would delete without changing anything. Enabled policies run
every `retention.interval` (default hourly). Deleting a tag only unlinks it; the space comes
back when garbage collection runs. Every deletion is recorded in the activity log as
`retention_delete_tag`.

```toml
[retention]
interval = "1h"      # how often enabled policies run
report_ttl = "10m"   # how long a storage report is reused
```

## Tag history and the Time Machine

Every change to a tag is recorded with who made it and when: pushes, moves, deletes,
restores, expiry, retention, mirror syncs, imports, cache refreshes and builds. The
repository's **History** tab lists them, and a tag page shows the history of that one tag.

The **Time Machine** keeps the images behind deleted or moved tags for a while. Within that
window, **Restore** points a tag back at the image it had, and garbage collection leaves those
images alone.

- The default window is `policy.time_machine` (7 days). `"0s"` turns it off.
- Organization admins can set their own window under **Settings → Time Machine** (off, 1–90
  days), or go back to the instance default.
- GC keeps everything restorable within the longest window in use.
- History entries are kept for 90 days, or for the window if that is longer.

```toml
[policy]
time_machine = "7d"
```

API: `GET /api/v1/repositories/{name}/history?tag=` and
`POST /api/v1/repositories/{name}/tags/{tag}/restore` with `{"digest": "sha256:..."}`.

## Tag expiration

A tag can delete itself at a set time. Two ways to set it:

- **In the UI:** the hourglass button on a tag (1, 7, 30 or 90 days, or a chosen time), or
  `PUT /api/v1/repositories/{name}/tags/{tag}/expiration` with
  `{"expires_at": "2026-11-01T00:00:00Z"}`. `null` removes it.
- **At push time:** the image label `quay.expires-after`, as in Quay. Values are a number and
  a unit: `30m`, `12h`, `3d`, `2w`.

  ```dockerfile
  LABEL quay.expires-after=2w
  ```

A background loop deletes expired tags every minute. It skips immutable tags and read-only
repositories. An expired tag can be restored from History while it is inside the Time Machine
window.

## Repository states

A repository is in one of three states (**Settings → State**, or
`PUT /api/v1/repositories/{name}/state` with `{"state": "read_only", "reason": "..."}`):

| State | Pushes and deletes | Use |
| --- | --- | --- |
| `normal` | allowed | default |
| `read_only` | refused, with the reason | release freezes, archived projects |
| `mirror` | only its mirror sync writes | set automatically when a mirror targets the repository |

Refused writes return `405 DENIED` with the reason, so `docker push` shows it. A banner on the
repository page shows the state, who set it and when.

## Pull policies

Each namespace (user or organization) can refuse to serve images, under **Settings → Pull
policy**. Only its admins can change this. It applies to every pull, `docker pull` or a
Kubernetes node alike, and the refusal names the reason (`DENIED: image blocked by the security
policy of acme: High vulnerabilities (CVE-2024-1234, ...)`).

| Setting | Effect |
| --- | --- |
| **Block vulnerabilities** | Refuse images whose latest scan has a finding at or above a severity. *Registry default* follows `scanner.block_pull_at`; *Off* turns it off for this namespace. |
| **Block unscanned images** | Refuse images without a finished scan (not scanned yet, still scanning, or failed). |
| **Require a cosign signature** | Refuse images pulled by tag that have no cosign signature, or none from the trusted public keys if any are given. The images inside a signed multi-platform index count as signed, so pulling a signed index works. |

**CVE allowlists** list vulnerabilities that don't count towards blocking: per namespace, next to
the policy, and registry-wide under **Admin → Maintenance** (`users:write`). Each entry has a
reason and an optional expiry, after which it stops applying. Scan reports mark allowlisted
findings.

The scanner is never blocked (its per-scan pull token, or the `scanner.username` account),
otherwise images could never be scanned or rescanned.

API: `GET/PUT /api/v1/namespaces/{ns}/security`,
`GET/POST /api/v1/namespaces/{ns}/cve-allowlist`, `DELETE .../cve-allowlist/{id}`, and the same
under `/api/v1/cve-allowlist` for the registry-wide list.

## Maintenance schedules

Garbage collection and vulnerability rescans can run on their own:

```toml
[gc]
interval = "24h"            # unset: only by hand (UI, API or `kontainer gc`)
delete_untagged = false

[scanner]
rescan_interval = "7d"      # rescan tagged images whose report is older than this
```

New vulnerabilities are published every day, so a report goes stale even when the image never
changes. A rescan queues every tagged image (each platform of a multi-platform image) whose
report is older than `rescan_interval`, and scans run on the normal scan queue. **Admin →
Maintenance → Scan everything** does the same by hand. **Scan unscanned only** skips images that
already have a report. The API is `POST /api/v1/scans/all[?missing_only=true]`.

Each run is recorded: the last 100 garbage collections and scans of everything, with who or
what started them and what they did. They are listed under **Admin → Maintenance**, or at
`GET /api/v1/maintenance/{gc|scan_all}/runs`. Only one run of each kind goes at a time; starting
another answers `409`. Scheduled runs count from the last scheduled run, so a restart doesn't
reset the clock. A run cut short by a restart is marked failed.

## Scanning budget

Scans are expensive, and on a busy registry scan on push and scheduled rescans can queue more
than the scanners get through. Two limits keep the queue in check:

```toml
[scanner]
max_auto_per_hour = 500   # automatic scans queued per hour, cluster-wide (0: unlimited, the default)
max_queue = 10000         # scans waiting or running beyond which new ones are skipped (0: unlimited)
```

- **Automatic** scans (scan on push, and the `rescan_interval` schedule) count against
  `max_auto_per_hour`. Once the hour's budget is spent, further ones are **skipped**: no job is
  queued and the image keeps whatever report it had. The hour starts with the first automatic
  scan after the previous hour ended.
- Scans someone **asks for** (`POST /api/v1/repositories/{name}/manifests/{ref}/scan`, the
  **Scan** button, and **Scan everything** started by an administrator) are not counted and not
  held to the budget.
- While the queue holds `max_queue` scans (waiting or running, on every instance), every new
  scan is skipped, requested ones included.
- An image already queued is not queued twice and costs no budget.

The budget is one row in PostgreSQL, updated with a single statement per scan, so it holds
for the whole cluster however many instances take pushes. Skipped scans are counted in
`kontainer_scans_skipped_total{reason="budget"|"queue_full"}` (per instance) and in the
budget row (cluster-wide, for the current hour).

**Admin → Maintenance** shows the budget next to **Scan everything**. The API:

```sh
curl -u admin https://registry.example.com/api/v1/admin/scanning
```

```json
{ "enabled": true, "limit": 500, "used": 500, "window_resets_at": "2026-10-22T14:03:11Z",
  "skipped_in_window": 37, "skipped_since_start": { "budget": 12 },
  "queue_depth": 812, "max_queue": 10000, "override_until": null, "override_by": null }
```

To let everything through for a while, for example after a scanner database update, lift the
budget (`max_queue` still applies). `{"hours": 0}` ends an override early. Overrides are
recorded in the audit log as `scan_budget_override`:

```sh
curl -u admin -X POST -H 'content-type: application/json' -d '{"hours": 6}' \
  https://registry.example.com/api/v1/admin/scanning/override
```

Both endpoints need the `gc` permission, like **Scan everything**.

## Metrics

`GET /metrics` serves Prometheus text format. It needs a token, because the output names every
namespace with its usage and quota, and the version. Until `metrics.token` (or
`KONTAINER_METRICS_TOKEN`) is set, it answers `403`. Configure your scraper to send
`Authorization: Bearer <token>`:

```toml
[metrics]
enabled = true
token = "a-long-random-string"
```

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kontainer_http_requests_total` | counter | `method`, `route`, `status` | Requests by route class (`manifest`, `blob`, `blob_upload`, `tags`, `catalog`, `referrers`, `api`, `auth`, `ui`) and status class |
| `kontainer_http_request_duration_seconds` | histogram | `method`, `route` | Request latency |
| `kontainer_pushes_total`, `kontainer_pulls_total` | counter | | Manifests pushed and pulled |
| `kontainer_blob_bytes_received_total`, `kontainer_blob_bytes_served_total` | counter | | Blob traffic |
| `kontainer_storage_physical_bytes`, `kontainer_storage_logical_bytes`, `kontainer_storage_reclaimable_bytes`, `kontainer_storage_blobs`, `kontainer_repositories` | gauge | | From the storage report, which is shared: every instance exports the same cluster-wide figures, so aggregate with `max()`, not `sum()` |
| `kontainer_namespace_bytes`, `kontainer_namespace_quota_bytes` | gauge | `namespace` | Usage and quota per namespace |
| `kontainer_storage_report_age_seconds` | gauge | | How old the storage figures are |
| `kontainer_search_documents` | gauge | | Repositories in the search index |
| `kontainer_scans_skipped_total` | counter | `reason` | Scans this instance did not queue: `budget` (`scanner.max_auto_per_hour` spent) or `queue_full` (`scanner.max_queue` reached). Only with a scanner configured |
| `kontainer_build_info`, `kontainer_uptime_seconds` | gauge | `version` | |

Route classes are used instead of paths so the number of label values stays bounded. Storage
gauges appear after the first report has been computed; scraping `/metrics` triggers one in
the background when the cached report is stale.

Example alerts:

```yaml
- alert: RegistryQuotaNearlyFull
  expr: kontainer_namespace_bytes / kontainer_namespace_quota_bytes > 0.9
- alert: RegistryErrors
  expr: sum(rate(kontainer_http_requests_total{status="5xx"}[5m])) > 0
```

## Upstream registries

Caches, mirrors and imports read from **registries** you register under
**Administration → Registries** (or `POST /api/v1/registries`). Each entry has a name, a URL
and optional credentials. Docker Hub can be given as `docker.io`. The token handshake is the
same one `docker` uses, so Docker Hub, GHCR, ECR (with a token as the password), other
Kontainer instances and any registry that speaks the OCI distribution API all work. Passwords are stored in the database and never returned by
the API. **Test** checks that the registry answers on `/v2/`.

## Pull-through caches

A pull-through cache binds a namespace to an upstream registry:

```sh
# Administration → Registries → New cache: namespace "hub", upstream docker.io
docker pull registry.example.com/hub/library/alpine:3.20
docker pull registry.example.com/hub/alpine          # Docker Hub's library/ is implied
```

- The first pull of a tag fetches the manifest and its layers from upstream and stores them.
  Later pulls are served locally.
- Tags are re-checked with a `HEAD` request once the **recheck** interval has passed. Pulls by
  digest are never re-checked.
- If the upstream is unreachable or rate-limited, the cached copy is served.
- Nobody can push to a cache namespace. Pulls need a signed-in user unless the cache allows
  anonymous pulls.
- Cached images are ordinary repositories. They count toward the namespace's storage, and
  retention policies and GC apply to them. Removing a cache stops proxying and keeps what was
  already cached.

### containerd mirrors

containerd can use a cache as a mirror for its upstream, so `ctr`, `nerdctl` and Kubernetes
nodes pull `docker.io/library/alpine` without image names changing. containerd sends each
request with the upstream's host in `?ns=`, as in
`GET /v2/library/alpine/manifests/latest?ns=docker.io`. Kontainer serves that request from the
cache whose upstream is that host, as `hub/library/alpine`:

```toml
# /etc/containerd/certs.d/docker.io/hosts.toml
server = "https://registry-1.docker.io"

[host."https://registry.example.com"]
  capabilities = ["pull", "resolve"]
```

The rules:

- Only pulls (`GET` and `HEAD` of manifests, blobs, tag lists and referrers). Pushes and uploads
  are never redirected.
- A repository that exists here under the requested name is always served as is. Only names
  that are not repositories here go to the cache.
- `ns` is matched against the host (and port, if not the default one) of each cache's upstream
  URL, ignoring case. `docker.io`, `index.docker.io` and `registry-1.docker.io` all mean Docker
  Hub. If no cache matches, the request is served as if `ns` were absent. With several caches
  for one upstream, the first by namespace name is used.
- Permissions are those of the cache namespace (`hub/...`). A cache that allows anonymous
  pulls works for nodes without credentials. Otherwise, give containerd credentials for
  the registry host.

Set `features.containerd_ns = false` to ignore `ns`.

## Mirrors

A mirror copies tags from `registry/source` into a local repository on a schedule
(**Administration → Mirrors**).

- Leave the tag list empty to mirror every tag. Otherwise list tags or globs (`latest`, `3.*`).
- At most the 200 newest matching tags are copied.
- Each sync compares digests and copies only the tags that changed.
- Multi-platform indexes are copied whole. Foreign (non-distributable) layers are skipped.
- A background loop checks every minute for mirrors that are due. **Sync** runs one now.
- The last result is shown on the mirror and on the health page.

Who can manage a mirror:

- instance administrators (`users:write`);
- anyone with the Admin permission on the target repository.

## Push replication

Replication copies repositories from this registry to another one: a disaster-recovery copy, an
edge site, a cloud registry. Mirrors do the opposite and pull from elsewhere. Add the target under
**Admin → Registries** (its stored credentials need push access), then a rule under **Admin →
Replication**:

| Field | Meaning |
| --- | --- |
| Repositories | Local repositories, as globs (`acme/**`, `web/*`) |
| Tags | Tag globs (`v*`, `latest`); empty means every tag |
| Destination prefix | Prepended on the target: `acme/api` goes to `dr/acme/api` with `dr` |
| When | **On every push** (just what changed, within seconds), **on a schedule** (everything that matches, from every 15 minutes to daily), or **only by hand** |
| Delete | Also delete tags on the target when they are deleted here (pushes, retention, expiry) |

Every tag change counts as a push, including builds, imports, mirror syncs and Time Machine
restores. Each image is pushed with all its platforms, and only blobs the target lacks are
uploaded. A cosign signature, attestation or SBOM (`sha256-<digest>.sig`, `.att`, `.sbom`) goes
along with its image. A full run skips tags that are already current on the target.

Each run is recorded (**Run** history per rule, last 50) and fires the `replication` webhook
event. The API is under `/api/v1/replication-rules` (`users:write`): list, create, `PUT`, `DELETE`,
`POST .../run` and `GET .../runs`.

Some registries can't delete by tag. Deletion then fails, and the failure shows in the rule's
history.

## Import and export

From a repository list, **Import** copies an image into the current namespace without
`docker push`. It needs Push on the target repository. There are two ways to import:

- **From a registry:** any registered upstream, by tag or `@digest`. This runs as a background
  job (`POST /api/v1/import`). Its progress is under Recent jobs on the Mirrors page and at
  `GET /api/v1/jobs`.
- **Upload archive:** an OCI image layout tarball, gzipped or plain. Every blob is checked
  against its digest before it is stored.

  ```sh
  docker save alpine:3.20 -o alpine.tar   # Docker 25+ writes an OCI layout
  skopeo copy docker://alpine:3.20 oci-archive:alpine.tar
  curl -u admin --data-binary @alpine.tar -H 'content-type: application/x-tar' \
    'https://registry.example.com/api/v1/import/archive/team/alpine?tag=3.20'
  ```

**Export .tar** on a tag page (or `GET /api/v1/repositories/{name}/manifests/{ref}/export`)
downloads the reverse: an OCI image layout with the tag and everything it references. For a
single-platform image it also includes a Docker `manifest.json`, so all of these load it:

- `docker load` (both older and newer versions);
- `skopeo copy oci-archive:...`;
- `crane` and `oras`.

Exports are audited.

## Activity export

**Activity → Export** downloads the log as CSV or JSON Lines, for a chosen range (7, 30 or 90
days, or everything). It contains only entries the caller may see, and the export itself is
logged.

```sh
curl -u admin:$TOKEN -o activity.csv \
  'https://registry.example.com/api/v1/logs/export?namespace=acme&since=2026-09-01T00:00:00Z&format=csv'
```

Parameters: `namespace`, `repository`, `q` (repository substring), `since` and `until`
(RFC 3339), `limit` (at most 100,000) and `format` (`csv` or `json`).

## Geo-replication

Across regions, Kontainer is one PostgreSQL database shared by every region, one object storage **location** per region, and registry instances in each region that
write to their own location. Manifests, tags and links are rows in the database, so a push in
one region is visible in every region at once. Blob bytes are copied to the other locations by
a background queue and pulled from the nearest location that already has them.

```toml
[storage]
location = "eu"                           # this instance's own location (KONTAINER_STORAGE_LOCATION)
redirect_ttl = "15m"
region_header = "CloudFront-Viewer-Country"
replication_concurrency = 8               # copy workers per instance

[[storage.locations]]
name = "eu"
driver = "s3"
regions = ["DE", "FR", "NL", "GB", "eu-*"]   # clients the header puts here
redirect = true
[storage.locations.s3]
bucket = "registry-eu"
region = "eu-central-1"

[[storage.locations]]
name = "us"
driver = "s3"
regions = ["US", "CA", "us-*"]
redirect = true
[storage.locations.s3]
bucket = "registry-us"
region = "us-east-1"

[[storage.locations]]
name = "dr"                               # standby copy: no regions, never redirected to
driver = "filesystem"
[storage.locations.filesystem]
root = "/mnt/backup/registry"
```

Run the same configuration in every region and set only `KONTAINER_STORAGE_LOCATION` per
region. The single-location form (`storage.driver` with `[storage.s3]`) is the same thing with
one location, and the older `[[storage.replicas]]` form still loads as locations.

**How blobs move**

- A pushed blob is written to the instance's own location and recorded in the `blob_placements`
  table. A copy job is queued for every other location. Workers on every instance take jobs
  with `FOR UPDATE SKIP LOCKED`, copy from a location that has the blob, verify the size and
  record the new placement. A failed copy is retried with backoff; after the last attempt the
  job is kept with its error and shown under **Administration → Storage → Locations**.
- Scan reports and activity logs are copied the same way.
- A pull from a region whose location does not have the blob yet is served from a location
  that does, streamed through the registry, so nothing is ever unavailable while a copy is
  in flight.
- Garbage collection deletes a blob from every location that holds it.
- **Sync now** on a location (or `kontainer replicate`) queues copy jobs for every blob it is
  missing. Use it to seed a location added later. A location removed from the configuration
  keeps its placement rows until `kontainer storage forget-location <name>`.

**Routing pulls to a region**

1. The CDN or load balancer in front of Kontainer sets a header naming the client's region:
   `CloudFront-Viewer-Country`, Cloudflare's `CF-IPCountry`, or your own.
2. `storage.region_header` names that header. Only use a header your proxy always overwrites;
   otherwise clients can pick their location.
3. A blob `GET` is served from the first location whose `regions` match the header value and
   that has the blob (matching ignores case, `*` is a wildcard), else from the instance's own
   location, else from any location that has it. If that location has `redirect = true` and
   can presign (S3, GCS or Azure), the client gets a `307` to a presigned URL valid for
   `redirect_ttl`; otherwise the bytes are streamed, and a stream that fails mid-way falls
   over to the next location.

Authorization is checked before any redirect, and a presigned URL grants only that one blob for
a short time. The bucket's CORS and network rules must allow clients to reach it directly.
Docker, containerd, podman and crane all follow these redirects.

**Monitoring**

- **Administration → Storage → Locations** shows, per location, blobs and bytes placed, copy
  jobs pending and failed, and the last error. **Administration → Health** probes the
  instance's own location (write, read, delete).
- Metrics:
  - `kontainer_replication_pending_blobs{location}` and
    `kontainer_replication_failed_blobs{location}`;
  - `kontainer_replication_copied_total{location}` and
    `kontainer_replication_copied_bytes_total{location}`;
  - `kontainer_replication_failures_total{location}`;
  - `kontainer_blob_redirects_total{location}`.

```yaml
- alert: RegistryLocationBehind
  expr: kontainer_replication_pending_blobs > 1000
  for: 30m
```

## Secrets at rest

Credentials the registry keeps in PostgreSQL are encrypted with AES-256-GCM before they are
written, and decrypted when read:

| Table | Columns |
| --- | --- |
| `registries` | `password` (upstream registries) |
| `webhooks` | `secret` (HMAC key), `auth_header` |
| `build_triggers` | `git_token`, `secret` (webhook secret) |
| `org_sso` | `client_secret` |
| `meta` | `jwt_secret` (the token-signing secret, when `auth.secret` is not set) |

Password hashes, access-token hashes, runner-token hashes and recovery-code hashes are hashes
already and stay as they are. TOTP secrets (`users.mfa_secret`, `mfa_setups.secret`) are not
encrypted yet. Secrets set in the configuration file never reach the database.

A stored value reads `enc:v1:<key id>:<base64(nonce, ciphertext)>`, where the key id is the
first 8 hex characters of the SHA-256 of the data key. Values without the `enc:` prefix are
plaintext.

**Setting the key.** Production deployments set one of:

- `auth.encryption_key` (`KONTAINER_ENCRYPTION_KEY`): any string of 32 bytes or more, e.g.
  `openssl rand -hex 32`. The data key is derived from it with HKDF-SHA256.
- `auth.secret` (`KONTAINER_AUTH_SECRET`) alone: the data key is derived from it, with a
  different HKDF label than the token-signing key.

With neither set, secrets are stored unencrypted, and the server logs a warning at startup and
the health report shows a warning. Every instance sharing the database needs the same keys.
If the database holds secrets encrypted with a key the instance doesn't have, it refuses to
start and names the key id.

Secrets stored before a key was set stay plaintext until the next rotation: after setting the
key, run `kontainer rotate-encryption-key` once to encrypt them.

**Rotating the key.**

1. Generate a new key. Set it as `auth.encryption_key` and move the old one to
   `auth.previous_encryption_keys` (`KONTAINER_PREVIOUS_ENCRYPTION_KEYS`, comma-separated). If
   the old key was derived from `auth.secret`, keep `auth.secret` set: while
   `auth.encryption_key` is set, the key derived from `auth.secret` counts as a previous key.
2. Roll the new configuration out to every instance. New values are encrypted with the new
   key, and existing ones are still read with the old key.
3. Run `kontainer rotate-encryption-key`. It re-encrypts every stored secret that isn't under
   the current key, in batches of `--batch` rows (default 500) per transaction, and prints a
   count per column. It skips values that are already current, so it is safe to run again.
4. Run `kontainer encryption-status`. When no column has rows under previous keys, remove the
   old key from `auth.previous_encryption_keys`.

```
$ kontainer encryption-status
current key   3f9c01ab
previous keys 7d2e4410

column                       plaintext   current  previous   unknown
registries.password                  0         4         0         0
webhooks.secret                      0         2         0         0
...
no secret needs the previous keys any more: they can be removed from auth.previous_encryption_keys
```

Running `rotate-encryption-key` with no current key and the old key in
`auth.previous_encryption_keys` decrypts everything back to plaintext.

Keep the key somewhere other than the database and its backups, such as a secret manager or a
Kubernetes Secret. A database dump without the key does not reveal the secrets. Without the
key, the secrets cannot be recovered, and they have to be entered again.

## Health

| Endpoint | Auth | Answers |
| --- | --- | --- |
| `GET /livez` | none | `200 ok` while the process is up |
| `GET /readyz` | none | `200` when the database answers and this instance's storage location can be listed (every location with `server.ready_requires_all_locations`), else `503` with the reason |
| `GET /api/v1/health` | `users:read` or `gc` | JSON report: database, a storage write/read/delete probe of this instance's location, every location's replication backlog, search index, scanner, secrets at rest, each upstream registry, mirror status and recently failed jobs |

**Administration → Health** shows the same report. For Kubernetes:

```yaml
livenessProbe:  { httpGet: { path: /livez,  port: 5000 } }
readinessProbe: { httpGet: { path: /readyz, port: 5000 }, periodSeconds: 10 }
```

## Backups

See [backup-restore.md](backup-restore.md).
