# Deployment

Kontainer is a stateless process in front of a PostgreSQL database and a blob store. Accounts,
settings, the build, scan and webhook queues and upload sessions live in PostgreSQL
(`auth.database_url`, any 14+ server). Image blobs live in object storage (S3, GCS, Azure) or
on a local `filesystem` volume. Run as many instances as you like against the same database and
object store; with the `filesystem` driver, run one instance, or give them all the same shared
volume. The data directory then only holds temporary files and scanner caches
(see [backup-restore.md](backup-restore.md)).

The image (`docker build -t kontainer:0.2.0 .` from the repository root) runs as UID 1000,
keeps everything under `/var/lib/registry`, listens on port 5000 and bundles `git`,
`buildctl` and `trivy`.

## Settings from the environment

Every setting in [config.example.toml](../config.example.toml) can also be set as an
environment variable named `KONTAINER__<SECTION>__<KEY>`, which wins over the file:

| Variable | Same as |
| --- | --- |
| `KONTAINER__BUILDS__ENABLED=true` | `[builds] enabled = true` |
| `KONTAINER__STORAGE__S3__BUCKET=registry` | `[storage.s3] bucket = "registry"` |
| `KONTAINER__AUTH__PUBLIC_REPOSITORIES='["public/**"]'` | `[auth] public_repositories = ["public/**"]` |
| `KONTAINER__SCANNER__ENV__TRIVY_CACHE_DIR=/cache` | `[scanner.env] TRIVY_CACHE_DIR = "/cache"` |

Values are read as TOML (`true`, `4`, `["a", "b"]`, `{ pool = "builds" }`); a setting that is
text stays text. Keys inside maps (`scanner.env`, `node_selector`) keep their case.

Credentials have their own variables, always read as text, so they can come from secrets:

| Variable | Sets |
| --- | --- |
| `KONTAINER_DATABASE_URL` | `auth.database_url`, the PostgreSQL connection URL |
| `KONTAINER_ADMIN_USERNAME`, `KONTAINER_ADMIN_PASSWORD` | the first administrator (`auth.bootstrap_admin`), created when there are no users |
| `KONTAINER_AUTH_SECRET` | the token signing key (generated and kept in the database when unset) |
| `KONTAINER_OIDC_CLIENT_SECRET` | `auth.oidc.client_secret` |
| `KONTAINER_LDAP_BIND_PASSWORD` | `auth.ldap.bind_password` |
| `KONTAINER_SCANNER_PASSWORD` | `scanner.password` |
| `KONTAINER_METRICS_TOKEN` | `metrics.token` |
| `KONTAINER_RUNNER_TOKEN` | a shared runner named `default` that builds for everyone (`builds.runners`) |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_STORAGE_ACCOUNT_KEY`, ... | object storage credentials, read by the storage drivers |

`kontainer check-config` prints the result, with secrets redacted (passwords, keys, session
and metrics tokens, runner tokens, `scanner.env` values, webhook headers and URL paths).

Commands that take a password (`hash-password`, `user create`, `user passwd`) prompt for it
without echoing, or read it from `KONTAINER_PASSWORD` or a pipe on stdin
(`printf %s "$PW" | kontainer hash-password`). Passing it as an argument still works but warns:
arguments are visible to other users in the process list.

The image runs `kontainer` under [tini](https://github.com/krallin/tini), which forwards
`SIGTERM` and reaps the processes git, BuildKit and the scanner leave behind. Its base images
and the bundled trivy are pinned (trivy by SHA-256); for fully reproducible builds pin the base
images by digest as well.

## Docker Compose

[deploy/compose](../deploy/compose) has a base file and add-ons:

```sh
cd deploy/compose
cp .env.example .env          # set KONTAINER_ADMIN_PASSWORD (and the add-ons' settings)
docker compose up -d          # registry + trivy, images in the `data` volume
```

| File | Adds |
| --- | --- |
| `compose.yaml` | the registry, scanning with trivy, a health check |
| `compose.s3.yaml` | [RustFS](https://github.com/rustfs/rustfs) for blobs, with its bucket created on start (console on `127.0.0.1:9001`) |
| `compose.ha.yaml` | three registry replicas behind Caddy, health-checked on `/readyz`; needs `compose.s3.yaml` (see [high-availability.md](high-availability.md)) |
| `compose.builds.yaml` | builds from Git: a shared runner and a BuildKit daemon (set `KONTAINER_RUNNER_TOKEN`). **Single-tenant**: all builds share one privileged BuildKit; see [builds.md](builds.md#isolation) |
| `compose.https.yaml` | Caddy in front with a Let's Encrypt certificate for `KONTAINER_DOMAIN`; the registry is no longer published directly |

Combine them with `-f`, or once in `.env`:

```sh
COMPOSE_FILE=compose.yaml:compose.s3.yaml:compose.builds.yaml:compose.https.yaml
```

The scanner needs no account: for each scan the registry mints a short-lived token that can
only pull that one repository. `KONTAINER_SCANNER_USERNAME` / `KONTAINER_SCANNER_PASSWORD` in
`.env` override that for a scanner that reaches the registry through another host.

`docker compose up` in the repository root runs the base setup too (it reads
`deploy/compose/.env`). [`config.toml`](../deploy/compose/config.toml) holds everything else;
restart the registry after editing it.

## Kubernetes (Helm)

```sh
helm install registry deploy/helm/kontainer -n registry --create-namespace \
  --set image.repository=registry.example.com/kontainer \
  --set ingress.enabled=true --set ingress.host=registry.example.com \
  --set ingress.tls.enabled=true
```

With `replicaCount: 1` (the default) the chart runs one pod with a PersistentVolumeClaim for
the data directory, updated with `Recreate` so the old pod lets go of the volume first. With
more replicas it requires object storage, rolls pods one at a time and gives each a scratch
volume. It prints how to get the generated administrator password. The main values (all in
[values.yaml](../deploy/helm/kontainer/values.yaml)):

| Value | |
| --- | --- |
| `image.repository`, `image.tag` | where you pushed the image |
| `publicUrl` | the registry's address; defaults to the ingress host |
| `admin.*` | the first administrator; the password is generated once and kept in `<release>-admin` |
| `config` | the TOML configuration (anything the values don't cover) |
| `storage.driver` and `storage.s3/gcs/azure` | object storage, with credentials from an existing Secret or the pod's cloud identity |
| `persistence.*` | the data volume; kept on uninstall unless `persistence.keep=false` |
| `ingress.*` | host, class, TLS and annotations (lift the body size limit: layers are large) |
| `scanner.kind` | `trivy` or `grype` |
| `builds.*` | builds from Git: on or off, self-hosted runners, the per-namespace limit, the timeout |
| `runner.*` | a shared runner in the cluster, each build a Job: namespace, resources, node selector, tolerations, a NetworkPolicy |
| `metrics.serviceMonitor.enabled` | a Prometheus Operator ServiceMonitor, with the generated metrics token |
| `extraEnv` | any other setting, as `KONTAINER__SECTION__KEY` |

Builds need a runner. With `runner.enabled`, the chart runs a shared one that builds for every
user and organization, with its own service account allowed to manage Jobs in the build
namespace (the registry itself gets no Kubernetes permissions). Rootless BuildKit needs the
`privileged` Pod Security level there: set `runner.builds.createNamespace=true` to create a
labelled namespace, or label an existing one. Users and organizations can run their own with the
[kontainer-runner chart](../deploy/helm/kontainer-runner). See [builds.md](builds.md#runners).

`helm test registry -n registry` checks that the registry answers `/readyz`.

## Behind a reverse proxy

- Allow request bodies of any size and long timeouts: layer uploads can be gigabytes.
- Don't buffer requests or responses.
- Set `server.public_url` (`KONTAINER_PUBLIC_URL`) to the external address; token realms and
  upload locations are built from it.
