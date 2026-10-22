# Builds from Git

A **build trigger** turns a Git push into an image: the commit is checked out, its Dockerfile is
built in BuildKit, and the result is tagged in the repository.

The registry never builds anything itself. It keeps the queue, and **runners** do the work:
`kontainer runner` processes, anywhere that can reach the registry, that claim queued builds and
hand back the image. A user or organization gets builds (and the **Builds** tab) once a runner
serves it:

- **Self-hosted runners** belong to one user or organization. Its admins register them under
  **Settings → Runners** (organization settings for an organization) and run them on their own
  machines or clusters.
- **Shared runners** belong to the registry. Superusers register them under **Admin → Runners**
  and choose whom they build for: everyone, or a list of users and organizations. Shared runners
  can also be defined in the configuration (below), which is how the Helm chart and Compose set
  up one next to the registry.

```toml
[builds]
enabled = true                 # false: no triggers or runners at all
self_hosted_runners = true     # let users and organizations register their own
timeout = "30m"                # longer builds are cancelled
max_per_namespace = 0          # builds one namespace runs at once (0: no limit)
max_log_bytes = 8388608        # a build's log is kept up to this size (8 MiB), then head + last 64 KiB
# heartbeat_timeout = "2m"     # a build whose runner goes quiet this long is failed
# allow_file_urls = false      # file:// Git URLs, for tests only

[[builds.runners]]             # a shared runner from the configuration (read-only in the UI)
name = "default"
token = "a-long-random-secret" # what the runner starts with
namespaces = []                # whom it builds for; empty: everyone
```

`KONTAINER_RUNNER_TOKEN` on the registry adds a shared runner named `default` that builds for
everyone, with that token.

Runners never get registry credentials: just their own token (to claim builds), then each
build's spec (including the Git token) and a token that works only for that build, only while
it runs. The image comes back as an OCI archive; its blobs are checked against their digests and
stored like a push.

## Runners

Register a runner (name it; a shared one also needs whom it builds for) and copy its token: it
is shown once. Then start it:

```sh
KONTAINER_RUNNER_TOKEN=kr_... kontainer runner --server https://registry.example.com
```

(`--token` works too, but flags are visible to every user of the machine in the process list;
the runner warns when the token comes from one.)

It asks for work every few seconds, so it needs only outbound HTTPS to the registry: no inbound
ports, no VPN. Run as many as you like; each build goes to exactly one. The runner list shows
each one's state (online, offline, waiting to connect), what it runs on, its version, and how
many builds it is running. **New token** replaces the token (the old one stops working at
once), and disabling a runner stops it getting builds.

Settings come from flags, a file (`--config-file`, or `KONTAINER_RUNNER_CONFIG`) and
`KONTAINER_RUNNER__<KEY>` variables, which follow the same rules as the registry's
([deployment.md](deployment.md#settings-from-the-environment)):

```toml
server = "https://registry.example.com"   # KONTAINER_SERVER
token = "kr_..."                          # KONTAINER_RUNNER_TOKEN
# name = "build-1"                        # shown on builds; default: the host name
executor = "local"                        # local | docker | kubernetes
concurrency = 2                           # builds at once; the registry keeps the rest queued
backend = "buildctl"                      # local builds: docker | buildctl
buildkit_addr = "tcp://127.0.0.1:1234"    # BUILDKIT_HOST
# work_dir = "./kontainer-builds"
# poll = "5s"
```

The runner is the process that claims queued builds. `executor` picks where it runs each one:

| Executor | Where the build runs | Isolation | Good for |
| --- | --- | --- | --- |
| `local` (default) | On the runner's own machine: it clones into `work_dir` and calls the `backend` (Docker or `buildctl`) itself | None: builds share the runner's filesystem, daemon and resources | One person or one trusted team on one machine |
| `docker` | In two disposable containers the runner starts per build on a Docker host (a BuildKit daemon and an agent that clones and drives it), removed afterwards | Each build has its own filesystem, network and CPU/memory limits; the runner's host is never touched | A shared runner on one or a few hosts |
| `kubernetes` | As a Job per build, with its own CPU, memory, disk and NetworkPolicy | Same as `docker`, scheduled by the cluster | Clusters |

Builds started elsewhere run `kontainer runner --build-id <id>` there with that build's token;
the runner keeps them alive while they start, fails them if their container or pod dies before
reporting, and cleans up after them. A build whose runner stays quiet for `heartbeat_timeout` is
failed, so a crashed machine or a deleted pod never leaves a build stuck. **Cancel** works the
same everywhere: the runner hears it at its next check-in.

On SIGTERM or Ctrl-C the runner stops claiming builds, cancels the ones running in its own
process and reports them as failed ("The runner shut down during the build"), giving them up to
25 seconds; set the container's stop timeout to 30 seconds or more (Compose's
`stop_grace_period`; Kubernetes' default is 30). Builds it launched as containers or Jobs carry
on and report on their own; a runner that restarts removes the containers of builds it no longer
tracks once they stop (or after six hours if they never do).

### Isolation

A Dockerfile's `RUN` steps are code from whoever controls the Git repository. How far apart
builds are depends on the executor:

- **`local` with a shared `buildkitd`** (what [Compose](deployment.md#docker-compose) sets up):
  every build runs in the same daemon, sharing its cache, and a privileged daemon is root on its
  host. **Single-tenant only**: use it when everyone who can create build triggers is trusted.
  Keep the daemon's port private (Compose puts it on a network only the runner joins). To reach
  a `buildkitd` on another machine, use mTLS: start it with `--tlscacert`, `--tlscert` and
  `--tlskey`, and give `buildctl` the client side (`BUILDKIT_HOST=tcp://...` plus `--tlscacert`,
  `--tlscert`, `--tlskey`, or the `BUILDKIT_TLS_*` settings of your BuildKit version).
- **`docker` and `kubernetes`**: a fresh rootless BuildKit per build, with its own limits,
  removed afterwards. Use these for several teams or untrusted users.

Git tokens never appear in a command line or in the log: the runner hands them to `git` as an
`Authorization` header through git's environment, and build commands (and scanners) inherit
only a short list of variables (`PATH`, `HOME`, proxies, CA bundles, `DOCKER_*`,
`BUILDKIT_HOST`) from the runner, never its token. A repository can't point the Dockerfile or
the context outside the checkout with a symbolic link.

### Local builds

`local` builds need `git` and a backend on the runner's machine:

- **`buildctl` (recommended):** the build runs in a separate `buildkitd`, ideally rootless, on
  another host or in a sidecar. The runner sends it the source and receives the image as an OCI
  archive. Keep `buildkitd`'s port private: anyone who can reach it can run builds on it.
- **`docker`:** `docker build` and `docker save` through the local daemon (Docker 25 or newer,
  with the containerd image store). Simpler on a single machine, but the runner then needs the
  Docker socket, which is root on that host.

The Kontainer image includes `git` and `buildctl`. [Compose](deployment.md#docker-compose) runs
one this way next to a BuildKit daemon.

### Docker

```toml
executor = "docker"

[docker]
image = "registry.example.com/kontainer:0.2.0"  # has kontainer, git, buildctl
# host = "unix:///var/run/docker.sock"          # default: DOCKER_HOST, else the local socket
# server_url = "http://host.docker.internal:5000"  # how build containers reach the registry; default: server
# build_network = "isolated"                   # "open": Docker's defaults plus host.docker.internal
# network = "kontainer"                         # default: kontainer-builds (isolated), bridge (open)
cpus = 2.0                                      # must be more than 0
memory = "4g"                                   # 4g, 512m, 4Gi...; a value that isn't a size is refused
# buildkit_image = "moby/buildkit:v0.17.3-rootless"
# rootless = true                               # false: privileged BuildKit, where user namespaces are blocked
```

For each build the runner starts two containers through the Docker API, and removes them when
the build ends: `kontainer-build-<id>-buildkitd` (rootless BuildKit, which does the build and
gets the `cpus` and `memory` limits) and `kontainer-build-<id>-agent` (`kontainer runner` for
that one build). They share the volume `kontainer-build-<id>`.

- The runner needs the Docker API: mount `/var/run/docker.sock` (as root) when it runs in a
  container, or point `host` at a remote daemon. Docker API access is root on that host, so
  prefer a dedicated build host.
- Build containers must reach the registry at `server_url`.
- The agent container runs with Docker's init (`--init`), so it stops cleanly.
- `RUN` steps run in BuildKit's container, on its network. With `build_network = "isolated"`
  (the default) both containers join `kontainer-builds`, a bridge (Linux interface
  `kontainer-bld`) created on first use with outgoing NAT but no traffic between containers;
  they get no `host.docker.internal` alias, and cloud metadata host names
  (`metadata.google.internal`, ...) point at 127.0.0.1. Docker can't block an address by
  itself: on cloud hosts also drop link-local traffic from the bridge,
  `iptables -I DOCKER-USER -i kontainer-bld -d 169.254.0.0/16 -j DROP` (and private ranges you
  don't want builds to reach). A registry on the same Docker host is then reached through its
  public URL, or set `build_network = "open"` to use `http://host.docker.internal:5000`.
- `rootless = false` runs a privileged BuildKit (root on the Docker host); the runner warns at
  startup.

### Kubernetes

```toml
executor = "kubernetes"
concurrency = 4                    # Jobs at once

[kubernetes]
namespace = "kontainer-builds"     # default: the runner's own namespace
image = "registry.example.com/kontainer:0.2.0"
# server_url = "http://kontainer.kontainer.svc:5000"  # how build pods reach the registry; default: server
cpu = "2"
memory = "4Gi"
ephemeral_storage = "20Gi"         # checkout, BuildKit layers and the archive
# node_selector = { pool = "builds" }
# tolerations = [{ key = "builds", operator = "Exists", effect = "NoSchedule" }]
# image_pull_secrets = ["regcred"]
# job_ttl = "10m"                  # finished Jobs are deleted after this
# network_policy = true            # a NetworkPolicy per build (see below)
# allow_private_network = false    # let builds reach 10/8, 172.16/12, 192.168/16
# egress_cidrs = ["10.20.0.0/16"]  # or just these, e.g. an internal Git host
# registry_pod_labels = { "app.kubernetes.io/name" = "kontainer" }
# registry_namespace = "kontainer" # default: registry pods in any namespace
```

Each build becomes a Job named `kontainer-build-<id>`: `kontainer runner` for that build next to
a rootless BuildKit sidecar, which does the build and gets the CPU, memory and disk limits. If
the pod fails (out of memory, evicted, never scheduled), the build fails with Kubernetes' reason.

The [kontainer-runner Helm chart](../deploy/helm/kontainer-runner) sets all of this up: the
runner, its permission to manage Jobs in the build namespace, and optionally that namespace and a
NetworkPolicy. The registry's chart can run a shared one too (`runner.enabled`).

- Needs Kubernetes 1.29 or newer (native sidecars), and nodes that allow the unconfined seccomp
  and AppArmor profiles rootless BuildKit needs (`pod-security.kubernetes.io/enforce: privileged`
  on the build namespace).
- Build pods get no service account token and no service environment variables
  (`enableServiceLinks: false`). The agent container drops every capability, can't gain
  privileges and runs under the `RuntimeDefault` seccomp profile; BuildKit keeps the relaxed
  profiles rootless builds need.
- The build's token is not in the Job: it is in a Secret of the same name, owned by the Job (so
  Kubernetes deletes it with the Job) and read through `secretKeyRef`. The runner's Role needs
  `secrets` (`create`, `delete`) besides `jobs`; the Helm charts grant both.
- Outside the cluster, set `api_url`, `token_file` and `ca_file` under `[kubernetes]`.

Build pods need to reach only the registry, your Git hosts and the registries base images come
from. With `network_policy = true` (the default) the runner creates a NetworkPolicy with each
Job (owned by it, so it goes with the Job): no ingress, and egress only to DNS, the registry's
pods (`registry_pod_labels`, `registry_namespace`), `egress_cidrs` and public addresses: never
private ranges (unless `allow_private_network`) or link-local ones (cloud metadata,
`169.254.169.254`). The runner's Role needs `networkpolicies` (`create`; `delete` to replace a
left-over one) in the `networking.k8s.io` group; a build fails rather than run without its
policy. It needs a CNI that enforces NetworkPolicy. A namespace-wide policy like this one (the
charts' `networkPolicy: true` creates one like it) does the same for every build pod:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kontainer-builds
  namespace: kontainer-builds
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: kontainer-build
  policyTypes: ["Ingress", "Egress"]   # nothing may connect in
  egress:
    - to:                               # the registry
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kontainer } }
          podSelector: { matchLabels: { app.kubernetes.io/name: kontainer } }
    - to:                               # the internet (Git hosts, base images), not the cluster
        - ipBlock:
            cidr: 0.0.0.0/0
            except: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
    - ports:                            # DNS
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
```

### The queue

- **Newest wins.** When a build is queued for a trigger and branch (or tag), older builds of the
  same trigger and branch that haven't started are cancelled ("Superseded by build #N"): five
  quick pushes build once, not five times. Running builds finish. **Start build** warns before
  it replaces a queued build.
- **Namespaces take turns.** Runners pick builds of the users and organizations with the fewest
  builds running first, oldest first among equals, so one busy organization can't hold every
  shared runner while others wait. `builds.max_per_namespace` also caps how many builds one
  namespace runs at once (default 0, no cap); its other builds wait while other namespaces'
  builds go ahead.
- **Queued builds say where they stand:** "Next up", "3 ahead", or "Waiting for acme's running
  build" when the namespace is at its cap.

### The runner protocol

Runners speak JSON over HTTP under `/api/v1/runner`, outside the registry's normal
authentication. You only need this to write your own runner.

| Request | Auth | Does |
| --- | --- | --- |
| `POST /claim` `{"hostname", "version", "executor", "concurrency", "running", "report_only"}` | runner token | The next queued build of a namespace it serves: `200 {"id", "token"}`, or `204`. Every claim also updates the runner's status |
| `GET /builds/{id}` | build token | The spec: Git URL and credentials, ref, Dockerfile, context, timeout |
| `POST /builds/{id}/log` `{"offset", "data", "tail"}` | build token | The check-in, every couple of seconds, and the heartbeat: `data` is what the log gained since byte `offset`, the length the registry last acknowledged (possibly nothing). It is appended only when `offset` equals the length the registry has; otherwise it is ignored. Answers `{"stop", "length", "truncated"}`: `length` is where the next check-in starts, so a runner whose reply got lost, or that restarted, resends from there. `stop` is true when the build was cancelled or is over. `truncated` means the log passed `builds.max_log_bytes`: send nothing more (just heartbeats) until the build ends, then the log's last 64 KiB with `"tail": true` and `offset` where they start. The registry keeps the head and that tail, between them a line `==> log truncated: <n> bytes omitted` |
| `POST /builds/{id}/heartbeat` | build token | Keeps a build alive while whatever runs it starts; same answer |
| `POST /builds/{id}/commit` `{"sha"}` | build token | After checkout. Answers `{"tags"}`, or `400` when no tag template fits |
| `PUT /builds/{id}/image` | build token | The OCI archive (`application/x-tar`). The build succeeds once it is imported |
| `POST /builds/{id}/finish` `{"status", "message", "line"}` | build token | Report `failed` or `cancelled`. Check in the end of the log first; `line` (optional) is a last line for a build that never got a log of its own |

Runners from before chunked logs sent the whole log as `{"log"}` on both; the registry still
takes what it lacks of it.

## Triggers

Create triggers in a repository's **Settings → Build triggers** (Admin on the repository, once a
runner serves its namespace), or `POST /api/v1/build-triggers`:

```json
{ "repository": "acme/api", "name": "main",
  "git_url": "https://github.com/acme/api.git",
  "git_username": "x-access-token", "git_token": "ghp_...",
  "branches": ["main", "release/**", "v*"],
  "dockerfile": "docker/Dockerfile", "context": ".",
  "tags": ["{branch}", "{sha7}", "latest"] }
```

| Field | Meaning |
| --- | --- |
| `git_url` | `https://` only. |
| `git_username`, `git_token` | For private repositories. The token is never returned by the API and is replaced by `***` in logs. Leave it out on an update to keep the stored one, unless `git_url` moves to another origin (scheme, host or port): then the stored token is cleared and must be given again. |
| `branches` | Branch or Git tag patterns that start a build. `*` stays within one `/` segment; `**` crosses them. Default: every branch and tag. |
| `dockerfile`, `context` | Paths inside the repository. Default: `Dockerfile` and `.`. |
| `tags` | Up to 10 templates, optional. Without any, the image is pushed by digest only (untagged); with `gc.delete_untagged`, garbage collection may then remove it. |
| `poll_secs` | Check Git for new commits this often (60 to 86400 seconds), for Git hosts that can't reach the registry's webhook. Omitted: webhooks only. |

Tag templates:

- `{branch}`: the branch name, with `/` replaced by `-`. Skipped for Git tag pushes.
- `{tag}`: the Git tag name. Only for Git tag pushes.
- `{sha}` and `{sha7}`: the full and short commit hash.
- Anything else is used as written, such as `latest`.

Templates that produce an invalid tag are skipped.

The response includes the trigger's **webhook URL** and **secret**. The secret is shown once;
`POST /api/v1/build-triggers/{id}/secret` replaces it.

With `poll_secs`, the registry lists the repository's branches and tags over Git's smart HTTP
protocol on that schedule (no `git` needed on the registry) and queues a build for each matching
one that moved. The first check only notes where everything is. The trigger shows the commit each
branch was last seen at, when Git was last checked and the last build; **Check now** checks at
once (`POST /api/v1/build-triggers/{id}/check`). Polling follows no redirects (use the
repository's final URL), reads at most 4 MiB of refs, and, like namespace webhooks, refuses Git
hosts on this machine, private networks or link-local addresses unless
`policy.webhooks_allow_private_targets` is set (see [Webhooks](webhooks.md#internal-addresses)).

## Webhooks

Point your Git host's push webhook at
`https://registry.example.com/api/v1/build-triggers/{id}/webhook`. Three ways to authenticate
are accepted:

| Host | Setting |
| --- | --- |
| GitHub | Content type `application/json`, **Secret** = the trigger secret (checked as `X-Hub-Signature-256`) |
| GitLab | **Secret token** = the trigger secret (`X-Gitlab-Token`) |
| Anything else | `?secret=<secret>` on the URL, or an `X-Kontainer-Secret` header |

The body is read for `ref` (`refs/heads/main` or `refs/tags/v1.2.0`) and the commit
(`checkout_sha`, `after` or `sha`). A webhook build checks out exactly that commit:

- A push that matches the trigger answers `202` with the build id.
- A push to another branch, a deleted branch, or GitHub's `ping` answers `200` and does
  nothing.
- A bad secret answers `401`.

**Run** in the UI (or `POST /api/v1/build-triggers/{id}/run` with `{"ref": "main"}`) starts a
build by hand. It needs Push on the repository.

## Following builds

The repository's **Builds** tab lists builds with their status, commit, tags, who started
them and how long they took. Expand a build to follow its log live, and **Cancel** to stop
it. The API equivalents are `GET /api/v1/builds?repository=`, `GET /api/v1/builds/{id}` (with
the log so far; `?log=false` leaves it out) and `POST /api/v1/builds/{id}/cancel`.

`GET /api/v1/builds/{id}/log/stream` follows a log as
[server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html) (it needs
the same access as reading the build). It sends the chunks stored so far, one event each with
`id: <seq>` and data `{"seq", "data"}`, then each new chunk as runners check it in (on any
instance: chunks are announced with PostgreSQL `NOTIFY`), and ends with `event: done`, data
`{"status", "message"}`, once the build has ended. A comment line every 15 seconds keeps
proxies from closing it. A client that reconnects with `Last-Event-ID` (as `EventSource` does)
resumes after that chunk.

```sh
curl -N -H 'Authorization: Bearer <token>' https://registry.example.com/api/v1/builds/42/log/stream
```

- Logs are kept up to `builds.max_log_bytes` (8 MiB). Past that the registry keeps the
  beginning and the last 64 KiB, with a `==> log truncated: <n> bytes omitted` line between.
- A `local` build still running when the server restarts is marked failed. Queued builds
  stay queued, and Kubernetes and external builds carry on.
- Tags set by a build show in the tag history as `build`, by `build #<id>`.
- Builds respect repository states: a build for a read-only or mirror repository is refused
  before it starts.
