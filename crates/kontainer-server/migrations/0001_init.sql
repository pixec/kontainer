-- Kontainer's PostgreSQL schema.
--
-- Conventions:
-- * ids and every other integer are BIGINT (`i64` on the Rust side; Postgres INTEGER is i32).
-- * is_* flags are BOOLEAN.
-- * Timestamps are TIMESTAMPTZ (`chrono::DateTime<Utc>` on the Rust side).
-- * JSON is TEXT: it is read into Rust as a `String` and parsed there (and must survive
--   unreadable values, which are reported rather than rejected on read).

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Accounts
CREATE TABLE organizations (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    display_name      TEXT,
    description       TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL,
    time_machine_secs BIGINT                        -- NULL: the instance default
);

CREATE TABLE users (
    id             BIGSERIAL PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT,
    email          TEXT,
    display_name   TEXT,                            -- doubles as the full name on the profile
    is_robot       BOOLEAN NOT NULL DEFAULT false,
    owner_id       BIGINT REFERENCES users(id) ON DELETE CASCADE,
    is_disabled    BOOLEAN NOT NULL DEFAULT false,
    is_managed     BOOLEAN NOT NULL DEFAULT false,  -- defined in the config file, not editable
    mfa_secret     TEXT,                            -- the TOTP secret; set exactly when MFA is on
    created_at     TIMESTAMPTZ NOT NULL,
    last_login_at  TIMESTAMPTZ,
    -- Robots owned by an organization (`org+name`).
    org_id         BIGINT REFERENCES organizations(id) ON DELETE CASCADE,
    -- Public profile.
    company        TEXT,
    location       TEXT,
    website        TEXT,
    gravatar_email TEXT,
    -- The last TOTP time step accepted: a one-time code is refused once its step (or a later
    -- one) has been used, so an observed code cannot be replayed within its window.
    last_totp_step BIGINT
);
CREATE INDEX users_owner ON users(owner_id);
CREATE INDEX users_org ON users(org_id);

CREATE TABLE roles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    rules       TEXT NOT NULL,                      -- json: [{repositories:[..], actions:[..]}]
    global      TEXT NOT NULL DEFAULT '[]',         -- json: ["users:write", ...]
    is_managed  BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    user_agent TEXT,
    ip         TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE access_tokens (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    hint         TEXT NOT NULL,                     -- the plaintext token's first characters, for the UI
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT,                              -- json rules restricting the token, or null
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX access_tokens_user ON access_tokens(user_id);

CREATE TABLE identities (
    provider   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (provider, subject)
);
CREATE INDEX identities_user ON identities(user_id);

CREATE TABLE oidc_states (
    state         TEXT PRIMARY KEY,
    nonce         TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    redirect_to   TEXT,
    created_at    TIMESTAMPTZ NOT NULL,
    org           TEXT,                             -- an organization's own provider
    link_user_id  BIGINT,                           -- a signed-in user linking the identity
    -- SHA-256 of the nonce in the short-lived cookie of the browser that started the login; a
    -- callback from a browser without it is refused (login CSRF).
    browser_hash  TEXT
);

-- MFA being set up: the secret shown to the user, waiting for a code from their authenticator
-- before it moves to users.mfa_secret. Expired rows are purged with the sessions.
CREATE TABLE mfa_setups (
    user_id    BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE recovery_codes (
    user_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    is_used   BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX recovery_user ON recovery_codes(user_id);

-- Keyless robot logins: an OIDC token from a trusted issuer (GitHub Actions, GitLab CI, ...)
-- whose subject matches stands in for the robot's credential.
CREATE TABLE robot_federations (
    id         BIGSERIAL PRIMARY KEY,
    robot_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer     TEXT NOT NULL,                       -- exact `iss`
    subject    TEXT NOT NULL,                       -- glob on `sub`
    audience   TEXT,                                -- required `aud`, or NULL to accept any
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX robot_federations_by_robot ON robot_federations(robot_id);

-- Organizations and teams
CREATE TABLE teams (
    id              BIGSERIAL PRIMARY KEY,
    org_id          BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    rules           TEXT NOT NULL DEFAULT '[]',     -- legacy json rules; converted at startup and emptied
    is_org_admin    BOOLEAN NOT NULL DEFAULT false, -- kept in step with role = 'admin'
    created_at      TIMESTAMPTZ NOT NULL,
    role            TEXT NOT NULL DEFAULT 'member', -- member | creator | admin
    base_permission TEXT,                           -- read | write | admin | NULL
    UNIQUE (org_id, name)
);

CREATE TABLE team_members (
    team_id BIGINT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX team_members_user ON team_members(user_id);

-- An organization's own OIDC identity provider.
CREATE TABLE org_sso (
    org_id        BIGINT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    issuer        TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    display_name  TEXT NOT NULL DEFAULT 'SSO',
    groups_claim  TEXT,
    updated_at    TIMESTAMPTZ NOT NULL
);

-- A team whose members come from a directory group: `ldap`, `oidc` or `org-oidc`.
CREATE TABLE team_syncs (
    team_id    BIGINT PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    group_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Repositories
-- A repository's catalogue entry (description, README, visibility), edited in the UI. Its
-- content is in the registry tables below; either may exist without the other (an entry made
-- before the first push, content pushed without an entry), so they are related by name only.
CREATE TABLE repositories (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    readme      TEXT NOT NULL DEFAULT '',
    visibility  TEXT NOT NULL DEFAULT 'private',    -- public | private
    topics      TEXT NOT NULL DEFAULT '[]',         -- json array
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX repositories_visibility ON repositories(visibility);

-- Registry metadata (see `kontainer_store::metadata` and `database::registry`): what used to be
-- `repositories/<name>/...` keys in object storage. Blob bytes stay in object storage under
-- `blobs/<alg>/<hex>/data`. A repository exists while it has a manifest; names, tags and digests
-- compare bytewise (COLLATE "C"), as the registry API sorts and paginates them.
CREATE TABLE manifests (
    repository     TEXT COLLATE "C" NOT NULL,
    digest         TEXT COLLATE "C" NOT NULL,
    media_type     TEXT NOT NULL,                   -- push-time Content-Type (or the body's own)
    size           BIGINT NOT NULL,
    body           BYTEA NOT NULL,                  -- at most server.max_manifest_size
    subject_digest TEXT COLLATE "C",                -- OCI 1.1 `subject`: this is a referrer
    artifact_type  TEXT,                            -- as the referrers API reports it
    pushed_at      TIMESTAMPTZ NOT NULL,            -- last pushed (garbage collection's grace)
    PRIMARY KEY (repository, digest)
);
-- Referrers of a subject.
CREATE INDEX manifests_by_subject ON manifests(repository, subject_digest) WHERE subject_digest IS NOT NULL;

CREATE TABLE tags (
    repository TEXT COLLATE "C" NOT NULL,
    tag        TEXT COLLATE "C" NOT NULL,
    digest     TEXT COLLATE "C" NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,                -- last pointed (even at the same manifest)
    PRIMARY KEY (repository, tag),
    -- A namespace rename moves the manifests and, with them, their tags.
    FOREIGN KEY (repository, digest) REFERENCES manifests(repository, digest) ON UPDATE CASCADE
);
CREATE INDEX tags_by_manifest ON tags(repository, digest);

-- Blobs a repository may read: uploaded, mounted or pulled into it.
CREATE TABLE blob_links (
    repository TEXT COLLATE "C" NOT NULL,
    digest     TEXT COLLATE "C" NOT NULL,
    size       BIGINT NOT NULL,
    linked_at  TIMESTAMPTZ NOT NULL,                -- last linked or referenced by a manifest push
    PRIMARY KEY (repository, digest)
);
-- Garbage collection: does anything still link a blob?
CREATE INDEX blob_links_by_digest ON blob_links(digest);

-- Which storage locations hold each blob (see `kontainer_store::placement`). A blob exists when
-- a configured location holds it; reads pick a location from here without asking the stores.
-- Rows of a location removed from the configuration stay until `kontainer storage
-- forget-location`.
CREATE TABLE blob_placements (
    digest    TEXT COLLATE "C" NOT NULL,
    location  TEXT NOT NULL,
    size      BIGINT NOT NULL,
    placed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (digest, location)
);
-- Per-location counts and backfills (what is missing at a location).
CREATE INDEX blob_placements_by_location ON blob_placements(location, digest);

-- Copies still to make between storage locations, claimed by workers on any instance like
-- `scan_jobs`. A copy that gave up keeps its row (failed_at, last_error) for the admin page until
-- it is queued again.
CREATE TABLE blob_replication_jobs (
    id         BIGSERIAL PRIMARY KEY,
    kind       TEXT NOT NULL DEFAULT 'blob',         -- blob | scan | log
    digest     TEXT COLLATE "C" NOT NULL,            -- the blob or scanned digest; the log id for logs
    location   TEXT NOT NULL,                        -- where to copy it
    attempts   INTEGER NOT NULL DEFAULT 0,           -- claims so far, including the current one
    next_at    TIMESTAMPTZ NOT NULL DEFAULT now(),   -- not claimed before (retry backoff)
    locked_by  TEXT,                                 -- the worker copying it
    locked_at  TIMESTAMPTZ,                          -- refreshed while the copy runs
    last_error TEXT,
    failed_at  TIMESTAMPTZ,                          -- set when given up after the last attempt
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- One live copy per object and location: queueing it again while it waits or runs is a no-op.
CREATE UNIQUE INDEX blob_replication_jobs_live ON blob_replication_jobs(kind, digest, location) WHERE failed_at IS NULL;
CREATE INDEX blob_replication_jobs_claim ON blob_replication_jobs(next_at, id) WHERE failed_at IS NULL;
CREATE INDEX blob_replication_jobs_by_location ON blob_replication_jobs(location);

-- Per-user stars. Keyed by name (not a FK): a repository can have content without a row.
CREATE TABLE stars (
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, repository)
);
CREATE INDEX stars_repository ON stars(repository);

-- Explicit Read/Write/Admin grants on repositories for users, robots and teams.
CREATE TABLE repo_user_permissions (
    repository TEXT NOT NULL,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    level      TEXT NOT NULL,                       -- read | write | admin
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (repository, user_id)
);
CREATE INDEX repo_user_permissions_user ON repo_user_permissions(user_id);

CREATE TABLE repo_team_permissions (
    repository TEXT NOT NULL,
    team_id    BIGINT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    level      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (repository, team_id)
);
CREATE INDEX repo_team_permissions_team ON repo_team_permissions(team_id);

-- Where a repository's content was last imported from.
CREATE TABLE repo_imports (
    repository  TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,                      -- `registry` or `archive`
    registry    TEXT,
    source      TEXT NOT NULL,
    actor       TEXT NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL
);

-- Every change to a tag, for history and the Time Machine.
CREATE TABLE tag_events (
    id         BIGSERIAL PRIMARY KEY,
    repository TEXT NOT NULL,
    tag        TEXT NOT NULL,
    action     TEXT NOT NULL,                       -- push, move, delete, restore, expire, sync, import, retention, build
    digest     TEXT,                                -- where the tag points afterwards (NULL once deleted)
    previous   TEXT,                                -- where it pointed before (NULL when created)
    actor      TEXT NOT NULL,
    at         TIMESTAMPTZ NOT NULL
);
CREATE INDEX tag_events_by_repo ON tag_events(repository, at);
CREATE INDEX tag_events_by_time ON tag_events(at);

-- Tags that delete themselves at a point in time.
CREATE TABLE tag_expirations (
    repository TEXT NOT NULL,
    tag        TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    set_by     TEXT NOT NULL,
    PRIMARY KEY (repository, tag)
);

-- `read_only` or `mirror`; no row is `normal`.
CREATE TABLE repo_states (
    repository TEXT PRIMARY KEY,
    state      TEXT NOT NULL,
    reason     TEXT,
    set_by     TEXT NOT NULL,
    set_at     TIMESTAMPTZ NOT NULL
);

-- Policies
CREATE TABLE quotas (
    namespace  TEXT PRIMARY KEY,
    max_bytes  BIGINT NOT NULL,                     -- 0: explicitly unlimited
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE retention_policies (
    id           BIGSERIAL PRIMARY KEY,
    namespace    TEXT NOT NULL,
    repositories TEXT NOT NULL DEFAULT '**',        -- glob relative to the namespace
    keep_last    BIGINT,
    max_age_days BIGINT,
    protect      TEXT NOT NULL DEFAULT '[]',        -- json tag globs never deleted
    is_enabled   BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL,
    last_run_at  TIMESTAMPTZ,
    last_deleted BIGINT
);
CREATE INDEX retention_policies_namespace ON retention_policies(namespace);

CREATE TABLE security_policies (
    namespace            TEXT PRIMARY KEY,
    block_severity       TEXT,                      -- NULL: the registry default; 'none': off
    is_block_unscanned   BOOLEAN NOT NULL DEFAULT false,
    is_require_signature BOOLEAN NOT NULL DEFAULT false,
    signing_keys         TEXT NOT NULL DEFAULT '[]', -- json PEM public keys; empty: any cosign signature
    updated_by           TEXT NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL
);

-- Vulnerabilities that don't count towards blocking: per namespace, or registry-wide (NULL).
CREATE TABLE cve_allowlist (
    id         BIGSERIAL PRIMARY KEY,
    namespace  TEXT,
    cve        TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX cve_allowlist_by_namespace ON cve_allowlist(namespace);

-- Other registries
CREATE TABLE registries (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    url         TEXT NOT NULL,
    username    TEXT,
    password    TEXT,
    is_insecure BOOLEAN NOT NULL DEFAULT false,     -- accept invalid TLS certificates
    created_at  TIMESTAMPTZ NOT NULL,
    -- Changes with every edit: instances rebuild their cached client for the registry when it
    -- no longer matches.
    updated_at  TIMESTAMPTZ NOT NULL
);

-- Pull-through cache: pulling `<namespace>/<repo>` fetches `<repo>` from the registry.
CREATE TABLE proxy_caches (
    namespace   TEXT PRIMARY KEY,
    registry_id BIGINT NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    ttl_secs    BIGINT NOT NULL DEFAULT 21600,
    is_public   BOOLEAN NOT NULL DEFAULT false,     -- anonymous pulls allowed
    created_at  TIMESTAMPTZ NOT NULL
);

-- Scheduled copies of an upstream repository's tags into a local repository.
CREATE TABLE mirrors (
    id            BIGSERIAL PRIMARY KEY,
    registry_id   BIGINT NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    source        TEXT NOT NULL,
    target        TEXT NOT NULL,
    tags          TEXT NOT NULL DEFAULT '[]',       -- json tag globs; empty = all
    interval_secs BIGINT NOT NULL DEFAULT 3600,
    is_enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL,
    last_sync_at  TIMESTAMPTZ,
    last_status   TEXT,                             -- ok | error
    last_message  TEXT
);

-- Push replication to another registry. Runs are recorded in task_runs as `replication/<id>`.
CREATE TABLE replication_rules (
    id                   BIGSERIAL PRIMARY KEY,
    name                 TEXT NOT NULL,
    registry_id          BIGINT NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    repositories         TEXT NOT NULL DEFAULT '["**"]', -- json globs of local repositories
    tags                 TEXT NOT NULL DEFAULT '[]',     -- json tag globs; empty = every tag
    destination          TEXT NOT NULL DEFAULT '',       -- prefix on the target ('' keeps names)
    trigger              TEXT NOT NULL DEFAULT 'push',   -- push | schedule | manual
    interval_secs        BIGINT,                         -- for `schedule`
    is_replicate_deletes BOOLEAN NOT NULL DEFAULT false,
    is_enabled           BOOLEAN NOT NULL DEFAULT true,
    last_run_at          TIMESTAMPTZ,
    last_status          TEXT,                           -- succeeded | failed
    last_message         TEXT,
    created_by           TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL
);

-- Builds
CREATE TABLE build_triggers (
    id           BIGSERIAL PRIMARY KEY,
    repository   TEXT NOT NULL,
    name         TEXT NOT NULL,
    git_url      TEXT NOT NULL,
    git_username TEXT,
    git_token    TEXT,                              -- for private repositories; never returned
    branches     TEXT NOT NULL DEFAULT '["*"]',     -- json globs a push must match
    dockerfile   TEXT NOT NULL DEFAULT 'Dockerfile',
    context      TEXT NOT NULL DEFAULT '.',
    tags         TEXT NOT NULL DEFAULT '["{branch}","{sha7}"]', -- json templates
    secret       TEXT NOT NULL,                     -- webhook secret / HMAC key
    is_enabled   BOOLEAN NOT NULL DEFAULT true,
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    poll_secs    BIGINT,                            -- NULL: webhooks only
    seen_refs    TEXT NOT NULL DEFAULT '{}',        -- json {"refs/heads/main": "<sha>"}
    checked_at   TIMESTAMPTZ,                       -- last poll
    check_error  TEXT                               -- why the last poll failed
);
CREATE INDEX build_triggers_by_repo ON build_triggers(repository);

-- Processes that claim queued builds and run them. Shared runners (namespace NULL) serve every
-- namespace or the ones in runner_namespaces; self-hosted runners belong to one namespace.
CREATE TABLE runners (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT NOT NULL,
    namespace         TEXT,
    is_all_namespaces BOOLEAN NOT NULL DEFAULT false,
    token_hash        TEXT NOT NULL UNIQUE,
    is_enabled        BOOLEAN NOT NULL DEFAULT true,
    is_from_config    BOOLEAN NOT NULL DEFAULT false, -- [[builds.runners]]; read-only in the UI
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    -- What it last said about itself, with each claim.
    last_seen_at      TIMESTAMPTZ,
    hostname          TEXT,
    version           TEXT,
    executor          TEXT,
    concurrency       BIGINT,
    running           BIGINT
);
CREATE INDEX runners_by_namespace ON runners(namespace);

CREATE TABLE runner_namespaces (
    runner_id BIGINT NOT NULL REFERENCES runners(id) ON DELETE CASCADE,
    namespace TEXT NOT NULL,
    PRIMARY KEY (runner_id, namespace)
);

CREATE TABLE builds (
    id                  BIGSERIAL PRIMARY KEY,
    trigger_id          BIGINT REFERENCES build_triggers(id) ON DELETE SET NULL,
    repository          TEXT NOT NULL,
    git_url             TEXT NOT NULL,
    git_ref             TEXT NOT NULL,              -- branch, tag or commit asked for
    commit_sha          TEXT,                       -- what was built
    tags                TEXT NOT NULL DEFAULT '[]', -- json, filled when known
    digest              TEXT,
    status              TEXT NOT NULL,              -- queued, running, succeeded, failed, cancelled
    message             TEXT,
    actor               TEXT NOT NULL,
    log                 TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL,
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    -- The agent holding a running build proves itself with a per-build token and checks in
    -- regularly; cancelling sets a flag it sees on its next check-in.
    agent               TEXT,
    agent_token_hash    TEXT,
    heartbeat_at        TIMESTAMPTZ,
    is_cancel_requested BOOLEAN NOT NULL DEFAULT false,
    tag_templates       TEXT,                       -- json, overriding the trigger's
    runner_id           BIGINT REFERENCES runners(id) ON DELETE SET NULL,
    -- The log arrives in chunks (build_log_chunks); `log` caches their concatenation once the
    -- build ends. Offsets are in the runner's log: `log_length` bytes of it are accounted for
    -- (stored, or dropped past `builds.max_log_bytes`), `log_stored` are stored, `log_seq` is
    -- the last chunk. Past the cap, storing stopped at runner offset `log_truncated_at`;
    -- `log_omitted` is set once the truncation marker is written.
    log_length          BIGINT NOT NULL DEFAULT 0,
    log_stored          BIGINT NOT NULL DEFAULT 0,
    log_seq             BIGINT NOT NULL DEFAULT 0,
    log_truncated_at    BIGINT,
    log_omitted         BIGINT
);
CREATE INDEX builds_by_repo ON builds(repository, id);
CREATE INDEX builds_by_status ON builds(status, id);
CREATE INDEX builds_by_trigger ON builds(trigger_id);

-- A build's log as it arrives: runner check-ins, the server's own lines, a truncation marker.
CREATE TABLE build_log_chunks (
    build_id   BIGINT NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    seq        BIGINT NOT NULL,                     -- 1, 2, ... per build
    data       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (build_id, seq)
);

-- Work queues
--
-- Durable queues, shared by every registry instance on this database. Workers claim a row with
-- `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1)`, stamping
-- `locked_by`/`locked_at`; a lock older than the queue's lease belongs to a worker that died, and
-- the row is claimed again. The webhook delivery queue is `webhook_deliveries`, below.

-- Vulnerability scans waiting for (or held by) a worker. Finished scans are deleted: their
-- report lives in storage next to the image. A scan that failed every attempt stays, with
-- `failed_at` and `last_error` set, until it is pruned or queued again.
CREATE TABLE scan_jobs (
    id           BIGSERIAL PRIMARY KEY,
    repository   TEXT NOT NULL,
    digest       TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts     INTEGER NOT NULL DEFAULT 0,          -- claims so far, including the current one
    next_at      TIMESTAMPTZ NOT NULL DEFAULT now(),  -- not claimed before (retry backoff)
    locked_by    TEXT,                                -- the queue instance working on it
    locked_at    TIMESTAMPTZ,                         -- refreshed while the scan runs
    last_error   TEXT,
    failed_at    TIMESTAMPTZ                          -- set when dropped after the last attempt
);
-- One live job per image: queueing it again while it waits or runs is a no-op.
CREATE UNIQUE INDEX scan_jobs_live ON scan_jobs(repository, digest) WHERE failed_at IS NULL;
CREATE INDEX scan_jobs_claim ON scan_jobs(requested_at, id) WHERE failed_at IS NULL;

-- Blob upload sessions, shared by every registry instance (see `kontainer_store::uploads`).
-- The bytes are chunk objects in the primary store under `_upload_chunks/<id>/<chunk>`; this
-- row says which chunks, in which order, make up the upload.
CREATE TABLE blob_uploads (
    id            TEXT PRIMARY KEY,                -- UUID, as in the upload URL
    repository    TEXT NOT NULL,
    upload_offset BIGINT NOT NULL DEFAULT 0,       -- bytes received (`offset` is reserved)
    chunks        TEXT[] NOT NULL DEFAULT '{}',    -- chunk object names, in order
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,            -- last chunk recorded or sealed
    is_sealed     BOOLEAN NOT NULL DEFAULT false,  -- being completed: no more chunks
    digest        TEXT                             -- what it was sealed for
);
CREATE INDEX blob_uploads_updated_at ON blob_uploads (updated_at);
-- Garbage collection spares a blob an upload is being completed into.
CREATE INDEX blob_uploads_by_digest ON blob_uploads (digest) WHERE digest IS NOT NULL;

-- Webhooks and maintenance
-- Webhooks per namespace, managed by its admins (config-file webhooks are not stored here).
CREATE TABLE webhooks (
    id            BIGSERIAL PRIMARY KEY,
    namespace     TEXT NOT NULL,
    name          TEXT NOT NULL,
    url           TEXT NOT NULL,
    format        TEXT NOT NULL DEFAULT 'default',  -- default | cloudevents | slack
    events        TEXT NOT NULL DEFAULT '[]',       -- json; empty = every event
    repositories  TEXT NOT NULL DEFAULT '[]',       -- json globs relative to the namespace; empty = all
    secret        TEXT,                             -- HMAC-SHA256 key; never returned
    auth_header   TEXT,                             -- sent as Authorization; never returned
    is_verify_tls BOOLEAN NOT NULL DEFAULT true,
    is_enabled    BOOLEAN NOT NULL DEFAULT true,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX webhooks_by_namespace ON webhooks(namespace);

-- Webhook deliveries: the delivery queue as well as the history the UI shows. A `pending` row
-- is waiting for its next attempt (at `next_at`) or being delivered (`locked_*`);
-- `response_code` and `error` hold the last attempt's status and error. Rows for `[[webhooks]]`
-- from the config file name their hook in `config_hook` instead of `webhook_id` (its URL and
-- headers stay in the config, never in the database).
CREATE TABLE webhook_deliveries (
    id            BIGSERIAL PRIMARY KEY,
    webhook_id    BIGINT REFERENCES webhooks(id) ON DELETE CASCADE,
    config_hook   TEXT,
    event         TEXT NOT NULL,
    payload       TEXT NOT NULL,                    -- the body as sent
    content_type  TEXT,
    status        TEXT NOT NULL,                    -- pending | succeeded | failed
    attempts      BIGINT NOT NULL DEFAULT 0,
    max_attempts  INTEGER NOT NULL DEFAULT 3,
    response_code BIGINT,
    response_body TEXT,                             -- the first KB
    error         TEXT,
    duration_ms   BIGINT,
    created_at    TIMESTAMPTZ NOT NULL,
    delivered_at  TIMESTAMPTZ,
    next_at       TIMESTAMPTZ,
    locked_by     TEXT,
    locked_at     TIMESTAMPTZ,
    CONSTRAINT webhook_deliveries_one_target CHECK ((webhook_id IS NULL) <> (config_hook IS NULL))
);
CREATE INDEX webhook_deliveries_by_hook ON webhook_deliveries(webhook_id, id);
CREATE INDEX webhook_deliveries_claim ON webhook_deliveries(id) WHERE status = 'pending';
CREATE INDEX webhook_deliveries_by_config_hook ON webhook_deliveries(config_hook, id) WHERE config_hook IS NOT NULL;

-- Maintenance runs (gc, scan_all, replication/<id>), scheduled or by hand.
CREATE TABLE task_runs (
    id          BIGSERIAL PRIMARY KEY,
    kind        TEXT NOT NULL,
    trigger     TEXT NOT NULL,                      -- schedule | manual | ...
    actor       TEXT NOT NULL,
    status      TEXT NOT NULL,                      -- running | succeeded | failed
    summary     TEXT,                               -- one line
    details     TEXT,                               -- json report
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    -- The instance running it (`Db::instance_id`), and when it last said it still is. A run
    -- still `running` whose heartbeat stopped belongs to an instance that died.
    instance_id  TEXT,
    heartbeat_at TIMESTAMPTZ
);
CREATE INDEX task_runs_by_kind ON task_runs(kind, id);
CREATE INDEX task_runs_running ON task_runs(heartbeat_at) WHERE status = 'running';

-- Background jobs started from the UI or API (imports, manual mirror syncs, replica syncs), so
-- every instance lists every job. The instance running a job (`instance_id`) updates its row
-- as it goes; a cancel request made on another instance sets `is_cancel_requested`, which the
-- owner polls. Finished jobs are pruned after 7 days.
CREATE TABLE jobs (
    id                  TEXT PRIMARY KEY,
    kind                TEXT NOT NULL,              -- import | mirror | replication
    subject             TEXT NOT NULL,              -- what it works on, shown as its title
    actor               TEXT NOT NULL,
    status              TEXT NOT NULL,              -- running | done | failed | cancelled
    message             TEXT,                       -- progress while running, the outcome when done
    error               TEXT,                       -- why it failed
    instance_id         TEXT NOT NULL,
    is_cancel_requested BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,       -- also the owner's heartbeat while running
    finished_at         TIMESTAMPTZ
);
CREATE INDEX jobs_by_created ON jobs(created_at DESC);
CREATE INDEX jobs_running ON jobs(updated_at) WHERE status = 'running';

-- Failed sign-in attempts per account (`u:<name>`) and per client address (`ip:<addr>`),
-- shared so that a lockout holds on every instance. A key is locked out until `locked_until`
-- once `failures` within the window starting at `window_started_at` reach its limit. Stale
-- rows are purged periodically.
CREATE TABLE login_failures (
    key               TEXT PRIMARY KEY,
    failures          BIGINT NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL,
    locked_until      TIMESTAMPTZ
);
CREATE INDEX login_failures_window ON login_failures(window_started_at);

-- The storage usage report: a full walk of storage, computed on one instance at a time (under
-- the advisory lock `usage`) and read by every other. One row.
CREATE TABLE usage_reports (
    id          BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    report      TEXT NOT NULL,                      -- json `kontainer_store::usage::UsageReport`
    computed_at TIMESTAMPTZ NOT NULL,
    instance_id TEXT NOT NULL
);

-- The automatic-scan budget (`scanner.max_auto_per_hour`), shared by every instance: scans
-- queued automatically (scan on push, scheduled rescans) in the hour starting at
-- `window_start`, and those skipped for the budget or a full queue. An administrator can lift
-- the budget until `override_until`. One row, created on first use.
CREATE TABLE scan_budget (
    id             BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    window_start   TIMESTAMPTZ NOT NULL,
    used           BIGINT NOT NULL DEFAULT 0,       -- automatic scans queued in this window
    skipped        BIGINT NOT NULL DEFAULT 0,       -- scans skipped in this window
    override_until TIMESTAMPTZ,                     -- the budget does not apply before this
    override_by    TEXT                             -- who lifted it
);

-- Identity linking with a SameSite=Strict session cookie: the provider's redirect back is a
-- cross-site navigation that does not carry the session, so the signed-in POST that starts a link
-- also sets a short-lived `kontainer_oidc_link` cookie (Lax, Path=/auth/oidc). Its SHA-256 is
-- kept here, next to `link_user_id`; the callback links only for a browser holding it.
ALTER TABLE oidc_states ADD COLUMN link_hash TEXT;

-- Passkeys (WebAuthn credentials). `credential` is webauthn-rs's `Passkey` as serde writes it
-- (public key, counter, backup state); `credential_id` is unique across every account.
CREATE TABLE passkeys (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    credential    TEXT NOT NULL,                    -- json `webauthn_rs::prelude::Passkey`
    name          TEXT NOT NULL,
    sign_count    BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL,
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX passkeys_by_user ON passkeys(user_id);

-- A WebAuthn ceremony between its start and finish requests, which may reach different
-- instances. Single use (taken with DELETE ... RETURNING); expired rows are purged with the
-- sessions.
CREATE TABLE webauthn_challenges (
    id         TEXT PRIMARY KEY,                    -- random, handed to the browser with the options
    kind       TEXT NOT NULL,                       -- register | login | discoverable
    user_id    BIGINT REFERENCES users(id) ON DELETE CASCADE,
    state      TEXT NOT NULL,                       -- json webauthn-rs ceremony state
    name       TEXT,                                -- register: the new passkey's name
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Confirmed deletions (a repository, or several tags): created with a preview, executed once
-- by the same user within five minutes with the repository name typed back.
CREATE TABLE delete_plans (
    id         TEXT PRIMARY KEY,
    actor_id   BIGINT REFERENCES users(id) ON DELETE CASCADE, -- NULL only with auth.mode = none
    actor      TEXT NOT NULL,
    repository TEXT NOT NULL,
    targets    TEXT NOT NULL,                       -- json {"repository": true} | {"tags": [...]}
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);
