
use std::future::Future;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand};
use tokio::sync::watch;

use kontainer_core::config::Config;
use kontainer_server::{build_router, build_state};
use kontainer_store::gc;

#[derive(Parser)]
#[command(name = "kontainer", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, env = "KONTAINER_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the registry server (default).
    Serve,
    /// Remove unreferenced blobs from storage.
    Gc {
        /// Only report what would be removed.
        #[arg(long = "dry-run")]
        is_dry_run: bool,
        /// Also remove manifests not reachable from any tag.
        #[arg(long = "delete-untagged")]
        is_delete_untagged: bool,
        /// Never collect objects modified more recently than this (e.g. `1h`). Defaults to
        /// `storage.upload_ttl`.
        #[arg(long)]
        grace: Option<String>,
    },
    /// Generate an Argon2id password hash for the `[[auth.users]]` section. Prompts for the
    /// password, or reads it from `KONTAINER_PASSWORD` or a pipe on stdin.
    HashPassword {
        /// Deprecated: visible to other users and kept in shell history.
        #[arg(hide = true)]
        password: Option<String>,
    },
    /// Print the effective configuration.
    CheckConfig,
    /// Re-encrypt every secret stored in the database under the current key
    /// (`auth.encryption_key`), opening them with the keys in `auth.previous_encryption_keys`.
    /// Also encrypts secrets stored before encryption was enabled. Safe to run again.
    RotateEncryptionKey {
        /// Rows re-encrypted per transaction.
        #[arg(long, default_value_t = 500)]
        batch: i64,
    },
    /// Count the secrets stored in the database per table: plaintext, under the current key,
    /// under previous keys, or under keys that aren't configured.
    EncryptionStatus,
    /// Manage user accounts.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// List roles and their permissions.
    Roles,
    /// Queue a copy of every blob each storage location is missing (the running servers make
    /// the copies). The servers also do this every `storage.replication_interval`.
    Replicate,
    /// Storage locations.
    Storage {
        #[command(subcommand)]
        cmd: StorageCmd,
    },
    /// Run builds for a registry: claim queued builds of the namespaces this runner serves and
    /// build them here, in Docker containers or as Kubernetes Jobs. Register the runner in the
    /// registry first (namespace settings, or Admin → Runners) for its token. Needs `git`, plus
    /// `docker` or `buildctl` for local builds. See docs/builds.md.
    #[command(alias = "build-agent")]
    Runner {
        /// A TOML file with the runner's settings; `KONTAINER_RUNNER__<KEY>` variables and the
        /// flags below win over it.
        #[arg(long, env = "KONTAINER_RUNNER_CONFIG")]
        config_file: Option<PathBuf>,
        /// The registry's URL, e.g. `https://registry.example.com` (`KONTAINER_SERVER`).
        #[arg(long)]
        server: Option<String>,
        /// The runner's token. Prefer the variable: flags are visible to other users.
        #[arg(long, env = "KONTAINER_RUNNER_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Shown on builds and in the registry; defaults to the host name (`KONTAINER_RUNNER_NAME`).
        #[arg(long)]
        name: Option<String>,
        /// `local`, `docker` or `kubernetes`.
        #[arg(long)]
        executor: Option<String>,
        /// Builds at once.
        #[arg(long)]
        concurrency: Option<usize>,
        /// Local builds: `docker` or `buildctl`.
        #[arg(long)]
        backend: Option<String>,
        /// For `buildctl`, e.g. `tcp://buildkitd:1234` (`BUILDKIT_HOST`).
        #[arg(long)]
        buildkit_addr: Option<String>,
        #[arg(long)]
        work_dir: Option<PathBuf>,
        /// Run just this build (with `KONTAINER_BUILD_TOKEN`) and exit: what launched builds run.
        #[arg(long)]
        build_id: Option<i64>,
        #[arg(long, env = "KONTAINER_BUILD_TOKEN", hide_env_values = true)]
        build_token: Option<String>,
        /// Read the build token from this file instead, and delete it (what the `docker`
        /// executor's agents use).
        #[arg(long, env = "KONTAINER_BUILD_TOKEN_FILE", conflicts_with = "build_token")]
        build_token_file: Option<PathBuf>,
    },
    /// Write a consistent backup: the database (`pg_dump`, safe while the server runs) and, with
    /// `--storage`, every stored object. See docs/backup-restore.md.
    Backup {
        /// Directory to create; must not exist yet.
        output: PathBuf,
        /// Also copy all registry storage (blobs, scans, logs) into `<output>/storage`, and the
        /// registry metadata (manifests, tags, blob links) into `<output>/metadata.jsonl`.
        #[arg(long)]
        storage: bool,
    },
    /// Copy registry metadata (manifests, tags, blob links) into the database: from the
    /// `repositories/...` keys that older versions kept in storage, or with `--from`
    /// from a backup's `metadata.jsonl`. Keeps rows that exist, so it can run again; deletes
    /// nothing. Prints what it inserted.
    MigrateMetadata {
        /// A `metadata.jsonl` written by `kontainer backup --storage`, instead of storage.
        #[arg(long)]
        from: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum StorageCmd {
    /// Forget what the database records about a location removed from the configuration
    /// (which blobs it holds, copies queued to it). Deletes no object.
    ForgetLocation {
        /// The location's name, as the admin page lists it under unknown locations.
        name: String,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Create a user. Prompts for the password, or reads it from `KONTAINER_PASSWORD` or a
    /// pipe on stdin.
    Create {
        username: String,
        /// Deprecated: visible to other users and kept in shell history.
        #[arg(short, long, hide = true)]
        password: Option<String>,
        /// Roles to assign (repeatable).
        #[arg(short, long = "role")]
        roles: Vec<String>,
        /// Grant the built-in `system` is_superuser role.
        #[arg(long)]
        system: bool,
        #[arg(long)]
        email: Option<String>,
    },
    List,
    Delete { username: String },
    /// Set a new password: prompted for, or from `KONTAINER_PASSWORD` or a pipe on stdin.
    Passwd {
        username: String,
        /// Deprecated: visible to other users and kept in shell history.
        #[arg(short, long, hide = true)]
        password: Option<String>,
    },
    /// Replace a user's roles.
    SetRoles { username: String, roles: Vec<String> },
    /// Remove two-factor authentication from an account.
    ResetMfa { username: String },
    /// Enable or disable an account.
    Disable { username: String, #[arg(long)] enable: bool },
}

/// How long builds get to cancel and report once the runner is told to stop. Below Docker's
/// `stop_grace_period` in deploy/compose (30s) and Kubernetes' default (30s).
const RUNNER_GRACE: Duration = Duration::from_secs(25);

/// Secrets belong in variables, files or a prompt; flags show up in `ps` and shell history.
const ARGV_SECRET: &str = "is visible to other users (process list) and kept in shell history";

/// Whether `arg` of subcommand `sub` was typed on the command line (not from its variable).
fn from_argv(m: &ArgMatches, sub: &str, arg: &str) -> bool {
    m.subcommand_matches(sub).and_then(|s| s.value_source(arg)) == Some(ValueSource::CommandLine)
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // A runner has its own configuration; the registry's isn't needed (or there) where it runs.
    if let Some(Command::Runner { config_file, server, token, name, executor, concurrency, backend, buildkit_addr, work_dir, build_id, build_token, build_token_file }) = cli.command {
        let log = std::env::var("KONTAINER_LOG").unwrap_or_else(|_| "info".into());
        tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(log)).init();
        for (arg, var) in [("token", "KONTAINER_RUNNER_TOKEN"), ("build_token", "KONTAINER_BUILD_TOKEN")] {
            if from_argv(&matches, "runner", arg) {
                tracing::warn!("--{} {ARGV_SECRET}; set {var} instead", arg.replace('_', "-"));
            }
        }
        let mut rc = kontainer_core::config::RunnerConfig::load(config_file.as_deref())?;
        let parse = |what: &str, v: String| toml::from_str::<toml::Table>(&format!("v = \"{v}\"")).ok().and_then(|mut t| t.remove("v")).with_context(|| format!("invalid --{what} `{v}`"));
        if let Some(v) = server { rc.server = v; }
        if let Some(v) = token { rc.token = Some(v.into()); }
        if let Some(v) = name { rc.name = Some(v); }
        if let Some(v) = executor { rc.executor = parse("executor", v)?.try_into().context("--executor: local, docker or kubernetes")?; }
        if let Some(v) = concurrency { rc.concurrency = v; }
        if let Some(v) = backend { rc.backend = parse("backend", v)?.try_into().context("--backend: docker or buildctl")?; }
        if let Some(v) = buildkit_addr { rc.buildkit_addr = v; }
        if let Some(v) = work_dir { rc.work_dir = v; }
        let build_token = match build_token_file {
            Some(path) => {
                let t = std::fs::read_to_string(&path).with_context(|| format!("reading the build token from {}", path.display()))?;
                // Nothing else in the container needs it.
                if let Err(e) = std::fs::remove_file(&path) {
                    tracing::warn!(path = %path.display(), error = %e, "removing the build token file");
                }
                Some(t.trim().to_string()).filter(|t| !t.is_empty())
            }
            None => build_token,
        };
        let runner = kontainer_server::runner::worker::Runner::new(&rc)?;
        let (stop, stopped) = watch::channel(false);
        return match (build_id, build_token) {
            (Some(id), Some(build_token)) => {
                anyhow::ensure!(!rc.server.is_empty(), "set the registry's URL (--server or KONTAINER_SERVER)");
                until_shutdown(runner.run_one_until(id, &build_token, stopped), stop).await
            }
            (Some(_), None) => anyhow::bail!("--build-id needs KONTAINER_BUILD_TOKEN or --build-token-file"),
            (None, _) => {
                rc.validate()?;
                until_shutdown(runner.serve_until(&rc, stopped), stop).await
            }
        };
    }
    let cfg = Config::load(cli.config.as_deref())?;
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(&cfg.server.log)).init();
    // Every database handle below (and the server's) seals and opens secrets with these keys.
    kontainer_server::database::install_keyring(&cfg);

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(cfg).await,
        Command::Backup { output, storage: with_storage } => backup(cfg, output, with_storage).await,
        Command::Runner { .. } => unreachable!("handled above"),
        Command::Gc { is_dry_run, is_delete_untagged, grace } => {
            let grace = match grace {
                Some(g) => kontainer_core::config::parse_duration(&g).with_context(|| format!("invalid --grace `{g}`"))?,
                None => cfg.storage.upload_ttl,
            };
            let (storage, db) = open_storage(&cfg).await?;
            // Keep what the Time Machine can still restore.
            let window = kontainer_server::tags::longest_time_machine(&db, cfg.policy.time_machine).await?;
            let restorable = kontainer_server::tags::restorable(&db, window).await?;
            let report = gc::run(&storage, is_delete_untagged, is_dry_run, grace, &restorable).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Replicate => {
            let (storage, db) = open_storage(&cfg).await?;
            anyhow::ensure!(storage.locations().len() > 1, "only one storage location is configured");
            let lock = db.try_advisory_lock(kontainer_server::locations::BACKFILL_LOCK).await?.context("a storage sync is already running")?;
            let result = kontainer_server::locations::backfill_all(&storage).await;
            lock.release().await;
            for (location, n) in result? {
                println!("{location}: {n} copies queued");
            }
            Ok(())
        }
        Command::Storage { cmd: StorageCmd::ForgetLocation { name } } => {
            let db = kontainer_server::database::Db::open(cfg.auth.database_url.expose(), cfg.auth.database_pool).await?;
            anyhow::ensure!(cfg.storage.resolved_locations()?.iter().all(|l| l.name != name), "storage location `{name}` is still configured: remove it from the configuration first");
            let (placements, jobs) = db.forget_location(&name).await?;
            println!("forgot storage location {name}: {placements} blob placements, {jobs} queued copies");
            Ok(())
        }
        Command::HashPassword { password } => {
            println!("{}", kontainer_server::auth::password::hash(&read_password(password)?)?);
            Ok(())
        }
        Command::User { cmd } => user_cmd(cfg, cmd).await,
        Command::MigrateMetadata { from } => migrate_metadata(cfg, from).await,
        Command::Roles => {
            let auth = kontainer_server::auth::Authenticator::new(&cfg).await?;
            for r in auth.db.list_roles().await? {
                println!("{}{}  {}", r.name, if r.is_managed { " (config)" } else { "" }, r.description);
                for g in &r.global {
                    println!("    global: {}", g.as_str());
                }
                for rule in &r.rules {
                    println!("    {} -> {}", rule.repositories.join(", "), rule.actions.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(","));
                }
            }
            Ok(())
        }
        Command::RotateEncryptionKey { batch } => rotate_encryption_key(cfg, batch).await,
        Command::EncryptionStatus => encryption_status(cfg).await,
        Command::CheckConfig => {
            let mut c = cfg;
            redact(&mut c);
            println!("{}", toml::to_string_pretty(&c)?);
            Ok(())
        }
    }
}

const REDACTED: &str = "<redacted>";

/// `cfg` without its secrets, for `check-config`. Credential fields are
/// [`kontainer_core::config::Secret`]s, which serialize as `[redacted]` on their own; what is left are
/// plain-text settings that may carry one.
fn redact(c: &mut Config) {
    // Scanner variables often carry registry or database credentials (TRIVY_PASSWORD...).
    for v in c.scanner.env.values_mut() {
        if !v.is_empty() {
            *v = REDACTED.into();
        }
    }
    for w in &mut c.webhooks {
        // Chat webhooks (Slack, Teams, Discord) carry their secret in the path.
        w.url = redact_url(&w.url);
    }
}

/// `https://user:pw@hooks.example.com/services/T0/B0/xyz?k=v` → `https://hooks.example.com/<redacted>`.
fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else { return REDACTED.into() };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest[..end].rsplit('@').next().unwrap_or_default();
    let tail = &rest[end..];
    if tail.is_empty() || tail == "/" {
        format!("{scheme}://{host}{tail}")
    } else {
        format!("{scheme}://{host}/{REDACTED}")
    }
}

/// Run `work` until it ends, or until SIGTERM / Ctrl-C: then tell it to stop through `stop`
/// and give it [`RUNNER_GRACE`] to cancel its builds and report them.
async fn until_shutdown(work: impl Future<Output = Result<()>>, stop: watch::Sender<bool>) -> Result<()> {
    tokio::pin!(work);
    tokio::select! {
        r = &mut work => r,
        _ = shutdown() => {
            let _ = stop.send(true);
            match tokio::time::timeout(RUNNER_GRACE, work).await {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!("builds didn't stop within {} seconds; exiting anyway", RUNNER_GRACE.as_secs());
                    Ok(())
                }
            }
        }
    }
}


async fn serve(cfg: Config) -> Result<()> {
    let bind = cfg.server.bind.clone();
    let state = build_state(cfg).await?;

    kontainer_server::start_background(&state).await;

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind).await.with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "registry listening");
    // The peer address is the client's address unless `server.trusted_proxies` vouch otherwise.
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).with_graceful_shutdown(shutdown()).await?;
    Ok(())
}

async fn backup(cfg: Config, output: PathBuf, with_storage: bool) -> Result<()> {
    if output.exists() {
        anyhow::bail!("{} already exists; choose a new directory", output.display());
    }
    // The dump holds password hashes and secrets: an owner-only directory.
    let mut dir = std::fs::DirBuilder::new();
    dir.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
    dir.create(&output).with_context(|| format!("creating {}", output.display()))?;
    let dump = output.join("database.dump");
    pg_dump(cfg.auth.database_url.expose(), &dump).await?;
    println!("database   {} ({} bytes)", dump.display(), std::fs::metadata(&dump)?.len());
    let (mut objects, mut bytes) = (0, 0);
    if with_storage {
        let (store, _) = open_storage(&cfg).await?;
        (objects, bytes) = store.export_to(&output.join("storage")).await.context("copying storage")?;
        println!("storage    {} ({objects} objects, {bytes} bytes)", output.join("storage").display());
        // The metadata is in the dump too; this copy restores without PostgreSQL tools
        // (`kontainer migrate-metadata --from`), and is readable.
        let db = kontainer_server::database::Db::open(cfg.auth.database_url.expose(), cfg.auth.database_pool).await?;
        let path = output.join(METADATA_FILE);
        let mut file = tokio::io::BufWriter::new(tokio::fs::File::create(&path).await.with_context(|| format!("creating {}", path.display()))?);
        let counts = kontainer_store::metadata::export_jsonl(&db, &mut file).await.context("exporting registry metadata")?;
        println!("metadata   {} ({} repositories, {} manifests, {} tags, {} blob links)", path.display(), counts.repositories, counts.manifests, counts.tags, counts.blob_links);
    }
    let manifest = serde_json::json!({
        "created_at": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "database": "database.dump",
        "storage": with_storage.then_some("storage"),
        "metadata": with_storage.then_some(METADATA_FILE),
        "storage_driver": format!("{:?}", cfg.storage.preferred_location()?.driver).to_lowercase(),
        "objects": objects,
        "bytes": bytes,
    });
    std::fs::write(output.join("backup.json"), serde_json::to_vec_pretty(&manifest)?)?;
    if !with_storage {
        println!("note: storage was not copied; back up your storage backend separately or pass --storage");
    }
    println!("backup complete: {}", output.display());
    Ok(())
}

/// `kontainer rotate-encryption-key`.
async fn rotate_encryption_key(cfg: Config, batch: i64) -> Result<()> {
    let db = kontainer_server::database::Db::open(cfg.auth.database_url.expose(), cfg.auth.database_pool).await?;
    let keyring = db.keyring();
    match keyring.current_id() {
        Some(id) => println!("re-encrypting stored secrets under key {id} (previous keys: {})", list_or_none(&keyring.previous_ids())),
        None if keyring.previous_ids().is_empty() => anyhow::bail!("no encryption key is configured: set auth.encryption_key (KONTAINER_ENCRYPTION_KEY) to the new key and list the old one in auth.previous_encryption_keys"),
        None => println!("no current key: DECRYPTING stored secrets encrypted with {}", keyring.previous_ids().join(", ")),
    }
    let mut total = 0;
    for r in db.reseal_secrets(batch).await? {
        println!("{:<28} {} re-encrypted", r.column, r.resealed);
        total += r.resealed;
    }
    println!("done: {total} secrets re-encrypted");
    Ok(())
}

/// `kontainer encryption-status`.
async fn encryption_status(cfg: Config) -> Result<()> {
    let db = kontainer_server::database::Db::open(cfg.auth.database_url.expose(), cfg.auth.database_pool).await?;
    let keyring = db.keyring();
    println!("current key   {}", keyring.current_id().unwrap_or("none (secrets are stored unencrypted)"));
    println!("previous keys {}", list_or_none(&keyring.previous_ids()));
    println!();
    println!("{:<28} {:>9} {:>9} {:>9} {:>9}", "column", "plaintext", "current", "previous", "unknown");
    let (mut previous, mut unknown, mut plaintext) = (std::collections::BTreeMap::<String, i64>::new(), std::collections::BTreeMap::<String, i64>::new(), 0);
    for s in db.encryption_status().await? {
        println!("{:<28} {:>9} {:>9} {:>9} {:>9}", s.column, s.plaintext, s.current, s.previous.values().sum::<i64>(), s.unknown.values().sum::<i64>());
        plaintext += s.plaintext;
        for (k, n) in s.previous {
            *previous.entry(k).or_default() += n;
        }
        for (k, n) in s.unknown {
            *unknown.entry(k).or_default() += n;
        }
    }
    println!();
    for (k, n) in &previous {
        println!("{n} secrets still under previous key {k}: run `kontainer rotate-encryption-key` before removing it");
    }
    for (k, n) in &unknown {
        println!("{n} secrets under key {k}, which is not configured: they can't be read until it is");
    }
    if plaintext > 0 && keyring.is_encrypting() {
        println!("{plaintext} secrets stored in plaintext: run `kontainer rotate-encryption-key` to encrypt them");
    }
    if previous.is_empty() && unknown.is_empty() && !keyring.previous_ids().is_empty() {
        println!("no secret needs the previous keys any more: they can be removed from auth.previous_encryption_keys");
    }
    Ok(())
}

fn list_or_none(ids: &[&str]) -> String {
    if ids.is_empty() { "none".into() } else { ids.join(", ") }
}

/// Storage backed by the database, as the server sets it up: upload sessions, registry
/// metadata and blob placements.
async fn open_storage(cfg: &Config) -> Result<(kontainer_store::Storage, kontainer_server::database::Db)> {
    let mut storage = kontainer_store::Storage::from_config(&cfg.storage).await?;
    let db = kontainer_server::database::Db::open(cfg.auth.database_url.expose(), cfg.auth.database_pool).await?;
    storage.uploads.set_sessions(std::sync::Arc::new(db.clone()));
    storage.set_metadata(std::sync::Arc::new(db.clone()));
    storage.set_placements(std::sync::Arc::new(db.clone()));
    Ok((storage, db))
}

/// Registry metadata in a backup, next to `storage/` (see `kontainer_store::metadata::export_jsonl`).
const METADATA_FILE: &str = "metadata.jsonl";

/// `kontainer migrate-metadata`: from the old storage layout, or from a backup's metadata file.
async fn migrate_metadata(cfg: Config, from: Option<PathBuf>) -> Result<()> {
    let db = kontainer_server::database::Db::open(cfg.auth.database_url.expose(), cfg.auth.database_pool).await?;
    let counts = match from {
        Some(path) => {
            let file = tokio::fs::File::open(&path).await.with_context(|| format!("opening {}", path.display()))?;
            kontainer_store::metadata::import_jsonl(&db, tokio::io::BufReader::new(file)).await.with_context(|| format!("importing {}", path.display()))?
        }
        None => {
            let mut storage = kontainer_store::Storage::from_config(&cfg.storage).await?;
            storage.set_metadata(std::sync::Arc::new(db.clone()));
            storage.set_placements(std::sync::Arc::new(db.clone()));
            if !storage.has_legacy_metadata().await? {
                println!("no metadata in the old layout (repositories/...) in storage; nothing to migrate");
            }
            kontainer_store::legacy::migrate(&storage).await?
        }
    };
    println!("repositories {}\nmanifests    {}\ntags         {}\nblob links   {}\nskipped      {}", counts.repositories, counts.manifests, counts.tags, counts.blob_links, counts.skipped);
    if counts.manifests + counts.tags + counts.blob_links > 0 {
        // Running instances pick the new repositories up (known repositories, search).
        db.notify(&kontainer_server::database::notify::Topic::Repos).await;
    }
    Ok(())
}

/// Dump the database at `url` into `file` with `pg_dump --format=custom` (restore it with
/// `pg_restore`). The password goes to `pg_dump` in `PGPASSWORD`, not on its command line.
async fn pg_dump(url: &str, file: &std::path::Path) -> Result<()> {
    let (url, password) = split_password(url)?;
    let mut cmd = tokio::process::Command::new("pg_dump");
    cmd.arg("--format=custom").arg("--file").arg(file).arg("--dbname").arg(&url);
    if let Some(p) = password {
        cmd.env("PGPASSWORD", p);
    }
    let out = match cmd.output().await {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("`pg_dump` was not found on PATH: install the PostgreSQL client tools (the same major version as the server, or newer) to back up the database")
        }
        Err(e) => return Err(e).context("running pg_dump"),
    };
    anyhow::ensure!(out.status.success(), "pg_dump failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr).trim());
    Ok(())
}

/// `url` without its password, and the password (percent-decoded).
fn split_password(url: &str) -> Result<(String, Option<String>)> {
    let mut u = url::Url::parse(url).map_err(|e| anyhow::anyhow!("auth.database_url is not a URL: {e}"))?;
    let password = u.password().map(percent_decode);
    if password.is_some() {
        u.set_password(None).map_err(|()| anyhow::anyhow!("auth.database_url: cannot separate the password"))?;
    }
    Ok((u.to_string(), password))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("sigterm");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    tracing::info!("shutting down");
}

/// A new password: `given` on the command line (deprecated, with a warning), else
/// `KONTAINER_PASSWORD`, else a prompt that doesn't echo (asked twice) on a terminal, else a
/// line of stdin. Always checked for strength.
fn read_password(given: Option<String>) -> Result<String> {
    let p = if let Some(p) = given {
        eprintln!("warning: a password given as an argument {ARGV_SECRET}; leave it out to be prompted, or set KONTAINER_PASSWORD");
        p
    } else if let Some(p) = std::env::var("KONTAINER_PASSWORD").ok().filter(|p| !p.is_empty()) {
        p
    } else if std::io::stdin().is_terminal() {
        let p = rpassword::prompt_password("Password: ")?;
        anyhow::ensure!(rpassword::prompt_password("Repeat the password: ")? == p, "the passwords don't match");
        p
    } else {
        let mut p = String::new();
        std::io::stdin().read_line(&mut p)?;
        p.trim_end_matches(['\r', '\n']).to_string()
    };
    anyhow::ensure!(!p.is_empty(), "no password given");
    kontainer_server::auth::password::check_strength(&p).map_err(|e| anyhow::anyhow!(e))?;
    Ok(p)
}

async fn user_cmd(cfg: Config, cmd: UserCmd) -> Result<()> {
    use kontainer_server::auth::password;
    use kontainer_server::auth::Authenticator;
    let auth = Authenticator::new(&cfg).await?;
    let db = &auth.db;
    async fn find(db: &kontainer_server::database::Db, name: &str) -> Result<kontainer_server::database::User> {
        db.user_by_name(name).await?.ok_or_else(|| anyhow::anyhow!("no such user `{name}`"))
    }
    match cmd {
        UserCmd::Create { username, password, mut roles, system, email } => {
            anyhow::ensure!(kontainer_core::perm::valid_username(&username), "invalid username");
            anyhow::ensure!(!db.name_taken(&username).await?, "that name is already used by a user or organization");
            let hash = password::hash(&read_password(password)?)?;
            if system {
                auth.ensure_system_role().await?;
                roles.push("system".into());
            }
            let known = auth.roles().await;
            for r in &roles {
                anyhow::ensure!(known.contains_key(r), "unknown role `{r}`");
            }
            let u = db.create_user(&username, Some(&hash), email.as_deref(), None, false, None, false).await?;
            db.set_user_roles(u.id, &roles).await?;
            println!("created user {} (id {}) with roles [{}]", u.username, u.id, roles.join(", "));
        }
        UserCmd::List => {
            for u in db.list_users().await? {
                let roles = db.user_roles(u.id).await?;
                println!(
                    "{:<32} {:<6} {:<8} mfa={:<5} roles=[{}]{}",
                    u.username,
                    if u.is_robot { "is_robot" } else { "user" },
                    if u.is_disabled { "is_disabled" } else { "active" },
                    u.is_mfa_enabled,
                    roles.join(", "),
                    if u.is_managed { " (config)" } else { "" }
                );
            }
        }
        UserCmd::Delete { username } => {
            let u = find(db, &username).await?;
            anyhow::ensure!(!u.is_managed, "user is defined in the config file");
            db.delete_user(u.id).await?;
            println!("deleted {username}");
        }
        UserCmd::Passwd { username, password } => {
            let u = find(db, &username).await?;
            anyhow::ensure!(!u.is_managed, "user is defined in the config file");
            db.set_password(u.id, Some(&password::hash(&read_password(password)?)?)).await?;
            db.delete_user_sessions(u.id).await?;
            println!("password updated for {username}");
        }
        UserCmd::SetRoles { username, roles } => {
            let u = find(db, &username).await?;
            anyhow::ensure!(!u.is_managed, "user is defined in the config file");
            let known = auth.roles().await;
            for r in &roles {
                anyhow::ensure!(known.contains_key(r), "unknown role `{r}`");
            }
            db.set_user_roles(u.id, &roles).await?;
            println!("roles for {username}: [{}]", roles.join(", "));
        }
        UserCmd::ResetMfa { username } => {
            let u = find(db, &username).await?;
            db.disable_mfa(u.id).await?;
            println!("two-factor authentication removed from {username}");
        }
        UserCmd::Disable { username, enable } => {
            let u = find(db, &username).await?;
            db.update_user(u.id, None, None, Some(!enable)).await?;
            if !enable {
                db.delete_user_sessions(u.id).await?;
            }
            println!("{username} is now {}", if enable { "enabled" } else { "is_disabled" });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_config_hides_secrets() {
        let mut c = Config::default();
        let secret = "hunter2-secret-value";
        c.auth.secret = Some(secret.into());
        c.auth.oidc.client_secret = secret.into();
        c.auth.ldap.bind_password = secret.into();
        c.auth.bootstrap_admin = Some(kontainer_core::config::BootstrapAdmin { username: "admin".into(), password: secret.into() });
        c.builds.runners.push(kontainer_core::config::ConfigRunner { name: "r".into(), token: secret.into(), namespaces: vec![] });
        c.metrics.token = Some(secret.into());
        c.storage.s3.secret_access_key = Some(secret.into());
        c.storage.s3.session_token = Some(secret.into());
        c.scanner.password = Some(secret.into());
        c.scanner.env.insert("TRIVY_PASSWORD".into(), secret.into());
        c.auth.database_url = format!("postgres://kontainer:{secret}@db:5432/kontainer").into();
        let mut replica: kontainer_core::config::ReplicaConfig = toml::from_str("name = \"dr\"").unwrap();
        replica.s3.session_token = Some(secret.into());
        replica.azure.access_key = Some(secret.into());
        c.storage.replicas.push(replica);
        c.webhooks.push(toml::from_str(&format!("name = \"slack\"\nurl = \"https://u:{secret}@hooks.example.com/services/{secret}\"\nheaders = {{ Authorization = \"Bearer {secret}\" }}")).unwrap());
        redact(&mut c);
        let out = toml::to_string_pretty(&c).unwrap();
        assert!(!out.contains(secret), "{out}");
        assert!(out.contains("https://hooks.example.com/<redacted>"));
        assert!(out.contains("TRIVY_PASSWORD"), "names stay, values go");
        assert!(out.contains("postgres://kontainer:***@db:5432/kontainer"), "{out}");
    }

    #[test]
    fn urls() {
        assert_eq!(redact_url("https://hooks.example.com"), "https://hooks.example.com");
        assert_eq!(redact_url("https://hooks.example.com/"), "https://hooks.example.com/");
        assert_eq!(redact_url("http://a:b@h:8080/x?y"), "http://h:8080/<redacted>");
        assert_eq!(redact_url("not a url"), "<redacted>");
    }

    #[test]
    fn database_password_stays_off_the_command_line() {
        let (url, pw) = split_password("postgres://kontainer:p%40ss%2Fw@db:5432/kontainer?sslmode=require").unwrap();
        assert_eq!(url, "postgres://kontainer@db:5432/kontainer?sslmode=require");
        assert_eq!(pw.as_deref(), Some("p@ss/w"));
        assert_eq!(split_password("postgres://db/kontainer").unwrap(), ("postgres://db/kontainer".to_string(), None));
    }

    #[test]
    fn secrets_from_flags_are_noticed() {
        let m = Cli::command().try_get_matches_from(["kontainer", "runner", "--token", "abc"]).unwrap();
        assert!(from_argv(&m, "runner", "token"));
        let m = Cli::command().try_get_matches_from(["kontainer", "runner"]).unwrap();
        assert!(!from_argv(&m, "runner", "token"));
    }
}
