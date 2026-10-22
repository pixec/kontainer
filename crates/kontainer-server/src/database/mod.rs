//! PostgreSQL persistence via sqlx: accounts and roles ([`users`]), organizations and teams
//! ([`orgs`]), repository catalogue entries ([`repos`]), and the registry's own metadata:
//! manifests, tags and blob links ([`registry`]). Blob bytes live in object storage; this
//! database holds everything that needs transactions and lookups.

pub mod builds;
pub mod jobs;
pub mod locks;
pub mod notify;
pub mod orgs;
pub mod placements;
pub mod policies;
pub mod remote;
pub mod registry;
pub mod replication;
pub mod repos;
pub mod tags;
pub mod runners;
pub mod secrets;
pub mod scan_jobs;
pub mod security;
pub mod sso;
pub mod tasks;
pub mod uploads;
pub mod users;
pub mod webhooks;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

use kontainer_core::config::{redact_url_password, Config};
use kontainer_core::crypto::Keyring;
use kontainer_core::random_token;

pub use orgs::{Organization, RepoGrant, Team};
pub use repos::{RepoMeta, Visibility};
pub use users::{AccessToken, Identity, OidcState, Profile, Session, User};

#[derive(Clone)]
pub struct Db {
    pool: PgPool,
    /// Who this process is among the instances sharing the database ([`Db::instance_id`]).
    instance: std::sync::Arc<str>,
    /// Seals the secrets this database stores and opens them again ([`secrets`]).
    keyring: std::sync::Arc<Keyring>,
}

/// Keyrings by database URL, for [`Db::open`]: see [`install_keyring`].
static KEYRINGS: std::sync::LazyLock<std::sync::RwLock<std::collections::HashMap<String, std::sync::Arc<Keyring>>>> = std::sync::LazyLock::new(Default::default);

/// Make every [`Db::open`] of `url` in this process use `keyring` for secrets at rest.
pub fn register_keyring(url: &str, keyring: Keyring) -> std::sync::Arc<Keyring> {
    let keyring = std::sync::Arc::new(keyring);
    KEYRINGS.write().unwrap_or_else(|e| e.into_inner()).insert(url.to_string(), keyring.clone());
    keyring
}

/// The keyring `cfg` describes (`auth.encryption_key`, `auth.previous_encryption_keys`,
/// `auth.secret`), registered for its database: what the server and the CLI call first.
pub fn install_keyring(cfg: &Config) -> std::sync::Arc<Keyring> {
    register_keyring(cfg.auth.database_url.expose(), Keyring::from_config(&cfg.auth))
}

/// Meta keys whose values are secrets, sealed like the secret columns.
pub const SECRET_META_KEYS: &[&str] = &["jwt_secret"];

/// A new instance id: the host name and a random part, so a restarted process (or a second
/// [`Db`] in one test process) never passes for an earlier one.
fn new_instance_id() -> String {
    let host = std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| "kontainer".into());
    format!("{host}/{}", random_token(6))
}

/// The current time, as stored in the database's TIMESTAMPTZ columns.
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Serde for timestamps in API responses: RFC 3339 as `to_rfc3339` writes it
/// (`2026-10-14T15:04:05.123456+00:00`), the format the API has always used, rather than
/// chrono's default `...Z`. Use with `#[serde(with = "crate::database::rfc3339")]`, or `::option`.
pub mod rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&t.to_rfc3339())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        DateTime::<Utc>::deserialize(d)
    }

    pub mod option {
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(t: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
            match t {
                Some(t) => s.serialize_some(&t.to_rfc3339()),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
            Option::<DateTime<Utc>>::deserialize(d)
        }
    }
}

impl Db {
    /// Connect to the PostgreSQL database at `url` with at most `max_connections`, and bring
    /// its schema up to date. The database itself must exist.
    pub async fn open(url: &str, max_connections: u32) -> Result<Self> {
        let shown = redact_url_password(url);
        let opts: PgConnectOptions = url.parse().with_context(|| format!("invalid database URL {shown}"))?;
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(opts)
            .await
            .with_context(|| format!("connecting to the database at {shown}"))?;
        sqlx::migrate!("./migrations").run(&pool).await.context("running database migrations")?;
        let keyring = KEYRINGS.read().unwrap_or_else(|e| e.into_inner()).get(url).cloned().unwrap_or_default();
        Ok(Self { pool, instance: new_instance_id().into(), keyring })
    }

    /// This handle with `keyring` for secrets at rest, rather than the one registered for its URL.
    pub fn with_keyring(mut self, keyring: Keyring) -> Self {
        self.keyring = std::sync::Arc::new(keyring);
        self
    }

    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// `plain`, ready for a secret column.
    pub fn seal_secret(&self, plain: &str) -> String {
        self.keyring.seal(plain)
    }

    /// [`Db::seal_secret`] for an optional value.
    pub fn seal_secret_opt(&self, plain: Option<&str>) -> Option<String> {
        plain.map(|p| self.keyring.seal(p))
    }

    /// The plaintext of `column` (`table.column`) in row `row`, as stored.
    pub fn open_secret(&self, column: &str, row: impl std::fmt::Display, stored: &str) -> Result<String> {
        self.keyring.open(stored).with_context(|| format!("reading {column} of row {row}"))
    }

    /// [`Db::open_secret`] for a nullable column.
    pub fn open_secret_opt(&self, column: &str, row: impl std::fmt::Display, stored: Option<String>) -> Result<Option<String>> {
        stored.map(|s| self.open_secret(column, row, &s)).transpose()
    }

    fn seal_meta(&self, key: &str, value: &str) -> String {
        if SECRET_META_KEYS.contains(&key) { self.seal_secret(value) } else { value.to_string() }
    }

    /// This instance's id, recorded on the work it owns (task runs, jobs, usage reports).
    pub fn instance_id(&self) -> &str {
        &self.instance
    }

    /// Store `value` under `key` unless something is there already, and return what is stored:
    /// instances starting together agree on the first value written.
    pub async fn meta_init(&self, key: &str, value: &str) -> Result<String> {
        sqlx::query("INSERT INTO meta(key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING").bind(key).bind(self.seal_meta(key, value)).execute(&self.pool).await?;
        self.meta_get(key).await?.with_context(|| format!("meta `{key}` vanished right after it was written"))
    }

    pub async fn meta_get(&self, key: &str) -> Result<Option<String>> {
        let value: Option<String> = sqlx::query_scalar("SELECT value FROM meta WHERE key = $1").bind(key).fetch_optional(&self.pool).await?;
        match value {
            Some(v) if SECRET_META_KEYS.contains(&key) => Ok(Some(self.open_secret("meta.value", key, &v)?)),
            v => Ok(v),
        }
    }

    pub async fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query("INSERT INTO meta(key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(key)
            .bind(self.seal_meta(key, value))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The shared storage report (json) and when it was computed.
    pub async fn usage_report(&self) -> Result<Option<(String, DateTime<Utc>)>> {
        Ok(sqlx::query_as("SELECT report, computed_at FROM usage_reports").fetch_optional(&self.pool).await?)
    }

    /// Replace the shared storage report with one this instance computed.
    pub async fn put_usage_report(&self, report: &str, computed_at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "INSERT INTO usage_reports (id, report, computed_at, instance_id) VALUES (true, $1, $2, $3)
             ON CONFLICT (id) DO UPDATE SET report = excluded.report, computed_at = excluded.computed_at, instance_id = excluded.instance_id",
        )
        .bind(report)
        .bind(computed_at)
        .bind(self.instance_id())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// URL-safe random string of `bytes` random bytes (hex encoded).
pub fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}
