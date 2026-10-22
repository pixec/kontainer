//! Upstream registries, pull-through cache namespaces and mirrors.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{now, Db};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Registry {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub username: Option<String>,
    #[serde(skip)]
    pub password: Option<String>,
    pub is_insecure: bool,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    /// Changes with every edit (cached clients are keyed by it).
    #[serde(with = "super::rfc3339")]
    pub updated_at: DateTime<Utc>,
}

impl Registry {
    pub fn client(&self) -> Result<kontainer_core::upstream::Upstream> {
        kontainer_core::upstream::Upstream::new(&self.url, self.username.clone(), self.password.clone(), self.is_insecure)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryInput {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    /// `None` keeps the stored password on update; `Some("")` clears it.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub is_insecure: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ProxyCache {
    pub namespace: String,
    pub registry_id: i64,
    pub ttl_secs: i64,
    pub is_public: bool,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Mirror {
    pub id: i64,
    pub registry_id: i64,
    pub source: String,
    pub target: String,
    pub tags: Vec<String>,
    pub interval_secs: i64,
    pub is_enabled: bool,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub last_message: Option<String>,
}

#[derive(sqlx::FromRow)]
struct MirrorRow {
    id: i64,
    registry_id: i64,
    source: String,
    target: String,
    tags: String,
    interval_secs: i64,
    is_enabled: bool,
    created_at: DateTime<Utc>,
    last_sync_at: Option<DateTime<Utc>>,
    last_status: Option<String>,
    last_message: Option<String>,
}

impl From<MirrorRow> for Mirror {
    fn from(r: MirrorRow) -> Self {
        Self {
            id: r.id,
            registry_id: r.registry_id,
            source: r.source,
            target: r.target,
            tags: serde_json::from_str(&r.tags).unwrap_or_default(),
            interval_secs: r.interval_secs,
            is_enabled: r.is_enabled,
            created_at: r.created_at,
            last_sync_at: r.last_sync_at,
            last_status: r.last_status,
            last_message: r.last_message,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MirrorInput {
    pub registry_id: i64,
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "hourly")]
    pub interval_secs: i64,
    #[serde(default = "yes")]
    pub is_enabled: bool,
}

fn hourly() -> i64 {
    3600
}
fn yes() -> bool {
    true
}

impl Db {
    /// A trivial query, for health checks.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1::BIGINT").fetch_one(&self.pool).await?;
        Ok(())
    }

    /// `r` with its password decrypted (see [`super::secrets`]).
    fn open_registry(&self, mut r: Registry) -> Result<Registry> {
        r.password = self.open_secret_opt("registries.password", r.id, r.password.take())?;
        Ok(r)
    }

    pub async fn registries(&self) -> Result<Vec<Registry>> {
        sqlx::query_as::<_, Registry>("SELECT * FROM registries ORDER BY name").fetch_all(&self.pool).await?.into_iter().map(|r| self.open_registry(r)).collect()
    }

    pub async fn registry(&self, id: i64) -> Result<Option<Registry>> {
        sqlx::query_as::<_, Registry>("SELECT * FROM registries WHERE id = $1").bind(id).fetch_optional(&self.pool).await?.map(|r| self.open_registry(r)).transpose()
    }

    pub async fn create_registry(&self, r: &RegistryInput) -> Result<Registry> {
        let id: i64 = sqlx::query_scalar("INSERT INTO registries(name, url, username, password, is_insecure, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id")
            .bind(&r.name)
            .bind(&r.url)
            .bind(r.username.as_deref().filter(|u| !u.is_empty()))
            .bind(self.seal_secret_opt(r.password.as_deref().filter(|p| !p.is_empty())))
            .bind(r.is_insecure)
            .bind(now())
            .fetch_one(&self.pool)
            .await?;
        Ok(self.registry(id).await?.expect("just inserted"))
    }

    pub async fn update_registry(&self, id: i64, r: &RegistryInput) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // `clock_timestamp()` rather than the API's `now()`: two edits in quick succession must
        // still differ, or an instance could keep a client built from the first.
        sqlx::query("UPDATE registries SET name = $1, url = $2, username = $3, is_insecure = $4, updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond') WHERE id = $5")
            .bind(&r.name)
            .bind(&r.url)
            .bind(r.username.as_deref().filter(|u| !u.is_empty()))
            .bind(r.is_insecure)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if let Some(p) = &r.password {
            sqlx::query("UPDATE registries SET password = $1 WHERE id = $2").bind(self.seal_secret_opt(Some(p.as_str()).filter(|p| !p.is_empty()))).bind(id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn delete_registry(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM registries WHERE id = $1").bind(id).execute(&self.pool).await?;
        // Its pull-through caches went with it.
        self.notify(&super::notify::Topic::Proxies).await;
        Ok(())
    }

    pub async fn proxy_caches(&self) -> Result<Vec<ProxyCache>> {
        Ok(sqlx::query_as::<_, ProxyCache>("SELECT * FROM proxy_caches ORDER BY namespace").fetch_all(&self.pool).await?)
    }

    pub async fn proxy_cache(&self, namespace: &str) -> Result<Option<ProxyCache>> {
        Ok(sqlx::query_as::<_, ProxyCache>("SELECT * FROM proxy_caches WHERE namespace = $1").bind(namespace).fetch_optional(&self.pool).await?)
    }

    pub async fn set_proxy_cache(&self, namespace: &str, registry_id: i64, ttl_secs: i64, is_public: bool) -> Result<()> {
        sqlx::query(
            "INSERT INTO proxy_caches(namespace, registry_id, ttl_secs, is_public, created_at) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(namespace) DO UPDATE SET registry_id = excluded.registry_id, ttl_secs = excluded.ttl_secs, is_public = excluded.is_public",
        )
        .bind(namespace)
        .bind(registry_id)
        .bind(ttl_secs)
        .bind(is_public)
        .bind(now())
        .execute(&self.pool)
        .await?;
        self.notify(&super::notify::Topic::Proxies).await;
        Ok(())
    }

    pub async fn delete_proxy_cache(&self, namespace: &str) -> Result<()> {
        sqlx::query("DELETE FROM proxy_caches WHERE namespace = $1").bind(namespace).execute(&self.pool).await?;
        self.notify(&super::notify::Topic::Proxies).await;
        Ok(())
    }

    pub async fn mirrors(&self) -> Result<Vec<Mirror>> {
        Ok(sqlx::query_as::<_, MirrorRow>("SELECT * FROM mirrors ORDER BY target").fetch_all(&self.pool).await?.into_iter().map(Into::into).collect())
    }

    pub async fn mirror(&self, id: i64) -> Result<Option<Mirror>> {
        Ok(sqlx::query_as::<_, MirrorRow>("SELECT * FROM mirrors WHERE id = $1").bind(id).fetch_optional(&self.pool).await?.map(Into::into))
    }

    pub async fn create_mirror(&self, m: &MirrorInput) -> Result<Mirror> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO mirrors(registry_id, source, target, tags, interval_secs, is_enabled, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(m.registry_id)
        .bind(&m.source)
        .bind(&m.target)
        .bind(serde_json::to_string(&m.tags)?)
        .bind(m.interval_secs)
        .bind(m.is_enabled)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        Ok(self.mirror(id).await?.expect("just inserted"))
    }

    pub async fn update_mirror(&self, id: i64, m: &MirrorInput) -> Result<()> {
        sqlx::query("UPDATE mirrors SET registry_id = $1, source = $2, target = $3, tags = $4, interval_secs = $5, is_enabled = $6 WHERE id = $7")
            .bind(m.registry_id)
            .bind(&m.source)
            .bind(&m.target)
            .bind(serde_json::to_string(&m.tags)?)
            .bind(m.interval_secs)
            .bind(m.is_enabled)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_mirror(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM mirrors WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn record_mirror_sync(&self, id: i64, ok: bool, message: &str) -> Result<()> {
        sqlx::query("UPDATE mirrors SET last_sync_at = $1, last_status = $2, last_message = $3 WHERE id = $4")
            .bind(now())
            .bind(if ok { "ok" } else { "error" })
            .bind(message)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
