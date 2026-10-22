//! Namespace quotas and tag retention policies.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{now, Db};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub id: i64,
    pub namespace: String,
    /// Glob relative to the namespace; `**` is every repository.
    pub repositories: String,
    /// Keep this many most recently pushed tags per repository.
    pub keep_last: Option<i64>,
    /// Delete tags pushed more than this many days ago.
    pub max_age_days: Option<i64>,
    /// Tag globs that are never deleted (e.g. `latest`, `v*`).
    pub protect: Vec<String>,
    pub is_enabled: bool,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_deleted: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    id: i64,
    namespace: String,
    repositories: String,
    keep_last: Option<i64>,
    max_age_days: Option<i64>,
    protect: String,
    is_enabled: bool,
    created_at: DateTime<Utc>,
    last_run_at: Option<DateTime<Utc>>,
    last_deleted: Option<i64>,
}

impl From<PolicyRow> for RetentionPolicy {
    fn from(r: PolicyRow) -> Self {
        Self {
            id: r.id,
            namespace: r.namespace,
            repositories: r.repositories,
            keep_last: r.keep_last,
            max_age_days: r.max_age_days,
            protect: serde_json::from_str(&r.protect).unwrap_or_default(),
            is_enabled: r.is_enabled,
            created_at: r.created_at,
            last_run_at: r.last_run_at,
            last_deleted: r.last_deleted,
        }
    }
}

/// The editable part of a policy.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyInput {
    #[serde(default = "all")]
    pub repositories: String,
    #[serde(default)]
    pub keep_last: Option<i64>,
    #[serde(default)]
    pub max_age_days: Option<i64>,
    #[serde(default)]
    pub protect: Vec<String>,
    #[serde(default = "yes")]
    pub is_enabled: bool,
}

fn all() -> String {
    "**".into()
}
fn yes() -> bool {
    true
}

impl Db {
    /// The namespace's own quota row: `Some(0)` means explicitly unlimited.
    pub async fn quota(&self, namespace: &str) -> Result<Option<u64>> {
        let v: Option<i64> = sqlx::query_scalar("SELECT max_bytes FROM quotas WHERE namespace = $1").bind(namespace).fetch_optional(&self.pool).await?;
        Ok(v.map(|b| b as u64))
    }

    /// Namespaces with a limit of their own (not the unlimited ones).
    pub async fn all_quotas(&self) -> Result<Vec<(String, u64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as("SELECT namespace, max_bytes FROM quotas WHERE max_bytes > 0 ORDER BY namespace").fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|(n, b)| (n, b as u64)).collect())
    }

    pub async fn set_quota(&self, namespace: &str, max_bytes: Option<u64>) -> Result<()> {
        match max_bytes {
            Some(b) => sqlx::query("INSERT INTO quotas(namespace, max_bytes, updated_at) VALUES ($1, $2, $3) ON CONFLICT(namespace) DO UPDATE SET max_bytes = excluded.max_bytes, updated_at = excluded.updated_at")
                .bind(namespace)
                .bind(b as i64)
                .bind(now())
                .execute(&self.pool)
                .await?,
            None => sqlx::query("DELETE FROM quotas WHERE namespace = $1").bind(namespace).execute(&self.pool).await?,
        };
        Ok(())
    }

    pub async fn retention_policies(&self, namespace: Option<&str>) -> Result<Vec<RetentionPolicy>> {
        let rows = match namespace {
            Some(ns) => sqlx::query_as::<_, PolicyRow>("SELECT * FROM retention_policies WHERE namespace = $1 ORDER BY id").bind(ns).fetch_all(&self.pool).await?,
            None => sqlx::query_as::<_, PolicyRow>("SELECT * FROM retention_policies ORDER BY id").fetch_all(&self.pool).await?,
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn retention_policy(&self, id: i64) -> Result<Option<RetentionPolicy>> {
        Ok(sqlx::query_as::<_, PolicyRow>("SELECT * FROM retention_policies WHERE id = $1").bind(id).fetch_optional(&self.pool).await?.map(Into::into))
    }

    pub async fn create_retention_policy(&self, namespace: &str, p: &PolicyInput) -> Result<RetentionPolicy> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO retention_policies(namespace, repositories, keep_last, max_age_days, protect, is_enabled, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(namespace)
        .bind(&p.repositories)
        .bind(p.keep_last)
        .bind(p.max_age_days)
        .bind(serde_json::to_string(&p.protect)?)
        .bind(p.is_enabled)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        Ok(self.retention_policy(id).await?.expect("just inserted"))
    }

    pub async fn update_retention_policy(&self, id: i64, p: &PolicyInput) -> Result<()> {
        sqlx::query("UPDATE retention_policies SET repositories = $1, keep_last = $2, max_age_days = $3, protect = $4, is_enabled = $5 WHERE id = $6")
            .bind(&p.repositories)
            .bind(p.keep_last)
            .bind(p.max_age_days)
            .bind(serde_json::to_string(&p.protect)?)
            .bind(p.is_enabled)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_retention_policy(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM retention_policies WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn record_retention_run(&self, id: i64, deleted: usize) -> Result<()> {
        sqlx::query("UPDATE retention_policies SET last_run_at = $1, last_deleted = $2 WHERE id = $3").bind(now()).bind(deleted as i64).bind(id).execute(&self.pool).await?;
        Ok(())
    }
}
