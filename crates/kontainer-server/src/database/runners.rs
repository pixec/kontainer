//! Build runners and the namespaces they serve.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{now, sha256_hex, Db};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Runner {
    pub id: i64,
    pub name: String,
    /// Self-hosted: the user or organization it belongs to. `None`: shared.
    pub namespace: Option<String>,
    pub is_all_namespaces: bool,
    #[serde(skip)]
    pub token_hash: String,
    pub is_enabled: bool,
    pub is_from_config: bool,
    pub created_by: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub last_seen_at: Option<DateTime<Utc>>,
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub executor: Option<String>,
    pub concurrency: Option<i64>,
    pub running: Option<i64>,
}

/// What a runner reports about itself when it asks for work.
#[derive(Debug, Clone, Default)]
pub struct RunnerReport<'a> {
    pub hostname: &'a str,
    pub version: &'a str,
    pub executor: &'a str,
    pub concurrency: i64,
    pub running: i64,
}

impl Db {
    pub async fn runner(&self, id: i64) -> Result<Option<Runner>> {
        Ok(sqlx::query_as::<_, Runner>("SELECT * FROM runners WHERE id = $1").bind(id).fetch_optional(self.pool()).await?)
    }

    /// The enabled runner `token` belongs to.
    pub async fn runner_by_token(&self, token: &str) -> Result<Option<Runner>> {
        Ok(sqlx::query_as::<_, Runner>("SELECT * FROM runners WHERE token_hash = $1 AND is_enabled = true").bind(sha256_hex(token)).fetch_optional(self.pool()).await?)
    }

    /// Every runner (administrators).
    pub async fn runners(&self) -> Result<Vec<Runner>> {
        Ok(sqlx::query_as::<_, Runner>("SELECT * FROM runners ORDER BY namespace IS NOT NULL, namespace, name").fetch_all(self.pool()).await?)
    }

    /// `namespace`'s own runners, and the shared ones that serve it.
    pub async fn runners_for(&self, namespace: &str) -> Result<Vec<Runner>> {
        Ok(sqlx::query_as::<_, Runner>(
            "SELECT * FROM runners WHERE namespace = $1 \
             OR (namespace IS NULL AND (is_all_namespaces = true OR id IN (SELECT runner_id FROM runner_namespaces WHERE namespace = $1))) \
             ORDER BY namespace IS NULL, name",
        )
        .bind(namespace)
        .fetch_all(self.pool())
        .await?)
    }

    /// Does an enabled runner serve `namespace`? (Whether it gets builds at all.)
    pub async fn has_runner_for(&self, namespace: &str) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM runners WHERE is_enabled = true AND (namespace = $1 \
             OR (namespace IS NULL AND (is_all_namespaces = true OR id IN (SELECT runner_id FROM runner_namespaces WHERE namespace = $1))))",
        )
        .bind(namespace)
        .fetch_one(self.pool())
        .await?
            > 0)
    }

    /// The namespaces shared runner `id` was assigned (not counting `is_all_namespaces`).
    pub async fn runner_namespaces(&self, id: i64) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT namespace FROM runner_namespaces WHERE runner_id = $1 ORDER BY namespace").bind(id).fetch_all(self.pool()).await?)
    }

    /// The namespaces `r` takes builds from; `None`: all of them.
    pub async fn runner_scope(&self, r: &Runner) -> Result<Option<Vec<String>>> {
        Ok(match (&r.namespace, r.is_all_namespaces) {
            (Some(ns), _) => Some(vec![ns.clone()]),
            (None, true) => None,
            (None, false) => Some(self.runner_namespaces(r.id).await?),
        })
    }

    pub async fn create_runner(&self, name: &str, namespace: Option<&str>, is_all: bool, token: &str, by: &str) -> Result<Runner> {
        let id: i64 = sqlx::query_scalar("INSERT INTO runners (name, namespace, is_all_namespaces, token_hash, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id")
            .bind(name)
            .bind(namespace)
            .bind(is_all && namespace.is_none())
            .bind(sha256_hex(token))
            .bind(by)
            .bind(now())
            .fetch_one(self.pool())
            .await?;
        Ok(self.runner(id).await?.expect("just inserted"))
    }

    pub async fn update_runner(&self, id: i64, name: &str, is_enabled: bool, is_all: bool) -> Result<()> {
        sqlx::query("UPDATE runners SET name = $1, is_enabled = $2, is_all_namespaces = (namespace IS NULL AND $3) WHERE id = $4").bind(name).bind(is_enabled).bind(is_all).bind(id).execute(self.pool()).await?;
        Ok(())
    }

    /// Replace the namespaces shared runner `id` serves.
    pub async fn set_runner_namespaces(&self, id: i64, namespaces: &[String]) -> Result<()> {
        let mut tx = self.pool().begin().await?;
        sqlx::query("DELETE FROM runner_namespaces WHERE runner_id = $1").bind(id).execute(&mut *tx).await?;
        for ns in namespaces {
            sqlx::query("INSERT INTO runner_namespaces (runner_id, namespace) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(id).bind(ns).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_runner_token(&self, id: i64, token: &str) -> Result<()> {
        sqlx::query("UPDATE runners SET token_hash = $1 WHERE id = $2").bind(sha256_hex(token)).bind(id).execute(self.pool()).await?;
        Ok(())
    }

    pub async fn delete_runner(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM runners WHERE id = $1").bind(id).execute(self.pool()).await?;
        Ok(())
    }

    /// Runner `id` asked for work.
    pub async fn runner_seen(&self, id: i64, r: &RunnerReport<'_>) -> Result<()> {
        sqlx::query("UPDATE runners SET last_seen_at = $1, hostname = $2, version = $3, executor = $4, concurrency = $5, running = $6 WHERE id = $7")
            .bind(now())
            .bind(r.hostname)
            .bind(r.version)
            .bind(r.executor)
            .bind(r.concurrency)
            .bind(r.running)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Make the configured shared runners (`name`, `token`, namespaces; empty: all) the ones
    /// marked as from the configuration: create or update them, and remove those no longer listed.
    pub async fn sync_config_runners(&self, runners: &[(String, String, Vec<String>)]) -> Result<()> {
        let names: Vec<&str> = runners.iter().map(|(n, _, _)| n.as_str()).collect();
        for r in sqlx::query_as::<_, Runner>("SELECT * FROM runners WHERE is_from_config = true").fetch_all(self.pool()).await? {
            if !names.contains(&r.name.as_str()) {
                self.delete_runner(r.id).await?;
            }
        }
        for (name, token, namespaces) in runners {
            let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM runners WHERE is_from_config = true AND name = $1").bind(name).fetch_optional(self.pool()).await?;
            let id = match existing {
                Some(id) => {
                    sqlx::query("UPDATE runners SET token_hash = $1, is_all_namespaces = $2, is_enabled = true WHERE id = $3").bind(sha256_hex(token)).bind(namespaces.is_empty()).bind(id).execute(self.pool()).await?;
                    id
                }
                None => sqlx::query_scalar("INSERT INTO runners (name, is_all_namespaces, token_hash, is_from_config, created_by, created_at) VALUES ($1, $2, $3, true, 'config', $4) RETURNING id")
                    .bind(name)
                    .bind(namespaces.is_empty())
                    .bind(sha256_hex(token))
                    .bind(now())
                    .fetch_one(self.pool())
                    .await?,
            };
            self.set_runner_namespaces(id, namespaces).await?;
        }
        Ok(())
    }
}
