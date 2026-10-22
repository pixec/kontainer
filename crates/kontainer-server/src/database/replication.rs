//! Push replication rules.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{now, Db};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ReplicationRule {
    pub id: i64,
    pub name: String,
    pub registry_id: i64,
    #[serde(serialize_with = "json_list")]
    pub repositories: String,
    #[serde(serialize_with = "json_list")]
    pub tags: String,
    pub destination: String,
    pub trigger: String,
    pub interval_secs: Option<i64>,
    pub is_replicate_deletes: bool,
    pub is_enabled: bool,
    #[serde(with = "super::rfc3339::option")]
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub last_message: Option<String>,
    pub created_by: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
}

fn json_list<S: serde::Serializer>(raw: &str, s: S) -> Result<S::Ok, S::Error> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default().serialize(s)
}

impl ReplicationRule {
    pub fn repository_list(&self) -> Vec<String> {
        serde_json::from_str(&self.repositories).unwrap_or_default()
    }
    pub fn tag_list(&self) -> Vec<String> {
        serde_json::from_str(&self.tags).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplicationInput {
    pub name: String,
    pub registry_id: i64,
    #[serde(default)]
    pub repositories: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub destination: String,
    #[serde(default = "push")]
    pub trigger: String,
    #[serde(default)]
    pub interval_secs: Option<i64>,
    #[serde(default)]
    pub is_replicate_deletes: bool,
    #[serde(default = "yes")]
    pub is_enabled: bool,
}

fn push() -> String {
    "push".into()
}
fn yes() -> bool {
    true
}

impl Db {
    pub async fn replication_rules(&self) -> Result<Vec<ReplicationRule>> {
        Ok(sqlx::query_as::<_, ReplicationRule>("SELECT * FROM replication_rules ORDER BY name").fetch_all(self.pool()).await?)
    }

    pub async fn replication_rule(&self, id: i64) -> Result<Option<ReplicationRule>> {
        Ok(sqlx::query_as::<_, ReplicationRule>("SELECT * FROM replication_rules WHERE id = $1").bind(id).fetch_optional(self.pool()).await?)
    }

    pub async fn create_replication_rule(&self, i: &ReplicationInput, by: &str) -> Result<ReplicationRule> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO replication_rules (name, registry_id, repositories, tags, destination, trigger, interval_secs, is_replicate_deletes, is_enabled, created_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
        )
        .bind(i.name.trim())
        .bind(i.registry_id)
        .bind(serde_json::to_string(&i.repositories)?)
        .bind(serde_json::to_string(&i.tags)?)
        .bind(i.destination.trim().trim_matches('/'))
        .bind(&i.trigger)
        .bind(i.interval_secs)
        .bind(i.is_replicate_deletes)
        .bind(i.is_enabled)
        .bind(by)
        .bind(now())
        .fetch_one(self.pool())
        .await?;
        Ok(self.replication_rule(id).await?.expect("just created"))
    }

    pub async fn update_replication_rule(&self, id: i64, i: &ReplicationInput) -> Result<()> {
        sqlx::query(
            "UPDATE replication_rules SET name = $1, registry_id = $2, repositories = $3, tags = $4, destination = $5, trigger = $6, interval_secs = $7, \
             is_replicate_deletes = $8, is_enabled = $9 WHERE id = $10",
        )
        .bind(i.name.trim())
        .bind(i.registry_id)
        .bind(serde_json::to_string(&i.repositories)?)
        .bind(serde_json::to_string(&i.tags)?)
        .bind(i.destination.trim().trim_matches('/'))
        .bind(&i.trigger)
        .bind(i.interval_secs)
        .bind(i.is_replicate_deletes)
        .bind(i.is_enabled)
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn delete_replication_rule(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM replication_rules WHERE id = $1").bind(id).execute(self.pool()).await?;
        sqlx::query("DELETE FROM task_runs WHERE kind = $1").bind(format!("replication/{id}")).execute(self.pool()).await?;
        Ok(())
    }

    pub async fn record_replication(&self, id: i64, ok: bool, message: &str) -> Result<()> {
        sqlx::query("UPDATE replication_rules SET last_run_at = $1, last_status = $2, last_message = $3 WHERE id = $4")
            .bind(now())
            .bind(if ok { "succeeded" } else { "failed" })
            .bind(message)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}
