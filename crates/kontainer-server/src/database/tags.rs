//! Tag history, expirations and repository states.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{now, Db};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TagEvent {
    pub id: i64,
    pub repository: String,
    pub tag: String,
    pub action: String,
    pub digest: Option<String>,
    pub previous: Option<String>,
    pub actor: String,
    #[serde(with = "super::rfc3339")]
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TagExpiration {
    pub repository: String,
    pub tag: String,
    #[serde(with = "super::rfc3339")]
    pub expires_at: DateTime<Utc>,
    pub set_by: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RepoState {
    pub repository: String,
    pub state: String,
    pub reason: Option<String>,
    pub set_by: String,
    #[serde(with = "super::rfc3339")]
    pub set_at: DateTime<Utc>,
}

impl Db {
    pub async fn record_tag_event(&self, repository: &str, tag: &str, action: &str, digest: Option<&str>, previous: Option<&str>, actor: &str) -> Result<()> {
        sqlx::query("INSERT INTO tag_events (repository, tag, action, digest, previous, actor, at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(repository)
            .bind(tag)
            .bind(action)
            .bind(digest)
            .bind(previous)
            .bind(actor)
            .bind(now())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Newest first. `tag` narrows to one tag.
    pub async fn tag_events(&self, repository: &str, tag: Option<&str>, limit: i64) -> Result<Vec<TagEvent>> {
        Ok(sqlx::query_as::<_, TagEvent>("SELECT * FROM tag_events WHERE repository = $1 AND ($2::text IS NULL OR tag = $3) ORDER BY id DESC LIMIT $4")
            .bind(repository)
            .bind(tag)
            .bind(tag)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    /// Digests that tags pointed at before a change made after `since`, by repository: what
    /// the Time Machine can still restore, so garbage collection must keep it.
    pub async fn restorable_digests(&self, since: DateTime<Utc>) -> Result<Vec<(String, String)>> {
        Ok(sqlx::query_as::<_, (String, String)>("SELECT DISTINCT repository, previous FROM tag_events WHERE previous IS NOT NULL AND at >= $1")
            .bind(since)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn prune_tag_events(&self, before: DateTime<Utc>) -> Result<u64> {
        Ok(sqlx::query("DELETE FROM tag_events WHERE at < $1").bind(before).execute(&self.pool).await?.rows_affected())
    }

    pub async fn set_tag_expiration(&self, repository: &str, tag: &str, expires_at: Option<DateTime<Utc>>, by: &str) -> Result<()> {
        match expires_at {
            Some(at) => {
                sqlx::query(
                    "INSERT INTO tag_expirations (repository, tag, expires_at, set_by) VALUES ($1, $2, $3, $4)
                     ON CONFLICT(repository, tag) DO UPDATE SET expires_at = excluded.expires_at, set_by = excluded.set_by",
                )
                .bind(repository)
                .bind(tag)
                .bind(at)
                .bind(by)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM tag_expirations WHERE repository = $1 AND tag = $2").bind(repository).bind(tag).execute(&self.pool).await?;
            }
        }
        Ok(())
    }

    pub async fn tag_expirations(&self, repository: &str) -> Result<Vec<TagExpiration>> {
        Ok(sqlx::query_as::<_, TagExpiration>("SELECT * FROM tag_expirations WHERE repository = $1").bind(repository).fetch_all(&self.pool).await?)
    }

    pub async fn due_tag_expirations(&self, now: DateTime<Utc>) -> Result<Vec<TagExpiration>> {
        Ok(sqlx::query_as::<_, TagExpiration>("SELECT * FROM tag_expirations WHERE expires_at <= $1").bind(now).fetch_all(&self.pool).await?)
    }

    pub async fn repo_state(&self, repository: &str) -> Result<Option<RepoState>> {
        Ok(sqlx::query_as::<_, RepoState>("SELECT * FROM repo_states WHERE repository = $1").bind(repository).fetch_optional(&self.pool).await?)
    }

    pub async fn repo_states(&self) -> Result<Vec<RepoState>> {
        Ok(sqlx::query_as::<_, RepoState>("SELECT * FROM repo_states").fetch_all(&self.pool).await?)
    }

    /// `normal` clears the row.
    pub async fn set_repo_state(&self, repository: &str, state: &str, reason: Option<&str>, by: &str) -> Result<()> {
        if state == "normal" {
            sqlx::query("DELETE FROM repo_states WHERE repository = $1").bind(repository).execute(&self.pool).await?;
        } else {
            sqlx::query(
                "INSERT INTO repo_states (repository, state, reason, set_by, set_at) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT(repository) DO UPDATE SET state = excluded.state, reason = excluded.reason, set_by = excluded.set_by, set_at = excluded.set_at",
            )
            .bind(repository)
            .bind(state)
            .bind(reason)
            .bind(by)
            .bind(now())
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn time_machine_secs(&self, namespace: &str) -> Result<Option<i64>> {
        Ok(sqlx::query_scalar::<_, Option<i64>>("SELECT time_machine_secs FROM organizations WHERE name = $1").bind(namespace).fetch_optional(&self.pool).await?.flatten())
    }

    pub async fn set_time_machine_secs(&self, org: &str, secs: Option<i64>) -> Result<()> {
        sqlx::query("UPDATE organizations SET time_machine_secs = $1 WHERE name = $2").bind(secs).bind(org).execute(&self.pool).await?;
        Ok(())
    }
}

/// A confirmed deletion waiting to be executed ([`Db::create_delete_plan`]).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DeletePlan {
    pub id: String,
    pub actor_id: Option<i64>,
    pub actor: String,
    pub repository: String,
    /// json `{"repository": true}` or `{"tags": [...]}`.
    pub targets: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub used_at: Option<DateTime<Utc>>,
}

impl Db {
    pub async fn create_delete_plan(&self, actor_id: Option<i64>, actor: &str, repository: &str, targets: &str, ttl: chrono::Duration) -> Result<DeletePlan> {
        let created = now();
        Ok(sqlx::query_as::<_, DeletePlan>(
            "INSERT INTO delete_plans(id, actor_id, actor, repository, targets, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        )
        .bind(super::random_token(24))
        .bind(actor_id)
        .bind(actor)
        .bind(repository)
        .bind(targets)
        .bind(created)
        .bind(created + ttl)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn delete_plan(&self, id: &str) -> Result<Option<DeletePlan>> {
        Ok(sqlx::query_as::<_, DeletePlan>("SELECT * FROM delete_plans WHERE id = $1").bind(id).fetch_optional(&self.pool).await?)
    }

    /// Mark plan `id` used, if it still is unused and unexpired: true for exactly one caller.
    pub async fn claim_delete_plan(&self, id: &str) -> Result<bool> {
        let n = sqlx::query("UPDATE delete_plans SET used_at = now() WHERE id = $1 AND used_at IS NULL AND expires_at > now()").bind(id).execute(&self.pool).await?.rows_affected();
        Ok(n == 1)
    }
}
