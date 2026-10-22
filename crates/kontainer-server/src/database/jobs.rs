//! Background jobs (imports, manual mirror syncs, storage location syncs): one row each, so that every
//! instance lists every job. The owner ([`Db::instance_id`]) records progress and, with each
//! update, learns whether a cancel was requested elsewhere (see [`crate::state::AppState::spawn_job`]).

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};

use super::{now, Db};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JobRow {
    pub id: String,
    pub kind: String,
    pub subject: String,
    pub actor: String,
    /// `running`, `done`, `failed` or `cancelled`.
    pub status: String,
    pub message: Option<String>,
    pub error: Option<String>,
    pub instance_id: String,
    pub is_cancel_requested: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl Db {
    /// Record a job this instance is about to run.
    pub async fn create_job(&self, id: &str, kind: &str, subject: &str, actor: &str) -> Result<()> {
        let at = now();
        sqlx::query("INSERT INTO jobs (id, kind, subject, actor, status, instance_id, created_at, updated_at) VALUES ($1, $2, $3, $4, 'running', $5, $6, $6)")
            .bind(id)
            .bind(kind)
            .bind(subject)
            .bind(actor)
            .bind(self.instance_id())
            .bind(at)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The owner's heartbeat, with its latest progress message if any. Returns whether a
    /// cancel was requested (`false` once the job is no longer running).
    pub async fn job_progress(&self, id: &str, message: Option<&str>) -> Result<bool> {
        let cancel: Option<bool> = sqlx::query_scalar("UPDATE jobs SET updated_at = $1, message = COALESCE($2, message) WHERE id = $3 AND status = 'running' RETURNING is_cancel_requested")
            .bind(now())
            .bind(message)
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
        Ok(cancel.unwrap_or(false))
    }

    /// Record how a job ended: `done` (with its result in `message`), `failed` (with `error`)
    /// or `cancelled`.
    pub async fn finish_job(&self, id: &str, status: &str, message: Option<&str>, error: Option<&str>) -> Result<()> {
        let at = now();
        sqlx::query("UPDATE jobs SET status = $1, message = COALESCE($2, message), error = $3, updated_at = $4, finished_at = $4 WHERE id = $5 AND status = 'running'")
            .bind(status)
            .bind(message)
            .bind(error)
            .bind(at)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Ask the instance running job `id` to cancel it. `false` when it is not running.
    pub async fn request_job_cancel(&self, id: &str) -> Result<bool> {
        Ok(sqlx::query("UPDATE jobs SET is_cancel_requested = true WHERE id = $1 AND status = 'running'").bind(id).execute(self.pool()).await?.rows_affected() == 1)
    }

    pub async fn job(&self, id: &str) -> Result<Option<JobRow>> {
        Ok(sqlx::query_as::<_, JobRow>("SELECT * FROM jobs WHERE id = $1").bind(id).fetch_optional(self.pool()).await?)
    }

    /// The newest `limit` jobs, of every instance; only `actor`'s when given.
    pub async fn list_jobs(&self, actor: Option<&str>, limit: i64) -> Result<Vec<JobRow>> {
        Ok(sqlx::query_as::<_, JobRow>("SELECT * FROM jobs WHERE ($1::text IS NULL OR actor = $1) ORDER BY created_at DESC, id LIMIT $2")
            .bind(actor)
            .bind(limit)
            .fetch_all(self.pool())
            .await?)
    }

    /// Fail running jobs whose owner stopped updating them `stale_after` ago: it died.
    pub async fn fail_stale_jobs(&self, stale_after: Duration) -> Result<u64> {
        let at = now();
        let cutoff = at - chrono::Duration::from_std(stale_after).unwrap_or_default();
        Ok(sqlx::query("UPDATE jobs SET status = 'failed', error = 'Interrupted: the instance running it stopped', updated_at = $1, finished_at = $1 WHERE status = 'running' AND updated_at < $2")
            .bind(at)
            .bind(cutoff)
            .execute(self.pool())
            .await?
            .rows_affected())
    }
}
