//! History of maintenance runs.
//!
//! A run is owned by the instance that started it ([`Db::instance_id`]), which refreshes its
//! `heartbeat_at` every [`HEARTBEAT`] while it is `running`. A run whose heartbeat is older
//! than [`STALE_AFTER`] belongs to an instance that died: it is marked failed, at startup and
//! periodically, by whichever instance notices first. Another instance's live run is left alone.

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{now, Db};

/// Runs kept per kind.
const KEEP_RUNS: i64 = 100;

/// How often a running task says it is still alive.
pub const HEARTBEAT: Duration = Duration::from_secs(30);

/// A `running` run without a heartbeat for this long was interrupted.
pub const STALE_AFTER: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TaskRun {
    pub id: i64,
    pub kind: String,
    pub trigger: String,
    pub actor: String,
    pub status: String,
    pub summary: Option<String>,
    #[serde(skip)]
    pub details: Option<String>,
    #[serde(with = "super::rfc3339")]
    pub started_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub finished_at: Option<DateTime<Utc>>,
}

impl Db {
    /// Record the start of a run owned by this instance. Until it is finished, the run's
    /// heartbeat is refreshed every [`HEARTBEAT`] in the background.
    pub async fn start_task_run(&self, kind: &str, trigger: &str, actor: &str) -> Result<i64> {
        let at = now();
        let id: i64 = sqlx::query_scalar("INSERT INTO task_runs (kind, trigger, actor, status, started_at, instance_id, heartbeat_at) VALUES ($1, $2, $3, 'running', $4, $5, $4) RETURNING id")
            .bind(kind)
            .bind(trigger)
            .bind(actor)
            .bind(at)
            .bind(self.instance_id())
            .fetch_one(self.pool())
            .await?;
        self.spawn_task_heartbeat(id, HEARTBEAT);
        sqlx::query("DELETE FROM task_runs WHERE kind = $1 AND id NOT IN (SELECT id FROM task_runs WHERE kind = $2 ORDER BY id DESC LIMIT $3)")
            .bind(kind)
            .bind(kind)
            .bind(KEEP_RUNS)
            .execute(self.pool())
            .await?;
        Ok(id)
    }

    pub async fn finish_task_run(&self, id: i64, ok: bool, summary: &str, details: Option<&serde_json::Value>) -> Result<()> {
        sqlx::query("UPDATE task_runs SET status = $1, summary = $2, details = $3, finished_at = $4 WHERE id = $5")
            .bind(if ok { "succeeded" } else { "failed" })
            .bind(summary)
            .bind(details.map(|d| d.to_string()))
            .bind(now())
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn task_runs(&self, kind: &str, limit: i64) -> Result<Vec<TaskRun>> {
        Ok(sqlx::query_as::<_, TaskRun>("SELECT * FROM task_runs WHERE kind = $1 ORDER BY id DESC LIMIT $2").bind(kind).bind(limit).fetch_all(self.pool()).await?)
    }

    /// The last finished run of `kind` started by the schedule, to know when the next is due.
    pub async fn last_scheduled_run(&self, kind: &str) -> Result<Option<DateTime<Utc>>> {
        Ok(sqlx::query_scalar("SELECT started_at FROM task_runs WHERE kind = $1 AND trigger = 'schedule' ORDER BY id DESC LIMIT 1").bind(kind).fetch_optional(self.pool()).await?)
    }

    /// Refresh run `id`'s heartbeat every `every` until it is no longer running (or the
    /// database says it is gone).
    fn spawn_task_heartbeat(&self, id: i64, every: Duration) {
        let db = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                match sqlx::query("UPDATE task_runs SET heartbeat_at = $1 WHERE id = $2 AND status = 'running'").bind(now()).bind(id).execute(db.pool()).await {
                    Ok(r) if r.rows_affected() == 0 => return,
                    Ok(_) => {}
                    Err(e) => tracing::warn!(run = id, error = %e, "refreshing a maintenance run's heartbeat"),
                }
            }
        });
    }

    /// Mark as failed the runs that can never finish: anyone's whose heartbeat is older than
    /// `stale_after` (the instance running it died) and, `at_startup`, this instance's own
    /// (nothing of ours runs yet, so a run under our id is left over). Live runs of other
    /// instances are never touched.
    pub async fn fail_interrupted_task_runs(&self, stale_after: Duration, at_startup: bool) -> Result<u64> {
        let cutoff = now() - chrono::Duration::from_std(stale_after).unwrap_or_default();
        Ok(sqlx::query(
            "UPDATE task_runs SET status = 'failed', summary = 'Interrupted: the instance running it stopped', finished_at = $1
             WHERE status = 'running' AND (($2 AND instance_id = $3) OR instance_id IS NULL OR heartbeat_at IS NULL OR heartbeat_at < $4)",
        )
        .bind(now())
        .bind(at_startup)
        .bind(self.instance_id())
        .bind(cutoff)
        .execute(self.pool())
        .await?
        .rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::database::test_support::fresh_database_url;
    use crate::database::Db;

    #[tokio::test]
    async fn startup_fails_only_dead_runs_never_another_instances_live_one() {
        let url = fresh_database_url();
        let (a, b) = (Db::open(&url, 2).await.unwrap(), Db::open(&url, 2).await.unwrap());
        assert_ne!(a.instance_id(), b.instance_id());
        let live = a.start_task_run("gc", "manual", "root").await.unwrap();
        // A run of an instance that died ten minutes ago, and one of a live instance that last
        // checked in a minute ago.
        let dead = b.start_task_run("scan_all", "schedule", "schedule").await.unwrap();
        sqlx::query("UPDATE task_runs SET instance_id = 'gone/1', heartbeat_at = now() - interval '10 minutes' WHERE id = $1").bind(dead).execute(b.pool()).await.unwrap();
        let recent = b.start_task_run("replication/1", "push", "x").await.unwrap();
        sqlx::query("UPDATE task_runs SET instance_id = 'busy/1', heartbeat_at = now() - interval '1 minute' WHERE id = $1").bind(recent).execute(b.pool()).await.unwrap();

        // Instance b starts up.
        assert_eq!(b.fail_interrupted_task_runs(super::STALE_AFTER, true).await.unwrap(), 1);
        let status = |id: i64| {
            let pool = a.pool().clone();
            async move { sqlx::query_scalar::<_, String>("SELECT status FROM task_runs WHERE id = $1").bind(id).fetch_one(&pool).await.unwrap() }
        };
        assert_eq!(status(live).await, "running", "a's run is live: not b's to fail");
        assert_eq!(status(recent).await, "running", "a recent heartbeat is live too");
        assert_eq!(status(dead).await, "failed");
        // The periodic check on a leaves its own live run alone; at a's startup the same run
        // could only be a leftover of an earlier life.
        assert_eq!(a.fail_interrupted_task_runs(super::STALE_AFTER, false).await.unwrap(), 0);
        assert_eq!(status(live).await, "running");
        assert_eq!(a.fail_interrupted_task_runs(super::STALE_AFTER, true).await.unwrap(), 1);
        assert_eq!(status(live).await, "failed");
    }

    #[tokio::test]
    async fn running_tasks_heartbeat_until_finished() {
        let db = Db::open(&fresh_database_url(), 2).await.unwrap();
        let id = db.start_task_run("gc", "manual", "root").await.unwrap();
        sqlx::query("UPDATE task_runs SET heartbeat_at = now() - interval '1 hour' WHERE id = $1").bind(id).execute(db.pool()).await.unwrap();
        db.spawn_task_heartbeat(id, Duration::from_millis(20));
        let fresh = async {
            for _ in 0..100 {
                let age: f64 = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM now() - heartbeat_at)::float8 FROM task_runs WHERE id = $1").bind(id).fetch_one(db.pool()).await.unwrap();
                if age < 60.0 {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            false
        };
        assert!(fresh.await, "the heartbeat was refreshed");
        db.finish_task_run(id, true, "done", None).await.unwrap();
        assert_eq!(db.fail_interrupted_task_runs(super::STALE_AFTER, true).await.unwrap(), 0, "finished runs are never touched");
    }
}
