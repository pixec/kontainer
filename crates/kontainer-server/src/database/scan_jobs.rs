//! The scan queue (`scan_jobs`): images waiting for a vulnerability scan, claimed by workers on
//! any instance. See [`crate::scan::queue`].

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};

use super::Db;

/// What queueing a scan did (see [`Db::enqueue_scan_job_within`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    Queued,
    /// One is already waiting or running for this image.
    AlreadyQueued,
    /// Not queued: the automatic-scan budget for this hour is spent.
    OverBudget,
    /// Not queued: the queue holds `scanner.max_queue` scans.
    QueueFull,
}

/// The limits an enqueue is checked against.
#[derive(Debug, Clone, Copy, Default)]
pub struct Limits {
    /// Counted against (and refused beyond) the hourly budget of automatic scans.
    pub is_automatic: bool,
    /// Automatic scans per hour; 0: unlimited.
    pub per_hour: u64,
    /// Scans waiting or running; 0: unlimited.
    pub max_queue: u64,
}

/// The automatic-scan budget as stored (`scan_budget`).
#[derive(Debug, Clone, Default, serde::Serialize, sqlx::FromRow)]
pub struct BudgetRow {
    pub window_start: Option<DateTime<Utc>>,
    pub used: i64,
    pub skipped: i64,
    pub override_until: Option<DateTime<Utc>>,
    pub override_by: Option<String>,
}

/// A claimed scan.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScanJob {
    pub id: i64,
    pub repository: String,
    pub digest: String,
    /// Claims so far, this one included.
    pub attempts: i32,
}

impl Db {
    /// Queue a scan of `repository@digest`. False when one is already waiting or running.
    pub async fn enqueue_scan_job(&self, repository: &str, digest: &str) -> Result<bool> {
        Ok(self.enqueue_scan_job_within(repository, digest, Limits::default()).await? == Enqueued::Queued)
    }

    /// Queue a scan of `repository@digest` within `limits`, in one transaction: the queue size
    /// and (for an automatic scan) the cluster-wide hourly budget are checked against the rows
    /// every instance shares, and a scan that is refused leaves nothing behind but a count of
    /// the skip. A duplicate costs no budget.
    pub async fn enqueue_scan_job_within(&self, repository: &str, digest: &str, limits: Limits) -> Result<Enqueued> {
        let mut tx = self.pool().begin().await?;
        sqlx::query("DELETE FROM scan_jobs WHERE repository = $1 AND digest = $2 AND failed_at IS NOT NULL").bind(repository).bind(digest).execute(&mut *tx).await?;
        let id: Option<i64> = sqlx::query_scalar("INSERT INTO scan_jobs (repository, digest) VALUES ($1, $2) ON CONFLICT (repository, digest) WHERE failed_at IS NULL DO NOTHING RETURNING id")
            .bind(repository)
            .bind(digest)
            .fetch_optional(&mut *tx)
            .await?;
        if id.is_none() {
            tx.commit().await?;
            return Ok(Enqueued::AlreadyQueued);
        }
        let refused = if limits.max_queue > 0 && self.scan_queue_depth_in(&mut tx).await? > i64::try_from(limits.max_queue).unwrap_or(i64::MAX) {
            Some(Enqueued::QueueFull)
        } else if limits.is_automatic && !self.take_scan_budget(&mut tx, limits.per_hour).await? {
            Some(Enqueued::OverBudget)
        } else {
            None
        };
        match refused {
            None => {
                tx.commit().await?;
                Ok(Enqueued::Queued)
            }
            Some(why) => {
                tx.rollback().await?;
                self.note_skipped_scan().await?;
                Ok(why)
            }
        }
    }

    /// Scans waiting or running (the one just inserted by this transaction included).
    async fn scan_queue_depth_in(&self, tx: &mut sqlx::PgConnection) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM scan_jobs WHERE failed_at IS NULL").fetch_one(tx).await?)
    }

    /// Scans waiting or running, cluster-wide.
    pub async fn scan_queue_depth(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM scan_jobs WHERE failed_at IS NULL").fetch_one(self.pool()).await?)
    }

    /// Count one automatic scan against the budget of `per_hour` (0: unlimited), starting a new
    /// window when the last one is over. False, counting nothing, when it is spent (and no
    /// override is in force). One statement: the row lock orders concurrent instances.
    async fn take_scan_budget(&self, tx: &mut sqlx::PgConnection, per_hour: u64) -> Result<bool> {
        let sql =
            "INSERT INTO scan_budget AS b (id, window_start, used) VALUES (true, now(), 1) \
             ON CONFLICT (id) DO UPDATE SET \
               window_start = CASE WHEN b.window_start <= now() - interval '1 hour' THEN now() ELSE b.window_start END, \
               used = CASE WHEN b.window_start <= now() - interval '1 hour' THEN 1 ELSE b.used + 1 END, \
               skipped = CASE WHEN b.window_start <= now() - interval '1 hour' THEN 0 ELSE b.skipped END \
             WHERE $1 = 0 OR b.override_until > now() OR b.window_start <= now() - interval '1 hour' OR b.used < $1 \
             RETURNING used";
        let used: Option<i64> = sqlx::query_scalar(sql).bind(i64::try_from(per_hour).unwrap_or(i64::MAX)).fetch_optional(tx).await?;
        Ok(used.is_some())
    }

    /// Count a skipped scan in the current window.
    async fn note_skipped_scan(&self) -> Result<()> {
        let sql =
            "INSERT INTO scan_budget AS b (id, window_start, skipped) VALUES (true, now(), 1) \
             ON CONFLICT (id) DO UPDATE SET \
               window_start = CASE WHEN b.window_start <= now() - interval '1 hour' THEN now() ELSE b.window_start END, \
               used = CASE WHEN b.window_start <= now() - interval '1 hour' THEN 0 ELSE b.used END, \
               skipped = CASE WHEN b.window_start <= now() - interval '1 hour' THEN 1 ELSE b.skipped + 1 END";
        sqlx::query(sql).execute(self.pool()).await?;
        Ok(())
    }

    /// The budget's current state. A window that is over reads as empty.
    pub async fn scan_budget(&self) -> Result<BudgetRow> {
        let sql =
            "SELECT CASE WHEN window_start <= now() - interval '1 hour' THEN NULL ELSE window_start END AS window_start, \
                    CASE WHEN window_start <= now() - interval '1 hour' THEN 0 ELSE used END AS used, \
                    CASE WHEN window_start <= now() - interval '1 hour' THEN 0 ELSE skipped END AS skipped, \
                    CASE WHEN override_until > now() THEN override_until END AS override_until, \
                    CASE WHEN override_until > now() THEN override_by END AS override_by \
             FROM scan_budget WHERE id";
        Ok(sqlx::query_as::<_, BudgetRow>(sql).fetch_optional(self.pool()).await?.unwrap_or_default())
    }

    /// Lift the budget for `hours` from now (0: end an override). Returns until when.
    pub async fn override_scan_budget(&self, hours: u32, by: &str) -> Result<Option<DateTime<Utc>>> {
        let until: Option<DateTime<Utc>> = sqlx::query_scalar(
            "INSERT INTO scan_budget AS b (id, window_start, override_until, override_by) \
             VALUES (true, now(), CASE WHEN $1 > 0 THEN now() + make_interval(hours => $1) END, CASE WHEN $1 > 0 THEN $2 END) \
             ON CONFLICT (id) DO UPDATE SET override_until = excluded.override_until, override_by = excluded.override_by \
             RETURNING override_until",
        )
        .bind(i32::try_from(hours).unwrap_or(i32::MAX))
        .bind(by)
        .fetch_one(self.pool())
        .await?;
        Ok(until)
    }

    /// Take the oldest due scan no live worker holds (one whose lock is older than `lease` was
    /// abandoned), for `worker`.
    pub async fn claim_scan_job(&self, worker: &str, lease: Duration) -> Result<Option<ScanJob>> {
        Ok(sqlx::query_as::<_, ScanJob>(
            "UPDATE scan_jobs SET locked_by = $1, locked_at = now(), attempts = attempts + 1 \
             WHERE id = (SELECT id FROM scan_jobs \
                         WHERE failed_at IS NULL AND next_at <= now() AND (locked_at IS NULL OR locked_at < now() - make_interval(secs => $2)) \
                         ORDER BY requested_at, id FOR UPDATE SKIP LOCKED LIMIT 1) \
             RETURNING id, repository, digest, attempts",
        )
        .bind(worker)
        .bind(lease.as_secs_f64())
        .fetch_optional(self.pool())
        .await?)
    }

    /// Still working on it. False when the job is no longer ours (it was reclaimed).
    pub async fn heartbeat_scan_job(&self, id: i64, worker: &str) -> Result<bool> {
        Ok(sqlx::query("UPDATE scan_jobs SET locked_at = now() WHERE id = $1 AND locked_by = $2").bind(id).bind(worker).execute(self.pool()).await?.rows_affected() > 0)
    }

    /// The scan finished: the job is done.
    pub async fn finish_scan_job(&self, id: i64, worker: &str) -> Result<()> {
        sqlx::query("DELETE FROM scan_jobs WHERE id = $1 AND locked_by = $2").bind(id).bind(worker).execute(self.pool()).await?;
        Ok(())
    }

    /// The attempt failed: try again after `delay`.
    pub async fn retry_scan_job(&self, id: i64, worker: &str, error: &str, delay: Duration) -> Result<()> {
        sqlx::query("UPDATE scan_jobs SET locked_by = NULL, locked_at = NULL, last_error = $3, next_at = now() + make_interval(secs => $4) WHERE id = $1 AND locked_by = $2")
            .bind(id)
            .bind(worker)
            .bind(error)
            .bind(delay.as_secs_f64())
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The last attempt failed: drop the job, keeping why.
    pub async fn fail_scan_job(&self, id: i64, worker: &str, error: &str) -> Result<()> {
        sqlx::query("UPDATE scan_jobs SET locked_by = NULL, locked_at = NULL, last_error = $3, failed_at = now() WHERE id = $1 AND locked_by = $2")
            .bind(id)
            .bind(worker)
            .bind(error)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Forget dropped scans older than `keep`.
    pub async fn prune_failed_scan_jobs(&self, keep: Duration) -> Result<u64> {
        Ok(sqlx::query("DELETE FROM scan_jobs WHERE failed_at < now() - make_interval(secs => $1)").bind(keep.as_secs_f64()).execute(self.pool()).await?.rows_affected())
    }

    /// The last error of a dropped scan of `repository@digest`, if there is one.
    pub async fn failed_scan_job(&self, repository: &str, digest: &str) -> Result<Option<(i32, Option<String>)>> {
        Ok(sqlx::query_as("SELECT attempts, last_error FROM scan_jobs WHERE repository = $1 AND digest = $2 AND failed_at IS NOT NULL")
            .bind(repository)
            .bind(digest)
            .fetch_optional(self.pool())
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::database::test_support::fresh_database_url;
    use crate::database::Db;

    const LEASE: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn one_claim_per_job_across_instances() {
        let url = fresh_database_url();
        let (a, b) = (Db::open(&url, 8).await.unwrap(), Db::open(&url, 8).await.unwrap());
        assert!(a.enqueue_scan_job("acme/app", "sha256:1").await.unwrap());
        assert!(!b.enqueue_scan_job("acme/app", "sha256:1").await.unwrap(), "deduplicated while pending");
        assert!(b.enqueue_scan_job("acme/other", "sha256:1").await.unwrap(), "per repository");
        // Many workers on both instances race for two jobs: each is claimed exactly once.
        let mut tasks = vec![];
        for i in 0..16 {
            let db = if i % 2 == 0 { a.clone() } else { b.clone() };
            tasks.push(tokio::spawn(async move { db.claim_scan_job(&format!("w{i}"), LEASE).await.unwrap() }));
        }
        let mut claimed = vec![];
        for t in tasks {
            claimed.extend(t.await.unwrap());
        }
        let mut repos: Vec<_> = claimed.iter().map(|j| j.repository.clone()).collect();
        repos.sort();
        assert_eq!(repos, ["acme/app", "acme/other"]);
        assert!(!a.enqueue_scan_job("acme/app", "sha256:1").await.unwrap(), "deduplicated while running");
        // An abandoned claim is taken over once its lease runs out.
        assert!(a.claim_scan_job("late", LEASE).await.unwrap().is_none());
        let j = b.claim_scan_job("late", Duration::ZERO).await.unwrap().expect("stale lock reclaimed");
        assert_eq!(j.attempts, 2);
        assert!(!a.heartbeat_scan_job(j.id, "w0").await.unwrap() && !a.heartbeat_scan_job(j.id, "w1").await.unwrap(), "the first holder lost it");
        assert!(a.heartbeat_scan_job(j.id, "late").await.unwrap());
        a.finish_scan_job(j.id, "late").await.unwrap();
        assert!(a.enqueue_scan_job(&j.repository, "sha256:1").await.unwrap(), "can be queued again once done");
    }

    #[tokio::test]
    async fn the_hourly_budget_holds_under_concurrency_across_instances() {
        use super::{Enqueued, Limits};
        let url = fresh_database_url();
        let (a, b) = (Db::open(&url, 8).await.unwrap(), Db::open(&url, 8).await.unwrap());
        let auto = Limits { is_automatic: true, per_hour: 5, max_queue: 0 };
        // 20 automatic scans race on two instances: exactly 5 are queued.
        let mut tasks = vec![];
        for i in 0..20 {
            let db = if i % 2 == 0 { a.clone() } else { b.clone() };
            tasks.push(tokio::spawn(async move { db.enqueue_scan_job_within("acme/app", &format!("sha256:{i}"), auto).await.unwrap() }));
        }
        let mut outcomes = vec![];
        for t in tasks {
            outcomes.push(t.await.unwrap());
        }
        assert_eq!(outcomes.iter().filter(|o| **o == Enqueued::Queued).count(), 5);
        assert_eq!(outcomes.iter().filter(|o| **o == Enqueued::OverBudget).count(), 15);
        assert_eq!(a.scan_queue_depth().await.unwrap(), 5, "skipped scans leave no job behind");
        let row = b.scan_budget().await.unwrap();
        assert_eq!((row.used, row.skipped), (5, 15));
        // A duplicate is not charged; a requested scan is not held to the budget.
        assert_eq!(a.enqueue_scan_job_within("acme/app", "sha256:0", auto).await.unwrap(), Enqueued::AlreadyQueued);
        assert_eq!(a.enqueue_scan_job_within("acme/app", "sha256:x", Limits { is_automatic: false, ..auto }).await.unwrap(), Enqueued::Queued);
        assert_eq!(a.scan_budget().await.unwrap().used, 5);
        // The queue limit applies to every scan.
        let full = Limits { is_automatic: false, per_hour: 0, max_queue: 6 };
        assert_eq!(a.enqueue_scan_job_within("acme/app", "sha256:y", full).await.unwrap(), Enqueued::QueueFull);
        // Once the hour is over, a new window starts with a fresh budget.
        sqlx::query("UPDATE scan_budget SET window_start = now() - interval '61 minutes'").execute(a.pool()).await.unwrap();
        assert_eq!(a.scan_budget().await.unwrap().used, 0, "an expired window reads as empty");
        assert_eq!(b.enqueue_scan_job_within("acme/app", "sha256:new", auto).await.unwrap(), Enqueued::Queued);
        let row = a.scan_budget().await.unwrap();
        assert_eq!((row.used, row.skipped), (1, 0));
        // An override lifts the limit until it ends.
        sqlx::query("UPDATE scan_budget SET used = 5").execute(a.pool()).await.unwrap();
        assert_eq!(a.enqueue_scan_job_within("acme/app", "sha256:o1", auto).await.unwrap(), Enqueued::OverBudget);
        assert!(b.override_scan_budget(1, "root").await.unwrap().is_some());
        assert_eq!(a.enqueue_scan_job_within("acme/app", "sha256:o1", auto).await.unwrap(), Enqueued::Queued);
        assert_eq!(a.scan_budget().await.unwrap().override_by.as_deref(), Some("root"));
        assert!(b.override_scan_budget(0, "root").await.unwrap().is_none());
        assert_eq!(a.enqueue_scan_job_within("acme/app", "sha256:o2", auto).await.unwrap(), Enqueued::OverBudget);
    }
}
