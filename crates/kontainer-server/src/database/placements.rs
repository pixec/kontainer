//! Blob placements and the copies queued between storage locations
//! ([`kontainer_store::placement::Placements`]) in PostgreSQL: tables `blob_placements` and
//! `blob_replication_jobs`. Jobs are claimed like `scan_jobs` (`FOR UPDATE SKIP LOCKED`), by
//! the workers of [`crate::locations`].
//!
//! Recording a placement takes the per-digest advisory lock in shared mode, as a blob link
//! does, so it waits for a garbage collection sweep of the digest in progress; a sweep drops the
//! digest's queued copies before deleting it, and a copy finished meanwhile finds its job gone
//! and deletes what it wrote.

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use kontainer_core::digest::Digest;
use kontainer_store::placement::{JobKind, PlacedBlob, Placements, ReplicationJob};

use super::registry::BLOB_LOCK;
use super::Db;

fn size(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| anyhow::anyhow!("blob size {n} out of range"))
}

#[derive(sqlx::FromRow)]
struct JobRow {
    id: i64,
    kind: String,
    digest: String,
    location: String,
    attempts: i32,
}

impl TryFrom<JobRow> for ReplicationJob {
    type Error = anyhow::Error;

    fn try_from(r: JobRow) -> Result<Self> {
        let kind = JobKind::parse(&r.kind).ok_or_else(|| anyhow::anyhow!("unknown replication job kind {:?}", r.kind))?;
        Ok(Self { id: r.id, kind, key: r.digest, location: r.location, attempts: r.attempts })
    }
}

/// What one storage location holds and still has to receive, for the admin page.
#[derive(Debug, Clone, Default, Serialize, sqlx::FromRow)]
pub struct LocationCounts {
    pub location: String,
    /// Blobs recorded there, and their bytes.
    pub blobs: i64,
    pub bytes: i64,
    /// Copies waiting or being made.
    pub pending: i64,
    /// Copies given up on (kept until queued again).
    pub failed: i64,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
}

#[async_trait::async_trait]
impl Placements for Db {
    async fn place(&self, d: &Digest, location: &str, n: u64) -> Result<()> {
        let mut tx = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock_shared($1, hashtext($2))").bind(BLOB_LOCK).bind(d.to_string()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO blob_placements (digest, location, size) VALUES ($1, $2, $3) ON CONFLICT (digest, location) DO NOTHING")
            .bind(d.to_string())
            .bind(location)
            .bind(size(n)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn placements(&self, d: &Digest) -> Result<Vec<(String, u64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as("SELECT location, size FROM blob_placements WHERE digest = $1 ORDER BY location").bind(d.to_string()).fetch_all(self.pool()).await?;
        Ok(rows.into_iter().map(|(l, n)| (l, u64::try_from(n).unwrap_or(0))).collect())
    }

    async fn unplace(&self, d: &Digest, location: &str) -> Result<bool> {
        Ok(sqlx::query("DELETE FROM blob_placements WHERE digest = $1 AND location = $2").bind(d.to_string()).bind(location).execute(self.pool()).await?.rows_affected() > 0)
    }

    async fn blobs_missing_at(&self, location: &str, limit: usize, after: Option<&Digest>) -> Result<Vec<Digest>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT p.digest FROM blob_placements p \
             WHERE p.digest > $2 AND NOT EXISTS (SELECT 1 FROM blob_placements h WHERE h.digest = p.digest AND h.location = $1) \
             ORDER BY p.digest LIMIT $3",
        )
        .bind(location)
        .bind(after.map(ToString::to_string).unwrap_or_default())
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(self.pool())
        .await?;
        Ok(rows.iter().filter_map(|d| d.parse().ok()).collect())
    }

    async fn location_has_placements(&self, location: &str) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM blob_placements WHERE location = $1)").bind(location).fetch_one(self.pool()).await?)
    }

    async fn placed_blobs(&self) -> Result<Vec<PlacedBlob>> {
        let rows: Vec<(String, i64, DateTime<Utc>)> = sqlx::query_as("SELECT digest, max(size), min(placed_at) FROM blob_placements GROUP BY digest").fetch_all(self.pool()).await?;
        Ok(rows.into_iter().filter_map(|(d, n, at)| Some(PlacedBlob { digest: d.parse().ok()?, size: u64::try_from(n).unwrap_or(0), placed_at: at })).collect())
    }

    async fn enqueue_replication(&self, kind: JobKind, keys: &[String], locations: &[String]) -> Result<usize> {
        if keys.is_empty() || locations.is_empty() {
            return Ok(0);
        }
        let mut tx = self.pool().begin().await?;
        // A copy that gave up earlier makes way for the new one.
        sqlx::query("DELETE FROM blob_replication_jobs WHERE kind = $1 AND digest = ANY($2) AND location = ANY($3) AND failed_at IS NOT NULL")
            .bind(kind.as_str())
            .bind(keys)
            .bind(locations)
            .execute(&mut *tx)
            .await?;
        let n = sqlx::query(
            "INSERT INTO blob_replication_jobs (kind, digest, location) \
             SELECT $1, k, l FROM unnest($2::text[]) AS k CROSS JOIN unnest($3::text[]) AS l \
             ON CONFLICT (kind, digest, location) WHERE failed_at IS NULL DO NOTHING",
        )
        .bind(kind.as_str())
        .bind(keys)
        .bind(locations)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    async fn cancel_replication(&self, kind: JobKind, key: &str) -> Result<u64> {
        Ok(sqlx::query("DELETE FROM blob_replication_jobs WHERE kind = $1 AND digest = $2").bind(kind.as_str()).bind(key).execute(self.pool()).await?.rows_affected())
    }

    async fn complete_replication(&self, job: &ReplicationJob, worker: &str, n: Option<u64>) -> Result<bool> {
        let mut tx = self.pool().begin().await?;
        if job.kind == JobKind::Blob {
            sqlx::query("SELECT pg_advisory_xact_lock_shared($1, hashtext($2))").bind(BLOB_LOCK).bind(&job.key).execute(&mut *tx).await?;
        }
        let ours = sqlx::query("DELETE FROM blob_replication_jobs WHERE id = $1 AND locked_by = $2").bind(job.id).bind(worker).execute(&mut *tx).await?.rows_affected() > 0;
        if !ours {
            tx.rollback().await?;
            return Ok(false);
        }
        if let (JobKind::Blob, Some(n)) = (job.kind, n) {
            sqlx::query("INSERT INTO blob_placements (digest, location, size) VALUES ($1, $2, $3) ON CONFLICT (digest, location) DO NOTHING")
                .bind(&job.key)
                .bind(&job.location)
                .bind(size(n)?)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(true)
    }
}

impl Db {
    /// Take the oldest due copy no live worker holds (one whose lock is older than `lease` was
    /// abandoned), for `worker`.
    pub async fn claim_replication_job(&self, worker: &str, lease: Duration) -> Result<Option<ReplicationJob>> {
        let row = sqlx::query_as::<_, JobRow>(
            "UPDATE blob_replication_jobs SET locked_by = $1, locked_at = now(), attempts = attempts + 1 \
             WHERE id = (SELECT id FROM blob_replication_jobs \
                         WHERE failed_at IS NULL AND next_at <= now() AND (locked_at IS NULL OR locked_at < now() - make_interval(secs => $2)) \
                         ORDER BY next_at, id FOR UPDATE SKIP LOCKED LIMIT 1) \
             RETURNING id, kind, digest, location, attempts",
        )
        .bind(worker)
        .bind(lease.as_secs_f64())
        .fetch_optional(self.pool())
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    /// Still copying. False when the job is no longer ours.
    pub async fn heartbeat_replication_job(&self, id: i64, worker: &str) -> Result<bool> {
        Ok(sqlx::query("UPDATE blob_replication_jobs SET locked_at = now() WHERE id = $1 AND locked_by = $2").bind(id).bind(worker).execute(self.pool()).await?.rows_affected() > 0)
    }

    /// The attempt failed: try again after `delay`.
    pub async fn retry_replication_job(&self, id: i64, worker: &str, error: &str, delay: Duration) -> Result<()> {
        sqlx::query("UPDATE blob_replication_jobs SET locked_by = NULL, locked_at = NULL, last_error = $3, next_at = now() + make_interval(secs => $4) WHERE id = $1 AND locked_by = $2")
            .bind(id)
            .bind(worker)
            .bind(error)
            .bind(delay.as_secs_f64())
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The last attempt failed: give up, keeping the row and why.
    pub async fn fail_replication_job(&self, id: i64, worker: &str, error: &str) -> Result<()> {
        sqlx::query("UPDATE blob_replication_jobs SET locked_by = NULL, locked_at = NULL, last_error = $3, failed_at = now() WHERE id = $1 AND locked_by = $2")
            .bind(id)
            .bind(worker)
            .bind(error)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Per location named in placements or jobs: blobs and bytes recorded, copies pending and
    /// failed, and the latest error (of a failed copy, or of a pending one's last attempt).
    pub async fn location_counts(&self) -> Result<Vec<LocationCounts>> {
        Ok(sqlx::query_as::<_, LocationCounts>(
            "WITH p AS (SELECT location, count(*) AS blobs, coalesce(sum(size), 0)::BIGINT AS bytes FROM blob_placements GROUP BY location), \
                  j AS (SELECT location, count(*) FILTER (WHERE failed_at IS NULL) AS pending, count(*) FILTER (WHERE failed_at IS NOT NULL) AS failed FROM blob_replication_jobs GROUP BY location), \
                  e AS (SELECT DISTINCT ON (location) location, last_error, coalesce(failed_at, locked_at, next_at) AS last_error_at FROM blob_replication_jobs \
                        WHERE last_error IS NOT NULL ORDER BY location, coalesce(failed_at, locked_at, next_at) DESC) \
             SELECT l.location, coalesce(p.blobs, 0) AS blobs, coalesce(p.bytes, 0) AS bytes, coalesce(j.pending, 0) AS pending, coalesce(j.failed, 0) AS failed, e.last_error, e.last_error_at \
             FROM (SELECT location FROM p UNION SELECT location FROM j) l \
             LEFT JOIN p USING (location) LEFT JOIN j USING (location) LEFT JOIN e USING (location) \
             ORDER BY l.location",
        )
        .fetch_all(self.pool())
        .await?)
    }

    /// The copies given up on for `location`, newest first: (kind, key, attempts, error).
    pub async fn failed_replication_jobs(&self, location: &str, limit: i64) -> Result<Vec<(String, String, i32, Option<String>)>> {
        Ok(sqlx::query_as("SELECT kind, digest, attempts, last_error FROM blob_replication_jobs WHERE location = $1 AND failed_at IS NOT NULL ORDER BY failed_at DESC LIMIT $2")
            .bind(location)
            .bind(limit)
            .fetch_all(self.pool())
            .await?)
    }

    /// Forget everything recorded about `location` (placements and queued copies), without
    /// touching any object: for a location removed from the configuration. Returns
    /// (placements, jobs) removed.
    pub async fn forget_location(&self, location: &str) -> Result<(u64, u64)> {
        let mut tx = self.pool().begin().await?;
        let p = sqlx::query("DELETE FROM blob_placements WHERE location = $1").bind(location).execute(&mut *tx).await?.rows_affected();
        let j = sqlx::query("DELETE FROM blob_replication_jobs WHERE location = $1").bind(location).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok((p, j))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kontainer_core::digest::Digest;
    use kontainer_store::placement::{JobKind, Placements};

    use crate::database::test_support::fresh_database_url;
    use crate::database::Db;

    const LEASE: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn placements_jobs_and_backfill() {
        let db = Db::open(&fresh_database_url(), 4).await.unwrap();
        let (a, b, c) = (Digest::sha256_of(b"a"), Digest::sha256_of(b"b"), Digest::sha256_of(b"c"));
        db.place(&a, "eu", 1).await.unwrap();
        db.place(&a, "eu", 1).await.unwrap();
        db.place(&b, "eu", 2).await.unwrap();
        db.place(&b, "us", 2).await.unwrap();
        db.place(&c, "us", 3).await.unwrap();
        assert_eq!(db.placements(&b).await.unwrap(), [("eu".to_string(), 2), ("us".to_string(), 2)]);
        assert!(db.location_has_placements("us").await.unwrap() && !db.location_has_placements("ap").await.unwrap());
        // Missing at us: only a; paged by digest.
        assert_eq!(db.blobs_missing_at("us", 10, None).await.unwrap(), std::slice::from_ref(&a));
        let mut all = db.blobs_missing_at("ap", 10, None).await.unwrap();
        assert_eq!(all.len(), 3);
        let first = db.blobs_missing_at("ap", 1, None).await.unwrap();
        let rest = db.blobs_missing_at("ap", 10, first.first()).await.unwrap();
        assert_eq!(first.len() + rest.len(), 3);
        all.retain(|d| !first.contains(d));
        assert_eq!(all, rest);

        // Queueing is deduplicated; a failed copy makes way for a new one.
        let keys = [a.to_string()];
        assert_eq!(db.enqueue_replication(JobKind::Blob, &keys, &["us".into(), "ap".into()]).await.unwrap(), 2);
        assert_eq!(db.enqueue_replication(JobKind::Blob, &keys, &["us".into()]).await.unwrap(), 0);
        let j = db.claim_replication_job("w", LEASE).await.unwrap().unwrap();
        db.fail_replication_job(j.id, "w", "bucket on fire").await.unwrap();
        let counts = db.location_counts().await.unwrap();
        let failed = counts.iter().find(|c| c.location == j.location).unwrap();
        assert_eq!((failed.failed, failed.last_error.as_deref()), (1, Some("bucket on fire")));
        assert_eq!(db.enqueue_replication(JobKind::Blob, &keys, std::slice::from_ref(&j.location)).await.unwrap(), 1, "queued afresh");

        // Completing records the placement; a cancelled job records nothing.
        let j = db.claim_replication_job("w", LEASE).await.unwrap().unwrap();
        assert!(db.complete_replication(&j, "w", Some(1)).await.unwrap());
        assert!(db.placements(&a).await.unwrap().iter().any(|(l, _)| *l == j.location));
        let j = db.claim_replication_job("w", LEASE).await.unwrap().unwrap();
        assert_eq!(db.cancel_replication(JobKind::Blob, &a.to_string()).await.unwrap(), 1);
        assert!(!db.complete_replication(&j, "w", Some(1)).await.unwrap());
        assert!(!db.placements(&a).await.unwrap().iter().any(|(l, _)| *l == j.location));

        let counts = db.location_counts().await.unwrap();
        let eu = counts.iter().find(|c| c.location == "eu").unwrap();
        assert_eq!((eu.blobs, eu.bytes), (2, 3));
        assert_eq!(db.forget_location("eu").await.unwrap(), (2, 0));
        assert!(!db.location_has_placements("eu").await.unwrap());
    }
}
