//! Cluster-wide mutual exclusion with PostgreSQL advisory locks, so that with several registry
//! instances on one database a periodic job (GC, rescans, retention, mirrors...) runs on one of
//! them at a time.
//!
//! The lock is a session lock: it lives on one pooled connection, held for as long as the job
//! runs. If the instance dies, its connection closes and PostgreSQL releases the lock.

use anyhow::Result;
use sqlx::pool::PoolConnection;
use sqlx::Postgres;

use super::Db;

/// Held while a job runs; [`AdvisoryLock::release`] it when done. Dropping it without releasing
/// (a panic) closes its connection instead, which also releases the lock.
pub struct AdvisoryLock {
    conn: Option<PoolConnection<Postgres>>,
    name: String,
}

/// The 64-bit key for `name`. Prefixed, to stay clear of other users of advisory locks.
const KEY: &str = "hashtextextended('kontainer:' || $1, 0)";

impl Db {
    /// Take the lock named `name` if no one (on any instance) holds it.
    pub async fn try_advisory_lock(&self, name: &str) -> Result<Option<AdvisoryLock>> {
        let mut conn = self.pool().acquire().await?;
        let got: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT pg_try_advisory_lock({KEY})"))).bind(name).fetch_one(&mut *conn).await?;
        Ok(got.then(|| AdvisoryLock { conn: Some(conn), name: name.to_string() }))
    }
}

impl AdvisoryLock {
    pub async fn release(mut self) {
        let Some(mut conn) = self.conn.take() else { return };
        let unlocked = sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(format!("SELECT pg_advisory_unlock({KEY})"))).bind(&self.name).fetch_one(&mut *conn).await;
        if !matches!(unlocked, Ok(true)) {
            tracing::warn!(lock = %self.name, "releasing an advisory lock failed; closing its connection");
            drop(conn.detach());
        }
    }
}

impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        // Never hand a connection still holding the lock back to the pool.
        if let Some(conn) = self.conn.take() {
            drop(conn.detach());
        }
    }
}

/// Run `job` if the lock named `name` is free; `None` when another runner holds it (or the
/// database could not be asked: skipping a periodic run is the safe side).
pub async fn exclusive<T, F>(db: &Db, name: &str, job: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let lock = match db.try_advisory_lock(name).await {
        Ok(Some(l)) => l,
        Ok(None) => {
            tracing::debug!(job = name, "another instance is running this job; skipping");
            return None;
        }
        Err(e) => {
            tracing::warn!(job = name, error = %e, "taking a job lock; skipping this run");
            return None;
        }
    };
    let out = job.await;
    lock.release().await;
    Some(out)
}

#[cfg(test)]
mod tests {
    use crate::database::test_support::fresh_database_url;
    use crate::database::Db;

    #[tokio::test]
    async fn a_held_lock_excludes_a_second_runner() {
        let url = fresh_database_url();
        // Two "instances": separate pools on one database.
        let (a, b) = (Db::open(&url, 2).await.unwrap(), Db::open(&url, 2).await.unwrap());
        let held = a.try_advisory_lock("gc").await.unwrap().expect("free at first");
        assert!(b.try_advisory_lock("gc").await.unwrap().is_none(), "held by the other instance");
        assert!(a.try_advisory_lock("gc").await.unwrap().is_none(), "held by another connection of the same instance");
        let other = b.try_advisory_lock("scan_all").await.unwrap().expect("other names are independent");
        // `exclusive` skips while held, and runs once released.
        assert_eq!(super::exclusive(&b, "gc", async { 1 }).await, None);
        held.release().await;
        assert_eq!(super::exclusive(&b, "gc", async { 1 }).await, Some(1));
        other.release().await;
        // A lock dropped without release (a panicking job) is freed with its connection.
        let dropped = a.try_advisory_lock("gc").await.unwrap().unwrap();
        drop(dropped);
        let mut freed = false;
        for _ in 0..50 {
            if let Some(l) = b.try_advisory_lock("gc").await.unwrap() {
                l.release().await;
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(freed, "a dropped lock is released");
    }
}
