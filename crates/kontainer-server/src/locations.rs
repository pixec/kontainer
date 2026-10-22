//! Geo-replication between storage locations: the workers that make the copies queued in
//! `blob_replication_jobs` (see [`kontainer_store::placement`] and
//! [`kontainer_store::replication`]), and the periodic catch-up.
//!
//! Every instance runs `storage.replication_concurrency` workers, which claim copies to any
//! location (`FOR UPDATE SKIP LOCKED`, see [`crate::workqueue`]). A failed copy is retried with
//! a growing delay; after the last attempt the row stays, with its error, for the admin page,
//! until a backfill queues it again.
//!
//! At startup and every `storage.replication_interval`, one instance at a time records the
//! blobs of locations that have no placements yet (a deployment from before placements, or a
//! location filled by other means) and queues every blob each location is missing (a
//! backfill). The admin "sync now" action runs the same backfill.

use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use kontainer_store::placement::ReplicationJob;
use kontainer_store::replication::Replicated;
use kontainer_store::Storage;

use crate::database::Db;
use crate::workqueue::{self, Options};

/// How often an idle worker looks for copies queued by other instances.
const POLL: Duration = Duration::from_secs(5);
/// A claim not refreshed for this long belongs to a worker that died.
const LEASE: Duration = Duration::from_secs(300);
/// The advisory lock of the periodic catch-up and of "sync now".
pub const BACKFILL_LOCK: &str = "storage-backfill";

/// How often a copy is tried, and the delay before the second attempt (doubling after).
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    pub attempts: u32,
    pub backoff: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self { attempts: 6, backoff: Duration::from_secs(30) }
    }
}

/// One worker's identity and settings.
#[derive(Clone)]
pub struct Worker {
    pub storage: Storage,
    pub db: Db,
    pub holder: String,
    pub lease: Duration,
    pub retry: Retry,
}

impl Worker {
    pub fn new(storage: Storage, db: Db, retry: Retry) -> Self {
        Self { storage, db, holder: workqueue::holder("replication"), lease: LEASE, retry }
    }

    /// Claim the next due copy and make it. `None` when nothing is due.
    pub async fn run_once(&self) -> Result<Option<std::result::Result<Replicated, String>>> {
        let Some(job) = self.db.claim_replication_job(&self.holder, self.lease).await? else { return Ok(None) };
        Ok(Some(self.process(job).await))
    }

    /// Make the copy `job` asks for, keeping the claim fresh meanwhile, and record the outcome:
    /// done, retry later, or given up.
    pub async fn process(&self, job: ReplicationJob) -> std::result::Result<Replicated, String> {
        let copy = self.storage.replicate(&job, &self.holder);
        tokio::pin!(copy);
        let mut beat = tokio::time::interval((self.lease / 4).max(Duration::from_millis(10)));
        beat.tick().await;
        let result = loop {
            tokio::select! {
                r = &mut copy => break r,
                _ = beat.tick() => match self.db.heartbeat_replication_job(job.id, &self.holder).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(location = %job.location, key = %job.key, "lost the claim on a copy in progress; leaving it to its new worker");
                        return Err("lost the claim".into());
                    }
                    Err(e) => tracing::warn!(error = %e, "refreshing a copy's claim"),
                },
            }
        };
        let error = match result {
            Ok(outcome) => {
                tracing::debug!(kind = job.kind.as_str(), key = %job.key, location = %job.location, ?outcome, "replicated");
                return Ok(outcome);
            }
            Err(e) => format!("{e:#}"),
        };
        self.storage.replication.failed(&job.location, format!("{}: {error}", job.key));
        let attempt = u32::try_from(job.attempts).unwrap_or(u32::MAX);
        // A location no longer configured never becomes reachable: give up at once.
        if attempt < self.retry.attempts && self.storage.location(&job.location).is_some() {
            let delay = workqueue::backoff(self.retry.backoff, attempt);
            tracing::warn!(kind = job.kind.as_str(), key = %job.key, location = %job.location, attempt, error = %error, retry_in = ?delay, "copying to another storage location failed; will retry");
            if let Err(e) = self.db.retry_replication_job(job.id, &self.holder, &error, delay).await {
                tracing::warn!(error = %e, "rescheduling a failed copy");
            }
        } else {
            tracing::warn!(kind = job.kind.as_str(), key = %job.key, location = %job.location, attempts = attempt, error = %error, "copying to another storage location failed; giving up");
            if let Err(e) = self.db.fail_replication_job(job.id, &self.holder, &error).await {
                tracing::warn!(error = %e, "recording a failed copy");
            }
        }
        Err(error)
    }
}

/// Start this instance's copy workers. Stops at `stop`.
pub fn start_workers(storage: &Storage, db: &Db, workers: usize, retry: Retry, stop: CancellationToken) {
    let worker = std::sync::Arc::new(Worker::new(storage.clone(), db.clone(), retry));
    let claim = {
        let w = worker.clone();
        move || {
            let w = w.clone();
            async move { w.db.claim_replication_job(&w.holder, w.lease).await }
        }
    };
    let opts = Options { workers, poll: POLL, lease: LEASE };
    workqueue::spawn("replication", opts, storage.replication.notifier(), stop, claim, move |job| {
        let w = worker.clone();
        async move {
            let _ = w.process(job).await;
        }
    });
}

/// Queue, for every location, the blobs it is missing. Returns (location, copies queued).
pub async fn backfill_all(storage: &Storage) -> Result<Vec<(String, usize)>> {
    let mut out = vec![];
    for l in storage.locations() {
        out.push((l.name.clone(), storage.backfill(&l.name).await?));
    }
    Ok(out)
}

/// The periodic catch-up: record the blobs of locations without placements, then backfill.
async fn catch_up(storage: &Storage) -> Result<()> {
    storage.index_unplaced_locations().await?;
    if storage.locations().len() > 1 {
        for (location, n) in backfill_all(storage).await? {
            if n > 0 {
                tracing::info!(%location, blobs = n, "queued copies of blobs missing at a storage location");
            }
        }
    }
    Ok(())
}

/// Start the workers and the periodic catch-up. Call once at startup.
pub fn start(storage: &Storage, db: &Db, workers: usize, interval: Duration) {
    if storage.locations().len() > 1 {
        tracing::info!(locations = storage.locations().len(), preferred = %storage.preferred().name, "replicating between storage locations");
        start_workers(storage, db, workers, Retry::default(), CancellationToken::new());
    }
    let (storage, db) = (storage.clone(), db.clone());
    crate::background::every(interval.max(Duration::from_secs(60)), true, move || {
        let (storage, db) = (storage.clone(), db.clone());
        async move {
            let s = storage.clone();
            if let Some(Err(e)) = crate::database::locks::exclusive(&db, BACKFILL_LOCK, async move { catch_up(&s).await }).await {
                tracing::warn!(error = %format!("{e:#}"), "catching up storage locations");
            }
        }
    });
}
