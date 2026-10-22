//! Which storage locations hold each blob, and the queue of copies still to make.
//!
//! Every location is a peer: an instance writes a new blob to its preferred location, records
//! the placement, and queues a copy to every other location (a [`ReplicationJob`]). Workers on
//! any instance take the jobs and copy the blob from a location that has it (see
//! [`crate::replication`]). Reads pick a location from the placements without asking the
//! object stores (see [`crate::Storage::blob_sources`]).
//!
//! The server keeps placements and jobs in PostgreSQL (`blob_placements`,
//! `blob_replication_jobs`); [`MemoryPlacements`] serves the store's own tests and
//! single-process tools.
//!
//! Scan reports and usage logs are queued the same way (by kind), but have no placements: they
//! are read from the preferred location first and from the others when it lacks them.

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::Result;
use chrono::{DateTime, Utc};

use kontainer_core::digest::Digest;

/// What a replication job copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobKind {
    /// `blobs/<alg>/<hex>/data`; the key is the digest.
    Blob,
    /// `scans/<alg>/<hex>/report.json`; the key is the scanned digest.
    Scan,
    /// `logs/<id>.json`; the key is the log id.
    Log,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Scan => "scan",
            Self::Log => "log",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "blob" => Some(Self::Blob),
            "scan" => Some(Self::Scan),
            "log" => Some(Self::Log),
            _ => None,
        }
    }
}

/// A claimed copy of one object to one location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationJob {
    pub id: i64,
    pub kind: JobKind,
    /// The digest (blobs, scan reports) or log id.
    pub key: String,
    /// Where to copy it.
    pub location: String,
    /// Claims so far, this one included.
    pub attempts: i32,
}

/// A blob with at least one placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedBlob {
    pub digest: Digest,
    pub size: u64,
    /// When it was first placed anywhere.
    pub placed_at: DateTime<Utc>,
}

/// Where blob placements and replication jobs are kept. Each method is atomic.
#[async_trait::async_trait]
pub trait Placements: Send + Sync {
    /// Record that `location` holds blob `digest` of `size` bytes (again: refreshes nothing).
    /// Waits for a garbage collection sweep of the digest in progress.
    async fn place(&self, digest: &Digest, location: &str, size: u64) -> Result<()>;
    /// The locations holding `digest`, with the size recorded there, by location name.
    async fn placements(&self, digest: &Digest) -> Result<Vec<(String, u64)>>;
    /// Forget that `location` holds `digest`. Whether it was recorded.
    async fn unplace(&self, digest: &Digest, location: &str) -> Result<bool>;
    /// Blobs placed somewhere but not at `location`, in digest order after `after`, at most
    /// `limit`: what a backfill of `location` queues.
    async fn blobs_missing_at(&self, location: &str, limit: usize, after: Option<&Digest>) -> Result<Vec<Digest>>;
    /// Whether `location` holds any blob at all (a location never indexed holds none).
    async fn location_has_placements(&self, location: &str) -> Result<bool>;
    /// Every placed blob (in any location, configured or not).
    async fn placed_blobs(&self) -> Result<Vec<PlacedBlob>>;

    /// Queue copies of each of `keys` to each of `locations`. A copy already waiting (or being
    /// made) is not queued twice; one that gave up earlier is queued afresh. Returns how many
    /// were queued.
    async fn enqueue_replication(&self, kind: JobKind, keys: &[String], locations: &[String]) -> Result<usize>;
    /// Drop every copy of `key` still queued, failed ones too (the object is being deleted).
    async fn cancel_replication(&self, kind: JobKind, key: &str) -> Result<u64>;
    /// Job `job` (claimed by `worker`) is done: with `size`, record the blob as placed at the
    /// job's location; then drop the job. Under the same per-digest lock as a garbage
    /// collection sweep: false, and nothing recorded, when the job no longer exists (a sweep
    /// cancelled it, and the copy just made must be deleted again).
    async fn complete_replication(&self, job: &ReplicationJob, worker: &str, size: Option<u64>) -> Result<bool>;
}

#[derive(Default)]
struct State {
    /// (digest, location) -> (size, placed_at)
    placements: BTreeMap<(String, String), (u64, DateTime<Utc>)>,
    /// (kind, key, location) -> id
    jobs: BTreeMap<(JobKind, String, String), i64>,
    next_id: i64,
}

/// Placements in process memory: for tests and single-process tools. Queued jobs are only
/// recorded ([`MemoryPlacements::queued`]); nothing claims them.
#[derive(Default)]
pub struct MemoryPlacements {
    state: Mutex<State>,
}

impl MemoryPlacements {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The jobs waiting, as (kind, key, location).
    pub fn queued(&self) -> Vec<(JobKind, String, String)> {
        self.lock().jobs.keys().cloned().collect()
    }

    /// The first job waiting, as a worker would claim it (it stays queued until completed).
    pub fn next_job(&self) -> Option<ReplicationJob> {
        self.lock().jobs.iter().next().map(|((kind, key, location), id)| ReplicationJob { id: *id, kind: *kind, key: key.clone(), location: location.clone(), attempts: 1 })
    }
}

#[async_trait::async_trait]
impl Placements for MemoryPlacements {
    async fn place(&self, digest: &Digest, location: &str, size: u64) -> Result<()> {
        self.lock().placements.entry((digest.to_string(), location.to_string())).or_insert((size, Utc::now()));
        Ok(())
    }

    async fn placements(&self, digest: &Digest) -> Result<Vec<(String, u64)>> {
        let d = digest.to_string();
        Ok(self.lock().placements.iter().filter(|((pd, _), _)| *pd == d).map(|((_, l), (n, _))| (l.clone(), *n)).collect())
    }

    async fn unplace(&self, digest: &Digest, location: &str) -> Result<bool> {
        Ok(self.lock().placements.remove(&(digest.to_string(), location.to_string())).is_some())
    }

    async fn blobs_missing_at(&self, location: &str, limit: usize, after: Option<&Digest>) -> Result<Vec<Digest>> {
        let s = self.lock();
        let after = after.map(|d| d.to_string());
        let mut out: Vec<String> = vec![];
        for (d, _) in s.placements.keys() {
            if after.as_ref().is_some_and(|a| d <= a) || out.last() == Some(d) || s.placements.contains_key(&(d.clone(), location.to_string())) {
                continue;
            }
            out.push(d.clone());
            if out.len() == limit {
                break;
            }
        }
        Ok(out.iter().filter_map(|d| d.parse().ok()).collect())
    }

    async fn location_has_placements(&self, location: &str) -> Result<bool> {
        Ok(self.lock().placements.keys().any(|(_, l)| l == location))
    }

    async fn placed_blobs(&self) -> Result<Vec<PlacedBlob>> {
        let s = self.lock();
        let mut out: BTreeMap<&str, PlacedBlob> = BTreeMap::new();
        for ((d, _), (size, at)) in &s.placements {
            let Ok(digest) = d.parse::<Digest>() else { continue };
            let e = out.entry(d).or_insert(PlacedBlob { digest, size: *size, placed_at: *at });
            e.placed_at = e.placed_at.min(*at);
        }
        Ok(out.into_values().collect())
    }

    async fn enqueue_replication(&self, kind: JobKind, keys: &[String], locations: &[String]) -> Result<usize> {
        let mut s = self.lock();
        let mut n = 0;
        for k in keys {
            for l in locations {
                let id = s.next_id + 1;
                if let std::collections::btree_map::Entry::Vacant(e) = s.jobs.entry((kind, k.clone(), l.clone())) {
                    e.insert(id);
                    s.next_id = id;
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    async fn cancel_replication(&self, kind: JobKind, key: &str) -> Result<u64> {
        let mut s = self.lock();
        let before = s.jobs.len();
        s.jobs.retain(|(k, key2, _), _| !(*k == kind && key2 == key));
        Ok((before - s.jobs.len()) as u64)
    }

    async fn complete_replication(&self, job: &ReplicationJob, _worker: &str, size: Option<u64>) -> Result<bool> {
        let mut s = self.lock();
        if s.jobs.remove(&(job.kind, job.key.clone(), job.location.clone())).is_none() {
            return Ok(false);
        }
        if let (JobKind::Blob, Some(size)) = (job.kind, size) {
            s.placements.entry((job.key.clone(), job.location.clone())).or_insert((size, Utc::now()));
        }
        Ok(true)
    }
}
