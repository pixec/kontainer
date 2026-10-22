//! Copying objects between storage locations.
//!
//! Every write to a location queues a copy to each other location (see [`crate::placement`]).
//! Workers on every instance take the copies from the queue (the server's dispatcher claims
//! them) and run [`Storage::replicate`]: it reads the object from a location that has it (the
//! preferred one when it can) and writes it to the job's location, checking a blob's size and
//! digest on the way, then records the new placement. A backfill ([`Storage::backfill`])
//! queues every blob a location is missing: after an outage, or for a newly added location.
//! Metadata (manifests, tags, links) is in the database, which every region reads, so only
//! content is copied: blobs, scan reports and usage logs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use chrono::Utc;
use futures::TryStreamExt;
use object_store::{ObjectStoreExt, PutPayload, WriteMultipart};
use serde::Serialize;
use tokio::sync::Notify;

use crate::placement::{JobKind, ReplicationJob};
use crate::{job_rel, Location, Storage, StoreError};
use kontainer_core::digest::Digest;

/// Objects up to this size are copied in one request; larger ones in parts.
const PART: usize = 8 * 1024 * 1024;

/// Copies this process made to one location since it started.
#[derive(Debug, Default, Clone, Serialize)]
pub struct LocationStats {
    pub copied: u64,
    pub copied_bytes: u64,
    pub failed: u64,
    pub last_error: Option<String>,
    pub last_error_at: Option<String>,
}

/// Per-process replication state: counters for metrics and the admin page, and the signal that
/// wakes this instance's workers when it queues a copy.
#[derive(Default)]
pub struct Replication {
    wake: Arc<Notify>,
    stats: Mutex<HashMap<String, LocationStats>>,
}

impl Replication {
    /// Woken when this instance queues copies.
    pub fn notifier(&self) -> Arc<Notify> {
        self.wake.clone()
    }

    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    pub fn stats(&self, location: &str) -> LocationStats {
        self.lock().get(location).cloned().unwrap_or_default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, LocationStats>> {
        self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn copied(&self, location: &str, bytes: u64) {
        let mut g = self.lock();
        let s = g.entry(location.to_string()).or_default();
        s.copied += 1;
        s.copied_bytes += bytes;
    }

    /// Record a failed copy attempt to `location`.
    pub fn failed(&self, location: &str, error: String) {
        let mut g = self.lock();
        let s = g.entry(location.to_string()).or_default();
        s.failed += 1;
        s.last_error = Some(error);
        s.last_error_at = Some(Utc::now().to_rfc3339());
    }
}

/// How a replication job ended (errors aside, which the caller retries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replicated {
    /// Copied; this many bytes.
    Copied(u64),
    /// The location had it already; now recorded.
    AlreadyThere,
    /// No location has it any more (deleted meanwhile): nothing to copy.
    Gone,
    /// Garbage collection deleted it while it was copied: the copy was removed again.
    Cancelled,
}

impl Storage {
    /// Make the copy job `job` (claimed by `worker`) asks for, and complete the job. An error
    /// leaves the job to the caller, to retry or give up on.
    pub async fn replicate(&self, job: &ReplicationJob, worker: &str) -> Result<Replicated> {
        let Some(target) = self.location(&job.location) else { bail!("unknown storage location `{}` (not in the configuration)", job.location) };
        let rel = job_rel(job.kind, &job.key)?;
        let outcome = match job.kind {
            JobKind::Blob => self.replicate_blob(job, worker, target, &rel).await?,
            JobKind::Scan | JobKind::Log => {
                let mut copied = None;
                for src in self.preferred_first().filter(|l| l.name != target.name) {
                    match copy(src, target, &rel, None).await {
                        Ok(n) => {
                            copied = Some(n);
                            break;
                        }
                        Err(StoreError::NotFound(_)) => {}
                        Err(StoreError::Other(e)) => return Err(e),
                    }
                }
                self.places.complete_replication(job, worker, None).await?;
                copied.map_or(Replicated::Gone, Replicated::Copied)
            }
        };
        if let Replicated::Copied(n) = outcome {
            self.replication.copied(&target.name, n);
        }
        Ok(outcome)
    }

    async fn replicate_blob(&self, job: &ReplicationJob, worker: &str, target: &Location, rel: &str) -> Result<Replicated> {
        let d: Digest = job.key.parse()?;
        let placed = self.places.placements(&d).await?;
        let Some(size) = placed.iter().map(|(_, n)| *n).next() else {
            // Deleted meanwhile.
            self.places.complete_replication(job, worker, None).await?;
            return Ok(Replicated::Gone);
        };
        if placed.iter().any(|(l, _)| *l == target.name) {
            self.places.complete_replication(job, worker, None).await?;
            return Ok(Replicated::AlreadyThere);
        }
        // Copied before (a backfill of a location holding objects nobody recorded, or a copy
        // whose completion was lost): only record it.
        if target.size_of(rel).await? == Some(size) {
            return Ok(if self.places.complete_replication(job, worker, Some(size)).await? { Replicated::AlreadyThere } else { Replicated::Cancelled });
        }
        let sources: Vec<&Location> = self.preferred_first().filter(|l| l.name != target.name && placed.iter().any(|(p, _)| *p == l.name)).collect();
        if sources.is_empty() {
            bail!("blob {d} is only in locations no longer configured ({})", placed.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>().join(", "));
        }
        let mut failed = None;
        for src in sources {
            match copy(src, target, rel, Some((&d, size))).await {
                Ok(n) => {
                    if !self.places.complete_replication(job, worker, Some(n)).await? {
                        // Garbage collection removed the blob (and this job) meanwhile.
                        target.delete_quiet(&target.key(rel)).await?;
                        return Ok(Replicated::Cancelled);
                    }
                    return Ok(Replicated::Copied(n));
                }
                Err(StoreError::NotFound(_)) => tracing::warn!(location = %src.name, %d, "a blob recorded in a storage location is missing there"),
                Err(StoreError::Other(e)) => {
                    tracing::debug!(from = %src.name, to = %target.name, %d, error = %format!("{e:#}"), "copying a blob; trying another source");
                    failed = Some(e);
                }
            }
        }
        match failed {
            Some(e) => Err(e),
            None => bail!("blob {d} is missing from every location recorded as holding it"),
        }
    }

    /// Queue a copy to `location` of every blob placed elsewhere but not there. Returns how
    /// many were queued (copies already waiting are not queued again).
    pub async fn backfill(&self, location: &str) -> Result<usize> {
        anyhow::ensure!(self.location(location).is_some(), "unknown storage location `{location}`");
        const BATCH: usize = 1000;
        let mut queued = 0;
        let mut after: Option<Digest> = None;
        loop {
            let batch = self.places.blobs_missing_at(location, BATCH, after.as_ref()).await?;
            let Some(last) = batch.last().cloned() else { break };
            let keys: Vec<String> = batch.iter().map(ToString::to_string).collect();
            queued += self.places.enqueue_replication(JobKind::Blob, &keys, &[location.to_string()]).await?;
            after = Some(last);
            if batch.len() < BATCH {
                break;
            }
        }
        if queued > 0 {
            self.replication.wake();
        }
        Ok(queued)
    }

    /// Write, read back and delete a small object in location `name`.
    pub async fn probe_location(&self, name: &str) -> Result<()> {
        let Some(l) = self.location(name) else { bail!("no storage location {name}") };
        l.probe().await
    }
}

/// Copy object `rel` from `src` to `dst`. With `verify` (a blob's digest and recorded size),
/// the bytes are hashed on the way and nothing is kept unless they match. Returns the size.
async fn copy(src: &Location, dst: &Location, rel: &str, verify: Option<(&Digest, u64)>) -> Result<u64, StoreError> {
    let res = match src.store.get(&src.key(rel)).await {
        Ok(res) => res,
        Err(object_store::Error::NotFound { .. }) => return Err(StoreError::NotFound(rel.to_string())),
        Err(e) => return Err(StoreError::Other(e.into())),
    };
    let size = res.meta.size;
    if let Some((d, expected)) = verify {
        if size != expected {
            return Err(StoreError::Other(anyhow::anyhow!("{rel} in {} is {size} bytes, {expected} recorded for {d}", src.name)));
        }
    }
    let dest = dst.key(rel);
    let mut hasher = verify.map(|(d, _)| Digest::hasher(d.algorithm()));
    let check = |hasher: Option<kontainer_core::digest::Hasher>| -> Result<()> {
        if let (Some((d, _)), Some(h)) = (verify, hasher) {
            let actual = h.finalize();
            anyhow::ensure!(&actual == d, "{rel} in {} hashes to {actual}, not {d}", src.name);
        }
        Ok(())
    };
    if size as usize <= PART {
        let bytes = res.bytes().await.map_err(|e| StoreError::Other(e.into()))?;
        if let Some(h) = hasher.as_mut() {
            h.update(&bytes);
        }
        check(hasher)?;
        dst.store.put(&dest, PutPayload::from(bytes)).await.map_err(|e| StoreError::Other(e.into()))?;
        return Ok(size);
    }
    let upload = dst.store.put_multipart(&dest).await.map_err(|e| StoreError::Other(e.into()))?;
    let mut w = WriteMultipart::new_with_chunk_size(upload, PART);
    let mut stream = res.into_stream();
    let copied: Result<()> = async {
        let mut read = 0u64;
        while let Some(chunk) = stream.try_next().await? {
            read += chunk.len() as u64;
            if let Some(h) = hasher.as_mut() {
                h.update(&chunk);
            }
            w.wait_for_capacity(4).await?;
            w.write(&chunk);
        }
        anyhow::ensure!(read == size, "{rel} in {} ended after {read} of {size} bytes", src.name);
        check(hasher.take())
    }
    .await;
    match copied {
        Ok(()) => {
            w.finish().await.map_err(|e| StoreError::Other(e.into()))?;
            Ok(size)
        }
        Err(e) => {
            let _ = w.abort().await;
            Err(StoreError::Other(e))
        }
    }
}
