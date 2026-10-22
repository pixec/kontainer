//! Resumable blob upload sessions that work across registry instances.
//!
//! A session's state (repository, bytes received, the chunks holding them, whether it is being
//! completed) lives behind the [`UploadSessions`] trait: the server keeps it in PostgreSQL, so
//! any instance behind a load balancer can take the next `PATCH`, answer a status `GET` or
//! complete the upload; [`MemoryUploadSessions`] serves tests and single-process tools.
//!
//! The bytes live in object storage, one object per accepted chunk, in the preferred location
//! of the instance that took the chunk:
//!
//! ```text
//! _upload_chunks/<uuid>/<start offset>-<random>
//! ```
//!
//! The session records each chunk as `<location>:<name>`, so whichever instance completes the
//! upload reads every chunk from the location that holds it (a name without a location, from
//! before chunks were spread over locations, is looked for in every location).
//!
//! A chunk is streamed to a local temporary file, stored as a new object under a name nobody
//! else uses, and only then claimed with a compare-and-set on the session's offset
//! ([`UploadSessions::advance`]): of two chunks for the same offset exactly one is recorded,
//! and the loser deletes its object and answers `416`. The session lists its chunk names in
//! order, so completing reads exactly the recorded chunks, whatever else sits under the prefix.
//!
//! Completing seals the session first ([`UploadSessions::seal`]), after which no chunk can be
//! claimed: what is verified and stored is exactly what was received.
//!
//! The prefix is not `_uploads/` because the default `storage.upload_dir` (`./data/_uploads`)
//! is inside the default filesystem root (`./data`). Nothing that walks the store (garbage
//! collection, replication, exports) lists it: they read `blobs/`, `scans/` and `logs/` only.
//!
//! [`UploadStaging`] also hands out local temporary files under `storage.upload_dir`, for work
//! that starts and ends within one request (chunk bodies on their way to the store, pull-through
//! downloads, archive imports).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt, TryStreamExt};
use object_store::ObjectStoreExt;
use tokio::io::AsyncWriteExt;

use kontainer_core::digest::{Algorithm, Digest};

use crate::Storage;

/// Where chunk objects live in each location.
pub const CHUNK_PREFIX: &str = "_upload_chunks/";

/// Why appending a chunk failed.
#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    /// The upload would grow past the size limit.
    #[error("the upload is larger than the {limit} bytes allowed")]
    TooLarge { limit: u64 },
    /// The chunk's `Content-Range` does not start at the session's offset, the body was not
    /// as long as the range says, or another chunk for the same offset was recorded first.
    /// Nothing of the chunk is kept; the session holds `offset` bytes.
    #[error("the chunk does not fit the upload, which holds {offset} bytes")]
    RangeMismatch { offset: u64 },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<std::io::Error> for AppendError {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.into())
    }
}

/// One upload session as the [`UploadSessions`] store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadSession {
    pub id: String,
    pub repository: String,
    /// Bytes received so far: the sum of the chunks' sizes.
    pub offset: u64,
    /// The chunk objects under `_upload_chunks/<id>/`, in upload order, as
    /// `<location>:<name>` (or just `<name>`: written before chunks named their location).
    pub chunks: Vec<String>,
    pub created_at: DateTime<Utc>,
    /// Last time a chunk was recorded or the session was sealed.
    pub updated_at: DateTime<Utc>,
    /// Being completed: no more chunks are accepted.
    pub sealed: bool,
    /// The digest the session was sealed for.
    pub digest: Option<String>,
}

/// Where upload session state is kept. Every method is atomic on its own: implementations
/// shared by several instances (the server's PostgreSQL one) must make [`Self::advance`] and
/// [`Self::seal`] single conditional updates.
#[async_trait::async_trait]
pub trait UploadSessions: Send + Sync {
    /// Record a new, empty session.
    async fn create(&self, id: &str, repository: &str) -> Result<()>;

    async fn get(&self, id: &str) -> Result<Option<UploadSession>>;

    /// Compare-and-set: when the session exists, is not sealed and holds exactly
    /// `expected_offset` bytes, add chunk `chunk` of `len` bytes (offset += len, chunk appended,
    /// `updated_at` = now) and return `true`. Otherwise change nothing and return `false`.
    async fn advance(&self, id: &str, expected_offset: u64, len: u64, chunk: &str) -> Result<bool>;

    /// Seal the session for completion with `digest` and return it as sealed. A session already
    /// sealed for the same digest is returned again (a retried `PUT`); one sealed for another
    /// digest, or missing, gives `None`.
    async fn seal(&self, id: &str, digest: &str) -> Result<Option<UploadSession>>;

    /// Forget the session. Returns whether it existed.
    async fn delete(&self, id: &str) -> Result<bool>;

    /// Sessions last updated before `cutoff`.
    async fn list_expired(&self, cutoff: DateTime<Utc>) -> Result<Vec<String>>;
}

/// [`UploadSessions`] in process memory: for tests and single-process use.
#[derive(Default)]
pub struct MemoryUploadSessions {
    sessions: Mutex<HashMap<String, UploadSession>>,
}

impl MemoryUploadSessions {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, UploadSession>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl UploadSessions for MemoryUploadSessions {
    async fn create(&self, id: &str, repository: &str) -> Result<()> {
        let now = Utc::now();
        let s = UploadSession { id: id.into(), repository: repository.into(), offset: 0, chunks: vec![], created_at: now, updated_at: now, sealed: false, digest: None };
        self.map().insert(id.into(), s);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<UploadSession>> {
        Ok(self.map().get(id).cloned())
    }

    async fn advance(&self, id: &str, expected_offset: u64, len: u64, chunk: &str) -> Result<bool> {
        let mut map = self.map();
        match map.get_mut(id) {
            Some(s) if !s.sealed && s.offset == expected_offset => {
                s.offset += len;
                s.chunks.push(chunk.into());
                s.updated_at = Utc::now();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn seal(&self, id: &str, digest: &str) -> Result<Option<UploadSession>> {
        let mut map = self.map();
        match map.get_mut(id) {
            Some(s) if !s.sealed || s.digest.as_deref() == Some(digest) => {
                s.sealed = true;
                s.digest = Some(digest.into());
                s.updated_at = Utc::now();
                Ok(Some(s.clone()))
            }
            _ => Ok(None),
        }
    }

    async fn delete(&self, id: &str) -> Result<bool> {
        Ok(self.map().remove(id).is_some())
    }

    async fn list_expired(&self, cutoff: DateTime<Utc>) -> Result<Vec<String>> {
        Ok(self.map().values().filter(|s| s.updated_at < cutoff).map(|s| s.id.clone()).collect())
    }
}

/// Upload session state and the local directory for per-request temporary files.
#[derive(Clone)]
pub struct UploadStaging {
    root: PathBuf,
    sessions: Arc<dyn UploadSessions>,
}

/// A temporary file under the staging directory, removed when dropped (also when the future
/// using it is cancelled).
#[derive(Debug)]
pub struct TempPath(PathBuf);

impl TempPath {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for TempPath {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TempPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        // A file or a directory (layout imports unpack into one).
        let p = &self.0;
        if std::fs::remove_file(p).is_err() {
            let _ = std::fs::remove_dir_all(p);
        }
    }
}

/// A request body written to a temporary file by [`Storage::stage_body`].
pub struct StagedBody {
    pub file: TempPath,
    pub len: u64,
    /// With an algorithm asked for: the body's digest.
    pub digest: Option<Digest>,
}

/// What [`Storage::upload_assemble`] found.
pub enum Assembled {
    /// The session's bytes match the digest; they are in this file.
    Verified(TempPath),
    /// They hash to something else.
    Mismatch,
    /// No such session, or it is being completed for another digest.
    Unknown,
}

/// What [`Storage::purge_stale_uploads`] removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Purged {
    /// Expired sessions (with their chunks).
    pub sessions: usize,
    /// Chunk objects no session refers to any more (an instance stopped between forgetting a
    /// session and deleting its chunks).
    pub orphan_chunks: usize,
    /// Local temporary files and leftover local session directories.
    pub local: usize,
}

impl Purged {
    pub fn total(&self) -> usize {
        self.sessions + self.orphan_chunks + self.local
    }
}

impl UploadStaging {
    pub async fn new(root: &Path) -> Result<Self> {
        tokio::fs::create_dir_all(root).await.with_context(|| format!("creating upload dir {}", root.display()))?;
        Ok(Self { root: root.to_path_buf(), sessions: Arc::new(MemoryUploadSessions::default()) })
    }

    /// Keep session state in `sessions` (the server's database) instead of process memory.
    pub fn set_sessions(&mut self, sessions: Arc<dyn UploadSessions>) {
        self.sessions = sessions;
    }

    pub fn sessions(&self) -> &Arc<dyn UploadSessions> {
        &self.sessions
    }

    /// A fresh path for a temporary download (pull-through cache, mirrors, imports). The
    /// caller removes it; [`Storage::purge_stale_uploads`] removes what leaks. Prefer
    /// [`Self::temp_file`].
    pub async fn temp_path(&self) -> std::io::Result<PathBuf> {
        let dir = self.root.join(FETCH_DIR);
        tokio::fs::create_dir_all(&dir).await?;
        Ok(dir.join(kontainer_core::random_token(16)))
    }

    /// Like [`Self::temp_path`], removed when the returned guard is dropped.
    pub async fn temp_file(&self) -> std::io::Result<TempPath> {
        self.temp_path().await.map(TempPath)
    }

    /// Remove local temporary files, and session directories left by versions that staged
    /// uploads on local disk, last modified before `cutoff` (unix seconds).
    async fn purge_local(&self, cutoff: u64) -> Result<usize> {
        let mut removed = 0;
        let mut entries = tokio::fs::read_dir(&self.root).await?;
        while let Some(e) = entries.next_entry().await? {
            let name = e.file_name().to_string_lossy().to_string();
            if name == FETCH_DIR {
                removed += purge_fetch(&e.path(), cutoff).await?;
            } else if uuid::Uuid::parse_str(&name).is_ok() {
                let Ok(meta) = e.metadata().await else { continue };
                if meta.is_dir() && mtime_secs(&meta).is_some_and(|t| t < cutoff) && tokio::fs::remove_dir_all(e.path()).await.is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok()
}

impl Storage {
    /// Where recorded chunk `recorded` of upload `id` may be: its location, or (a chunk
    /// recorded without one) every location, the preferred one first.
    fn chunk_objects(&self, id: &str, recorded: &str) -> Vec<(&crate::Location, object_store::path::Path)> {
        if let Some((loc, name)) = recorded.split_once(':') {
            if let Some(l) = self.location(loc) {
                return vec![(l, l.key(format!("{CHUNK_PREFIX}{id}/{name}")))];
            }
        }
        let name = recorded.rsplit(':').next().unwrap_or(recorded);
        self.preferred_first().map(|l| (l, l.key(format!("{CHUNK_PREFIX}{id}/{name}")))).collect()
    }

    /// Start an upload session for `repository`. Returns its id.
    pub async fn upload_start(&self, repository: &str) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.uploads.sessions.create(&id, repository).await?;
        Ok(id)
    }

    pub async fn upload_session(&self, id: &str) -> Result<Option<UploadSession>> {
        if !valid_id(id) {
            return Ok(None);
        }
        self.uploads.sessions.get(id).await
    }

    /// Write a request body to a temporary file. With `limit`, refuse a body that would take
    /// the upload (`already` bytes so far) past `limit` bytes in all; with `exact`, a body of
    /// another length is [`AppendError::RangeMismatch`] at offset `already`; with `alg`, hash it.
    pub async fn stage_body<S, E>(&self, mut body: S, already: u64, limit: Option<u64>, exact: Option<u64>, alg: Option<Algorithm>) -> Result<StagedBody, AppendError>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: std::fmt::Display,
    {
        let file = self.uploads.temp_file().await?;
        let mut f = tokio::fs::File::create(&file).await?;
        let mut hasher = alg.map(Digest::hasher);
        let mut len = 0u64;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| anyhow::anyhow!("reading request body: {e}"))?;
            len += chunk.len() as u64;
            if exact.is_some_and(|n| len > n) {
                return Err(AppendError::RangeMismatch { offset: already });
            }
            if let Some(limit) = limit.filter(|l| already.saturating_add(len) > *l) {
                return Err(AppendError::TooLarge { limit });
            }
            if let Some(h) = hasher.as_mut() {
                h.update(&chunk);
            }
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
        if exact.is_some_and(|n| len != n) {
            return Err(AppendError::RangeMismatch { offset: already });
        }
        Ok(StagedBody { file, len, digest: hasher.map(|h| h.finalize()) })
    }

    /// Append a body to upload `id`. Returns the new offset. With `limit`, the upload may hold
    /// at most that many bytes in all: the chunk that would go past it is not recorded and
    /// [`AppendError::TooLarge`] is returned (what was recorded before stays).
    pub async fn upload_append<S, E>(&self, id: &str, body: S, limit: Option<u64>) -> Result<u64, AppendError>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: std::fmt::Display,
    {
        self.upload_append_range(id, body, limit, None).await
    }

    /// [`Self::upload_append`] for a chunk with a `Content-Range` of `range` (inclusive start
    /// and end): the start must be the session's offset and the body exactly `end - start + 1`
    /// bytes, otherwise [`AppendError::RangeMismatch`] and the session is left as it was.
    ///
    /// The chunk is recorded with a compare-and-set on the offset read before the body, so of
    /// two concurrent chunks for the same offset (on any instances) only one lands; the other
    /// gets `RangeMismatch` and its object is deleted.
    pub async fn upload_append_range<S, E>(&self, id: &str, body: S, limit: Option<u64>, range: Option<(u64, u64)>) -> Result<u64, AppendError>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: std::fmt::Display,
    {
        let Some(s) = self.upload_session(id).await? else {
            return Err(anyhow::anyhow!("unknown upload {id}").into());
        };
        if s.sealed {
            return Err(anyhow::anyhow!("upload {id} is being completed; no more data is accepted").into());
        }
        let start = s.offset;
        let exact = match range {
            Some((a, b)) if a == start && b >= a => Some(b - a + 1),
            Some(_) => return Err(AppendError::RangeMismatch { offset: start }),
            None => None,
        };
        let staged = self.stage_body(body, start, limit, exact, None).await?;
        if staged.len == 0 {
            return Ok(start);
        }
        // A name of its own: a racing chunk for the same offset never overwrites ours.
        let name = format!("{start:020}-{}", kontainer_core::random_token(8));
        let here = self.preferred();
        let key = here.key(format!("{CHUNK_PREFIX}{id}/{name}"));
        let len = self.put_file(&key, staged.file.path(), None).await?;
        drop(staged);
        let chunk = format!("{}:{name}", here.name);
        let recorded = match self.uploads.sessions.advance(id, start, len, &chunk).await {
            Ok(r) => r,
            Err(e) => {
                let _ = here.delete_quiet(&key).await;
                return Err(e.into());
            }
        };
        if recorded {
            return Ok(self.upload_session(id).await?.map_or(start, |s| s.offset));
        }
        // Lost the race (or the session was sealed or removed meanwhile).
        if let Err(e) = here.delete_quiet(&key).await {
            tracing::warn!(upload = id, %key, error = %e, "removing a chunk that was not recorded");
        }
        match self.upload_session(id).await? {
            Some(s) if !s.sealed => Err(AppendError::RangeMismatch { offset: s.offset }),
            Some(_) => Err(anyhow::anyhow!("upload {id} is being completed; no more data is accepted").into()),
            None => Err(anyhow::anyhow!("unknown upload {id}").into()),
        }
    }

    /// Seal upload `id` for `expected` (no more chunks are accepted), concatenate its chunks
    /// into a local file while hashing them with `expected`'s algorithm, and compare.
    pub async fn upload_assemble(&self, id: &str, expected: &Digest) -> Result<Assembled> {
        if !valid_id(id) {
            return Ok(Assembled::Unknown);
        }
        let Some(s) = self.uploads.sessions.seal(id, &expected.to_string()).await? else {
            return Ok(Assembled::Unknown);
        };
        let file = self.uploads.temp_file().await?;
        let mut f = tokio::fs::File::create(&file).await?;
        let mut hasher = Digest::hasher(expected.algorithm());
        let mut len = 0u64;
        for chunk in &s.chunks {
            let mut opened = None;
            let mut failed = None;
            for (l, key) in self.chunk_objects(id, chunk) {
                match l.store.get(&key).await {
                    Ok(r) => {
                        opened = Some(r);
                        break;
                    }
                    Err(e) => failed = Some(e),
                }
            }
            let Some(r) = opened else {
                let e = failed.map(anyhow::Error::from).unwrap_or_else(|| anyhow::anyhow!("no storage location"));
                return Err(e.context(format!("reading chunk {chunk} of upload {id}")));
            };
            let mut stream = r.into_stream();
            while let Some(b) = stream.try_next().await? {
                len += b.len() as u64;
                hasher.update(&b);
                f.write_all(&b).await?;
            }
        }
        f.flush().await?;
        anyhow::ensure!(len == s.offset, "upload {id} holds {len} bytes in its chunks but recorded {}", s.offset);
        if &hasher.finalize() != expected {
            return Ok(Assembled::Mismatch);
        }
        Ok(Assembled::Verified(file))
    }

    /// Forget upload `id` and delete its chunks.
    pub async fn upload_remove(&self, id: &str) -> Result<()> {
        if !valid_id(id) {
            return Ok(());
        }
        // Session first: a chunk being recorded now loses its compare-and-set and removes
        // its own object.
        self.uploads.sessions.delete(id).await?;
        for l in self.locations() {
            for m in l.list(&format!("{CHUNK_PREFIX}{id}/")).await? {
                l.delete_quiet(&m.location).await?;
            }
        }
        Ok(())
    }

    /// Remove upload sessions not updated for `ttl` with their chunks, chunk objects older
    /// than `ttl` that no session refers to, and stale local temporary files.
    pub async fn purge_stale_uploads(&self, ttl: Duration) -> Result<Purged> {
        let mut purged = Purged::default();
        let cutoff = Utc::now() - chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::MAX);
        for id in self.uploads.sessions.list_expired(cutoff).await? {
            self.upload_remove(&id).await?;
            purged.sessions += 1;
        }
        // Chunks of every location: an instance elsewhere may have stopped mid-upload.
        let mut orphans: HashMap<String, Vec<(&crate::Location, object_store::path::Path)>> = HashMap::new();
        for l in self.locations() {
            for m in l.list(CHUNK_PREFIX).await? {
                if m.last_modified >= cutoff {
                    continue;
                }
                if let Some(id) = l.rel(&m.location).strip_prefix(CHUNK_PREFIX).and_then(|r| r.split('/').next()) {
                    orphans.entry(id.to_string()).or_default().push((l, m.location.clone()));
                }
            }
        }
        for (id, keys) in orphans {
            if valid_id(&id) && self.uploads.sessions.get(&id).await?.is_some() {
                continue;
            }
            for (l, k) in keys {
                l.delete_quiet(&k).await?;
                purged.orphan_chunks += 1;
            }
        }
        purged.local = self.uploads.purge_local(now().saturating_sub(ttl.as_secs())).await?;
        Ok(purged)
    }

    /// The chunk objects of upload `id` in every location, recorded or not.
    pub async fn upload_chunk_objects(&self, id: &str) -> Result<usize> {
        let mut n = 0;
        for l in self.locations() {
            n += l.list(&format!("{CHUNK_PREFIX}{id}/")).await?.len();
        }
        Ok(n)
    }
}

/// Temporary downloads live here, under `storage.upload_dir`.
const FETCH_DIR: &str = "_fetch";

fn mtime_secs(m: &std::fs::Metadata) -> Option<u64> {
    m.modified().ok().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()).map(|d| d.as_secs())
}

/// Remove entries of the temporary download directory last modified before `cutoff`.
async fn purge_fetch(dir: &Path, cutoff: u64) -> Result<usize> {
    let mut removed = 0;
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(e) = entries.next_entry().await? {
        let Ok(meta) = e.metadata().await else { continue };
        if mtime_secs(&meta).is_none_or(|t| t >= cutoff) {
            continue;
        }
        let res = if meta.is_dir() { tokio::fs::remove_dir_all(e.path()).await } else { tokio::fs::remove_file(e.path()).await };
        match res {
            Ok(()) => removed += 1,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => tracing::warn!(path = %e.path().display(), error = %err, "removing a stale temporary download"),
        }
    }
    Ok(removed)
}

fn now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
