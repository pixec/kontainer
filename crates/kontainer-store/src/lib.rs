//! Storage backend.
//!
//! Content lives in [`object_store::ObjectStore`]s, which give us local filesystem,
//! S3-compatible, GCS and Azure backends for free:
//!
//! ```text
//! blobs/<alg>/<hex>/data
//! scans/<alg>/<hex>/report.json
//! logs/<id>.json
//! _upload_chunks/<uuid>/<chunk>                                 (in-progress uploads, see [`uploads`])
//! ```
//!
//! Registry metadata (manifests with their bodies, tags, which blobs each repository links,
//! referrers and the push-time media type) is not in object storage: it lives behind
//! [`metadata::Metadata`] (the server's PostgreSQL database), set with
//! [`Storage::set_metadata`], so a push on any instance is visible on every other right away.
//! Deployments from before that keep their old `repositories/<name>/...` keys until
//! [`legacy::migrate`] (`kontainer migrate-metadata`) has copied them into the database.
//!
//! There may be several storage [`Location`]s (buckets in different regions), all peers. Each
//! instance writes to its preferred location (`storage.location`): new blobs, upload chunks,
//! scan reports and logs. Which locations hold each blob is recorded in
//! [`placement::Placements`] (the database), and copies to the other locations are queued
//! there and made in the background ([`replication`]). A blob exists when some configured
//! location holds it; reads pick a location from the placements ([`Storage::blob_sources`]),
//! without asking the object stores.
//!
//! In-progress uploads are staged as chunk objects in the preferred location of the instance
//! that took each chunk, with their session state (which names the chunk's location) behind
//! [`uploads::UploadSessions`] (the server's database), so any instance can take the next
//! chunk or complete the upload; they are committed to `blobs/` once their digest has been
//! verified.

pub mod gc;
pub mod layerfs;
pub mod layout;
pub mod legacy;
pub mod metadata;
pub mod placement;
pub mod replication;
pub mod uploads;
pub mod usage;

use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use object_store::path::Path;
use object_store::signer::Signer;
use object_store::{GetOptions, GetRange, GetResult, ObjectMeta, ObjectStore, ObjectStoreExt, PutPayload};

use kontainer_core::config::{LocationConfig, StorageConfig, StorageDriver};
use kontainer_core::digest::Digest;

use placement::JobKind;

/// A storage failure for callers that branch on it. Lookups express absence as `Option`
/// instead; this is for operations where a missing object is an outcome of its own (e.g. it was
/// deleted while being copied).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The object (registry-relative path) does not exist.
    #[error("{0} not found in storage")]
    NotFound(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Clone)]
pub struct Storage {
    /// Every configured location, in configuration order.
    locations: Arc<Vec<Location>>,
    /// Index of this instance's preferred location in `locations`.
    preferred: usize,
    pub uploads: uploads::UploadStaging,
    redirect_ttl: Duration,
    /// Copy counters, and the signal that wakes this instance's replication workers.
    pub replication: Arc<replication::Replication>,
    /// Recently computed namespace usage, for quota checks (see [`usage::namespace_missing`]).
    ns_usage: usage::NamespaceCache,
    /// Manifests, tags, blob links (see [`metadata`]).
    meta: Arc<dyn metadata::Metadata>,
    /// Which locations hold which blobs, and the copies queued (see [`placement`]).
    places: Arc<dyn placement::Placements>,
}

/// One storage location: a bucket (or directory) holding a copy of the registry's objects.
pub struct Location {
    pub name: String,
    pub driver: StorageDriver,
    /// Client regions served from here (`storage.region_header` values, globs).
    pub regions: Vec<String>,
    store: Arc<dyn ObjectStore>,
    signer: Option<Arc<dyn Signer>>,
    prefix: Option<String>,
    is_redirect: bool,
}

impl Location {
    fn key(&self, rel: impl AsRef<str>) -> Path {
        key_in(&self.prefix, rel.as_ref())
    }

    fn rel<'a>(&self, key: &'a Path) -> &'a str {
        rel_in(&self.prefix, key)
    }

    /// Whether it redirects downloads (configured, and the backend can presign URLs).
    pub fn redirects(&self) -> bool {
        self.is_redirect && self.signer.is_some()
    }

    /// Whether clients in `region` (lowercase) are sent here.
    fn serves(&self, region: &str) -> bool {
        self.regions.iter().any(|p| kontainer_core::glob::matches(&p.to_ascii_lowercase(), region))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>> {
        Ok(self.store.list(Some(&self.key(prefix))).try_collect().await?)
    }

    async fn delete_quiet(&self, key: &Path) -> Result<()> {
        match self.store.delete(key).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn size_of(&self, rel: &str) -> Result<Option<u64>> {
        match self.store.head(&self.key(rel)).await {
            Ok(meta) => Ok(Some(meta.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Write, read back and delete a small object: proves the backend works end to end.
    pub async fn probe(&self) -> Result<()> {
        let key = self.key(format!("_health/{}", kontainer_core::random_token(8)));
        let payload = Bytes::from_static(b"kontainer health probe");
        self.store.put(&key, PutPayload::from(payload.clone())).await.context("writing")?;
        let read = self.store.get(&key).await.context("reading")?.bytes().await?;
        self.store.delete(&key).await.context("deleting")?;
        if read != payload {
            anyhow::bail!("read back different bytes than written");
        }
        Ok(())
    }
}

fn key_in(prefix: &Option<String>, rel: &str) -> Path {
    match prefix {
        Some(p) => Path::from(format!("{}/{}", p.trim_matches('/'), rel)),
        None => Path::from(rel),
    }
}

fn rel_in<'a>(prefix: &Option<String>, key: &'a Path) -> &'a str {
    let s = key.as_ref();
    match prefix {
        Some(p) => s.strip_prefix(p.trim_matches('/')).and_then(|s| s.strip_prefix('/')).unwrap_or(s),
        None => s,
    }
}

fn blob_rel(d: &Digest) -> String {
    format!("blobs/{}/{}/data", d.algorithm().as_str(), d.hex())
}

fn scan_rel(d: &Digest) -> String {
    format!("scans/{}/{}/report.json", d.algorithm().as_str(), d.hex())
}

fn log_rel(id: &str) -> String {
    format!("logs/{id}.json")
}

/// The object a replication job copies.
fn job_rel(kind: JobKind, key: &str) -> Result<String> {
    Ok(match kind {
        JobKind::Blob => blob_rel(&key.parse()?),
        JobKind::Scan => scan_rel(&key.parse()?),
        JobKind::Log => log_rel(key),
    })
}

type Backend = (Arc<dyn ObjectStore>, Option<Arc<dyn Signer>>);

/// Open one storage location. S3, GCS and Azure can also presign download URLs.
fn open_backend(l: &LocationConfig) -> Result<Backend> {
    let (fs, s3, gcs, azure) = (&l.filesystem, &l.s3, &l.gcs, &l.azure);
    Ok(match l.driver {
        StorageDriver::Filesystem => {
            std::fs::create_dir_all(&fs.root).with_context(|| format!("creating {}", fs.root.display()))?;
            (Arc::new(object_store::local::LocalFileSystem::new_with_prefix(&fs.root)?.with_automatic_cleanup(true)), None)
        }
        StorageDriver::Memory => (Arc::new(object_store::memory::InMemory::new()), None),
        StorageDriver::S3 => {
            let mut b = object_store::aws::AmazonS3Builder::from_env()
                .with_bucket_name(&s3.bucket)
                .with_allow_http(s3.is_allow_http)
                .with_virtual_hosted_style_request(s3.is_virtual_hosted_style)
                .with_skip_signature(s3.is_skip_signature);
            if let Some(r) = &s3.region {
                b = b.with_region(r);
            }
            if let Some(e) = &s3.endpoint {
                b = b.with_endpoint(e);
            }
            if let Some(k) = &s3.access_key_id {
                b = b.with_access_key_id(k);
            }
            if let Some(k) = &s3.secret_access_key {
                b = b.with_secret_access_key(k.expose());
            }
            if let Some(t) = &s3.session_token {
                b = b.with_token(t.expose());
            }
            let s = Arc::new(b.build().context("building S3 client")?);
            (s.clone(), Some(s))
        }
        StorageDriver::Gcs => {
            let mut b = object_store::gcp::GoogleCloudStorageBuilder::from_env().with_bucket_name(&gcs.bucket);
            if let Some(p) = &gcs.service_account_path {
                b = b.with_service_account_path(p);
            }
            let s = Arc::new(b.build().context("building GCS client")?);
            (s.clone(), Some(s))
        }
        StorageDriver::Azure => {
            let mut b = object_store::azure::MicrosoftAzureBuilder::from_env().with_container_name(&azure.container);
            if let Some(a) = &azure.account {
                b = b.with_account(a);
            }
            if let Some(k) = &azure.access_key {
                b = b.with_access_key(k.expose());
            }
            let s = Arc::new(b.build().context("building Azure client")?);
            (s.clone(), Some(s))
        }
    })
}

pub struct BlobStream {
    pub stream: BoxStream<'static, object_store::Result<Bytes>>,
    pub total_size: u64,
    pub range: Range<u64>,
}

#[derive(Debug, Clone)]
pub struct TagEntry {
    pub tag: String,
    pub digest: Digest,
    /// When the tag was last pointed at a manifest.
    pub pushed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ReferrerEntry {
    pub digest: Digest,
}

impl Storage {
    pub async fn from_config(cfg: &StorageConfig) -> Result<Self> {
        let mut locations = vec![];
        for l in cfg.resolved_locations()? {
            let (store, signer) = open_backend(&l).with_context(|| format!("opening storage location {}", l.name))?;
            locations.push(Location { name: l.name, driver: l.driver, regions: l.regions, store, signer, prefix: l.prefix.filter(|p| !p.is_empty()), is_redirect: l.is_redirect });
        }
        let preferred = locations.iter().position(|l| l.name == cfg.location).with_context(|| format!("storage.location `{}` names none of the storage locations", cfg.location))?;
        let uploads = uploads::UploadStaging::new(&cfg.upload_dir).await?;
        Ok(Self {
            locations: Arc::new(locations),
            preferred,
            uploads,
            redirect_ttl: cfg.redirect_ttl,
            replication: Arc::default(),
            ns_usage: usage::NamespaceCache::default(),
            meta: Arc::new(metadata::MemoryMetadata::default()),
            places: Arc::new(placement::MemoryPlacements::default()),
        })
    }

    /// Keep registry metadata in `meta` (the server's database) instead of process memory.
    /// Set once at startup, before the storage is cloned.
    pub fn set_metadata(&mut self, meta: Arc<dyn metadata::Metadata>) {
        self.meta = meta;
    }

    pub fn metadata(&self) -> &Arc<dyn metadata::Metadata> {
        &self.meta
    }

    /// Keep blob placements and the replication queue in `places` (the server's database)
    /// instead of process memory. Set once at startup, before the storage is cloned.
    pub fn set_placements(&mut self, places: Arc<dyn placement::Placements>) {
        self.places = places;
    }

    pub fn placements(&self) -> &Arc<dyn placement::Placements> {
        &self.places
    }

    /// Every configured location, in configuration order.
    pub fn locations(&self) -> &[Location] {
        &self.locations
    }

    /// This instance's preferred location: where it writes.
    pub fn preferred(&self) -> &Location {
        &self.locations[self.preferred]
    }

    pub fn location(&self, name: &str) -> Option<&Location> {
        self.locations.iter().find(|l| l.name == name)
    }

    /// The other locations: where what this instance writes is copied.
    fn others(&self) -> Vec<String> {
        self.locations.iter().enumerate().filter(|(i, _)| *i != self.preferred).map(|(_, l)| l.name.clone()).collect()
    }

    /// Locations, the preferred one first, then in configuration order.
    fn preferred_first(&self) -> impl Iterator<Item = &Location> {
        std::iter::once(self.preferred()).chain(self.locations.iter().enumerate().filter(|(i, _)| *i != self.preferred).map(|(_, l)| l))
    }

    fn key(&self, rel: impl AsRef<str>) -> Path {
        self.preferred().key(rel)
    }

    /// Strip the preferred location's prefix from a key, returning the registry-relative path.
    fn rel<'a>(&self, key: &'a Path) -> &'a str {
        self.preferred().rel(key)
    }

    /// Objects under `prefix` in the preferred location.
    async fn list_objects(&self, prefix: &str) -> Result<Vec<ObjectMeta>> {
        self.preferred().list(prefix).await
    }

    /// Read from the preferred location; when it fails (other than "not found"), from the first
    /// other location that answers. For objects without placements (old-layout metadata).
    async fn get_any(&self, key: &Path, opts: GetOptions) -> object_store::Result<GetResult> {
        let here = self.preferred();
        match here.store.get_opts(key, opts.clone()).await {
            Err(e) if !matches!(e, object_store::Error::NotFound { .. }) && self.locations.len() > 1 => {
                let rel = here.rel(key);
                for l in self.preferred_first().skip(1) {
                    if let Ok(res) = l.store.get_opts(&l.key(rel), opts.clone()).await {
                        tracing::warn!(location = %l.name, key = rel, error = %e, "preferred storage location failed; read from another");
                        return Ok(res);
                    }
                }
                Err(e)
            }
            other => other,
        }
    }

    /// Read `rel` from the first location that has it, the preferred one first: for scan
    /// reports and logs, which have no placements and may not have been copied yet.
    async fn get_anywhere(&self, rel: &str) -> Result<Option<Bytes>> {
        let mut failed = None;
        for l in self.preferred_first() {
            match l.store.get(&l.key(rel)).await {
                Ok(r) => return Ok(Some(r.bytes().await?)),
                Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => {
                    tracing::warn!(location = %l.name, key = rel, error = %e, "reading from a storage location");
                    failed = Some(e);
                }
            }
        }
        match failed {
            Some(e) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Where to read blob `d`, best first, with its size: the locations holding it (configured
    /// ones only) ordered as the location serving `region` (the client's region header) first,
    /// then the preferred location, then the rest in configuration order. Empty when no
    /// configured location holds it.
    ///
    /// A blob without any placement is looked for (one `HEAD`) in the preferred location, and
    /// recorded there when found: blobs written before placements were recorded.
    pub async fn blob_sources(&self, d: &Digest, region: Option<&str>) -> Result<Vec<(&Location, u64)>> {
        let placed = self.places.placements(d).await?;
        let mut out: Vec<(usize, u64)> = placed.iter().filter_map(|(name, size)| self.locations.iter().position(|l| &l.name == name).map(|i| (i, *size))).collect();
        if out.is_empty() {
            if placed.is_empty() {
                if let Some(size) = self.preferred().size_of(&blob_rel(d)).await? {
                    self.places.place(d, &self.preferred().name, size).await?;
                    return Ok(vec![(self.preferred(), size)]);
                }
            }
            return Ok(vec![]);
        }
        let region = region.map(|r| r.trim().to_ascii_lowercase()).filter(|r| !r.is_empty());
        let rank = |i: usize| -> (u8, usize) {
            if region.as_deref().is_some_and(|r| self.locations[i].serves(r)) {
                (0, i)
            } else if i == self.preferred {
                (1, i)
            } else {
                (2, i)
            }
        };
        out.sort_by_key(|(i, _)| rank(*i));
        Ok(out.into_iter().map(|(i, n)| (&self.locations[i], n)).collect())
    }

    /// A presigned download URL for blob `d`, when the location it would be read from (see
    /// [`Self::blob_sources`]) redirects downloads. `None` means stream it.
    pub async fn blob_redirect(&self, d: &Digest, region: Option<&str>) -> Option<(String, object_store::signer::Url)> {
        use object_store::signer::Method;
        let sources = match self.blob_sources(d, region).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(%d, error = %format!("{e:#}"), "looking up where a blob is stored");
                return None;
            }
        };
        let (l, _) = sources.first()?;
        if !l.redirects() {
            return None;
        }
        match l.signer.as_ref()?.signed_url(Method::GET, &l.key(blob_rel(d)), self.redirect_ttl).await {
            Ok(url) => Some((l.name.clone(), url)),
            Err(e) => {
                tracing::warn!(location = %l.name, error = %e, "presigning a download URL");
                None
            }
        }
    }

    /// Record blob `d` as stored in the preferred location and queue copies to the others.
    async fn placed_here(&self, d: &Digest, size: u64) -> Result<()> {
        self.places.place(d, &self.preferred().name, size).await?;
        self.enqueue_copies(JobKind::Blob, &d.to_string()).await;
        Ok(())
    }

    /// Queue copies of an object just written here to the other locations. Best effort: a
    /// copy that could not be queued is caught up by the next backfill.
    async fn enqueue_copies(&self, kind: JobKind, key: &str) {
        let others = self.others();
        if others.is_empty() {
            return;
        }
        match self.places.enqueue_replication(kind, &[key.to_string()], &others).await {
            Ok(n) if n > 0 => self.replication.wake(),
            Ok(_) => {}
            Err(e) => tracing::warn!(kind = kind.as_str(), key, error = %format!("{e:#}"), "queueing copies to other storage locations"),
        }
    }

    /// The size of blob `d` if a configured location holds it. Asks the placements, not the
    /// object stores.
    pub async fn blob_size(&self, d: &Digest) -> Result<Option<u64>> {
        Ok(self.blob_sources(d, None).await?.first().map(|(_, n)| *n))
    }

    pub async fn blob_bytes(&self, d: &Digest) -> Result<Option<Bytes>> {
        match self.blob_get(d, None, GetOptions::default()).await? {
            Some(r) => Ok(Some(r.bytes().await?)),
            None => Ok(None),
        }
    }

    /// Open blob `d` from the best location (see [`Self::blob_sources`]), failing over to the
    /// next one holding it when a location errors or turns out not to have it.
    async fn blob_get(&self, d: &Digest, region: Option<&str>, opts: GetOptions) -> Result<Option<GetResult>> {
        let rel = blob_rel(d);
        let mut failed = None;
        for (l, _) in self.blob_sources(d, region).await? {
            match l.store.get_opts(&l.key(&rel), opts.clone()).await {
                Ok(r) => return Ok(Some(r)),
                Err(object_store::Error::NotFound { .. }) => tracing::warn!(location = %l.name, %d, "a blob recorded in a storage location is missing there"),
                Err(e) => {
                    tracing::warn!(location = %l.name, %d, error = %e, "reading a blob; trying the next location");
                    failed = Some(e);
                }
            }
        }
        match failed {
            Some(e) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Stream a blob, optionally restricted to `range` (end exclusive, clamped to the object).
    pub async fn blob_stream(&self, d: &Digest, range: Option<Range<u64>>) -> Result<Option<BlobStream>> {
        self.blob_stream_near(d, range, None).await
    }

    /// [`Self::blob_stream`] from the location serving the client's `region` when it has it.
    pub async fn blob_stream_near(&self, d: &Digest, range: Option<Range<u64>>, region: Option<&str>) -> Result<Option<BlobStream>> {
        let opts = GetOptions { range: range.map(GetRange::Bounded), ..Default::default() };
        Ok(self.blob_get(d, region, opts).await?.map(|r| {
            let total_size = r.meta.size;
            let range = r.range.clone();
            BlobStream { stream: r.into_stream(), total_size, range }
        }))
    }

    pub async fn blob_put(&self, d: &Digest, data: Bytes) -> Result<()> {
        let size = data.len() as u64;
        self.preferred().store.put(&self.key(blob_rel(d)), PutPayload::from(data)).await?;
        self.placed_here(d, size).await
    }

    /// Upload a staged file to the preferred location (multipart for large files). Exactly the
    /// file's length at open time is read, and the content is hashed on the way: if it does not
    /// match `d` (the file changed after it was verified) nothing is stored.
    pub async fn blob_put_file(&self, d: &Digest, file: &std::path::Path) -> Result<()> {
        let size = self.put_file(&self.key(blob_rel(d)), file, Some(d)).await?;
        self.placed_here(d, size).await
    }

    /// Store a local file as object `key` of the preferred location (multipart for large files)
    /// and return its length. Exactly the file's length at open time is read; with `expected`,
    /// the content is hashed on the way and nothing is stored unless it matches.
    async fn put_file(&self, key: &Path, file: &std::path::Path, expected: Option<&Digest>) -> Result<u64> {
        use tokio::io::AsyncReadExt;
        const PART: usize = 8 * 1024 * 1024;
        let store = &self.preferred().store;
        let f = tokio::fs::File::open(file).await.with_context(|| format!("opening {}", file.display()))?;
        let len = f.metadata().await?.len();
        let mut f = f.take(len);
        let mut hasher = expected.map(|d| Digest::hasher(d.algorithm()));
        let check = |hasher: Option<kontainer_core::digest::Hasher>, read: u64| match (expected, hasher) {
            (Some(d), Some(h)) => check_content(d, h.finalize(), read, len),
            _ if read != len => anyhow::bail!("staged file {} changed size while it was stored ({read} of {len} bytes)", file.display()),
            _ => Ok(()),
        };
        if len <= PART as u64 {
            let mut data = Vec::with_capacity(len as usize);
            f.read_to_end(&mut data).await?;
            if let Some(h) = hasher.as_mut() {
                h.update(&data);
            }
            check(hasher, data.len() as u64)?;
            store.put(key, PutPayload::from(data)).await?;
            return Ok(len);
        }
        let upload = store.put_multipart(key).await?;
        let mut w = object_store::WriteMultipart::new_with_chunk_size(upload, PART);
        let copied: Result<()> = async {
            let mut buf = vec![0u8; 1024 * 1024];
            let mut read = 0u64;
            loop {
                let n = f.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                read += n as u64;
                if let Some(h) = hasher.as_mut() {
                    h.update(&buf[..n]);
                }
                w.wait_for_capacity(4).await?;
                w.write(&buf[..n]);
            }
            check(hasher.take(), read)
        }
        .await;
        match copied {
            Ok(()) => {
                w.finish().await?;
                Ok(len)
            }
            Err(e) => {
                if let Err(abort) = w.abort().await {
                    tracing::warn!(%key, error = %abort, "aborting a multipart upload");
                }
                Err(e)
            }
        }
    }

    /// Delete a blob everywhere: queued copies are dropped first, then the object is deleted
    /// from every configured location and its placements are removed (a placement stays where
    /// the delete failed, so the next collection tries again). Garbage collection goes through
    /// [`metadata::Metadata::sweep_blob`], which runs this under the per-digest lock, so that a
    /// link (or a finished copy) committed meanwhile waits for it.
    pub async fn blob_delete(&self, d: &Digest) -> Result<()> {
        self.places.cancel_replication(JobKind::Blob, &d.to_string()).await?;
        let rel = blob_rel(d);
        let mut kept = vec![];
        for l in self.locations.iter() {
            if let Err(e) = l.delete_quiet(&l.key(&rel)).await {
                tracing::warn!(location = %l.name, %d, error = %format!("{e:#}"), "deleting a blob");
                kept.push(l.name.as_str());
            }
        }
        for (name, _) in self.places.placements(d).await? {
            if !kept.contains(&name.as_str()) {
                self.places.unplace(d, &name).await?;
            }
        }
        if kept.contains(&self.preferred().name.as_str()) {
            anyhow::bail!("blob {d} could not be deleted from storage location {}", self.preferred().name);
        }
        Ok(())
    }

    /// Every blob with when it was stored and its size: the placed ones (in any location), and
    /// objects in the preferred location without a placement (left by a write that stopped
    /// before recording it).
    pub async fn all_blobs(&self) -> Result<Vec<(Digest, DateTime<Utc>, u64)>> {
        let mut out: std::collections::HashMap<Digest, (DateTime<Utc>, u64)> = self.places.placed_blobs().await?.into_iter().map(|b| (b.digest, (b.placed_at, b.size))).collect();
        let here = self.preferred();
        for meta in here.list("blobs/").await? {
            let rel = here.rel(&meta.location);
            let mut parts = rel.split('/');
            if let (Some("blobs"), Some(alg), Some(hex), Some("data")) = (parts.next(), parts.next(), parts.next(), parts.next()) {
                if let Ok(d) = format!("{alg}:{hex}").parse::<Digest>() {
                    out.entry(d).or_insert((meta.last_modified, meta.size));
                }
            }
        }
        Ok(out.into_iter().map(|(d, (at, n))| (d, at, n)).collect())
    }

    /// Record every blob found in each configured location that holds no placements yet: the
    /// objects of a deployment from before placements were recorded (or of a location that
    /// was filled by other means). Returns (location, blobs recorded) per location indexed.
    pub async fn index_unplaced_locations(&self) -> Result<Vec<(String, usize)>> {
        let mut out = vec![];
        for l in self.locations.iter() {
            if self.places.location_has_placements(&l.name).await? {
                continue;
            }
            let mut n = 0;
            for meta in l.list("blobs/").await.with_context(|| format!("listing location {}", l.name))? {
                let rel = l.rel(&meta.location);
                let mut parts = rel.split('/');
                if let (Some("blobs"), Some(alg), Some(hex), Some("data")) = (parts.next(), parts.next(), parts.next(), parts.next()) {
                    if let Ok(d) = format!("{alg}:{hex}").parse::<Digest>() {
                        self.places.place(&d, &l.name, meta.size).await?;
                        n += 1;
                    }
                }
            }
            if n > 0 {
                tracing::info!(location = %l.name, blobs = n, "recorded the blobs already in a storage location");
            }
            out.push((l.name.clone(), n));
        }
        Ok(out)
    }

    // Metadata (see [`metadata`])
    /// Does `repo` have access to blob `d`, and if so how large is it?
    pub async fn repo_blob_size(&self, repo: &str, d: &Digest) -> Result<Option<u64>> {
        Ok(self.meta.blob_link(repo, d).await?.map(|l| l.size))
    }

    /// Link blob `d` (`size` bytes, already stored) into `repo`. Returns `false`, and leaves
    /// no link, when the blob is not in storage: a garbage collection may have removed it just
    /// before the link landed (the link waits for one in progress), so a caller holding the
    /// content stores it again and links once more (see [`Storage::store_and_link_file`]).
    pub async fn link_blob(&self, repo: &str, d: &Digest, size: u64) -> Result<bool> {
        self.meta.link_blob(repo, d, size).await?;
        if self.blob_size(d).await?.is_some() {
            return Ok(true);
        }
        self.meta.unlink_blob(repo, d).await?;
        Ok(false)
    }

    /// Store a verified file as blob `d` unless it is stored already, and link it into `repo`.
    pub async fn store_and_link_file(&self, repo: &str, d: &Digest, file: &std::path::Path) -> Result<()> {
        let size = tokio::fs::metadata(file).await.with_context(|| format!("reading {}", file.display()))?.len();
        self.store_and_link(repo, d, size, || self.blob_put_file(d, file)).await
    }

    /// [`Storage::store_and_link_file`] for content in memory.
    pub async fn store_and_link_bytes(&self, repo: &str, d: &Digest, data: Bytes) -> Result<()> {
        let size = data.len() as u64;
        self.store_and_link(repo, d, size, || self.blob_put(d, data.clone())).await
    }

    /// Store (with `put`) unless stored, then link; again if a garbage collection removed the
    /// blob meanwhile. A put that fails while a collection deletes the same object (the
    /// filesystem backend removes emptied directories as another writer creates them) is
    /// retried too.
    async fn store_and_link<F, Fut>(&self, repo: &str, d: &Digest, size: u64, put: F) -> Result<()>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        const ATTEMPTS: usize = 3;
        for attempt in 1..=ATTEMPTS {
            if self.blob_size(d).await?.is_none() {
                if let Err(e) = put().await {
                    if attempt == ATTEMPTS {
                        return Err(e);
                    }
                    tracing::debug!(%d, error = %format!("{e:#}"), attempt, "storing a blob; retrying");
                    continue;
                }
            }
            if self.link_blob(repo, d, size).await? {
                return Ok(());
            }
        }
        anyhow::bail!("blob {d} keeps disappearing while it is linked into {repo}")
    }

    pub async fn unlink_blob(&self, repo: &str, d: &Digest) -> Result<bool> {
        self.meta.unlink_blob(repo, d).await
    }

    /// Blob links of a repository.
    pub async fn repo_blob_links(&self, repo: &str) -> Result<Vec<metadata::BlobLink>> {
        self.meta.blob_links(repo).await
    }

    /// Store manifest `m` in `repo` (and point `tag` at it) in one transaction; see
    /// [`metadata::Metadata::put_manifest`].
    pub async fn put_manifest(&self, repo: &str, m: &metadata::StoredManifest, blobs: &[Digest], children: &[Digest], tag: Option<&str>) -> Result<metadata::PutManifest> {
        self.meta.put_manifest(repo, m, blobs, children, tag).await
    }

    pub async fn manifest(&self, repo: &str, d: &Digest) -> Result<Option<metadata::StoredManifest>> {
        self.meta.manifest(repo, d).await
    }

    /// The body of manifest `d` of `repo`.
    pub async fn manifest_bytes(&self, repo: &str, d: &Digest) -> Result<Option<Bytes>> {
        Ok(self.meta.manifest(repo, d).await?.map(|m| m.body))
    }

    pub async fn has_manifest(&self, repo: &str, d: &Digest) -> Result<bool> {
        self.meta.has_manifest(repo, d).await
    }

    /// Delete a manifest and the tags pointing at it; `None` if `repo` doesn't have it,
    /// otherwise the tags removed.
    pub async fn delete_manifest(&self, repo: &str, d: &Digest) -> Result<Option<Vec<String>>> {
        self.meta.delete_manifest(repo, d).await
    }

    pub async fn repo_manifests(&self, repo: &str) -> Result<Vec<Digest>> {
        self.meta.manifest_digests(repo).await
    }

    pub async fn resolve_tag(&self, repo: &str, tag: &str) -> Result<Option<Digest>> {
        self.meta.resolve_tag(repo, tag).await
    }

    /// Point `tag` at manifest `d`; returns where it pointed before.
    pub async fn put_tag(&self, repo: &str, tag: &str, d: &Digest) -> Result<Option<Digest>> {
        self.meta.put_tag(repo, tag, d).await
    }

    /// Returns where the tag pointed, if it existed.
    pub async fn delete_tag(&self, repo: &str, tag: &str) -> Result<Option<Digest>> {
        self.meta.delete_tag(repo, tag).await
    }

    /// Sorted tag names.
    pub async fn list_tags(&self, repo: &str) -> Result<Vec<String>> {
        self.meta.tags(repo, None, None).await
    }

    /// Sorted tag names after `last`, at most `limit`.
    pub async fn list_tags_page(&self, repo: &str, last: Option<&str>, limit: Option<usize>) -> Result<Vec<String>> {
        self.meta.tags(repo, last, limit).await
    }

    /// Tag count and when a tag last moved.
    pub async fn tag_summary(&self, repo: &str) -> Result<(usize, Option<DateTime<Utc>>)> {
        self.meta.tag_summary(repo).await
    }

    /// Every tag with the manifest it points at, in tag order.
    pub async fn list_tags_resolved(&self, repo: &str) -> Result<Vec<TagEntry>> {
        self.meta.tags_resolved(repo).await
    }

    /// Manifests of `repo` whose subject is `subject`, optionally only of `artifact_type`.
    pub async fn list_referrers(&self, repo: &str, subject: &Digest, artifact_type: Option<&str>) -> Result<Vec<metadata::StoredManifest>> {
        self.meta.referrers(repo, subject, artifact_type).await
    }

    /// Whether `repo` has a manifest of its own (not one of a repository nested under its
    /// name): a push creates a repository with its first manifest, layers uploaded before it
    /// don't.
    pub async fn repository_exists(&self, repo: &str) -> Result<bool> {
        self.meta.repository_exists(repo).await
    }

    /// All repository names with content (manifests or blob links), sorted.
    pub async fn list_repositories(&self) -> Result<Vec<String>> {
        self.meta.repositories().await
    }

    /// Repositories with at least one manifest, sorted.
    pub async fn repositories_with_manifests(&self) -> Result<Vec<String>> {
        self.meta.repositories_with_manifests().await
    }

    /// Whether any repository exists under `<namespace>/` (or is named `namespace`).
    pub async fn namespace_has_repositories(&self, namespace: &str) -> Result<bool> {
        self.meta.namespace_has_repositories(namespace).await
    }

    /// Remove a repository's manifests, tags and links. Repositories nested under it
    /// (`<repo>/sub`) are left alone; blobs go with the next garbage collection.
    pub async fn delete_repository(&self, repo: &str) -> Result<()> {
        self.meta.delete_repository(repo).await
    }

    /// Whether the preferred location answers a listing (readiness probe).
    pub async fn reachable(&self) -> Result<()> {
        self.preferred().list("_health/").await.map(|_| ())
    }

    /// Whether the preferred location still holds metadata keys of the layout before metadata
    /// moved into the database (`repositories/...`), so [`legacy::migrate`] should run.
    pub async fn has_legacy_metadata(&self) -> Result<bool> {
        let p = self.key(legacy::PREFIX);
        Ok(self.preferred().store.list(Some(&p)).try_next().await?.is_some())
    }

    /// Copy every registry object (blobs, scans, usage logs) into `dir`, streaming each one to a
    /// file: every blob from wherever it is stored, and the scan reports and logs of every
    /// location (the preferred location's copy when several have one). Used by
    /// `kontainer backup --storage`. Metadata (manifests, tags, links) is in the database:
    /// [`metadata::export_jsonl`] writes it out.
    pub async fn export_to(&self, dir: &std::path::Path) -> Result<(usize, u64)> {
        use tokio::io::AsyncWriteExt;
        let (mut objects, mut bytes) = (0usize, 0u64);
        let write = |rel: String| {
            let dest = dir.join(rel);
            async move {
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::File::create(&dest).await.with_context(|| format!("creating {}", dest.display()))
            }
        };
        for (d, _, _) in self.all_blobs().await? {
            let Some(r) = self.blob_get(&d, None, GetOptions::default()).await? else { continue };
            let mut file = write(blob_rel(&d)).await?;
            let mut stream = r.into_stream();
            while let Some(chunk) = stream.try_next().await? {
                bytes += chunk.len() as u64;
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            objects += 1;
        }
        // Only the registry's own data: other files that happen to live in the same directory
        // (such as an old SQLite database) are not ours to copy byte-for-byte.
        let mut seen = std::collections::HashSet::new();
        for l in self.preferred_first() {
            for prefix in ["scans/", "logs/"] {
                for meta in l.list(prefix).await? {
                    let rel = l.rel(&meta.location).to_string();
                    if !seen.insert(rel.clone()) {
                        continue;
                    }
                    let mut file = write(rel).await?;
                    let mut stream = l.store.get(&meta.location).await?.into_stream();
                    while let Some(chunk) = stream.try_next().await? {
                        bytes += chunk.len() as u64;
                        file.write_all(&chunk).await?;
                    }
                    file.flush().await?;
                    objects += 1;
                }
            }
        }
        Ok((objects, bytes))
    }

    /// Write, read back and delete a small object in the preferred location.
    pub async fn probe(&self) -> Result<()> {
        self.preferred().probe().await
    }

    pub async fn put_log(&self, id: &str, data: Vec<u8>) -> Result<()> {
        self.preferred().store.put(&self.key(log_rel(id)), PutPayload::from(data)).await?;
        self.enqueue_copies(JobKind::Log, id).await;
        Ok(())
    }

    pub async fn get_log(&self, id: &str) -> Result<Option<Bytes>> {
        self.get_anywhere(&log_rel(id)).await
    }

    /// Log ids in any location.
    pub async fn list_log_ids(&self) -> Result<Vec<String>> {
        let mut out = std::collections::BTreeSet::new();
        for l in self.locations.iter() {
            let keys = match l.list("logs/").await {
                Ok(k) => k,
                // The preferred location must answer; the others are best effort.
                Err(e) if l.name != self.preferred().name => {
                    tracing::warn!(location = %l.name, error = %format!("{e:#}"), "listing logs");
                    continue;
                }
                Err(e) => return Err(e),
            };
            out.extend(keys.iter().filter_map(|m| l.rel(&m.location).strip_prefix("logs/").and_then(|s| s.strip_suffix(".json")).map(str::to_string)));
        }
        Ok(out.into_iter().collect())
    }

    pub async fn get_scan(&self, d: &Digest) -> Result<Option<Bytes>> {
        self.get_anywhere(&scan_rel(d)).await
    }

    pub async fn put_scan(&self, d: &Digest, data: Vec<u8>) -> Result<()> {
        self.preferred().store.put(&self.key(scan_rel(d)), PutPayload::from(data)).await?;
        self.enqueue_copies(JobKind::Scan, &d.to_string()).await;
        Ok(())
    }

    /// Delete a scan report from every location.
    pub async fn delete_scan(&self, d: &Digest) -> Result<()> {
        self.places.cancel_replication(JobKind::Scan, &d.to_string()).await?;
        let rel = scan_rel(d);
        for l in self.locations.iter() {
            if let Err(e) = l.delete_quiet(&l.key(&rel)).await {
                if l.name == self.preferred().name {
                    return Err(e);
                }
                tracing::warn!(location = %l.name, %d, error = %format!("{e:#}"), "deleting a scan report");
            }
        }
        Ok(())
    }

    /// Digests with a scan report in any location.
    pub async fn all_scans(&self) -> Result<Vec<Digest>> {
        let mut out = std::collections::HashSet::new();
        for l in self.locations.iter() {
            for m in l.list("scans/").await? {
                let rel = l.rel(&m.location);
                let mut parts = rel.split('/');
                if let (Some("scans"), Some(alg), Some(hex)) = (parts.next(), parts.next(), parts.next()) {
                    if let Ok(d) = format!("{alg}:{hex}").parse::<Digest>() {
                        out.insert(d);
                    }
                }
            }
        }
        Ok(out.into_iter().collect())
    }
}

/// Parse a stored manifest. Manifests are not required to carry `mediaType`; when it is absent
/// the type is inferred from the structure (`manifests` means an index).
pub fn parse_stored_manifest(bytes: &[u8]) -> Result<kontainer_core::manifest::Manifest, kontainer_core::manifest::ManifestError> {
    use kontainer_core::manifest::{Manifest, ManifestError, OCI_INDEX, OCI_MANIFEST};
    match Manifest::parse(bytes, None) {
        Ok((m, _)) => Ok(m),
        Err(ManifestError::UnknownMediaType) => {
            let v: serde_json::Value = serde_json::from_slice(bytes).map_err(ManifestError::Json)?;
            let hint = if v.get("manifests").is_some() { OCI_INDEX } else { OCI_MANIFEST };
            Manifest::parse(bytes, Some(hint)).map(|(m, _)| m)
        }
        Err(e) => Err(e),
    }
}

/// The media type of a manifest body: its `mediaType`, else inferred from its structure
/// (`manifests` means an index).
pub fn infer_media_type(body: &[u8]) -> String {
    use kontainer_core::manifest::{Manifest, OCI_INDEX, OCI_MANIFEST};
    match Manifest::parse(body, None) {
        Ok((_, mt)) => mt,
        Err(_) => {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            if v.get("manifests").is_some() { OCI_INDEX.into() } else { OCI_MANIFEST.into() }
        }
    }
}

/// The manifests of a repository, parsed.
pub(crate) struct RepoManifests {
    pub revisions: Vec<Digest>,
    pub parsed: std::collections::HashMap<Digest, kontainer_core::manifest::Manifest>,
    /// Revisions whose content is unparseable: what they reference is unknown.
    pub unknown: Vec<Digest>,
}

pub(crate) fn parse_manifests(repo: &str, manifests: &[metadata::StoredManifest]) -> RepoManifests {
    let mut parsed = std::collections::HashMap::with_capacity(manifests.len());
    let mut unknown = vec![];
    for m in manifests {
        match parse_stored_manifest(&m.body) {
            Ok(p) => {
                parsed.insert(m.digest.clone(), p);
            }
            Err(e) => {
                tracing::warn!(%repo, d = %m.digest, error = %e, "unparseable manifest; treating everything the repository links as referenced");
                unknown.push(m.digest.clone());
            }
        }
    }
    RepoManifests { revisions: manifests.iter().map(|m| m.digest.clone()).collect(), parsed, unknown }
}

fn check_content(d: &Digest, actual: Digest, read: u64, len: u64) -> Result<()> {
    if read != len {
        anyhow::bail!("staged file for {d} changed size while it was stored ({read} of {len} bytes)");
    }
    if &actual != d {
        anyhow::bail!("staged file for {d} hashes to {actual}; not storing it");
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[allow(dead_code)]
pub async fn collect<T>(s: BoxStream<'static, object_store::Result<T>>) -> Result<Vec<T>> {
    Ok(s.collect::<Vec<_>>().await.into_iter().collect::<object_store::Result<Vec<_>>>()?)
}
