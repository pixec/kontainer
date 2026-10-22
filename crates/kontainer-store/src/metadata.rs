//! Registry metadata: manifests (with their bodies), tags, repository blob links and
//! referrers, held by a [`Metadata`] implementation rather than in object storage, so that a
//! push on any instance in any region is visible everywhere as soon as it commits.
//!
//! The server keeps them in PostgreSQL (`kontainer_server::database::registry`), where every
//! operation that touches several rows (a manifest push with its tag, a manifest delete with
//! the tags pointing at it, a repository delete) is one transaction. [`MemoryMetadata`] serves
//! the store's own tests and single-process tools.
//!
//! Referrers are not stored separately: a manifest's `subject` digest and `artifactType` are
//! columns of its row, and the referrers of a subject are the manifests naming it.
//!
//! Blob bytes stay in object storage (`blobs/<alg>/<hex>/data`). Garbage collection deletes a
//! blob only through [`Metadata::sweep_blob`], which checks that nothing links it while holding
//! a lock that [`Metadata::link_blob`] also takes, so a blob is never deleted from under a link
//! committed concurrently (see [`crate::gc`]).

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

use anyhow::{bail, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;

use kontainer_core::digest::Digest;

use crate::TagEntry;

/// A manifest as stored in one repository.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredManifest {
    pub digest: Digest,
    /// What GET answers with when the body has no `mediaType` of its own: the push-time
    /// `Content-Type` (or the type the body declares or implies).
    pub media_type: String,
    pub body: Bytes,
    /// The `subject` this manifest refers to (OCI 1.1 referrers).
    pub subject: Option<Digest>,
    /// `artifactType` as the referrers API reports it (the config media type for images that
    /// don't declare one).
    pub artifact_type: Option<String>,
    pub pushed_at: DateTime<Utc>,
}

impl StoredManifest {
    /// A manifest pushed now. `subject` and `artifact_type` are read from the body.
    pub fn new(digest: Digest, media_type: impl Into<String>, body: Bytes) -> Self {
        let parsed = crate::parse_stored_manifest(&body).ok();
        Self {
            digest,
            media_type: media_type.into(),
            subject: parsed.as_ref().and_then(|m| m.subject()).map(|s| s.digest.clone()),
            artifact_type: parsed.as_ref().and_then(|m| m.artifact_type()),
            body,
            pushed_at: Utc::now(),
        }
    }

    pub fn size(&self) -> u64 {
        self.body.len() as u64
    }
}

/// A repository's link to a blob: the repository may read it.
#[derive(Debug, Clone, PartialEq)]
pub struct BlobLink {
    pub digest: Digest,
    pub size: u64,
    /// When it was last linked, or referenced by a manifest push.
    pub linked_at: DateTime<Utc>,
}

/// Everything one repository holds, read consistently (one snapshot).
#[derive(Debug, Clone, Default)]
pub struct RepoSnapshot {
    pub manifests: Vec<StoredManifest>,
    /// In tag order.
    pub tags: Vec<TagEntry>,
    pub links: Vec<BlobLink>,
}

/// The outcome of [`Metadata::put_manifest`].
#[derive(Debug, Clone, PartialEq)]
pub enum PutManifest {
    /// Stored; the tag (if one was given) pointed at `previous_tag` before.
    Stored { previous_tag: Option<Digest> },
    /// Nothing was stored: these blobs are not linked in the repository, or these child
    /// manifests are not in it.
    Missing(Vec<Digest>),
}

/// Where registry metadata lives. Each method is atomic.
#[async_trait::async_trait]
pub trait Metadata: Send + Sync {
    /// Store manifest `m` in `repo` and point `tag` at it, in one transaction, provided that
    /// every one of `blobs` is linked in `repo` (their links count as just used, so a
    /// concurrent garbage collection keeps them) and every one of `children` is a manifest of
    /// `repo`. Pushing a stored manifest again refreshes its `pushed_at` and media type.
    async fn put_manifest(&self, repo: &str, m: &StoredManifest, blobs: &[Digest], children: &[Digest], tag: Option<&str>) -> Result<PutManifest>;
    async fn manifest(&self, repo: &str, digest: &Digest) -> Result<Option<StoredManifest>>;
    async fn has_manifest(&self, repo: &str, digest: &Digest) -> Result<bool>;
    async fn manifest_digests(&self, repo: &str) -> Result<Vec<Digest>>;
    async fn manifests(&self, repo: &str) -> Result<Vec<StoredManifest>>;
    /// Delete a manifest and the tags pointing at it. `None` when `repo` doesn't have it,
    /// otherwise the tags removed.
    async fn delete_manifest(&self, repo: &str, digest: &Digest) -> Result<Option<Vec<String>>>;
    /// Garbage collection: delete a manifest unless a tag points at it or it was pushed after
    /// `cutoff`. Whether it was deleted.
    async fn collect_manifest(&self, repo: &str, digest: &Digest, cutoff: DateTime<Utc>) -> Result<bool>;
    /// Manifests of `repo` whose `subject` is `subject`, optionally only of `artifact_type`.
    async fn referrers(&self, repo: &str, subject: &Digest, artifact_type: Option<&str>) -> Result<Vec<StoredManifest>>;

    async fn resolve_tag(&self, repo: &str, tag: &str) -> Result<Option<Digest>>;
    /// Point `tag` at `digest` (a manifest of `repo`); returns where it pointed before. Its time
    /// is refreshed even when it already pointed there.
    async fn put_tag(&self, repo: &str, tag: &str, digest: &Digest) -> Result<Option<Digest>>;
    /// Returns where the tag pointed, if it existed.
    async fn delete_tag(&self, repo: &str, tag: &str) -> Result<Option<Digest>>;
    /// Tag names in byte order: after `last` when given, at most `limit`.
    async fn tags(&self, repo: &str, last: Option<&str>, limit: Option<usize>) -> Result<Vec<String>>;
    async fn tags_resolved(&self, repo: &str) -> Result<Vec<TagEntry>>;
    /// Tag count and when a tag last moved.
    async fn tag_summary(&self, repo: &str) -> Result<(usize, Option<DateTime<Utc>>)>;

    /// Link blob `digest` (`size` bytes) into `repo`, or refresh the link's time. Waits for a
    /// [`Metadata::sweep_blob`] of the same digest in progress: the caller must check that the
    /// blob still exists afterwards.
    async fn link_blob(&self, repo: &str, digest: &Digest, size: u64) -> Result<()>;
    async fn blob_link(&self, repo: &str, digest: &Digest) -> Result<Option<BlobLink>>;
    async fn unlink_blob(&self, repo: &str, digest: &Digest) -> Result<bool>;
    /// Garbage collection: remove a link not used since `cutoff`. Whether it was removed.
    async fn collect_blob_link(&self, repo: &str, digest: &Digest, cutoff: DateTime<Utc>) -> Result<bool>;
    async fn blob_links(&self, repo: &str) -> Result<Vec<BlobLink>>;
    /// Garbage collection: run `delete` (which removes the blob's objects) if, under a lock
    /// that keeps [`Metadata::link_blob`] out meanwhile, no repository links `digest` and no
    /// upload is completing it. Whether it ran.
    async fn sweep_blob(&self, digest: &Digest, delete: BoxFuture<'_, Result<()>>) -> Result<bool>;

    /// Every repository with content (manifests or blob links), in byte order.
    async fn repositories(&self) -> Result<Vec<String>>;
    /// Repositories with at least one manifest, in byte order.
    async fn repositories_with_manifests(&self) -> Result<Vec<String>>;
    /// Whether `repo` has a manifest of its own (blob links alone don't make a repository).
    async fn repository_exists(&self, repo: &str) -> Result<bool>;
    /// Whether any repository named `namespace` or under `namespace/` has content.
    async fn namespace_has_repositories(&self, namespace: &str) -> Result<bool>;
    /// Remove a repository's manifests, tags and links (not those of repositories nested
    /// under its name).
    async fn delete_repository(&self, repo: &str) -> Result<()>;
    async fn snapshot(&self, repo: &str) -> Result<RepoSnapshot>;
    /// Whether nothing at all is stored.
    async fn is_empty(&self) -> Result<bool>;

    /// Restore (backup import, migration): insert unless present. Whether it was inserted.
    async fn restore_manifest(&self, repo: &str, m: &StoredManifest) -> Result<bool>;
    async fn restore_tag(&self, repo: &str, tag: &str, digest: &Digest, updated_at: DateTime<Utc>) -> Result<bool>;
    async fn restore_blob_link(&self, repo: &str, link: &BlobLink) -> Result<bool>;
}

/// Is `repo` the namespace or under it?
pub fn in_namespace(repo: &str, namespace: &str) -> bool {
    repo == namespace || repo.strip_prefix(namespace).is_some_and(|rest| rest.starts_with('/'))
}

#[derive(Default)]
struct State {
    /// (repository, digest) -> manifest
    manifests: BTreeMap<(String, String), StoredManifest>,
    /// (repository, tag) -> (digest, updated_at)
    tags: BTreeMap<(String, String), (Digest, DateTime<Utc>)>,
    /// (repository, digest) -> link
    links: BTreeMap<(String, String), BlobLink>,
}

impl State {
    fn repo_manifests(&self, repo: &str) -> impl Iterator<Item = &StoredManifest> {
        let repo = repo.to_string();
        self.manifests.iter().filter(move |((r, _), _)| *r == repo).map(|(_, m)| m)
    }

    fn repo_tags(&self, repo: &str) -> Vec<TagEntry> {
        self.tags
            .iter()
            .filter(|((r, _), _)| r == repo)
            .map(|((_, t), (d, at))| TagEntry { tag: t.clone(), digest: d.clone(), pushed_at: Some(*at) })
            .collect()
    }
}

fn key(repo: &str, s: impl ToString) -> (String, String) {
    (repo.to_string(), s.to_string())
}

/// Metadata in process memory: for tests and single-process tools. Sweeps are serialized
/// with links by the one lock.
#[derive(Default)]
pub struct MemoryMetadata {
    state: Mutex<State>,
    /// Held across a sweep's `delete`, as the database's advisory lock is.
    sweep: tokio::sync::Mutex<()>,
}

impl MemoryMetadata {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl Metadata for MemoryMetadata {
    async fn put_manifest(&self, repo: &str, m: &StoredManifest, blobs: &[Digest], children: &[Digest], tag: Option<&str>) -> Result<PutManifest> {
        let mut s = self.lock();
        let mut missing: Vec<Digest> = blobs.iter().filter(|d| !s.links.contains_key(&key(repo, d))).cloned().collect();
        missing.extend(children.iter().filter(|d| !s.manifests.contains_key(&key(repo, d))).cloned());
        if !missing.is_empty() {
            let mut seen = HashSet::new();
            missing.retain(|d| seen.insert(d.clone()));
            return Ok(PutManifest::Missing(missing));
        }
        let now = Utc::now();
        for d in blobs {
            if let Some(l) = s.links.get_mut(&key(repo, d)) {
                l.linked_at = now;
            }
        }
        s.manifests.insert(key(repo, &m.digest), StoredManifest { pushed_at: now, ..m.clone() });
        let previous_tag = match tag {
            Some(t) => s.tags.insert(key(repo, t), (m.digest.clone(), now)).map(|(d, _)| d),
            None => None,
        };
        Ok(PutManifest::Stored { previous_tag })
    }

    async fn manifest(&self, repo: &str, digest: &Digest) -> Result<Option<StoredManifest>> {
        Ok(self.lock().manifests.get(&key(repo, digest)).cloned())
    }

    async fn has_manifest(&self, repo: &str, digest: &Digest) -> Result<bool> {
        Ok(self.lock().manifests.contains_key(&key(repo, digest)))
    }

    async fn manifest_digests(&self, repo: &str) -> Result<Vec<Digest>> {
        Ok(self.lock().repo_manifests(repo).map(|m| m.digest.clone()).collect())
    }

    async fn manifests(&self, repo: &str) -> Result<Vec<StoredManifest>> {
        Ok(self.lock().repo_manifests(repo).cloned().collect())
    }

    async fn delete_manifest(&self, repo: &str, digest: &Digest) -> Result<Option<Vec<String>>> {
        let mut s = self.lock();
        if s.manifests.remove(&key(repo, digest)).is_none() {
            return Ok(None);
        }
        let tags: Vec<String> = s.tags.iter().filter(|((r, _), (d, _))| r == repo && d == digest).map(|((_, t), _)| t.clone()).collect();
        for t in &tags {
            s.tags.remove(&key(repo, t));
        }
        Ok(Some(tags))
    }

    async fn collect_manifest(&self, repo: &str, digest: &Digest, cutoff: DateTime<Utc>) -> Result<bool> {
        let mut s = self.lock();
        let tagged = s.tags.iter().any(|((r, _), (d, _))| r == repo && d == digest);
        let old = s.manifests.get(&key(repo, digest)).is_some_and(|m| m.pushed_at <= cutoff);
        Ok(!tagged && old && s.manifests.remove(&key(repo, digest)).is_some())
    }

    async fn referrers(&self, repo: &str, subject: &Digest, artifact_type: Option<&str>) -> Result<Vec<StoredManifest>> {
        Ok(self
            .lock()
            .repo_manifests(repo)
            .filter(|m| m.subject.as_ref() == Some(subject) && artifact_type.is_none_or(|a| m.artifact_type.as_deref() == Some(a)))
            .cloned()
            .collect())
    }

    async fn resolve_tag(&self, repo: &str, tag: &str) -> Result<Option<Digest>> {
        Ok(self.lock().tags.get(&key(repo, tag)).map(|(d, _)| d.clone()))
    }

    async fn put_tag(&self, repo: &str, tag: &str, digest: &Digest) -> Result<Option<Digest>> {
        let mut s = self.lock();
        if !s.manifests.contains_key(&key(repo, digest)) {
            bail!("{repo} has no manifest {digest} to tag");
        }
        Ok(s.tags.insert(key(repo, tag), (digest.clone(), Utc::now())).map(|(d, _)| d))
    }

    async fn delete_tag(&self, repo: &str, tag: &str) -> Result<Option<Digest>> {
        Ok(self.lock().tags.remove(&key(repo, tag)).map(|(d, _)| d))
    }

    async fn tags(&self, repo: &str, last: Option<&str>, limit: Option<usize>) -> Result<Vec<String>> {
        let s = self.lock();
        let names = s.tags.keys().filter(|(r, t)| r == repo && last.is_none_or(|l| t.as_str() > l)).map(|(_, t)| t.clone());
        Ok(match limit {
            Some(n) => names.take(n).collect(),
            None => names.collect(),
        })
    }

    async fn tags_resolved(&self, repo: &str) -> Result<Vec<TagEntry>> {
        Ok(self.lock().repo_tags(repo))
    }

    async fn tag_summary(&self, repo: &str) -> Result<(usize, Option<DateTime<Utc>>)> {
        let tags = self.lock().repo_tags(repo);
        Ok((tags.len(), tags.iter().filter_map(|t| t.pushed_at).max()))
    }

    async fn link_blob(&self, repo: &str, digest: &Digest, size: u64) -> Result<()> {
        let _sweep = self.sweep.lock().await;
        self.lock().links.insert(key(repo, digest), BlobLink { digest: digest.clone(), size, linked_at: Utc::now() });
        Ok(())
    }

    async fn blob_link(&self, repo: &str, digest: &Digest) -> Result<Option<BlobLink>> {
        Ok(self.lock().links.get(&key(repo, digest)).cloned())
    }

    async fn unlink_blob(&self, repo: &str, digest: &Digest) -> Result<bool> {
        Ok(self.lock().links.remove(&key(repo, digest)).is_some())
    }

    async fn collect_blob_link(&self, repo: &str, digest: &Digest, cutoff: DateTime<Utc>) -> Result<bool> {
        let mut s = self.lock();
        let old = s.links.get(&key(repo, digest)).is_some_and(|l| l.linked_at <= cutoff);
        Ok(old && s.links.remove(&key(repo, digest)).is_some())
    }

    async fn blob_links(&self, repo: &str) -> Result<Vec<BlobLink>> {
        Ok(self.lock().links.iter().filter(|((r, _), _)| r == repo).map(|(_, l)| l.clone()).collect())
    }

    async fn sweep_blob(&self, digest: &Digest, delete: BoxFuture<'_, Result<()>>) -> Result<bool> {
        let _sweep = self.sweep.lock().await;
        if self.lock().links.values().any(|l| &l.digest == digest) {
            return Ok(false);
        }
        delete.await?;
        Ok(true)
    }

    async fn repositories(&self) -> Result<Vec<String>> {
        let s = self.lock();
        let names: std::collections::BTreeSet<String> = s.manifests.keys().chain(s.links.keys()).map(|(r, _)| r.clone()).collect();
        Ok(names.into_iter().collect())
    }

    async fn repositories_with_manifests(&self) -> Result<Vec<String>> {
        let names: std::collections::BTreeSet<String> = self.lock().manifests.keys().map(|(r, _)| r.clone()).collect();
        Ok(names.into_iter().collect())
    }

    async fn repository_exists(&self, repo: &str) -> Result<bool> {
        Ok(self.lock().manifests.keys().any(|(r, _)| r == repo))
    }

    async fn namespace_has_repositories(&self, namespace: &str) -> Result<bool> {
        let s = self.lock();
        Ok(s.manifests.keys().chain(s.links.keys()).any(|(r, _)| in_namespace(r, namespace)))
    }

    async fn delete_repository(&self, repo: &str) -> Result<()> {
        let mut s = self.lock();
        s.tags.retain(|(r, _), _| r != repo);
        s.manifests.retain(|(r, _), _| r != repo);
        s.links.retain(|(r, _), _| r != repo);
        Ok(())
    }

    async fn snapshot(&self, repo: &str) -> Result<RepoSnapshot> {
        let s = self.lock();
        Ok(RepoSnapshot {
            manifests: s.repo_manifests(repo).cloned().collect(),
            tags: s.repo_tags(repo),
            links: s.links.iter().filter(|((r, _), _)| r == repo).map(|(_, l)| l.clone()).collect(),
        })
    }

    async fn is_empty(&self) -> Result<bool> {
        let s = self.lock();
        Ok(s.manifests.is_empty() && s.links.is_empty())
    }

    async fn restore_manifest(&self, repo: &str, m: &StoredManifest) -> Result<bool> {
        let mut s = self.lock();
        let k = key(repo, &m.digest);
        if s.manifests.contains_key(&k) {
            return Ok(false);
        }
        s.manifests.insert(k, m.clone());
        Ok(true)
    }

    async fn restore_tag(&self, repo: &str, tag: &str, digest: &Digest, updated_at: DateTime<Utc>) -> Result<bool> {
        let mut s = self.lock();
        let k = key(repo, tag);
        if s.tags.contains_key(&k) {
            return Ok(false);
        }
        if !s.manifests.contains_key(&key(repo, digest)) {
            bail!("{repo} has no manifest {digest} to tag");
        }
        s.tags.insert(k, (digest.clone(), updated_at));
        Ok(true)
    }

    async fn restore_blob_link(&self, repo: &str, link: &BlobLink) -> Result<bool> {
        let mut s = self.lock();
        let k = key(repo, &link.digest);
        if s.links.contains_key(&k) {
            return Ok(false);
        }
        s.links.insert(k, link.clone());
        Ok(true)
    }
}

/// How much metadata an export wrote, or an import / migration inserted.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Counts {
    pub repositories: usize,
    pub manifests: usize,
    pub tags: usize,
    pub blob_links: usize,
    /// Rows that were already there (import), or could not be inserted (a tag whose manifest
    /// is missing).
    pub skipped: usize,
}

/// One line of a metadata export (`metadata.jsonl`).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Line {
    Manifest { repository: String, digest: Digest, media_type: String, body: String, pushed_at: DateTime<Utc> },
    Tag { repository: String, tag: String, digest: Digest, updated_at: DateTime<Utc> },
    BlobLink { repository: String, digest: Digest, size: u64, linked_at: DateTime<Utc> },
}

/// Write every repository's manifests (bodies base64), tags and blob links as JSON lines,
/// repository by repository, manifests before the tags pointing at them. What
/// `kontainer backup --storage` puts next to `storage/`; [`import_jsonl`] reads it back.
pub async fn export_jsonl<W: tokio::io::AsyncWrite + Unpin + Send>(meta: &dyn Metadata, out: &mut W) -> Result<Counts> {
    use base64::Engine;
    use tokio::io::AsyncWriteExt;
    let mut counts = Counts::default();
    for repo in meta.repositories().await? {
        let snap = meta.snapshot(&repo).await?;
        let mut lines = vec![];
        for m in snap.manifests {
            let body = base64::engine::general_purpose::STANDARD.encode(&m.body);
            lines.push(Line::Manifest { repository: repo.clone(), digest: m.digest, media_type: m.media_type, body, pushed_at: m.pushed_at });
            counts.manifests += 1;
        }
        for t in snap.tags {
            lines.push(Line::Tag { repository: repo.clone(), tag: t.tag, digest: t.digest, updated_at: t.pushed_at.unwrap_or_else(Utc::now) });
            counts.tags += 1;
        }
        for l in snap.links {
            lines.push(Line::BlobLink { repository: repo.clone(), digest: l.digest, size: l.size, linked_at: l.linked_at });
            counts.blob_links += 1;
        }
        for line in lines {
            let mut buf = serde_json::to_vec(&line)?;
            buf.push(b'\n');
            out.write_all(&buf).await?;
        }
        counts.repositories += 1;
    }
    out.flush().await?;
    Ok(counts)
}

/// Insert what [`export_jsonl`] wrote, keeping rows that already exist. Idempotent.
pub async fn import_jsonl<R: tokio::io::AsyncBufRead + Unpin + Send>(meta: &dyn Metadata, input: R) -> Result<Counts> {
    use anyhow::Context;
    use base64::Engine;
    use tokio::io::AsyncBufReadExt;
    let mut counts = Counts::default();
    let mut repos = HashSet::new();
    let mut lines = input.lines();
    let mut n = 0usize;
    while let Some(line) = lines.next_line().await? {
        n += 1;
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Line = serde_json::from_str(&line).with_context(|| format!("line {n}"))?;
        let inserted = match parsed {
            Line::Manifest { repository, digest, media_type, body, pushed_at } => {
                let body = base64::engine::general_purpose::STANDARD.decode(body).with_context(|| format!("line {n}: manifest body"))?;
                let m = StoredManifest { pushed_at, ..StoredManifest::new(digest, media_type, Bytes::from(body)) };
                let ok = meta.restore_manifest(&repository, &m).await?;
                repos.insert(repository);
                counts.manifests += usize::from(ok);
                ok
            }
            Line::Tag { repository, tag, digest, updated_at } => {
                let ok = meta.restore_tag(&repository, &tag, &digest, updated_at).await?;
                counts.tags += usize::from(ok);
                ok
            }
            Line::BlobLink { repository, digest, size, linked_at } => {
                let ok = meta.restore_blob_link(&repository, &BlobLink { digest, size, linked_at }).await?;
                repos.insert(repository);
                counts.blob_links += usize::from(ok);
                ok
            }
        };
        counts.skipped += usize::from(!inserted);
    }
    counts.repositories = repos.len();
    Ok(counts)
}
