//! Copying images from other registries: the engine behind mirrors, imports and the
//! pull-through cache.
//!
//! Layers already in storage are linked rather than downloaded again (blobs are content
//! addressed), so re-syncing an image that shares layers with others is cheap. Manifests and
//! tags are written through the same metadata transactions as a push.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use futures::future::{BoxFuture, FutureExt, Shared};

use crate::database::remote::{ProxyCache, Registry};
use kontainer_core::digest::Digest;
use kontainer_core::manifest::Manifest;
use kontainer_core::names::Reference;
use crate::state::AppState;
use kontainer_core::upstream::{FetchedManifest, Upstream, UpstreamError};
use kontainer_store::metadata::{PutManifest, StoredManifest};

/// Make `digest` available in `dst_repo`, downloading it from upstream only if storage lacks it.
/// Returns the bytes downloaded (0 when it was already stored). `size` (from the manifest)
/// caps the download; without it, `server.max_blob_size` (or the upstream client's default).
///
/// A blob stored for some other repository is only linked into `dst_repo` once the upstream
/// confirms it serves that blob from `src_repo`: knowing a digest must not be enough to read a
/// private repository's layers through a pull-through cache, a mirror or an import.
pub async fn ensure_blob(state: &AppState, up: &Upstream, src_repo: &str, dst_repo: &str, digest: &Digest, size: Option<u64>) -> Result<u64, ProxyError> {
    let storage = &state.storage;
    if storage.repo_blob_size(dst_repo, digest).await?.is_some() {
        return Ok(0);
    }
    if let Some(stored) = storage.blob_size(digest).await? {
        if !up.head_blob(src_repo, digest).await? {
            return Err(ProxyError::NotFound(format!("{src_repo}@{digest}")));
        }
        // `false`: collected just now; download it below.
        if storage.link_blob(dst_repo, digest, stored).await? {
            return Ok(0);
        }
    }
    // Removed when dropped, also if this future is cancelled mid-download.
    let path = storage.uploads.temp_file().await.context("creating a temporary file")?;
    let n = up.blob_to_file(src_repo, digest, &path, size.or(state.config.server.max_blob_bytes())).await?;
    storage.store_and_link_file(dst_repo, digest, &path).await?;
    Ok(n)
}

/// Store a fetched manifest in `dst_repo` (no tag). Its blobs are not required to be linked:
/// the pull-through cache fetches them when they are first pulled (mirrors and imports link
/// them first), and an index may be copied with only some of its children.
async fn store_manifest(state: &AppState, dst_repo: &str, m: &FetchedManifest) -> Result<()> {
    // The upstream's Content-Type, unless the body says (or nothing was sent).
    let media_type = match kontainer_core::manifest::body_media_type(&m.bytes) {
        None if !m.media_type.is_empty() => m.media_type.clone(),
        _ => kontainer_store::infer_media_type(&m.bytes),
    };
    let row = StoredManifest::new(m.digest.clone(), media_type, m.bytes.clone());
    match state.storage.put_manifest(dst_repo, &row, &[], &[], None).await? {
        PutManifest::Stored { .. } => Ok(()),
        PutManifest::Missing(gone) => bail!("{dst_repo}@{}: {} missing", m.digest, gone.iter().map(Digest::to_string).collect::<Vec<_>>().join(", ")),
    }
}

#[derive(Debug, Default, serde::Serialize)]
pub struct CopyStats {
    pub manifests: usize,
    pub blobs_downloaded: usize,
    pub bytes_downloaded: u64,
}

/// Copy a manifest (and, for an index, every child) with all its blobs into `dst_repo`.
pub async fn copy_manifest(state: &AppState, up: &Upstream, src_repo: &str, reference: &str, dst_repo: &str, stats: &mut CopyStats) -> Result<FetchedManifest> {
    let m = up.manifest(src_repo, reference).await?.with_context(|| format!("{src_repo}:{reference} not found upstream"))?;
    let (parsed, _) = Manifest::parse(&m.bytes, Some(&m.media_type)).map_err(|e| anyhow::anyhow!("{src_repo}:{reference}: {e}"))?;
    match &parsed {
        Manifest::Index(ix) => {
            for child in &ix.manifests {
                Box::pin(copy_manifest(state, up, src_repo, &child.digest.to_string(), dst_repo, stats)).await?;
            }
        }
        Manifest::Image(_) => {
            // Foreign layers (Windows base images) are not distributed by registries.
            for b in parsed.required_blobs() {
                let n = ensure_blob(state, up, src_repo, dst_repo, &b.digest, Some(b.size)).await?;
                if n > 0 {
                    stats.blobs_downloaded += 1;
                    stats.bytes_downloaded += n;
                }
            }
        }
    }
    store_manifest(state, dst_repo, &m).await?;
    stats.manifests += 1;
    Ok(m)
}

/// What copying `top` (already fetched from `src_repo`) stores: every manifest under it and
/// the blobs they reference, with sizes (blobs by what the manifests declare), for a quota
/// check before downloading. Children of an index are fetched (manifests are small).
pub async fn import_contents(up: &Upstream, src_repo: &str, top: &FetchedManifest) -> Result<Vec<(Digest, u64)>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = vec![];
    let mut stack = vec![top.clone()];
    while let Some(m) = stack.pop() {
        if !seen.insert(m.digest.clone()) {
            continue;
        }
        out.push((m.digest.clone(), m.bytes.len() as u64));
        let (parsed, _) = Manifest::parse(&m.bytes, Some(&m.media_type)).map_err(|e| anyhow::anyhow!("{src_repo}@{}: {e}", m.digest))?;
        match &parsed {
            Manifest::Index(ix) => {
                for child in ix.manifests.iter().filter(|c| !seen.contains(&c.digest)) {
                    stack.push(up.manifest(src_repo, &child.digest.to_string()).await?.with_context(|| format!("{src_repo}@{} not found upstream", child.digest))?);
                }
            }
            Manifest::Image(_) => {
                for b in parsed.required_blobs() {
                    if seen.insert(b.digest.clone()) {
                        out.push((b.digest.clone(), b.size));
                    }
                }
            }
        }
    }
    Ok(out)
}

/// What [`copy_tag`] copies, and on whose behalf.
pub struct TagCopy<'a> {
    pub src_repo: &'a str,
    /// Tag or digest upstream.
    pub reference: &'a str,
    pub dst_repo: &'a str,
    pub dst_tag: &'a str,
    /// For the tag's history: what moved it (`import`, `sync`) and who.
    pub action: &'a str,
    pub actor: &'a str,
}

/// Copy `src_repo:reference` into `dst_repo:dst_tag` and make it visible (catalogue, search).
pub async fn copy_tag(state: &AppState, up: &Upstream, c: &TagCopy<'_>) -> Result<(Digest, CopyStats)> {
    let mut stats = CopyStats::default();
    let m = copy_manifest(state, up, c.src_repo, c.reference, c.dst_repo, &mut stats).await?;
    crate::tags::set(state, c.dst_repo, c.dst_tag, &m.digest, c.action, c.actor).await?;
    state.auth.note_repo(c.dst_repo, true).await;
    state.reindex(c.dst_repo).await;
    Ok((m.digest, stats))
}

// Pull-through cache
/// A blob download shared by every request waiting for it.
type Flight = Shared<BoxFuture<'static, Result<(), ProxyError>>>;

/// A registry's client and the `registries.updated_at` it was built from.
type CachedUpstream = (chrono::DateTime<chrono::Utc>, Arc<Upstream>);

/// Pull-through cache state shared across requests: one upstream client per registry (so
/// connections and bearer tokens are reused), and the blob downloads in flight.
#[derive(Clone, Default)]
pub struct ProxyState {
    /// Clients by registry id, with the `registries.updated_at` each was built from: an edit
    /// made on any instance changes it, so the next use here builds a new client.
    upstreams: Arc<Mutex<HashMap<i64, CachedUpstream>>>,
    inflight: Arc<Mutex<HashMap<(String, Digest), Flight>>>,
}

impl ProxyState {
    /// The (cached) client for `registry`, as just read from the database.
    pub fn upstream(&self, registry: &Registry) -> Result<Arc<Upstream>> {
        let mut map = self.upstreams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, up)) = map.get(&registry.id) {
            if *at == registry.updated_at {
                return Ok(up.clone());
            }
        }
        let up = Arc::new(registry.client()?);
        map.insert(registry.id, (registry.updated_at, up.clone()));
        Ok(up)
    }

    /// Drop the cached client after the registry changed or was deleted (on other instances
    /// the changed `updated_at` does it).
    pub fn forget(&self, registry_id: i64) {
        self.upstreams.lock().unwrap_or_else(|e| e.into_inner()).remove(&registry_id);
    }
}

/// Why a pull-through fetch failed. Cloneable: concurrent requests share one download's result.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProxyError {
    /// The upstream does not have what was asked for: a 404, not an outage.
    #[error("{0} not found upstream")]
    NotFound(String),
    /// The upstream (unreachable, refusing, misbehaving) or our storage failed.
    #[error("{0:#}")]
    Failed(Arc<anyhow::Error>),
}

impl From<anyhow::Error> for ProxyError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(Arc::new(e))
    }
}

impl From<UpstreamError> for ProxyError {
    fn from(e: UpstreamError) -> Self {
        match e {
            UpstreamError::NotFound(what) => Self::NotFound(what),
            other => Self::Failed(Arc::new(other.into())),
        }
    }
}

/// The proxy cache serving `repo` (`<namespace>/<upstream repo>`), with the upstream repo name.
pub async fn proxy_for(state: &AppState, repo: &str) -> Result<Option<(ProxyCache, String, Arc<Upstream>)>> {
    let Some((ns, rest)) = repo.split_once('/') else { return Ok(None) };
    // Every manifest and blob GET comes through here: ask the in-memory set first.
    if !state.auth.proxies_contains(ns).await {
        return Ok(None);
    }
    let Some(proxy) = state.auth.db.proxy_cache(ns).await? else { return Ok(None) };
    let Some(registry) = state.auth.db.registry(proxy.registry_id).await? else { return Ok(None) };
    Ok(Some((proxy, rest.to_string(), state.proxy.upstream(&registry)?)))
}


/// A registry host as containerd names it in `?ns=` and as a registry URL names it: lower
/// case `host[:port]`, without a default port, and Docker Hub's aliases as `docker.io`.
pub fn canonical_host(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    let (scheme, rest) = match s.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_string()), rest.to_string()),
        None => (None, s),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let authority = match (scheme.as_deref(), authority.rsplit_once(':')) {
        (Some("https") | None, Some((h, "443"))) | (Some("http"), Some((h, "80"))) => h,
        _ => authority,
    };
    if authority.is_empty() {
        return None;
    }
    Some(match authority {
        "docker.io" | "registry-1.docker.io" | "index.docker.io" | "registry.hub.docker.com" => "docker.io".into(),
        h => h.into(),
    })
}

/// containerd's mirror support: a pull of `name` sent with `?ns=<host>` (containerd uses this
/// registry as a mirror for `host`) is served from the pull-through cache namespace whose
/// upstream is `host`, as `<namespace>/<name>`, unless `name` is a repository here (a local
/// repository always wins) or already lies in a proxy namespace. `None`: serve `name` as is.
/// With several proxy namespaces for one host, the first by name is used.
pub async fn containerd_ns_target(state: &AppState, principal: &crate::auth::Principal, ns: &str, name: &str) -> Result<Option<String>> {
    if principal.proxies.is_empty() || principal.proxies.contains_key(kontainer_core::names::namespace(name)) {
        return Ok(None);
    }
    let Some(host) = canonical_host(ns) else { return Ok(None) };
    if principal.known_repos.contains(name) || state.storage.repository_exists(name).await? {
        return Ok(None);
    }
    let registries: HashMap<i64, Registry> = state.auth.db.registries().await?.into_iter().map(|r| (r.id, r)).collect();
    for proxy in state.auth.db.proxy_caches().await? {
        let matches = registries.get(&proxy.registry_id).and_then(|r| canonical_host(&r.url)).is_some_and(|h| h == host);
        if matches {
            let target = format!("{}/{name}", proxy.namespace);
            return Ok(kontainer_core::names::is_valid_repository(&target).then_some(target));
        }
    }
    Ok(None)
}

/// Before serving a manifest from a proxy namespace: fetch it if missing, and re-check tags
/// older than the cache TTL. If the upstream is unreachable, a cached copy is served stale.
pub async fn proxy_manifest(state: &AppState, repo: &str, reference: &Reference) -> Result<(), ProxyError> {
    let Some((proxy, upstream_repo, up)) = proxy_for(state, repo).await? else { return Ok(()) };
    let storage = &state.storage;
    let reference = match reference {
        Reference::Digest(d) => {
            if storage.has_manifest(repo, d).await? {
                return Ok(());
            }
            let m = up.manifest(&upstream_repo, &d.to_string()).await?.ok_or_else(|| ProxyError::NotFound(format!("{upstream_repo}@{d}")))?;
            store_manifest(state, repo, &m).await?;
            state.auth.note_repo(repo, true).await;
            return Ok(());
        }
        Reference::Tag(t) => t.as_str(),
    };
    let local = storage.list_tags_resolved(repo).await?.into_iter().find(|t| t.tag == reference);
    let fresh = local.as_ref().and_then(|t| t.pushed_at).is_some_and(|p| (chrono::Utc::now() - p).num_seconds() < proxy.ttl_secs);
    if fresh {
        return Ok(());
    }
    let refreshed: Result<(), ProxyError> = async {
        match up.head_manifest(&upstream_repo, reference).await? {
            None if local.is_none() => Err(ProxyError::NotFound(format!("{upstream_repo}:{reference}"))),
            None => Ok(()), // removed upstream: keep serving what we have
            Some(d) if local.as_ref().is_some_and(|t| t.digest == d) => {
                storage.put_tag(repo, reference, &d).await?; // still current: restart the TTL
                Ok(())
            }
            Some(d) => {
                let m = up.manifest(&upstream_repo, &d.to_string()).await?.with_context(|| format!("{upstream_repo}@{d} vanished upstream"))?;
                store_manifest(state, repo, &m).await?;
                crate::tags::set(state, repo, reference, &m.digest, "cache", "pull-through cache").await?;
                state.auth.note_repo(repo, true).await;
                state.reindex(repo).await;
                Ok(())
            }
        }
    }
    .await;
    match refreshed {
        Err(e) if local.is_some() => {
            tracing::warn!(%repo, %reference, error = %e, "upstream unavailable; serving the cached manifest");
            Ok(())
        }
        other => other,
    }
}

/// Before serving a blob from a proxy namespace: download it if it is not cached yet.
/// Concurrent requests for the same blob share one download, which runs in its own task so a
/// client hanging up does not abort it for the others.
pub async fn proxy_blob(state: &AppState, repo: &str, digest: &Digest) -> Result<(), ProxyError> {
    if state.storage.repo_blob_size(repo, digest).await?.is_some() {
        return Ok(());
    }
    let Some((_, upstream_repo, up)) = proxy_for(state, repo).await? else { return Ok(()) };
    let key = (repo.to_string(), digest.clone());
    let flight = {
        let mut inflight = state.proxy.inflight.lock().unwrap_or_else(|e| e.into_inner());
        match inflight.get(&key) {
            Some(f) => f.clone(),
            None => {
                let (st, k) = (state.clone(), key.clone());
                // Spawned while the map is locked: its removal below waits until it is inserted.
                let task = tokio::spawn(async move {
                    let (repo, digest) = (&k.0, &k.1);
                    // A 404 from the upstream comes back as `ProxyError::NotFound`: a miss, not an outage.
                    let result = ensure_blob(&st, &up, &upstream_repo, repo, digest, None).await.map(|_| ());
                    st.proxy.inflight.lock().unwrap_or_else(|e| e.into_inner()).remove(&k);
                    result
                });
                let f: Flight = async move { task.await.unwrap_or_else(|e| Err(anyhow::anyhow!("blob download task failed: {e}").into())) }.boxed().shared();
                inflight.insert(key, f.clone());
                f
            }
        }
    };
    flight.await
}

// Mirrors
/// Tags considered per sync, newest names last as the upstream lists them.
const MAX_MIRROR_TAGS: usize = 200;

/// Bring a mirror up to date: copy every matching upstream tag whose digest differs locally.
pub async fn sync_mirror(state: &AppState, m: &crate::database::remote::Mirror) -> Result<String> {
    let result = async {
        let registry = state.auth.db.registry(m.registry_id).await?.context("the mirror's registry was deleted")?;
        let up = state.proxy.upstream(&registry)?;
        let mut tags: Vec<String> = up.tags(&m.source).await?.into_iter().filter(|t| m.tags.is_empty() || kontainer_core::glob::any_matches(m.tags.iter(), t)).collect();
        let skipped = tags.len().saturating_sub(MAX_MIRROR_TAGS);
        tags.drain(..skipped);
        let (mut copied, mut current, mut failed, mut bytes) = (0, 0, vec![], 0u64);
        for (i, tag) in tags.iter().enumerate() {
            crate::state::job_progress(format!("Tag {} of {}: {tag}", i + 1, tags.len()));
            let step = async {
                let Some(remote) = up.head_manifest(&m.source, tag).await? else { return Ok::<_, anyhow::Error>(None) };
                if state.storage.resolve_tag(&m.target, tag).await? == Some(remote) {
                    return Ok(None);
                }
                Ok(Some(copy_tag(state, &up, &TagCopy { src_repo: &m.source, reference: tag, dst_repo: &m.target, dst_tag: tag, action: "sync", actor: "mirror" }).await?.1))
            }
            .await;
            match step {
                Ok(Some(stats)) => { copied += 1; bytes += stats.bytes_downloaded; }
                Ok(None) => current += 1,
                Err(e) => failed.push(format!("{tag}: {e:#}")),
            }
        }
        let mut msg = format!("{copied} updated, {current} up to date ({} downloaded)", kontainer_store::usage::human(bytes));
        if skipped > 0 {
            msg.push_str(&format!(", {skipped} older tags skipped"));
        }
        if !failed.is_empty() {
            bail!("{msg}; {} failed: {}", failed.len(), failed.join("; "));
        }
        Ok(msg)
    }
    .await;
    let (ok, message) = match &result {
        Ok(m) => (true, m.clone()),
        Err(e) => (false, format!("{e:#}")),
    };
    state.auth.db.record_mirror_sync(m.id, ok, &message).await?;
    state.webhooks.fire(crate::webhook::Event::mirror_sync(&m.target, ok, &message));
    result
}

/// Run every enabled mirror that is due (the background schedule).
pub async fn sync_due_mirrors(state: &AppState) -> Result<usize> {
    let now = chrono::Utc::now();
    let mut n = 0;
    for m in state.auth.db.mirrors().await?.into_iter().filter(|m| m.is_enabled) {
        let due = m.last_sync_at.is_none_or(|t| (now - t).num_seconds() >= m.interval_secs);
        if due {
            if let Err(e) = sync_mirror(state, &m).await {
                tracing::warn!(mirror = m.id, error = %e, "mirror sync failed");
            }
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::canonical_host;

    #[test]
    fn hosts_compare_as_containerd_names_them() {
        let h = |s: &str| canonical_host(s);
        assert_eq!(h("https://registry-1.docker.io"), Some("docker.io".into()));
        assert_eq!(h("docker.io"), Some("docker.io".into()));
        assert_eq!(h("index.docker.io"), Some("docker.io".into()));
        assert_eq!(h("https://GHCR.io/"), Some("ghcr.io".into()));
        assert_eq!(h("https://registry.example.com:443/v2"), Some("registry.example.com".into()));
        assert_eq!(h("http://127.0.0.1:5000"), Some("127.0.0.1:5000".into()));
        assert_eq!(h("127.0.0.1:5000"), Some("127.0.0.1:5000".into()));
        assert_eq!(h("http://mirror.local:80"), Some("mirror.local".into()));
        assert_eq!(h("https://user:pw@registry.example.com"), Some("registry.example.com".into()));
        assert_eq!(h(""), None);
    }
}
