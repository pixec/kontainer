//! Storage analytics: where the bytes are, what is shared, and what could be reclaimed.
//!
//! Blobs are content addressed and stored once, but each repository links the blobs its
//! manifests reference. So a repository's *size* (everything it references) can be much larger
//! than its *unique* bytes (what would be freed if only it were deleted), and the sum of all
//! repository sizes exceeds what is physically stored. The difference is deduplication.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use kontainer_core::digest::Digest;
use kontainer_core::manifest::Manifest;
use crate::Storage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoUsage {
    pub name: String,
    pub namespace: String,
    pub tags: usize,
    pub manifests: usize,
    /// Every blob the repository's manifests reference (what a full pull would download).
    pub bytes: u64,
    /// Blobs no other repository references: freed if this repository were deleted and GC ran.
    pub unique_bytes: u64,
    /// Bytes only reachable from untagged manifests in this repository.
    pub untagged_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceUsage {
    pub namespace: String,
    pub repositories: usize,
    /// Distinct blobs referenced by the namespace's repositories (what a quota counts).
    pub bytes: u64,
    /// Blobs no repository outside the namespace references.
    pub unique_bytes: u64,
    pub quota: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedLayer {
    pub digest: String,
    pub size: u64,
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReport {
    pub computed_at: String,
    /// Bytes of every blob in storage.
    pub physical_bytes: u64,
    pub blobs: usize,
    /// Sum of every repository's `bytes`: what storage would be without deduplication.
    pub logical_bytes: u64,
    /// `logical_bytes` minus what referenced blobs physically take.
    pub dedup_savings: u64,
    /// Blobs no manifest references: freed by the next garbage collection.
    pub unreferenced_bytes: u64,
    /// Blobs only reachable from untagged manifests: freed by GC with "delete untagged".
    pub untagged_bytes: u64,
    pub repositories: Vec<RepoUsage>,
    pub namespaces: Vec<NamespaceUsage>,
    /// Largest blobs referenced by more than one repository.
    pub shared_layers: Vec<SharedLayer>,
}

/// What each manifest of a repository references, and which manifests are reachable from tags.
struct RepoGraph {
    tags: usize,
    manifests: usize,
    all: HashSet<Digest>,
    tagged: HashSet<Digest>,
    /// Sizes the metadata knows: manifest bodies and linked blobs.
    sizes: HashMap<Digest, u64>,
}

async fn repo_graph(storage: &Storage, repo: &str) -> Result<RepoGraph> {
    let snap = storage.metadata().snapshot(repo).await?;
    let crate::RepoManifests { revisions, parsed, unknown } = crate::parse_manifests(repo, &snap.manifests);
    let refs = |d: &Digest, out: &mut HashSet<Digest>| {
        out.insert(d.clone());
        if let Some(m) = parsed.get(d) {
            match m {
                Manifest::Image(im) => {
                    out.insert(im.config.digest.clone());
                    out.extend(im.layers.iter().map(|l| l.digest.clone()));
                }
                Manifest::Index(ix) => out.extend(ix.manifests.iter().map(|c| c.digest.clone())),
            }
        }
    };
    let mut all = HashSet::new();
    for d in &revisions {
        refs(d, &mut all);
    }
    // What unreadable manifests reference is unknown: count every blob the repository links.
    let linked: HashSet<Digest> = if unknown.is_empty() { HashSet::new() } else { snap.links.iter().map(|l| l.digest.clone()).collect() };
    all.extend(linked.iter().cloned());
    // Reachable from tags through index children and referrers (as garbage collection does).
    let mut referrers: HashMap<Digest, Vec<Digest>> = HashMap::new();
    for m in &snap.manifests {
        if let Some(s) = &m.subject {
            referrers.entry(s.clone()).or_default().push(m.digest.clone());
        }
    }
    let mut seen = HashSet::new();
    let mut stack: Vec<Digest> = snap.tags.iter().map(|t| t.digest.clone()).collect();
    let mut tagged = linked;
    while let Some(d) = stack.pop() {
        if !seen.insert(d.clone()) {
            continue;
        }
        refs(&d, &mut tagged);
        if let Some(m) = parsed.get(&d) {
            stack.extend(m.child_manifests().iter().map(|c| c.digest.clone()));
        }
        if let Some(rs) = referrers.get(&d) {
            stack.extend(rs.iter().cloned());
        }
    }
    let sizes = snap.manifests.iter().map(|m| (m.digest.clone(), m.size())).chain(snap.links.iter().map(|l| (l.digest.clone(), l.size))).collect();
    Ok(RepoGraph { tags: snap.tags.len(), manifests: revisions.len(), all, tagged, sizes })
}

fn namespace_of(repo: &str) -> String {
    kontainer_core::names::namespace(repo).to_string()
}

/// Full scan of storage. Proportional to the number of manifests and blobs; callers cache it.
/// Manifests count as stored objects too (their bodies are in the database).
pub async fn compute(storage: &Storage, quotas: &[(String, u64)]) -> Result<UsageReport> {
    let mut sizes: HashMap<Digest, u64> = storage.all_blobs().await?.into_iter().map(|(d, _, n)| (d, n)).collect();

    let mut graphs: BTreeMap<String, RepoGraph> = BTreeMap::new();
    for repo in storage.list_repositories().await? {
        let g = repo_graph(storage, &repo).await?;
        // Manifest bodies (not blob objects) are only known to the metadata.
        for (d, n) in &g.sizes {
            sizes.entry(d.clone()).or_insert(*n);
        }
        graphs.insert(repo.clone(), g);
    }
    let size = |d: &Digest| sizes.get(d).copied().unwrap_or(0);
    // Which repositories reference each blob, and which reference it from a tag.
    let mut users: HashMap<&Digest, Vec<&str>> = HashMap::new();
    let mut tagged_anywhere: HashSet<&Digest> = HashSet::new();
    for (name, g) in &graphs {
        for d in &g.all {
            users.entry(d).or_default().push(name);
        }
        tagged_anywhere.extend(g.tagged.iter());
    }

    let mut repositories = vec![];
    for (name, g) in &graphs {
        let bytes = g.all.iter().map(size).sum();
        let unique_bytes = g.all.iter().filter(|d| users.get(d).is_some_and(|u| u.len() == 1)).map(size).sum();
        let untagged_bytes = g.all.iter().filter(|d| !tagged_anywhere.contains(d)).map(size).sum();
        repositories.push(RepoUsage { name: name.clone(), namespace: namespace_of(name), tags: g.tags, manifests: g.manifests, bytes, unique_bytes, untagged_bytes });
    }

    let quota: HashMap<&str, u64> = quotas.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    let mut ns_blobs: BTreeMap<String, HashSet<&Digest>> = BTreeMap::new();
    let mut ns_repos: HashMap<String, usize> = HashMap::new();
    for (name, g) in &graphs {
        let ns = namespace_of(name);
        ns_blobs.entry(ns.clone()).or_default().extend(g.all.iter());
        *ns_repos.entry(ns).or_default() += 1;
    }
    let namespaces = ns_blobs
        .iter()
        .map(|(ns, blobs)| NamespaceUsage {
            namespace: ns.clone(),
            repositories: ns_repos.get(ns).copied().unwrap_or(0),
            bytes: blobs.iter().map(|d| size(d)).sum(),
            unique_bytes: blobs.iter().filter(|d| users.get(*d).is_some_and(|u| u.iter().all(|r| namespace_of(r) == *ns))).map(|d| size(d)).sum(),
            quota: quota.get(ns.as_str()).copied(),
        })
        .collect();

    let referenced: u64 = users.keys().map(|d| size(d)).sum();
    let physical_bytes: u64 = sizes.values().sum();
    let logical_bytes: u64 = repositories.iter().map(|r: &RepoUsage| r.bytes).sum();
    let mut shared_layers: Vec<SharedLayer> = users
        .iter()
        .filter(|(_, u)| u.len() > 1)
        .map(|(d, u)| SharedLayer { digest: d.to_string(), size: size(d), repositories: u.iter().map(|s| s.to_string()).collect() })
        .collect();
    shared_layers.sort_by_key(|l| std::cmp::Reverse(l.size * l.repositories.len() as u64));
    shared_layers.truncate(20);

    Ok(UsageReport {
        computed_at: chrono::Utc::now().to_rfc3339(),
        physical_bytes,
        blobs: sizes.len(),
        logical_bytes,
        dedup_savings: logical_bytes.saturating_sub(referenced),
        unreferenced_bytes: sizes.iter().filter(|(d, _)| !users.contains_key(d)).map(|(_, n)| n).sum(),
        untagged_bytes: users.keys().filter(|d| !tagged_anywhere.contains(*d)).map(|d| size(d)).sum(),
        repositories,
        namespaces,
        shared_layers,
    })
}

/// The blobs one namespace's repositories reference and their total size (what a quota counts).
pub async fn namespace_blobs(storage: &Storage, namespace: &str) -> Result<(HashSet<Digest>, u64)> {
    let mut blobs = HashSet::new();
    let mut sizes: HashMap<Digest, u64> = HashMap::new();
    // The repository named exactly after the namespace belongs to it too (`namespace_of`).
    for repo in storage.list_repositories().await?.into_iter().filter(|r| crate::metadata::in_namespace(r, namespace)) {
        let g = repo_graph(storage, &repo).await?;
        blobs.extend(g.all);
        sizes.extend(g.sizes);
    }
    // Sizes from the metadata (link and manifest rows); a referenced blob no repository of the
    // namespace links counts nothing, as a missing blob did.
    let bytes = blobs.iter().map(|d| sizes.get(d).copied().unwrap_or(0)).sum();
    Ok((blobs, bytes))
}

/// How long a namespace's computed usage is trusted by quota checks. Pushes update it in place;
/// deletions and garbage collection are only seen once it expires (the quota is soft).
const NAMESPACE_CACHE_TTL: Duration = Duration::from_secs(60);

struct CachedNamespace {
    computed: Instant,
    blobs: HashSet<Digest>,
    bytes: u64,
}

#[derive(Clone, Default)]
pub(crate) struct NamespaceCache(Arc<Mutex<HashMap<String, CachedNamespace>>>);

impl NamespaceCache {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, CachedNamespace>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// For a quota check: the bytes `namespace` holds and which of `digests` it does not hold yet.
/// Served from a short-lived per-namespace cache, so a push does not walk the whole namespace.
pub async fn namespace_missing(storage: &Storage, namespace: &str, digests: Vec<Digest>) -> Result<(u64, Vec<Digest>)> {
    fn answer(c: &CachedNamespace, wanted: &HashSet<Digest>) -> (u64, Vec<Digest>) {
        (c.bytes, wanted.iter().filter(|d| !c.blobs.contains(*d)).cloned().collect())
    }
    let wanted: HashSet<Digest> = digests.into_iter().collect();
    // The guard is dropped before any await.
    let hit = storage.ns_usage.lock().get(namespace).filter(|c| c.computed.elapsed() < NAMESPACE_CACHE_TTL).map(|c| answer(c, &wanted));
    if let Some(out) = hit {
        return Ok(out);
    }
    let (blobs, bytes) = namespace_blobs(storage, namespace).await?;
    let entry = CachedNamespace { computed: Instant::now(), blobs, bytes };
    let out = answer(&entry, &wanted);
    storage.ns_usage.lock().insert(namespace.to_string(), entry);
    Ok(out)
}

/// Count blobs a push just added to `namespace` in the cached usage.
pub fn record_namespace_blobs(storage: &Storage, namespace: &str, added: impl IntoIterator<Item = (Digest, u64)>) {
    if let Some(c) = storage.ns_usage.lock().get_mut(namespace) {
        for (d, n) in added {
            if c.blobs.insert(d) {
                c.bytes += n;
            }
        }
    }
}

/// `1.5 GB`-style sizes for messages.
pub fn human(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    // Binary units, matching the web UI.
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", units[i]) }
}
