//! The metadata layout from before metadata moved into the database, and the migration out
//! of it (`kontainer migrate-metadata`).
//!
//! Older deployments kept metadata as small objects next to the blobs:
//!
//! ```text
//! repositories/<name>/_layers/<alg>/<hex>/link                      (blob link)
//! repositories/<name>/_manifests/revisions/<alg>/<hex>/link         (manifest; body in blobs/)
//! repositories/<name>/_manifests/revisions/<alg>/<hex>/mediatype    (push-time Content-Type)
//! repositories/<name>/_manifests/tags/<tag>/current/link            (tag)
//! repositories/<name>/_referrers/<alg>/<hex>/<alg>/<hex>/link       (derived from the manifests now)
//! _touched/<alg>/<hex>                                              (GC markers, no longer needed)
//! ```
//!
//! [`migrate`] reads those keys and inserts the rows, keeping rows that exist already, so it
//! can run again (or while the registry serves). It deletes nothing: once the registry runs
//! on the database, the old keys (and manifest bodies under `blobs/`, which garbage
//! collection then removes as unreferenced) are left to the operator.

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use chrono::{DateTime, Utc};
use object_store::GetOptions;

use kontainer_core::digest::Digest;

use crate::metadata::{BlobLink, Counts, StoredManifest};
use crate::Storage;

/// Where the old layout kept repository metadata.
pub const PREFIX: &str = "repositories/";

/// What one old key is.
#[derive(Debug, PartialEq)]
enum Key {
    Layer(Digest),
    Revision(Digest),
    MediaType(Digest),
    Tag(String),
}

/// Split `repositories/<name>/<dir>/...` into the repository name and what the key is.
fn parse_key(rel: &str) -> Option<(String, Key)> {
    let rest = rel.strip_prefix(PREFIX)?;
    // Repository path components never start with `_`, so the first `/_<dir>/` ends the name.
    for dir in ["/_layers/", "/_manifests/", "/_referrers/"] {
        let Some(idx) = rest.find(dir) else { continue };
        let name = &rest[..idx];
        let tail: Vec<&str> = rest[idx + dir.len()..].split('/').collect();
        let digest = |alg: &str, hex: &str| format!("{alg}:{hex}").parse::<Digest>().ok();
        let key = match (dir, tail.as_slice()) {
            ("/_layers/", [alg, hex, "link"]) => Key::Layer(digest(alg, hex)?),
            ("/_manifests/", ["revisions", alg, hex, "link"]) => Key::Revision(digest(alg, hex)?),
            ("/_manifests/", ["revisions", alg, hex, "mediatype"]) => Key::MediaType(digest(alg, hex)?),
            ("/_manifests/", ["tags", tag, "current", "link"]) => Key::Tag(tag.to_string()),
            _ => return None,
        };
        return Some((name.to_string(), key));
    }
    None
}

#[derive(Default)]
struct Repo {
    layers: Vec<(Digest, DateTime<Utc>)>,
    revisions: Vec<(Digest, DateTime<Utc>)>,
    media_types: HashMap<Digest, object_store::path::Path>,
    tags: Vec<(String, object_store::path::Path, DateTime<Utc>)>,
}

impl Storage {
    async fn read_small(&self, key: &object_store::path::Path) -> Result<Option<bytes::Bytes>> {
        match self.get_any(key, GetOptions::default()).await {
            Ok(r) => Ok(Some(r.bytes().await?)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Copy the old layout's metadata into [`Storage::metadata`]: manifests (bodies from
/// `blobs/`, media type from the sidecar when there is one), tags and blob links, with the
/// keys' modification times as their times. Rows that exist are kept. Manifests whose body is
/// missing, tags whose manifest is missing and links whose blob is missing are skipped.
pub async fn migrate(storage: &Storage) -> Result<Counts> {
    let mut repos: BTreeMap<String, Repo> = BTreeMap::new();
    for meta in storage.list_objects(PREFIX).await? {
        let Some((name, key)) = parse_key(storage.rel(&meta.location)) else { continue };
        let r = repos.entry(name).or_default();
        match key {
            Key::Layer(d) => r.layers.push((d, meta.last_modified)),
            Key::Revision(d) => r.revisions.push((d, meta.last_modified)),
            Key::MediaType(d) => {
                r.media_types.insert(d, meta.location);
            }
            Key::Tag(t) => r.tags.push((t, meta.location, meta.last_modified)),
        }
    }
    let meta = storage.metadata();
    let mut counts = Counts::default();
    for (name, r) in &repos {
        for (d, at) in &r.revisions {
            let Some(body) = storage.blob_bytes(d).await? else {
                tracing::warn!(repo = %name, %d, "manifest body missing from blobs/; skipped");
                counts.skipped += 1;
                continue;
            };
            let sidecar = match r.media_types.get(d) {
                Some(k) => storage.read_small(k).await?.and_then(|b| String::from_utf8(b.to_vec()).ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
                None => None,
            };
            let media_type = match kontainer_core::manifest::body_media_type(&body) {
                Some(_) => crate::infer_media_type(&body),
                None => sidecar.unwrap_or_else(|| crate::infer_media_type(&body)),
            };
            let m = StoredManifest { pushed_at: *at, ..StoredManifest::new(d.clone(), media_type, body) };
            if meta.restore_manifest(name, &m).await? {
                counts.manifests += 1;
            } else {
                counts.skipped += 1;
            }
        }
        for (tag, key, at) in &r.tags {
            let target = storage.read_small(key).await?.and_then(|b| std::str::from_utf8(&b).ok().and_then(|s| s.trim().parse::<Digest>().ok()));
            let Some(d) = target else {
                tracing::warn!(repo = %name, %tag, "unreadable tag link; skipped");
                counts.skipped += 1;
                continue;
            };
            if !meta.has_manifest(name, &d).await? {
                tracing::warn!(repo = %name, %tag, %d, "tag points at a manifest the repository doesn't have; skipped");
                counts.skipped += 1;
                continue;
            }
            if meta.restore_tag(name, tag, &d, *at).await? {
                counts.tags += 1;
            } else {
                counts.skipped += 1;
            }
        }
        for (d, at) in &r.layers {
            let Some(size) = storage.blob_size(d).await? else {
                tracing::warn!(repo = %name, %d, "linked blob missing; skipped");
                counts.skipped += 1;
                continue;
            };
            if meta.restore_blob_link(name, &BlobLink { digest: d.clone(), size, linked_at: *at }).await? {
                counts.blob_links += 1;
            } else {
                counts.skipped += 1;
            }
        }
        counts.repositories += 1;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let d = "sha256:".to_string() + &"a".repeat(64);
        let hex = "a".repeat(64);
        let parsed = |k: String| parse_key(&k);
        assert_eq!(parsed(format!("repositories/org/app/_layers/sha256/{hex}/link")), Some(("org/app".into(), Key::Layer(d.parse().unwrap()))));
        assert_eq!(parsed(format!("repositories/a/_manifests/revisions/sha256/{hex}/link")), Some(("a".into(), Key::Revision(d.parse().unwrap()))));
        assert_eq!(parsed(format!("repositories/a/_manifests/revisions/sha256/{hex}/mediatype")), Some(("a".into(), Key::MediaType(d.parse().unwrap()))));
        assert_eq!(parsed("repositories/a/b/c/_manifests/tags/v1.0/current/link".into()), Some(("a/b/c".into(), Key::Tag("v1.0".into()))));
        assert_eq!(parsed("repositories/a/_manifests/tags/v1/index/sha256/x/link".into()), None);
        assert_eq!(parsed(format!("repositories/a/_referrers/sha256/{hex}/sha256/{hex}/link")), None);
        assert_eq!(parsed("blobs/sha256/aa/data".into()), None);
    }
}
