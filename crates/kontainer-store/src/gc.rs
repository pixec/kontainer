//! Mark-and-sweep garbage collection.
//!
//! Mark: every manifest in every repository, plus every blob those manifests reference, read
//! from the metadata tables one repository at a time, each from one consistent snapshot. With
//! `is_delete_untagged`, only manifests reachable from a tag (through index children and
//! referrers) are marked and the rest are deleted first.
//! Sweep: repository blob links that were not marked are removed, then blobs (in every storage
//! location, with their placements and queued copies) no repository links, as are scan reports for digests that are no longer anywhere.
//!
//! Nothing younger than `grace` is touched: blobs by when they were first stored, links by when
//! they were last linked or referenced by a manifest push (`linked_at`), manifests by when they
//! were last pushed. So an in-flight push (blobs uploaded, manifest not yet landed) survives a
//! concurrent collection.
//!
//! Every removal is conditional in the database, so what changed since the mark phase read it
//! is kept:
//! * a link is removed only if it is still older than the cutoff: a manifest push referencing
//!   it refreshes it in the push's own transaction (or, if the removal won, the push fails with
//!   `MANIFEST_BLOB_UNKNOWN` instead of landing without its blob);
//! * a manifest is removed only if no tag points at it and it was not pushed again;
//! * a blob object is deleted through [`crate::metadata::Metadata::sweep_blob`], which checks
//!   that no repository links it and no upload is completing it while holding a per-digest lock
//!   that [`crate::metadata::Metadata::link_blob`] waits for. A link landing during the delete
//!   therefore commits after it, and the linker, finding the blob gone, stores it again
//!   ([`Storage::link_blob`]).

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use kontainer_core::digest::Digest;
use kontainer_core::manifest::Manifest;
use crate::Storage;

#[derive(Debug, Default, Serialize)]
pub struct GcReport {
    pub is_dry_run: bool,
    pub repositories: usize,
    pub manifests_kept: usize,
    pub manifests_removed: Vec<String>,
    pub links_removed: Vec<String>,
    pub blobs_removed: Vec<String>,
    pub scans_removed: Vec<String>,
    pub bytes_freed: u64,
    /// Unreferenced objects skipped because they are younger than the grace window (or were
    /// used again while the collection ran).
    pub skipped_recent: usize,
}

/// `restorable`: manifests the Time Machine can still bring back, by repository; they count as
/// tagged (see `kontainer_server::tags::restorable`).
pub async fn run(storage: &Storage, is_delete_untagged: bool, is_dry_run: bool, grace: Duration, restorable: &HashMap<String, Vec<Digest>>) -> Result<GcReport> {
    let meta = storage.metadata();
    // Never collect against empty metadata while the old layout is still there: every blob
    // would look unreferenced.
    if meta.is_empty().await? && storage.has_legacy_metadata().await? {
        anyhow::bail!("storage still holds metadata in the old layout (repositories/...) and the database has none: run `kontainer migrate-metadata` first");
    }
    let mut report = GcReport { is_dry_run, ..Default::default() };
    let cutoff = chrono::Utc::now() - chrono::Duration::from_std(grace).unwrap_or(chrono::Duration::zero());
    // Blob objects something still references or links.
    let mut marked_blobs: HashSet<Digest> = HashSet::new();
    // Manifests that remain, whose scan reports are kept too.
    let mut marked_manifests: HashSet<Digest> = HashSet::new();
    let repos = storage.list_repositories().await?;
    report.repositories = repos.len();

    for repo in &repos {
        let snap = meta.snapshot(repo).await?;
        let crate::RepoManifests { revisions, parsed, unknown } = crate::parse_manifests(repo, &snap.manifests);
        // A manifest we cannot read references blobs we cannot name: nothing in this repository
        // is collected (never delete on uncertainty).
        let is_uncertain = !unknown.is_empty();

        // Which manifests survive in this repo?
        let keep: HashSet<Digest> = if is_delete_untagged && !is_uncertain {
            let mut keep = HashSet::new();
            let mut stack: Vec<Digest> = snap.tags.iter().map(|t| t.digest.clone()).collect();
            stack.extend(restorable.get(repo).into_iter().flatten().cloned());
            // referrers index: subject -> referrers
            let mut referrers: HashMap<Digest, Vec<Digest>> = HashMap::new();
            for m in &snap.manifests {
                if let Some(s) = &m.subject {
                    referrers.entry(s.clone()).or_default().push(m.digest.clone());
                }
            }
            while let Some(d) = stack.pop() {
                if !keep.insert(d.clone()) {
                    continue;
                }
                if let Some(m) = parsed.get(&d) {
                    stack.extend(m.child_manifests().iter().map(|c| c.digest.clone()));
                }
                if let Some(rs) = referrers.get(&d) {
                    stack.extend(rs.iter().cloned());
                }
            }
            keep
        } else {
            revisions.iter().cloned().collect()
        };

        let mut repo_marked: HashSet<Digest> = HashSet::new();
        for m in &snap.manifests {
            if keep.contains(&m.digest) {
                continue;
            }
            if m.pushed_at > cutoff {
                report.skipped_recent += 1;
                repo_marked.insert(m.digest.clone());
                mark_references(parsed.get(&m.digest), &mut repo_marked);
                continue;
            }
            if !is_dry_run && !meta.collect_manifest(repo, &m.digest, cutoff).await? {
                // Tagged or pushed again since the snapshot.
                report.skipped_recent += 1;
                repo_marked.insert(m.digest.clone());
                mark_references(parsed.get(&m.digest), &mut repo_marked);
                continue;
            }
            report.manifests_removed.push(format!("{repo}@{}", m.digest));
        }

        for d in &keep {
            if revisions.contains(d) {
                report.manifests_kept += 1;
            }
            repo_marked.insert(d.clone());
            mark_references(parsed.get(d), &mut repo_marked);
        }
        for link in &snap.links {
            if is_uncertain || repo_marked.contains(&link.digest) {
                repo_marked.insert(link.digest.clone());
                continue;
            }
            if link.linked_at > cutoff || (!is_dry_run && !meta.collect_blob_link(repo, &link.digest, cutoff).await?) {
                // Recent, or linked (or referenced by a push) again since the snapshot.
                report.skipped_recent += 1;
                repo_marked.insert(link.digest.clone());
                continue;
            }
            report.links_removed.push(format!("{repo}@{}", link.digest));
        }
        // Manifest bodies are rows, not blob objects: a blob object under a manifest's digest
        // is a leftover of the old layout (or of a push of the same bytes as a blob, which a
        // link then marks).
        let manifests: HashSet<&Digest> = snap.manifests.iter().map(|m| &m.digest).collect();
        let linked: HashSet<&Digest> = snap.links.iter().map(|l| &l.digest).collect();
        for d in repo_marked {
            if manifests.contains(&d) {
                marked_manifests.insert(d.clone());
                if !linked.contains(&d) {
                    continue;
                }
            }
            marked_blobs.insert(d);
        }
    }

    for (blob, modified, size) in storage.all_blobs().await? {
        if marked_blobs.contains(&blob) {
            continue;
        }
        if modified > cutoff {
            report.skipped_recent += 1;
            continue;
        }
        if !is_dry_run && !meta.sweep_blob(&blob, Box::pin(storage.blob_delete(&blob))).await? {
            // Linked (or being uploaded) again since the mark phase.
            report.skipped_recent += 1;
            continue;
        }
        report.bytes_freed += size;
        report.blobs_removed.push(blob.to_string());
    }
    for scan in storage.all_scans().await? {
        if !marked_blobs.contains(&scan) && !marked_manifests.contains(&scan) {
            report.scans_removed.push(scan.to_string());
            if !is_dry_run {
                storage.delete_scan(&scan).await?;
            }
        }
    }
    Ok(report)
}

/// What manifest `m` references: its config and layers, or its children.
fn mark_references(m: Option<&Manifest>, out: &mut HashSet<Digest>) {
    match m {
        Some(Manifest::Image(im)) => {
            out.insert(im.config.digest.clone());
            out.extend(im.layers.iter().map(|l| l.digest.clone()));
        }
        Some(Manifest::Index(ix)) => out.extend(ix.manifests.iter().map(|c| c.digest.clone())),
        None => {}
    }
}
