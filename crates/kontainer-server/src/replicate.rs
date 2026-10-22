//! Push replication: copy local repositories to another registry, following the rules in
//! `replication_rules`. On push (just what was pushed), on a schedule or by hand (everything
//! that matches, skipping what is already there). Cosign signatures and attestations follow the
//! images they belong to. Every run is recorded as task run `replication/<rule id>`.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::TryStreamExt;
use serde::Serialize;

use kontainer_core::digest::Digest;
use kontainer_core::glob;
use kontainer_core::manifest::Manifest;
use crate::database::replication::ReplicationRule;
use kontainer_core::upstream::Upstream;

use crate::state::AppState;

/// Where `repo` goes on the target registry.
pub fn destination(rule: &ReplicationRule, repo: &str) -> String {
    if rule.destination.is_empty() { repo.to_string() } else { format!("{}/{repo}", rule.destination) }
}

fn wants_repo(rule: &ReplicationRule, repo: &str) -> bool {
    let repos = rule.repository_list();
    repos.is_empty() || glob::any_matches(&repos, repo)
}

fn wants_tag(rule: &ReplicationRule, tag: &str) -> bool {
    let tags = rule.tag_list();
    tags.is_empty() || glob::any_matches(&tags, tag)
}

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub copied: usize,
    pub current: usize,
    pub blobs: usize,
    pub bytes: u64,
    pub failed: Vec<String>,
}

impl Stats {
    fn summary(&self) -> String {
        let mut s = format!("{} tags copied ({} uploaded), {} up to date", self.copied, kontainer_store::usage::human(self.bytes), self.current);
        if !self.failed.is_empty() {
            s.push_str(&format!("; {} failed: {}", self.failed.len(), self.failed.join("; ")));
        }
        s
    }
}

async fn client(state: &AppState, rule: &ReplicationRule) -> Result<Upstream> {
    state.auth.db.registry(rule.registry_id).await?.context("the rule's registry was deleted")?.client()
}

/// Upload blob `d` unless the target has it.
async fn ensure_blob(state: &AppState, up: &Upstream, dst: &str, d: &Digest, stats: &mut Stats) -> Result<()> {
    if up.blob_exists(dst, d).await? {
        return Ok(());
    }
    let blob = state.storage.blob_stream(d, None).await?.ok_or_else(|| anyhow!("blob {d} is missing locally"))?;
    let size = blob.total_size;
    let body = reqwest::Body::wrap_stream(blob.stream.map_err(std::io::Error::other));
    up.push_blob(dst, d, size, body).await?;
    stats.blobs += 1;
    stats.bytes += size;
    Ok(())
}

/// Push manifest `digest` (and everything it references) to `dst` as `reference`.
fn copy_manifest<'a>(state: &'a AppState, up: &'a Upstream, repo: &'a str, dst: &'a str, digest: &'a Digest, reference: &'a str, stats: &'a mut Stats) -> futures::future::BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let row = state.storage.manifest(repo, digest).await?.ok_or_else(|| anyhow!("manifest {digest} is missing locally"))?;
        let bytes = row.body;
        let (manifest, media_type) = Manifest::parse(&bytes, Some(&row.media_type)).map_err(|e| anyhow!("{digest}: {e}"))?;
        match &manifest {
            Manifest::Image(_) => {
                for b in manifest.required_blobs() {
                    ensure_blob(state, up, dst, &b.digest, stats).await?;
                }
            }
            Manifest::Index(ix) => {
                for child in &ix.manifests {
                    // Platforms we don't have (a partial pull-through copy) can't be replicated.
                    if state.storage.has_manifest(repo, &child.digest).await? {
                        copy_manifest(state, up, repo, dst, &child.digest, &child.digest.to_string(), stats).await?;
                    }
                }
            }
        }
        up.put_manifest(dst, reference, &media_type, bytes).await?;
        Ok(())
    })
}

/// Replicate `repo:tag` under `rule`, then its signatures and attestations.
async fn replicate_tag(state: &AppState, rule: &ReplicationRule, up: &Upstream, repo: &str, tag: &str, stats: &mut Stats) -> Result<()> {
    let Some(local) = state.storage.resolve_tag(repo, tag).await? else { return Ok(()) };
    let dst = destination(rule, repo);
    if up.head_manifest(&dst, tag).await? == Some(local.clone()) {
        stats.current += 1;
    } else {
        copy_manifest(state, up, repo, &dst, &local, tag, stats).await?;
        stats.copied += 1;
    }
    // cosign stores these as `sha256-<hex>.sig` / `.att` / `.sbom` tags.
    let hex = local.to_string().replace(':', "-");
    for suffix in [".sig", ".att", ".sbom"] {
        let t = format!("{hex}{suffix}");
        if t != tag {
            if let Some(d) = state.storage.resolve_tag(repo, &t).await? {
                if up.head_manifest(&dst, &t).await? != Some(d.clone()) {
                    copy_manifest(state, up, repo, &dst, &d, &t, stats).await?;
                }
            }
        }
    }
    Ok(())
}

/// Replicate under `rule`: just `only` (a pushed `repo:tag`), or everything that matches.
/// Returns the summary.
pub async fn run(state: &AppState, rule: &ReplicationRule, trigger: &str, actor: &str, only: Option<(&str, &str)>) -> Result<Stats> {
    // A full run at a time per rule; released however the run ends.
    let _slot = if only.is_none() { Some(crate::maintenance::KeyedSlot::take(&state.running.replication, rule.id, "this replication rule")?) } else { None };
    // And one at a time across instances.
    let lock = match only {
        None => Some(crate::maintenance::cluster_slot(state, &format!("replication/{}", rule.id), "this replication rule").await?),
        Some(_) => None,
    };
    let kind = format!("replication/{}", rule.id);
    let run_id = state.auth.db.start_task_run(&kind, trigger, actor).await?;
    let mut stats = Stats::default();
    let mut touched = BTreeSet::new();
    let result = async {
        let up = client(state, rule).await?;
        match only {
            Some((repo, tag)) => {
                touched.insert(repo.to_string());
                replicate_tag(state, rule, &up, repo, tag, &mut stats).await?;
            }
            None => {
                for repo in state.storage.list_repositories().await?.into_iter().filter(|r| wants_repo(rule, r)) {
                    for tag in state.storage.list_tags(&repo).await?.into_iter().filter(|t| wants_tag(rule, t)) {
                        if let Err(e) = replicate_tag(state, rule, &up, &repo, &tag, &mut stats).await {
                            stats.failed.push(format!("{repo}:{tag}: {e:#}"));
                        }
                        touched.insert(repo.clone());
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let (ok, message) = match &result {
        Ok(()) if stats.failed.is_empty() => (true, stats.summary()),
        Ok(()) => (false, stats.summary()),
        Err(e) => (false, format!("{e:#}")),
    };
    state.auth.db.finish_task_run(run_id, ok, &message, serde_json::to_value(&stats).ok().as_ref()).await?;
    state.auth.db.record_replication(rule.id, ok, &message).await?;
    if let Some(lock) = lock {
        lock.release().await;
    }
    let target = state.auth.db.registry(rule.registry_id).await.ok().flatten().map(|r| r.name).unwrap_or_default();
    for repo in &touched {
        state.webhooks.fire(crate::webhook::Event::replication(repo, &target, ok, &message));
    }
    result.map(|_| stats)
}

/// A tag was pushed: replicate it under every rule that replicates on push.
pub fn on_push(state: &AppState, repo: &str, tag: &str) {
    let (state, repo, tag) = (state.clone(), repo.to_string(), tag.to_string());
    tokio::spawn(async move {
        let Ok(rules) = state.auth.db.replication_rules().await else { return };
        for rule in rules.into_iter().filter(|r| r.is_enabled && r.trigger == "push" && wants_repo(r, &repo) && wants_tag(r, &tag)) {
            if let Err(e) = run(&state, &rule, "push", "push", Some((&repo, &tag))).await {
                tracing::warn!(rule = rule.id, %repo, %tag, error = %format!("{e:#}"), "replication failed");
            }
        }
    });
}

/// A tag was deleted: delete it on targets whose rules replicate deletions.
pub fn on_delete(state: &AppState, repo: &str, tag: &str) {
    let (state, repo, tag) = (state.clone(), repo.to_string(), tag.to_string());
    tokio::spawn(async move {
        let Ok(rules) = state.auth.db.replication_rules().await else { return };
        for rule in rules.into_iter().filter(|r| r.is_enabled && r.is_replicate_deletes && wants_repo(r, &repo) && wants_tag(r, &tag)) {
            let result = async { client(&state, &rule).await?.delete_manifest(&destination(&rule, &repo), &tag).await }.await;
            let (ok, message) = match &result {
                Ok(true) => (true, format!("deleted {}:{tag}", destination(&rule, &repo))),
                Ok(false) => (true, format!("{}:{tag} was already gone", destination(&rule, &repo))),
                Err(e) => (false, format!("deleting {}:{tag}: {e:#}", destination(&rule, &repo))),
            };
            if let Ok(id) = state.auth.db.start_task_run(&format!("replication/{}", rule.id), "delete", "push").await {
                if let Err(e) = state.auth.db.finish_task_run(id, ok, &message, None).await {
                    tracing::warn!(rule = rule.id, error = %e, "recording a replication run");
                }
            }
            if let Err(e) = state.auth.db.record_replication(rule.id, ok, &message).await {
                tracing::warn!(rule = rule.id, error = %e, "recording a replication result");
            }
        }
    });
}

/// Run scheduled rules when they are due. Call once at startup.
pub fn start(state: &AppState) {
    let state = state.clone();
    crate::background::every(Duration::from_secs(60), true, move || {
        let state = state.clone();
        async move {
            let Ok(rules) = state.auth.db.replication_rules().await else { return };
            let now = chrono::Utc::now();
            for rule in rules.into_iter().filter(|r| r.is_enabled && r.trigger == "schedule") {
                let every = rule.interval_secs.unwrap_or(3600).max(300);
                let due = rule.last_run_at.is_none_or(|t| (now - t).num_seconds() >= every);
                if due {
                    let state = state.clone();
                    tokio::spawn(async move {
                        match run(&state, &rule, "schedule", "schedule", None).await {
                            Ok(_) => {}
                            // Still running from an earlier tick, here or on another instance.
                            Err(e) if e.downcast_ref::<crate::maintenance::AlreadyRunning>().is_some() => tracing::debug!(rule = rule.id, "scheduled replication still running"),
                            Err(e) => tracing::warn!(rule = rule.id, error = %format!("{e:#}"), "scheduled replication failed"),
                        }
                    });
                }
            }
        }
    });
}
