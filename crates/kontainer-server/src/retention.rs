//! Tag retention: delete old tags by rule, per namespace.
//!
//! A policy keeps the `keep_last` most recently pushed tags of each matching repository and/or
//! deletes tags older than `max_age_days`. With both set, a tag goes only when it is outside the
//! newest `keep_last` *and* older than `max_age_days`, so a quiet repository is never emptied.
//! Protected tag globs and immutable tags are never deleted. cosign signature/SBOM tags
//! (`sha256-<hex>.sig`) follow their image: they go when nothing tagged points at it any more.
//!
//! Deleting tags only unlinks them; the space comes back when garbage collection runs.

use std::collections::HashSet;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use kontainer_core::glob;
use crate::database::policies::RetentionPolicy;
use kontainer_store::Storage;

use crate::auth::Principal;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct Deletion {
    pub repository: String,
    pub tag: String,
    pub digest: String,
    pub pushed_at: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub policy: i64,
    pub repositories: usize,
    pub deletions: Vec<Deletion>,
    /// Tags that matched a rule but were kept because they are protected or immutable.
    pub kept_protected: usize,
}

/// Work out what a policy would delete right now. `is_immutable(repo, tag)` is the registry's
/// immutable-tag check.
pub async fn evaluate(storage: &Storage, policy: &RetentionPolicy, now: DateTime<Utc>, is_immutable: &(dyn Fn(&str, &str) -> bool + Sync)) -> Result<Outcome> {
    let prefix = format!("{}/", policy.namespace);
    let repos: Vec<String> = storage
        .list_repositories()
        .await?
        .into_iter()
        .filter(|r| r.strip_prefix(&prefix).is_some_and(|rest| glob::any_matches(std::iter::once(&policy.repositories), rest)))
        .collect();
    let mut out = Outcome { policy: policy.id, repositories: repos.len(), deletions: vec![], kept_protected: 0 };
    if policy.keep_last.is_none() && policy.max_age_days.is_none() {
        return Ok(out);
    }
    let cutoff = policy.max_age_days.map(|d| now - chrono::Duration::days(d.max(0)));
    for repo in &repos {
        let mut tags = storage.list_tags_resolved(repo).await?;
        let (attached, mut regular): (Vec<_>, Vec<_>) = tags.drain(..).partition(|t| kontainer_core::artifact::cosign_tag_target(&t.tag).is_some());
        regular.sort_by_key(|t| std::cmp::Reverse(t.pushed_at));
        let mut doomed = vec![];
        let mut surviving_digests: HashSet<String> = HashSet::new();
        // Protected tags do not count towards `keep_last`: it is about the rest.
        let mut rank = 0usize;
        for t in &regular {
            let protected = glob::any_matches(policy.protect.iter(), &t.tag) || is_immutable(repo, &t.tag);
            let over_count = policy.keep_last.is_some_and(|n| !protected && rank >= n.max(0) as usize);
            let too_old = match (cutoff, t.pushed_at) {
                (Some(c), Some(p)) => p < c,
                (Some(_), None) => false, // unknown age: never delete on age
                (None, _) => true,
            };
            let matches = match (policy.keep_last, policy.max_age_days) {
                (Some(_), Some(_)) => over_count && too_old,
                (Some(_), None) => over_count,
                (None, Some(_)) => too_old,
                (None, None) => false,
            };
            if !protected {
                rank += 1;
            }
            if matches && protected {
                out.kept_protected += 1;
            }
            if matches && !protected {
                let reason = match (policy.keep_last, policy.max_age_days) {
                    (Some(n), Some(d)) => format!("not in the newest {n} and older than {d} days"),
                    (Some(n), None) => format!("not in the newest {n}"),
                    (_, Some(d)) => format!("older than {d} days"),
                    _ => String::new(),
                };
                doomed.push((t, reason));
            } else {
                surviving_digests.insert(t.digest.to_string());
            }
        }
        for (t, reason) in &doomed {
            out.deletions.push(Deletion { repository: repo.clone(), tag: t.tag.clone(), digest: t.digest.to_string(), pushed_at: t.pushed_at.map(|p| p.to_rfc3339()), reason: reason.clone() });
        }
        // Attachments of images that will no longer be tagged.
        let doomed_digests: HashSet<String> = doomed.iter().map(|(t, _)| t.digest.to_string()).filter(|d| !surviving_digests.contains(d)).collect();
        for t in &attached {
            if let Some((target, _)) = kontainer_core::artifact::cosign_tag_target(&t.tag) {
                if doomed_digests.contains(&target) && !is_immutable(repo, &t.tag) {
                    out.deletions.push(Deletion { repository: repo.clone(), tag: t.tag.clone(), digest: t.digest.to_string(), pushed_at: t.pushed_at.map(|p| p.to_rfc3339()), reason: "attached to a deleted image".into() });
                }
            }
        }
    }
    Ok(out)
}

/// What `policy` would delete right now, without deleting anything.
pub async fn preview(state: &AppState, policy: &RetentionPolicy) -> Result<Outcome> {
    let s = state.clone();
    evaluate(&state.storage, policy, Utc::now(), &move |repo, tag| s.tag_is_immutable(repo, tag)).await
}

/// Evaluate and apply `policy`, recording what it did. The outcome lists only what was actually
/// deleted: read-only and mirrored repositories are left alone.
pub async fn run(state: &AppState, policy: &RetentionPolicy, actor: &Principal) -> Result<Outcome> {
    let mut outcome = preview(state, policy).await?;
    let mut deleted = Vec::with_capacity(outcome.deletions.len());
    for d in std::mem::take(&mut outcome.deletions) {
        if state.auth.db.repo_state(&d.repository).await?.is_some() {
            continue;
        }
        crate::tags::remove(state, &d.repository, &d.tag, "retention", actor.name()).await?;
        state.audit.record(actor, "retention_delete_tag", Some(&d.repository), Some(&d.tag), Some(&d.digest), Some(format!("policy #{}: {}", policy.id, d.reason)));
        deleted.push(d);
    }
    outcome.deletions = deleted;
    let repos: std::collections::BTreeSet<&str> = outcome.deletions.iter().map(|d| d.repository.as_str()).collect();
    for r in repos {
        state.reindex(r).await;
    }
    state.auth.db.record_retention_run(policy.id, outcome.deletions.len()).await?;
    if !outcome.deletions.is_empty() {
        let tags: Vec<String> = outcome.deletions.iter().map(|d| format!("{}:{}", d.repository, d.tag)).collect();
        state.webhooks.fire(crate::webhook::Event::retention(&policy.namespace, &tags));
    }
    Ok(outcome)
}

/// Run every enabled policy (the background schedule). Returns the number of tags deleted.
pub async fn run_all(state: &AppState) -> Result<usize> {
    // Nothing can be deleted; don't fail every policy every time.
    if !state.config.features.is_delete {
        return Ok(0);
    }
    let system = state.auth.anonymous().await;
    let mut total = 0;
    for policy in state.auth.db.retention_policies(None).await?.into_iter().filter(|p| p.is_enabled) {
        match run(state, &policy, &system).await {
            Ok(o) => total += o.deletions.len(),
            Err(e) => tracing::warn!(policy = policy.id, error = %format!("{e:#}"), "retention policy failed"),
        }
    }
    Ok(total)
}
