//! Watching Git without webhooks: triggers with `poll_secs` set ask the Git host for its
//! branches and tags that often, and queue a build for each matching one that moved. The first
//! check only notes where everything is.

use std::collections::BTreeMap;
use std::time::Duration;

use futures::StreamExt;

use kontainer_core::glob;
use crate::database::builds::BuildTrigger;

use super::{short_ref, valid_ref};
use crate::state::AppState;

/// Who polled builds are started by (shown as the Git host).
pub const ACTOR: &str = "git (poll)";

/// The shortest polling interval accepted.
pub const MIN_SECS: i64 = 60;

/// Check due triggers forever. Call once, when builds are enabled.
pub async fn run(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        // One instance polls at a time, or two could both see a ref move and queue two builds.
        let db = state.auth.db.clone();
        crate::database::locks::exclusive(&db, "build-poll", async {
            let triggers = match state.auth.db.polling_build_triggers().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, "listing build triggers to poll");
                    return;
                }
            };
            let now = chrono::Utc::now();
            let due = triggers.into_iter().filter(|t| {
                let every = t.poll_secs.unwrap_or(MIN_SECS).max(MIN_SECS);
                t.checked_at.is_none_or(|c| (now - c).num_seconds() >= every)
            });
            futures::stream::iter(due).for_each_concurrent(4, |t| {
                let state = &state;
                async move {
                    if let Err(e) = check(state, &t).await {
                        tracing::warn!(trigger = t.id, error = %format!("{e:#}"), "polling Git");
                    }
                }
            }).await;
        })
        .await;
    }
}

/// Ask Git where `t`'s branches and tags are now, and build the ones that moved. Returns the
/// builds queued.
pub async fn check(state: &AppState, t: &BuildTrigger) -> anyhow::Result<Vec<i64>> {
    let refs = match super::git::ls_remote(&t.git_url, t.git_username.as_deref(), t.git_token.as_deref(), state.config.policy.is_webhooks_allow_private_targets).await {
        Ok(r) => r,
        Err(e) => {
            state.auth.db.record_build_poll(t.id, None, Some(&format!("{e:#}"))).await?;
            return Ok(vec![]);
        }
    };
    let patterns = t.branch_list();
    let now: BTreeMap<String, String> = refs
        .into_iter()
        .filter(|(name, sha)| (name.starts_with("refs/heads/") || name.starts_with("refs/tags/")) && valid_ref(name) && valid_ref(sha) && glob::any_matches(patterns.iter(), short_ref(name)))
        .collect();
    let before = t.seen();
    let first = t.checked_at.is_none() && before.is_empty();
    state.auth.db.record_build_poll(t.id, Some(&now), None).await?;
    if first || !t.is_enabled {
        return Ok(vec![]);
    }
    let mut queued = vec![];
    for (name, sha) in now.iter().filter(|(n, s)| before.get(*n) != Some(*s)) {
        match super::queue(state, t, name, Some(sha), None, ACTOR).await {
            Ok(q) => {
                tracing::info!(trigger = t.id, git_ref = %name, sha = %sha, build = q.id, "new commit found by polling; build queued");
                queued.push(q.id);
            }
            Err(e) => tracing::warn!(trigger = t.id, git_ref = %name, error = %e, "queueing a polled build"),
        }
    }
    Ok(queued)
}
