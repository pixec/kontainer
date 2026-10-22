//! Image builds from Git, the registry's side: the queue, and what runners need from it (the
//! build spec, its tags, importing the result). Builds never run here: **runners**
//! (`kontainer runner`, see `runner`) claim them over HTTP (`api::runner`) and run
//! them wherever they are, in-process, in containers or as Kubernetes Jobs.
//!
//! Builds wait in the database as `queued`. A runner claims one atomically, for a namespace it
//! serves, and checks in while it works; a build whose runner goes quiet is failed. Runners
//! never get registry credentials: they hand back an OCI archive that the server imports.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};

use kontainer_core::build::protocol::BuildSpec;
use crate::database::builds::{Build, BuildTrigger};

use crate::state::AppState;

pub mod git;
pub mod logs;
pub mod poll;

pub use kontainer_core::build::{and_list, render_tags, sentence, short_ref, valid_ref};

/// A fresh build token and the hash stored for it.
pub fn new_token() -> (String, String) {
    let token = kontainer_core::random_token(24);
    let hash = crate::database::sha256_hex(&token);
    (token, hash)
}

/// Make the database's configured runners match `[[builds.runners]]`.
pub async fn sync_config_runners(state: &AppState) -> Result<()> {
    let runners: Vec<(String, String, Vec<String>)> = state.config.builds.runners.iter().map(|r| (r.name.clone(), r.token.expose().to_string(), r.namespaces.clone())).collect();
    state.auth.db.sync_config_runners(&runners).await?;
    if !runners.is_empty() {
        tracing::info!(runners = runners.len(), "shared runners from the configuration");
    }
    Ok(())
}

/// Start the queue's housekeeping. Call once, when builds are enabled.
pub async fn start(state: &AppState) {
    tokio::spawn(reap(state.clone()));
    tokio::spawn(poll::run(state.clone()));
}

/// Fail builds whose runner stopped checking in.
async fn reap(state: AppState) {
    let mut every = tokio::time::interval(Duration::from_secs(15));
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(state.config.builds.heartbeat_timeout).unwrap_or(chrono::Duration::minutes(2));
        match state.auth.db.fail_stale_builds(cutoff).await {
            Ok(ids) => {
                for id in ids {
                    tracing::warn!(build = id, "build runner stopped responding; build failed");
                    notify(&state, id).await;
                }
            }
            Err(e) => tracing::warn!(error = %e, "checking for stalled builds"),
        }
    }
}

/// Cancel a queued or running build. A running one stops at its runner's next check-in.
pub async fn cancel(state: &AppState, b: &Build) -> Result<()> {
    if state.auth.db.cancel_build(b.id).await? {
        notify(state, b.id).await;
    }
    Ok(())
}

/// A build that was queued, and the older queued builds of the same ref it replaced.
pub struct Queued {
    pub id: i64,
    pub superseded: Vec<i64>,
}

/// Queue a build of `git_ref` (at `commit`, if known) for trigger `t`, optionally with its own
/// tag templates. A known commit is remembered as where the ref was last seen. Older builds of
/// the same trigger and ref that haven't started are cancelled: only the newest is worth building.
pub async fn queue(state: &AppState, t: &BuildTrigger, git_ref: &str, commit: Option<&str>, tags: Option<&[String]>, actor: &str) -> crate::error::Result<Queued> {
    if !valid_ref(git_ref) || commit.is_some_and(|c| !valid_ref(c)) {
        return Err(crate::error::RegistryError::bad_request("invalid ref"));
    }
    state.require_writable(&t.repository).await?;
    let db = &state.auth.db;
    let id = db.create_build(Some(t.id), &t.repository, &t.git_url, git_ref, actor).await?;
    if let Some(c) = commit {
        db.set_build_result(id, Some(c), &[], None).await?;
        db.see_build_ref(t.id, git_ref, c).await?;
    }
    if let Some(tags) = tags {
        db.set_build_tag_templates(id, tags).await?;
    }
    let superseded = db.supersede_builds(t.id, git_ref, id).await?;
    for old in &superseded {
        tracing::info!(build = old, by = id, "queued build superseded by a newer one");
        notify(state, *old).await;
    }
    Ok(Queued { id, superseded })
}

/// What a runner needs to run build `b`.
pub async fn spec(state: &AppState, b: &Build) -> Result<BuildSpec> {
    let trigger = match b.trigger_id {
        Some(t) => state.auth.db.build_trigger(t).await?.ok_or_else(|| anyhow!("Its build trigger was deleted"))?,
        None => bail!("Builds need a build trigger"),
    };
    Ok(BuildSpec {
        id: b.id,
        repository: b.repository.clone(),
        git_url: trigger.git_url.clone(),
        git_username: trigger.git_username.clone(),
        git_token: trigger.git_token.clone().map(Into::into),
        git_ref: b.git_ref.clone(),
        // A webhook pins the exact commit; a manual build follows the ref.
        target: b.commit_sha.clone().unwrap_or_else(|| b.git_ref.clone()),
        dockerfile: trigger.dockerfile.clone(),
        context: trigger.context.clone(),
        timeout_secs: state.config.builds.timeout.as_secs(),
    })
}

/// The checkout of build `b` is at `sha`: pick its tags.
pub async fn commit(state: &AppState, b: &Build, sha: &str) -> Result<Vec<String>> {
    if !valid_ref(sha) {
        bail!("Invalid commit {sha:?}");
    }
    let trigger = match b.trigger_id {
        Some(t) => state.auth.db.build_trigger(t).await?.ok_or_else(|| anyhow!("Its build trigger was deleted"))?,
        None => bail!("Builds need a build trigger"),
    };
    // A build started by hand may bring its own templates.
    let templates = b.tag_templates.as_deref().and_then(|t| serde_json::from_str::<Vec<String>>(t).ok()).unwrap_or_else(|| trigger.tag_list());
    let tags = render_tags(&templates, &b.git_ref, sha);
    // No templates at all is a choice (push by digest only); templates that all fail are a typo.
    if tags.is_empty() && !templates.is_empty() {
        bail!("None of the build trigger's tag templates makes a valid tag for {}", short_ref(&b.git_ref));
    }
    state.auth.db.set_build_result(b.id, Some(sha), &tags, None).await?;
    Ok(tags)
}

/// Import the archive build `b` produced and tag it. Returns the summary for the log.
pub async fn import(state: &AppState, b: &Build, archive: &Path) -> Result<String> {
    // The tags were chosen at commit time.
    let b = state.auth.db.build(b.id).await?.ok_or_else(|| anyhow!("Build {} no longer exists", b.id))?;
    let tags: Vec<String> = serde_json::from_str(&b.tags).unwrap_or_default();
    if b.commit_sha.is_none() {
        bail!("The build never reported its commit");
    }
    // Only names the archive's image for the import; the build's own tags are applied below.
    let name = tags.first().map(String::as_str).unwrap_or("build");
    let unpack = state.storage.uploads.temp_path().await?;
    tokio::fs::create_dir_all(&unpack).await?;
    let imported = kontainer_store::layout::import(&state.storage, &b.repository, archive, &unpack, Some(name)).await;
    let _ = tokio::fs::remove_dir_all(&unpack).await;
    let imported = imported?;
    let digest = imported.roots.first().map(|(_, d)| d.clone()).ok_or_else(|| anyhow!("The build produced no image"))?;
    let actor = format!("build #{}", b.id);
    for t in &tags {
        crate::tags::set(state, &b.repository, t, &digest, "build", &actor).await?;
    }
    state.auth.note_repo(&b.repository, true).await;
    state.reindex(&b.repository).await;
    state.auth.db.set_build_result(b.id, None, &tags, Some(&digest.to_string())).await?;
    let short = &digest.to_string()[..19];
    Ok(if tags.is_empty() {
        format!("Pushed {} untagged, by digest only ({short})", b.repository)
    } else {
        format!("Pushed {} as {} ({short})", b.repository, and_list(&tags))
    })
}

/// End running build `id`, with a last `line` for its log, and tell webhooks and log followers.
/// False when it had already ended.
pub async fn end(state: &AppState, id: i64, status: &str, message: &str, line: Option<&str>) -> Result<bool> {
    let changed = state.auth.db.finish_build(id, status, &sentence(message), line).await?;
    if changed {
        fire(state, id).await;
    }
    Ok(changed)
}

/// A build ended some other way than [`end`] (cancelled while queued, superseded, failed for
/// going quiet): tell webhooks and log followers.
async fn notify(state: &AppState, id: i64) {
    state.auth.db.notify_build_log(id).await;
    fire(state, id).await;
}

/// Fire the `build` webhook event for a build that has ended.
async fn fire(state: &AppState, id: i64) {
    if let Ok(Some(b)) = state.auth.db.build(id).await {
        let tags: Vec<String> = serde_json::from_str(&b.tags).unwrap_or_default();
        state.webhooks.fire(crate::webhook::Event::build(&b.repository, b.id, &b.status, b.message.as_deref().unwrap_or_default(), &tags, b.digest.as_deref()));
    }
}

/// Record the outcome of build `id`, ending its log with it.
pub async fn finish(state: &AppState, id: i64, outcome: Result<String>) {
    let (status, message) = match outcome {
        Ok(summary) => ("succeeded", summary),
        Err(e) => ("failed", sentence(&format!("{e:#}"))),
    };
    if let Err(e) = end(state, id, status, &message, Some(&format!("==> {message}"))).await {
        tracing::warn!(build = id, error = %e, "recording the build result");
    }
}
