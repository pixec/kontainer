//! Build triggers, builds, and the webhook that starts them.

use std::collections::HashMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use kontainer_core::perm::Action;
use crate::auth::{require, Principal};
use crate::database::builds::{BuildTrigger, TriggerInput};
use crate::error::{Code, RegistryError, Result};
use kontainer_core::names;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/build-triggers", get(list_triggers).post(create_trigger))
        .route("/api/v1/build-triggers/{id}", put(update_trigger).delete(delete_trigger))
        .route("/api/v1/build-triggers/{id}/secret", post(rotate_secret))
        .route("/api/v1/build-triggers/{id}/run", post(run_trigger))
        .route("/api/v1/build-triggers/{id}/check", post(check_trigger))
        .route("/api/v1/build-triggers/{id}/webhook", post(webhook))
        .route("/api/v1/builds", get(list_builds))
        .route("/api/v1/builds/{id}", get(get_build))
        .route("/api/v1/builds/{id}/cancel", post(cancel_build))
        .route("/api/v1/builds/{id}/log/stream", get(stream_log))
}



fn enabled(state: &AppState) -> Result<()> {
    if state.config.builds.is_enabled { Ok(()) } else { Err(RegistryError::with_message(Code::Unsupported, "builds are disabled on this registry (builds.enabled)")) }
}

/// Builds need a runner serving the repository's namespace.
async fn require_runner(state: &AppState, repository: &str) -> Result<()> {
    let ns = names::namespace(repository);
    if state.auth.db.has_runner_for(ns).await? {
        Ok(())
    } else {
        Err(RegistryError::with_message(Code::Conflict, format!("no runner builds images for {ns} yet: register a self-hosted runner in its settings, or ask an administrator for a shared one")))
    }
}

fn webhook_url(state: &AppState, id: i64) -> String {
    format!("{}/api/v1/build-triggers/{id}/webhook", state.auth.public_url.trim_end_matches('/'))
}

async fn view(state: &AppState, t: &BuildTrigger) -> Result<serde_json::Value> {
    let mut v = serde_json::to_value(t).unwrap_or_default();
    v["webhook_url"] = webhook_url(state, t.id).into();
    v["has_token"] = t.git_token.is_some().into();
    v["last_build"] = state.auth.db.last_trigger_build(t.id).await?.map(|b| serde_json::json!({
        "id": b.id, "status": b.status, "git_ref": b.git_ref, "commit_sha": b.commit_sha, "created_at": b.created_at.to_rfc3339(),
    })).into();
    Ok(v)
}

#[derive(Deserialize)]
struct RepoQuery {
    repository: String,
}

async fn list_triggers(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(q): Query<RepoQuery>) -> Result<Response> {
    enabled(&state)?;
    require(&state, &p, Action::Pull, &q.repository)?;
    let admin = p.allowed(Action::Builds, &q.repository);
    let mut list = vec![];
    for t in state.auth.db.build_triggers(&q.repository).await? {
        let mut v = view(&state, &t).await?;
        if !admin {
            v["webhook_url"] = serde_json::Value::Null;
            v["check_error"] = serde_json::Value::Null;
        }
        list.push(v);
    }
    Ok(Json(list).into_response())
}

fn validate(state: &AppState, i: &mut TriggerInput) -> Result<()> {
    if i.name.trim().is_empty() || i.name.len() > 64 {
        return Err(RegistryError::bad_request("name: 1-64 characters"));
    }
    let url = i.git_url.trim();
    let ok = url.starts_with("https://") || (state.config.builds.is_allow_file_urls && url.starts_with("file://"));
    if !ok || url.len() > 500 || url.chars().any(char::is_whitespace) {
        return Err(RegistryError::bad_request("git_url must be an https:// URL"));
    }
    if i.branches.is_empty() {
        i.branches = vec!["**".into()];
    }
    if i.poll_secs.is_some_and(|s| !(crate::build::poll::MIN_SECS..=86_400).contains(&s)) {
        return Err(RegistryError::bad_request("poll_secs: between 60 (a minute) and 86400 (a day)"));
    }
    if i.branches.len() > 20 || i.tags.len() > 10 {
        return Err(RegistryError::bad_request("at most 20 branch patterns and 10 tags"));
    }
    for p in [i.dockerfile.as_deref(), i.context.as_deref()].into_iter().flatten() {
        if p.starts_with('/') || p.split('/').any(|s| s == "..") {
            return Err(RegistryError::bad_request("dockerfile and context are paths inside the repository"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct CreateBody {
    repository: String,
    #[serde(flatten)]
    trigger: TriggerInput,
}

async fn create_trigger(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(mut b): Json<CreateBody>) -> Result<Response> {
    enabled(&state)?;
    if !names::is_valid_repository(&b.repository) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    require(&state, &p, Action::Builds, &b.repository)?;
    require_runner(&state, &b.repository).await?;
    validate(&state, &mut b.trigger)?;
    let secret = kontainer_core::random_token(24);
    let t = state.auth.db.create_build_trigger(&b.repository, &b.trigger, &secret, p.name()).await?;
    state.audit.record(&p, "build_trigger_created", Some(&b.repository), None, None, Some(t.git_url.clone()));
    let mut v = view(&state, &t).await?;
    v["secret"] = secret.into(); // shown once
    Ok((StatusCode::CREATED, Json(v)).into_response())
}

async fn trigger_for(state: &AppState, p: &Principal, id: i64, action: Action) -> Result<BuildTrigger> {
    enabled(state)?;
    let t = state.auth.db.build_trigger(id).await?.ok_or_else(|| RegistryError::not_found("build trigger"))?;
    require(state, p, action, &t.repository)?;
    Ok(t)
}

async fn update_trigger(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(mut i): Json<TriggerInput>) -> Result<Response> {
    let t = trigger_for(&state, &p, id, Action::Builds).await?;
    validate(&state, &mut i)?;
    state.auth.db.update_build_trigger(id, &i).await?;
    state.audit.record(&p, "build_trigger_updated", Some(&t.repository), None, None, Some(i.git_url.clone()));
    let t = state.auth.db.build_trigger(id).await?.ok_or_else(|| RegistryError::not_found("build trigger"))?;
    Ok(Json(view(&state, &t).await?).into_response())
}

/// Poll Git now instead of waiting for the next check.
async fn check_trigger(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let t = trigger_for(&state, &p, id, Action::Builds).await?;
    let queued = crate::build::poll::check(&state, &t).await.map_err(RegistryError::internal)?;
    let t = state.auth.db.build_trigger(id).await?.ok_or_else(|| RegistryError::not_found("build trigger"))?;
    let mut v = view(&state, &t).await?;
    v["queued"] = queued.into();
    Ok(Json(v).into_response())
}

async fn delete_trigger(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let t = trigger_for(&state, &p, id, Action::Builds).await?;
    state.auth.db.delete_build_trigger(id).await?;
    state.audit.record(&p, "build_trigger_deleted", Some(&t.repository), None, None, Some(t.git_url));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn rotate_secret(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let t = trigger_for(&state, &p, id, Action::Builds).await?;
    let secret = kontainer_core::random_token(24);
    state.auth.db.set_build_trigger_secret(id, &secret).await?;
    state.audit.record(&p, "build_trigger_secret", Some(&t.repository), None, None, None);
    Ok(Json(serde_json::json!({ "secret": secret, "webhook_url": webhook_url(&state, id) })).into_response())
}

#[derive(Deserialize)]
struct RunBody {
    /// Branch, tag or commit; defaults to the first literal branch pattern, else `main`.
    #[serde(default, rename = "ref")]
    git_ref: Option<String>,
    /// Tag templates for this build only, instead of the trigger's (same syntax: `{branch}`,
    /// `{sha7}`, literals).
    #[serde(default)]
    tags: Vec<String>,
}

async fn run_trigger(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, body: Option<Json<RunBody>>) -> Result<Response> {
    let t = trigger_for(&state, &p, id, Action::Push).await?;
    require_runner(&state, &t.repository).await?;
    let default = t.branch_list().into_iter().find(|b| !b.contains('*') && !b.contains('?')).unwrap_or_else(|| "main".into());
    let (r, tags) = match body {
        Some(Json(b)) => (b.git_ref, b.tags),
        None => (None, vec![]),
    };
    let r = r.map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).unwrap_or(default);
    let tags: Vec<String> = tags.into_iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    if tags.len() > 10 || tags.iter().any(|t| t.len() > 128) {
        return Err(RegistryError::bad_request("at most 10 tags, each up to 128 characters"));
    }
    let git_ref = if r.starts_with("refs/") || (r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit())) { r } else { format!("refs/heads/{r}") };
    // Catch typos now: a template must be able to produce a valid tag for this ref.
    if !tags.is_empty() && crate::build::render_tags(&tags, &git_ref, &"0".repeat(40)).is_empty() {
        return Err(RegistryError::bad_request("none of these tags is valid (letters, digits, `.`, `_`, `-`; up to 128 characters)"));
    }
    let q = crate::build::queue(&state, &t, &git_ref, None, (!tags.is_empty()).then_some(tags.as_slice()), p.name()).await?;
    state.audit.record(&p, "build_started", Some(&t.repository), Some(&git_ref), None, Some(format!("build #{}", q.id)));
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "build": q.id, "superseded": q.superseded }))).into_response())
}

fn github_signature_ok(secret: &str, body: &[u8], header: &str) -> bool {
    let Some(hex_sig) = header.strip_prefix("sha256=") else { return false };
    let Ok(sig) = hex::decode(hex_sig) else { return false };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else { return false };
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

fn eq_ct(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
struct WebhookQuery {
    #[serde(default)]
    secret: Option<String>,
}

/// GitHub (`X-Hub-Signature-256`), GitLab (`X-Gitlab-Token`) or generic (`?secret=`, body
/// `{"ref": "refs/heads/main", "sha": "..."}`) push events.
async fn webhook(State(state): State<AppState>, Path(id): Path<i64>, Query(q): Query<WebhookQuery>, headers: HeaderMap, body: Bytes) -> Result<Response> {
    enabled(&state)?;
    let denied = || RegistryError::with_message(Code::Denied, "bad webhook secret or signature").status(StatusCode::UNAUTHORIZED);
    let t = state.auth.db.build_trigger(id).await?.ok_or_else(denied)?;
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let authentic = if !h("x-hub-signature-256").is_empty() {
        github_signature_ok(&t.secret, &body, &h("x-hub-signature-256"))
    } else if !h("x-gitlab-token").is_empty() {
        eq_ct(&h("x-gitlab-token"), &t.secret)
    } else {
        q.secret.as_deref().or(headers.get("x-kontainer-secret").and_then(|v| v.to_str().ok())).is_some_and(|s| eq_ct(s, &t.secret))
    };
    if !authentic {
        return Err(denied());
    }
    if h("x-github-event") == "ping" {
        return Ok(Json(serde_json::json!({ "ok": true, "message": "pong" })).into_response());
    }
    if !t.is_enabled {
        return Ok(Json(serde_json::json!({ "ok": true, "message": "trigger is disabled" })).into_response());
    }
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| RegistryError::bad_request("body must be JSON"))?;
    let git_ref = v["ref"].as_str().unwrap_or_default().to_string();
    if v["deleted"].as_bool() == Some(true) || v["after"].as_str().is_some_and(|a| a.chars().all(|c| c == '0')) {
        return Ok(Json(serde_json::json!({ "ok": true, "message": "branch deleted; nothing to build" })).into_response());
    }
    let sha = v["checkout_sha"].as_str().or(v["after"].as_str()).or(v["sha"].as_str()).filter(|s| !s.is_empty()).map(str::to_string);
    if git_ref.is_empty() {
        return Err(RegistryError::bad_request("no ref in the event"));
    }
    let name = crate::build::short_ref(&git_ref);
    if !kontainer_core::glob::any_matches(t.branch_list().iter(), name) {
        return Ok(Json(serde_json::json!({ "ok": true, "message": format!("{name} does not match this trigger's branches") })).into_response());
    }
    let pusher = v["pusher"]["name"].as_str().or(v["user_username"].as_str()).unwrap_or("webhook");
    let q = crate::build::queue(&state, &t, &git_ref, sha.as_deref(), None, &format!("{pusher} (webhook)")).await?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "ok": true, "build": q.id, "superseded": q.superseded }))).into_response())
}

#[derive(Deserialize)]
struct BuildsQuery {
    repository: String,
    #[serde(default)]
    limit: Option<i64>,
}

/// Who started a build, for showing them: `zack` or `zack (webhook)` → the account's display
/// name and avatar. Unknown actors (deleted accounts, `build #3`) keep just their name.
async fn actor_view(state: &AppState, actor: &str, seen: &mut HashMap<String, serde_json::Value>) -> Result<serde_json::Value> {
    if actor == crate::build::poll::ACTOR {
        return Ok(serde_json::json!({ "name": "git", "display_name": "Git", "avatar_url": null, "via_webhook": false, "via_poll": true }));
    }
    let username = actor.strip_suffix(" (webhook)").unwrap_or(actor);
    if let Some(v) = seen.get(username) {
        return Ok(v.clone());
    }
    let mut v = serde_json::json!({ "name": username, "display_name": null, "avatar_url": null, "via_webhook": actor.ends_with(" (webhook)"), "via_poll": false });
    if let Some(u) = state.auth.db.user_by_name(username).await? {
        let profile = state.auth.db.profile(u.id).await?;
        v["display_name"] = profile.as_ref().and_then(|p| p.display_name.clone()).or(u.display_name.clone()).filter(|d| !d.is_empty()).into();
        let email = profile.and_then(|p| p.gravatar_email).or(u.email).filter(|e| !e.is_empty());
        v["avatar_url"] = email.map(|e| super::auth::gravatar_url(&e)).into();
    }
    seen.insert(username.to_string(), v.clone());
    Ok(v)
}

/// For a queued build: how many queued builds are older, and whether its namespace is at its
/// limit (`max_per_namespace`).
async fn queue_view(state: &AppState, b: &crate::database::builds::Build) -> Result<serde_json::Value> {
    if b.status != "queued" {
        return Ok(serde_json::Value::Null);
    }
    let (ahead, running) = state.auth.db.build_queue_position(b.id, &b.repository).await?;
    let limit = state.config.builds.max_per_namespace;
    Ok(serde_json::json!({
        "ahead": ahead,
        "namespace": names::namespace(&b.repository),
        "namespace_running": running,
        "namespace_limit": (limit > 0).then_some(limit),
    }))
}

async fn list_builds(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(q): Query<BuildsQuery>) -> Result<Response> {
    enabled(&state)?;
    require(&state, &p, Action::Pull, &q.repository)?;
    let mut seen = HashMap::new();
    let mut out = vec![];
    for b in state.auth.db.builds(&q.repository, q.limit.unwrap_or(50).clamp(1, 200)).await? {
        let mut v = serde_json::to_value(&b).unwrap_or_default();
        v["actor_user"] = actor_view(&state, &b.actor, &mut seen).await?;
        v["queue"] = queue_view(&state, &b).await?;
        out.push(v);
    }
    Ok(Json(out).into_response())
}

#[derive(Deserialize)]
struct BuildQuery {
    /// `false`: leave the log out (a client following it on the stream).
    #[serde(default)]
    log: Option<bool>,
}

async fn get_build(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Query(q): Query<BuildQuery>) -> Result<Response> {
    enabled(&state)?;
    let b = state.auth.db.build(id).await?.ok_or_else(|| RegistryError::not_found("build"))?;
    require(&state, &p, Action::Pull, &b.repository)?;
    let mut v = serde_json::to_value(&b).unwrap_or_default();
    // Cached once the build ends; until then, put together from its chunks.
    if q.log != Some(false) {
        v["log"] = if b.status == "running" { state.auth.db.build_log_text(id).await? } else { b.log.clone() }.into();
    }
    v["actor_user"] = actor_view(&state, &b.actor, &mut HashMap::new()).await?;
    v["queue"] = queue_view(&state, &b).await?;
    Ok(Json(v).into_response())
}

async fn cancel_build(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    enabled(&state)?;
    let b = state.auth.db.build(id).await?.ok_or_else(|| RegistryError::not_found("build"))?;
    require(&state, &p, Action::Push, &b.repository)?;
    if !matches!(b.status.as_str(), "queued" | "running") {
        return Err(RegistryError::bad_request(format!("build #{id} already {}", b.status)));
    }
    crate::build::cancel(&state, &b).await?;
    state.audit.record(&p, "build_cancelled", Some(&b.repository), None, None, Some(format!("build #{id}")));
    Ok(StatusCode::ACCEPTED.into_response())
}

/// Chunks sent per database read while following a log.
const STREAM_BATCH: i64 = 200;
/// How often a log stream looks for news without being told (a notification may have been
/// lost), and sends a comment so proxies keep it open.
const STREAM_IDLE: Duration = Duration::from_secs(15);

/// The log of build `id` as server-sent events: each chunk as it arrives (`id: <seq>`, data
/// `{"seq", "data"}`), starting after the client's `Last-Event-ID`, then `event: done` with
/// `{"status", "message"}` once the build has ended.
async fn stream_log(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, headers: HeaderMap) -> Result<Response> {
    enabled(&state)?;
    let b = state.auth.db.build(id).await?.ok_or_else(|| RegistryError::not_found("build"))?;
    require(&state, &p, Action::Pull, &b.repository)?;
    let last = headers.get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(0).max(0);
    // Following before the first read, so nothing appended in between is missed.
    let follower = state.build_logs.follow(id);
    let follow = LogStream { state, id, last, follower, done: false };
    let events = futures::stream::unfold(follow, |mut f| async move {
        if f.done {
            return None;
        }
        match f.next().await {
            Ok(events) => Some((futures::stream::iter(events.into_iter().map(Ok::<_, std::convert::Infallible>)), f)),
            Err(e) => {
                // The client reconnects and resumes from its last event.
                tracing::warn!(build = f.id, error = %format!("{e:#}"), "streaming a build log");
                None
            }
        }
    })
    .flatten();
    let sse = Sse::new(events).keep_alive(KeepAlive::new().interval(STREAM_IDLE));
    Ok(([(axum::http::header::HeaderName::from_static("x-accel-buffering"), "no")], sse).into_response())
}

/// One client following one build's log.
struct LogStream {
    state: AppState,
    id: i64,
    /// The last chunk sent.
    last: i64,
    follower: crate::build::logs::LogFollower,
    done: bool,
}

impl LogStream {
    /// The next events: chunks after `last`, or `done`; waits for either.
    async fn next(&mut self) -> anyhow::Result<Vec<Event>> {
        let db = &self.state.auth.db;
        loop {
            // The status before the chunks: once a build has ended its log is complete, so
            // seeing it ended and then no new chunk means there are none to come.
            let (status, message) = db.build_status(self.id).await?.unwrap_or_else(|| ("deleted".into(), None));
            let chunks = db.build_log_chunks(self.id, self.last, STREAM_BATCH).await?;
            if let Some(c) = chunks.last() {
                self.last = c.seq;
                return chunks.iter().map(|c| Ok(Event::default().id(c.seq.to_string()).json_data(c)?)).collect();
            }
            if !matches!(status.as_str(), "queued" | "running") {
                self.done = true;
                return Ok(vec![Event::default().event("done").json_data(serde_json::json!({ "status": status, "message": message }))?]);
            }
            tokio::select! {
                _ = self.follower.changed() => {}
                _ = tokio::time::sleep(STREAM_IDLE) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn github_signature() {
        // Example from GitHub's documentation.
        let sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        assert!(super::github_signature_ok("It's a Secret to Everybody", b"Hello, World!", sig));
        assert!(!super::github_signature_ok("wrong", b"Hello, World!", sig));
    }
}
