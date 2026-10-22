//! The runner protocol (see `kontainer_core::build::protocol`). Mounted outside the registry's
//! auth layer: runners claim builds with their own token, then use the build's token.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use futures::TryStreamExt;
use tokio::io::AsyncWriteExt;

use kontainer_core::build::protocol::{CheckIn, CheckInReply, ClaimRequest, Claimed, Commit, CommitReply, Finish, ImageReply, BASE};
use crate::database::builds::{Build, LogInput};
use crate::database::runners::RunnerReport;

use crate::build;
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(&format!("{BASE}/claim"), post(claim))
        .route(&format!("{BASE}/builds/{{id}}"), get(spec))
        .route(&format!("{BASE}/builds/{{id}}/log"), post(checkin))
        .route(&format!("{BASE}/builds/{{id}}/heartbeat"), post(heartbeat))
        .route(&format!("{BASE}/builds/{{id}}/commit"), post(commit))
        .route(&format!("{BASE}/builds/{{id}}/image"), put(image).layer(axum::extract::DefaultBodyLimit::disable()))
        .route(&format!("{BASE}/builds/{{id}}/finish"), post(finish))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(str::trim).filter(|t| !t.is_empty())
}

fn unauthorized() -> RegistryError {
    RegistryError::with_message(Code::Unauthorized, "invalid runner or build token")
}

/// The running build `id`, if `headers` carry its token.
async fn running(state: &AppState, id: i64, headers: &HeaderMap) -> Result<Build> {
    if !state.config.builds.is_enabled {
        return Err(RegistryError::with_message(Code::Unsupported, "builds are disabled on this registry"));
    }
    let token = bearer(headers).ok_or_else(unauthorized)?;
    let b = state.auth.db.build(id).await?.ok_or_else(unauthorized)?;
    if b.agent_token_hash.as_deref() != Some(crate::database::sha256_hex(token).as_str()) {
        return Err(unauthorized());
    }
    if b.status != "running" {
        return Err(RegistryError::with_message(Code::Conflict, format!("build #{id} is {}", b.status)));
    }
    Ok(b)
}

/// What a runner says about itself: shown in the UI, so keep it short and plain.
fn clean(raw: &str) -> String {
    raw.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+')).take(64).collect()
}

/// A runner asks for work: the next queued build of a namespace it serves, if any. Every claim
/// also reports the runner's state, so it doubles as its heartbeat.
async fn claim(State(state): State<AppState>, headers: HeaderMap, Json(req): Json<ClaimRequest>) -> Result<Response> {
    if !state.config.builds.is_enabled {
        return Err(RegistryError::with_message(Code::Unsupported, "builds are disabled on this registry"));
    }
    let runner = state.auth.db.runner_by_token(bearer(&headers).ok_or_else(unauthorized)?).await?.ok_or_else(unauthorized)?;
    let (hostname, version, executor) = (clean(&req.hostname), clean(&req.version), clean(&req.executor));
    let report = RunnerReport { hostname: &hostname, version: &version, executor: &executor, concurrency: req.concurrency as i64, running: req.running as i64 };
    state.auth.db.runner_seen(runner.id, &report).await?;
    let scope = state.auth.db.runner_scope(&runner).await?;
    if req.report_only || scope.as_ref().is_some_and(Vec::is_empty) {
        return Ok(StatusCode::NO_CONTENT.into_response()); // assigned to no namespace yet
    }
    let (token, hash) = build::new_token();
    let agent = if hostname.is_empty() { runner.name.clone() } else { format!("{} ({hostname})", runner.name) };
    match state.auth.db.claim_build(Some(runner.id), &agent, &hash, scope.as_deref(), state.config.builds.max_per_namespace).await? {
        Some(id) => {
            tracing::info!(build = id, runner = %runner.name, "build claimed");
            Ok(Json(Claimed { id, token: token.into() }).into_response())
        }
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

/// A runner that started the build elsewhere (a container, a Job) keeps it alive while that
/// starts, before it checks in itself.
async fn heartbeat(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> Result<Response> {
    let stop = match running(&state, id, &headers).await {
        Ok(_) => {
            state.auth.db.touch_build(id).await?;
            state.auth.db.build(id).await?.is_none_or(|b| b.is_cancel_requested)
        }
        Err(e) if e.code == Code::Conflict => true,
        Err(e) => return Err(e),
    };
    Ok(Json(CheckInReply { stop, ..Default::default() }).into_response())
}

async fn spec(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> Result<Response> {
    let b = running(&state, id, &headers).await?;
    match build::spec(&state, &b).await {
        Ok(spec) => Ok(Json(spec).into_response()),
        Err(e) => {
            // Nothing an agent can do about it.
            let msg = format!("{e:#}");
            build::end(&state, id, "failed", &msg, Some(&format!("==> {msg}"))).await?;
            Err(RegistryError::with_message(Code::Conflict, msg))
        }
    }
}

/// The check-in: the heartbeat, and the log from where the server's copy ends.
async fn checkin(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, Json(c): Json<CheckIn>) -> Result<Response> {
    let reply = match running(&state, id, &headers).await {
        Ok(_) => append(&state, id, &c).await?,
        // Over already (cancelled, or failed for going quiet): tell the agent to stop.
        Err(e) if e.code == Code::Conflict => CheckInReply { stop: true, ..Default::default() },
        Err(e) => return Err(e),
    };
    Ok(Json(reply).into_response())
}

async fn append(state: &AppState, id: i64, c: &CheckIn) -> Result<CheckInReply> {
    let input = match &c.log {
        Some(whole) => LogInput::Whole(whole),
        None => LogInput::At { offset: c.offset, data: &c.data, tail: c.tail },
    };
    let a = state.auth.db.append_build_log(id, input, state.config.builds.max_log_bytes).await?;
    Ok(CheckInReply { stop: a.stop, length: a.length, truncated: a.truncated })
}

async fn commit(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, Json(c): Json<Commit>) -> Result<Response> {
    let b = running(&state, id, &headers).await?;
    let tags = build::commit(&state, &b, &c.sha).await.map_err(|e| RegistryError::bad_request(format!("{e:#}")))?;
    Ok(Json(CommitReply { tags }).into_response())
}

/// Largest image archive a build may upload, unless `server.max_blob_size` is larger (an
/// archive holds every layer, so it may be bigger than the largest single blob).
const MAX_IMAGE_ARCHIVE_BYTES: u64 = 8 << 30;

async fn image(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, body: axum::body::Body) -> Result<Response> {
    let b = running(&state, id, &headers).await?;
    let limit = state.config.server.max_blob_bytes().map_or(MAX_IMAGE_ARCHIVE_BYTES, |m| m.max(MAX_IMAGE_ARCHIVE_BYTES));
    let declared = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    let archive = state.storage.uploads.temp_path().await?;
    let outcome = async {
        if declared.is_some_and(|n| n > limit) {
            anyhow::bail!("the image archive is larger than the {limit} bytes allowed");
        }
        let mut file = tokio::fs::File::create(&archive).await?;
        let mut stream = body.into_data_stream();
        let mut size = 0u64;
        while let Some(chunk) = stream.try_next().await? {
            size += chunk.len() as u64;
            if size > limit {
                anyhow::bail!("the image archive is larger than the {limit} bytes allowed");
            }
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        // Quota: the archive's size bounds what it can add, as for an archive import.
        if let Some(q) = state.quota_check(&b.repository).await? {
            state.admit_write(&q, &b.repository, vec![], size, &format!("build #{}", b.id)).await?;
        }
        build::import(&state, &b, &archive).await
    }
    .await;
    let _ = tokio::fs::remove_file(&archive).await;
    // The runner checked in the log up to the upload; the outcome ends it.
    match outcome {
        Ok(summary) => {
            build::finish(&state, id, Ok(summary.clone())).await;
            Ok(Json(ImageReply { summary }).into_response())
        }
        Err(e) => {
            let msg = format!("Couldn't import the image: {e:#}");
            build::finish(&state, id, Err(anyhow::anyhow!(msg.clone()))).await;
            Err(RegistryError::bad_request(msg))
        }
    }
}

async fn finish(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>, Json(f): Json<Finish>) -> Result<Response> {
    running(&state, id, &headers).await?;
    let status = if f.status == "cancelled" { "cancelled" } else { "failed" };
    let message: String = f.message.chars().take(2000).collect();
    // An older runner sends its whole log here: keep what we lack of it first.
    if let Some(log) = &f.log {
        state.auth.db.append_build_log(id, LogInput::Whole(log), state.config.builds.max_log_bytes).await?;
    }
    let line = f.line.as_deref().map(|l| l.chars().take(2000).collect::<String>());
    build::end(&state, id, status, &message, line.as_deref()).await?;
    Ok(Json(serde_json::json!({})).into_response())
}

#[cfg(test)]
mod tests {
    #[test]
    fn runner_reports() {
        assert_eq!(super::clean("ci-runner-1.example.com"), "ci-runner-1.example.com");
        assert_eq!(super::clean("<script>"), "script");
        assert_eq!(super::clean("0.2.0+abc"), "0.2.0+abc");
    }
}
