//! Build runners: registering them, choosing whom they serve, and seeing how they are doing.
//!
//! **Shared** runners belong to the registry: superusers register them and assign them to every
//! namespace or to chosen ones. **Self-hosted** runners belong to one user or organization,
//! whose admins register them (unless `builds.self_hosted_runners` is off). A runner's token is
//! shown once, when it is registered or replaced.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;

use kontainer_core::names;
use crate::database::runners::Runner;
use kontainer_core::perm::Global;

use super::namespaces::require_ns_admin;
use crate::auth::Principal;
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/runners", get(list_shared).post(create))
        .route("/api/v1/runners/{id}", put(update).delete(delete))
        .route("/api/v1/runners/{id}/token", post(rotate))
        .route("/api/v1/namespaces/{ns}/runners", get(list_for_namespace))
}

/// A runner that asked for work this recently is online (runners ask every few seconds).
const ONLINE_SECS: i64 = 60;

fn enabled(state: &AppState) -> Result<()> {
    if state.config.builds.is_enabled { Ok(()) } else { Err(RegistryError::with_message(Code::Unsupported, "builds are disabled on this registry (builds.enabled)")) }
}

fn require_superuser(state: &AppState, p: &Principal) -> Result<()> {
    if p.has_global(Global::System) { Ok(()) } else { Err(state.auth.denied(p, None)) }
}

/// May `p` manage runner `r`?
async fn require_manager(state: &AppState, p: &Principal, r: &Runner) -> Result<()> {
    match &r.namespace {
        Some(ns) => require_ns_admin(state, p, ns).await,
        None => require_superuser(state, p),
    }
}

async fn view(state: &AppState, r: &Runner) -> Result<serde_json::Value> {
    let mut v = serde_json::to_value(r).unwrap_or_default();
    let seen = r.last_seen_at;
    v["status"] = match seen {
        Some(t) if (chrono::Utc::now() - t).num_seconds() < ONLINE_SECS => "online",
        Some(_) => "offline",
        None => "never",
    }
    .into();
    v["namespaces"] = if r.namespace.is_none() && !r.is_all_namespaces { state.auth.db.runner_namespaces(r.id).await?.into() } else { serde_json::Value::Null };
    Ok(v)
}

async fn views(state: &AppState, runners: &[Runner]) -> Result<Vec<serde_json::Value>> {
    let mut out = vec![];
    for r in runners {
        out.push(view(state, r).await?);
    }
    Ok(out)
}

/// Every runner, shared and self-hosted (superusers).
async fn list_shared(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    enabled(&state)?;
    require_superuser(&state, &p)?;
    Ok(Json(views(&state, &state.auth.db.runners().await?).await?).into_response())
}

/// A namespace's own runners and the shared ones serving it (its admins).
async fn list_for_namespace(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>) -> Result<Response> {
    enabled(&state)?;
    require_ns_admin(&state, &p, &ns).await?;
    let mut list = views(&state, &state.auth.db.runners_for(&ns).await?).await?;
    // Other namespaces a shared runner serves are none of this one's business.
    for v in &mut list {
        if v["namespace"].is_null() {
            v["namespaces"] = serde_json::Value::Null;
            v["hostname"] = serde_json::Value::Null;
        }
    }
    Ok(Json(serde_json::json!({ "runners": list, "self_hosted": state.config.builds.is_self_hosted_runners })).into_response())
}

#[derive(Deserialize)]
struct RunnerInput {
    name: String,
    /// Self-hosted, for this user or organization. Absent: shared.
    #[serde(default)]
    namespace: Option<String>,
    /// Shared: serve every namespace.
    #[serde(default)]
    all_namespaces: bool,
    /// Shared: the namespaces it serves, unless `all_namespaces`.
    #[serde(default)]
    namespaces: Vec<String>,
    #[serde(default = "yes")]
    is_enabled: bool,
}

fn yes() -> bool {
    true
}

fn check(i: &RunnerInput) -> Result<String> {
    let name = i.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return Err(RegistryError::bad_request("name: 1-64 characters"));
    }
    if i.namespaces.len() > 200 || i.namespaces.iter().any(|n| !names::is_valid_repository(n) || n.contains('/')) {
        return Err(RegistryError::bad_request("namespaces: user or organization names"));
    }
    Ok(name)
}

fn with_token(mut v: serde_json::Value, token: &str, state: &AppState) -> serde_json::Value {
    v["token"] = token.into(); // shown once
    v["server_url"] = state.auth.public_url.trim_end_matches('/').into();
    v
}

async fn create(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(i): Json<RunnerInput>) -> Result<Response> {
    enabled(&state)?;
    let name = check(&i)?;
    match i.namespace.as_deref() {
        Some(ns) => {
            require_ns_admin(&state, &p, ns).await?;
            if !state.config.builds.is_self_hosted_runners && !p.has_global(Global::System) {
                return Err(RegistryError::with_message(Code::Denied, "self-hosted runners are turned off on this registry: ask an administrator for a shared one"));
            }
        }
        None => require_superuser(&state, &p)?,
    }
    let token = format!("kr_{}", kontainer_core::random_token(24));
    let r = state.auth.db.create_runner(&name, i.namespace.as_deref(), i.all_namespaces, &token, p.name()).await?;
    if r.namespace.is_none() && !r.is_all_namespaces {
        state.auth.db.set_runner_namespaces(r.id, &i.namespaces).await?;
    }
    state.audit.record(&p, "runner_created", None, None, None, Some(format!("{name} ({})", i.namespace.as_deref().unwrap_or("shared"))));
    let v = view(&state, &r).await?;
    Ok((StatusCode::CREATED, Json(with_token(v, &token, &state))).into_response())
}

async fn runner_for(state: &AppState, p: &Principal, id: i64) -> Result<Runner> {
    enabled(state)?;
    let r = state.auth.db.runner(id).await?.ok_or_else(|| RegistryError::not_found("runner"))?;
    require_manager(state, p, &r).await?;
    Ok(r)
}

fn not_from_config(r: &Runner) -> Result<()> {
    if r.is_from_config { Err(RegistryError::with_message(Code::Conflict, "this runner is defined in the configuration file ([[builds.runners]])")) } else { Ok(()) }
}

async fn update(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(i): Json<RunnerInput>) -> Result<Response> {
    let r = runner_for(&state, &p, id).await?;
    not_from_config(&r)?;
    let name = check(&i)?;
    state.auth.db.update_runner(id, &name, i.is_enabled, i.all_namespaces).await?;
    if r.namespace.is_none() {
        state.auth.db.set_runner_namespaces(id, if i.all_namespaces { &[] } else { &i.namespaces }).await?;
    }
    state.audit.record(&p, "runner_updated", None, None, None, Some(name));
    let r = state.auth.db.runner(id).await?.ok_or_else(|| RegistryError::not_found("runner"))?;
    Ok(Json(view(&state, &r).await?).into_response())
}

async fn rotate(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let r = runner_for(&state, &p, id).await?;
    not_from_config(&r)?;
    let token = format!("kr_{}", kontainer_core::random_token(24));
    state.auth.db.set_runner_token(id, &token).await?;
    state.audit.record(&p, "runner_token", None, None, None, Some(r.name.clone()));
    Ok(Json(with_token(view(&state, &r).await?, &token, &state)).into_response())
}

async fn delete(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let r = runner_for(&state, &p, id).await?;
    not_from_config(&r)?;
    state.auth.db.delete_runner(id).await?;
    state.audit.record(&p, "runner_deleted", None, None, None, Some(r.name));
    Ok(StatusCode::NO_CONTENT.into_response())
}
