//! Namespace administration: storage usage, quotas and tag retention policies.
//!
//! A namespace is a user (`zack/`) or an organization (`acme/`). Members can see its storage;
//! its admins (org admins, or the user themselves) manage retention; quotas are set by instance
//! administrators.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use kontainer_core::perm::Global;
use crate::auth::Principal;
use crate::database::policies::{PolicyInput, RetentionPolicy};
use crate::error::{RegistryError, Result};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/storage", get(storage_report))
        .route("/api/v1/namespaces/{ns}/storage", get(namespace_storage))
        .route("/api/v1/namespaces/{ns}/quota", put(set_quota))
        .route("/api/v1/namespaces/{ns}/retention", get(list_policies).post(create_policy))
        .route("/api/v1/namespaces/{ns}/retention/{id}", put(update_policy).delete(delete_policy))
        .route("/api/v1/namespaces/{ns}/retention/{id}/preview", post(preview_policy))
        .route("/api/v1/namespaces/{ns}/retention/{id}/run", post(run_policy))
}



/// The namespace must be an organization or a user; returns whether it is an organization.
async fn namespace_kind(state: &AppState, ns: &str) -> Result<bool> {
    if state.auth.db.org_by_name(ns).await?.is_some() {
        return Ok(true);
    }
    match state.auth.db.user_by_name(ns).await? {
        Some(u) if !u.is_robot => Ok(false),
        _ => Err(RegistryError::not_found("namespace")),
    }
}

async fn require_member(state: &AppState, p: &Principal, ns: &str) -> Result<()> {
    let is_org = namespace_kind(state, ns).await?;
    let ok = p.has_global(Global::UsersRead) || if is_org { p.org_member(ns) } else { !p.is_robot && p.username.as_deref() == Some(ns) };
    if ok { Ok(()) } else { Err(state.auth.denied(p, None)) }
}

pub(crate) async fn require_ns_admin(state: &AppState, p: &Principal, ns: &str) -> Result<()> {
    let is_org = namespace_kind(state, ns).await?;
    let ok = p.has_global(Global::UsersWrite) || if is_org { p.is_org_admin(ns) } else { !p.is_robot && p.username.as_deref() == Some(ns) };
    if ok { Ok(()) } else { Err(state.auth.denied(p, None)) }
}

#[derive(Deserialize)]
struct RefreshQuery {
    #[serde(default)]
    refresh: Option<String>,
}

/// Whole-registry storage report (instance administrators).
async fn storage_report(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(q): Query<RefreshQuery>) -> Result<Response> {
    if !(p.has_global(Global::Gc) || p.has_global(Global::UsersRead)) {
        return Err(state.auth.denied(&p, None));
    }
    let report = state.usage_report(q.refresh.is_some()).await.map_err(RegistryError::internal)?;
    Ok(Json(report).into_response())
}

#[derive(Serialize)]
struct NamespaceStorage {
    namespace: String,
    bytes: u64,
    unique_bytes: u64,
    quota: Option<u64>,
    /// Where `quota` comes from: `namespace`, `default` or `none`.
    quota_source: &'static str,
    /// The configured default for this kind of namespace, if any.
    default_quota: Option<u64>,
    repositories: Vec<kontainer_store::usage::RepoUsage>,
    computed_at: String,
}

async fn namespace_storage(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>, Query(q): Query<RefreshQuery>) -> Result<Response> {
    require_member(&state, &p, &ns).await?;
    let is_org = namespace_kind(&state, &ns).await?;
    let report = state.usage_report(q.refresh.is_some()).await.map_err(RegistryError::internal)?;
    // The report may predate a quota change; read the live value.
    let quota = state.quota_for(&ns).await?;
    let n = report.namespaces.iter().find(|n| n.namespace == ns);
    Ok(Json(NamespaceStorage {
        namespace: ns.clone(),
        bytes: n.map_or(0, |n| n.bytes),
        unique_bytes: n.map_or(0, |n| n.unique_bytes),
        quota: quota.max_bytes,
        quota_source: quota.source,
        default_quota: state.default_quota(is_org),
        repositories: report.repositories.iter().filter(|r| r.namespace == ns).cloned().collect(),
        computed_at: report.computed_at.clone(),
    })
    .into_response())
}

#[derive(Deserialize)]
struct QuotaBody {
    /// `null`: back to the default. `0`: no limit, even when there is a default.
    max_bytes: Option<u64>,
}

async fn set_quota(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>, Json(body): Json<QuotaBody>) -> Result<Response> {
    namespace_kind(&state, &ns).await?;
    if !p.has_global(Global::UsersWrite) {
        return Err(state.auth.denied(&p, None));
    }
    state.auth.db.set_quota(&ns, body.max_bytes).await?;
    let change = match body.max_bytes { None => "default".into(), Some(0) => "unlimited".into(), Some(b) => kontainer_store::usage::human(b) };
    state.audit.record_org(&p, "quota_changed", &ns, Some(change));
    Ok(Json(serde_json::json!({ "namespace": ns, "max_bytes": body.max_bytes })).into_response())
}

fn validate(p: &PolicyInput) -> Result<()> {
    if p.keep_last.is_none() && p.max_age_days.is_none() {
        return Err(RegistryError::bad_request("set keep_last, max_age_days, or both"));
    }
    if p.keep_last.is_some_and(|n| n < 1) || p.max_age_days.is_some_and(|d| d < 1) {
        return Err(RegistryError::bad_request("keep_last and max_age_days must be at least 1"));
    }
    if p.repositories.trim().is_empty() || p.repositories.starts_with('/') || p.repositories.contains("..") {
        return Err(RegistryError::bad_request("repositories is a pattern relative to the namespace, e.g. `**` or `api/*`"));
    }
    Ok(())
}

async fn list_policies(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>) -> Result<Response> {
    require_member(&state, &p, &ns).await?;
    Ok(Json(state.auth.db.retention_policies(Some(&ns)).await?).into_response())
}

async fn create_policy(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>, Json(body): Json<PolicyInput>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    validate(&body)?;
    let policy = state.auth.db.create_retention_policy(&ns, &body).await?;
    state.audit.record_org(&p, "retention_created", &ns, Some(format!("#{}", policy.id)));
    Ok((StatusCode::CREATED, Json(policy)).into_response())
}

async fn policy_in(state: &AppState, ns: &str, id: i64) -> Result<RetentionPolicy> {
    match state.auth.db.retention_policy(id).await? {
        Some(p) if p.namespace == ns => Ok(p),
        _ => Err(RegistryError::not_found("retention policy")),
    }
}

async fn update_policy(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>, Json(body): Json<PolicyInput>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    policy_in(&state, &ns, id).await?;
    validate(&body)?;
    state.auth.db.update_retention_policy(id, &body).await?;
    state.audit.record_org(&p, "retention_updated", &ns, Some(format!("#{id}")));
    Ok(Json(policy_in(&state, &ns, id).await?).into_response())
}

async fn delete_policy(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    policy_in(&state, &ns, id).await?;
    state.auth.db.delete_retention_policy(id).await?;
    state.audit.record_org(&p, "retention_deleted", &ns, Some(format!("#{id}")));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// What the policy would delete right now, without deleting anything.
async fn preview_policy(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    let policy = policy_in(&state, &ns, id).await?;
    Ok(Json(crate::retention::preview(&state, &policy).await.map_err(RegistryError::internal)?).into_response())
}

async fn run_policy(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    let policy = policy_in(&state, &ns, id).await?;
    if !state.config.features.is_delete {
        return Err(RegistryError::bad_request("deletion is disabled on this registry (features.delete)"));
    }
    Ok(Json(crate::retention::run(&state, &policy, &p).await.map_err(RegistryError::internal)?).into_response())
}
