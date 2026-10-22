//! Security policies and CVE allowlists: per namespace (its admins), and the registry-wide
//! allowlist (instance administrators).

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Deserialize;

use crate::database::security::SecurityPolicyInput;
use kontainer_core::perm::Global;

use super::namespaces::require_ns_admin;
use crate::auth::{require_global, Principal};
use crate::error::{RegistryError, Result};
use crate::state::AppState;

const SEVERITIES: &[&str] = &["none", "critical", "high", "medium", "low", "negligible", "unknown"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/namespaces/{ns}/security", get(get_policy).put(put_policy))
        .route("/api/v1/namespaces/{ns}/cve-allowlist", get(list_ns).post(add_ns))
        .route("/api/v1/namespaces/{ns}/cve-allowlist/{id}", delete(remove_ns))
        .route("/api/v1/cve-allowlist", get(list_global).post(add_global))
        .route("/api/v1/cve-allowlist/{id}", delete(remove_global))
}

async fn get_policy(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    let policy = state.auth.db.security_policy(&ns).await?;
    let default = state.config.scanner.block_pull_at.map(|s| serde_json::to_value(s).unwrap_or_default());
    Ok(Json(serde_json::json!({
        "policy": policy,
        // What `block_severity: null` means here.
        "registry_block_severity": default,
        "scanner": state.scans.is_some(),
    }))
    .into_response())
}

async fn put_policy(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>, Json(mut body): Json<SecurityPolicyInput>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    if body.block_severity.as_deref().is_some_and(|s| !SEVERITIES.contains(&s)) {
        return Err(RegistryError::bad_request("block_severity: none, critical, high, medium, low, negligible or unknown (null: the registry default)"));
    }
    body.signing_keys = body.signing_keys.iter().map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect();
    if body.signing_keys.len() > 10 {
        return Err(RegistryError::bad_request("at most 10 signing keys"));
    }
    for (i, k) in body.signing_keys.iter().enumerate() {
        kontainer_core::artifact::parse_public_key(k).map_err(|e| RegistryError::bad_request(format!("signing key {}: {e}", i + 1)))?;
    }
    state.auth.db.set_security_policy(&ns, &body, p.name()).await?;
    state.audit.record_org(&p, "security_policy_changed", &ns, Some(format!("block {:?}, unscanned {}, signatures {}", body.block_severity, body.is_block_unscanned, body.is_require_signature)));
    get_policy(State(state), Extension(p), Path(ns)).await
}

#[derive(Deserialize)]
struct AllowBody {
    cve: String,
    #[serde(default)]
    reason: String,
    /// RFC 3339; `null` never.
    #[serde(default)]
    expires_at: Option<String>,
}

fn validate(b: &AllowBody) -> Result<()> {
    let cve = b.cve.trim();
    if cve.is_empty() || cve.len() > 64 || !cve.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')) {
        return Err(RegistryError::bad_request("cve: an identifier such as CVE-2024-1234 or GHSA-xxxx-xxxx-xxxx"));
    }
    if b.reason.len() > 500 {
        return Err(RegistryError::bad_request("reason: at most 500 characters"));
    }
    if expires_at(b)?.is_some_and(|t| t <= chrono::Utc::now()) {
        return Err(RegistryError::bad_request("expires_at must be in the future"));
    }
    Ok(())
}

fn expires_at(b: &AllowBody) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    b.expires_at.as_deref().map(|e| chrono::DateTime::parse_from_rfc3339(e).map(|t| t.to_utc()).map_err(|_| RegistryError::bad_request("expires_at: an RFC 3339 time"))).transpose()
}

async fn list_ns(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    Ok(Json(state.auth.db.cve_allowlist(Some(&ns)).await?).into_response())
}

async fn add_ns(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>, Json(b): Json<AllowBody>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    validate(&b)?;
    let row = state.auth.db.allow_cve(Some(&ns), b.cve.trim(), b.reason.trim(), expires_at(&b)?, p.name()).await?;
    state.audit.record_org(&p, "cve_allowed", &ns, Some(row.cve.clone()));
    Ok((StatusCode::CREATED, Json(row)).into_response())
}

async fn remove_ns(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    if !state.auth.db.disallow_cve(Some(&ns), id).await? {
        return Err(RegistryError::not_found("allowlist entry"));
    }
    state.audit.record_org(&p, "cve_disallowed", &ns, Some(format!("#{id}")));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn list_global(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    // Namespace admins see what the registry already allows, next to their own list.
    crate::auth::require_user(&state, &p)?;
    Ok(Json(state.auth.db.cve_allowlist(None).await?).into_response())
}

async fn add_global(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(b): Json<AllowBody>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    validate(&b)?;
    let row = state.auth.db.allow_cve(None, b.cve.trim(), b.reason.trim(), expires_at(&b)?, p.name()).await?;
    state.audit.record(&p, "cve_allowed", None, None, None, Some(format!("registry-wide: {}", row.cve)));
    Ok((StatusCode::CREATED, Json(row)).into_response())
}

async fn remove_global(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    if !state.auth.db.disallow_cve(None, id).await? {
        return Err(RegistryError::not_found("allowlist entry"));
    }
    state.audit.record(&p, "cve_disallowed", None, None, None, Some(format!("registry-wide #{id}")));
    Ok(StatusCode::NO_CONTENT.into_response())
}
