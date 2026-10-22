//! Push replication rules (instance administrators, like the registries they push to).

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::database::replication::{ReplicationInput, ReplicationRule};
use kontainer_core::perm::Global;

use crate::auth::{require_global, Principal};
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/replication-rules", get(list).post(create))
        .route("/api/v1/replication-rules/{id}", put(update).delete(delete))
        .route("/api/v1/replication-rules/{id}/run", post(run_now))
        .route("/api/v1/replication-rules/{id}/runs", get(runs))
}

async fn validate(state: &AppState, i: &mut ReplicationInput) -> Result<()> {
    if i.name.trim().is_empty() || i.name.len() > 64 {
        return Err(RegistryError::bad_request("name: 1 to 64 characters"));
    }
    if state.auth.db.registry(i.registry_id).await?.is_none() {
        return Err(RegistryError::bad_request("registry_id: no such registry (add it under Registries first)"));
    }
    i.repositories.retain(|r| !r.trim().is_empty());
    if i.repositories.is_empty() {
        i.repositories = vec!["**".into()];
    }
    if i.repositories.len() > 20 || i.tags.len() > 20 {
        return Err(RegistryError::bad_request("at most 20 repository and 20 tag patterns"));
    }
    let dest = i.destination.trim().trim_matches('/');
    if !dest.is_empty() && !kontainer_core::names::is_valid_repository(dest) {
        return Err(RegistryError::bad_request("destination: a namespace or path like `mirror` or `dr/eu`"));
    }
    match i.trigger.as_str() {
        "push" | "manual" => i.interval_secs = None,
        "schedule" => {
            if i.interval_secs.is_none_or(|s| s < 300) {
                return Err(RegistryError::bad_request("interval_secs: at least 300 for a scheduled rule"));
            }
        }
        _ => return Err(RegistryError::bad_request("trigger: push, schedule or manual")),
    }
    Ok(())
}

async fn rule(state: &AppState, id: i64) -> Result<ReplicationRule> {
    state.auth.db.replication_rule(id).await?.ok_or_else(|| RegistryError::not_found("replication rule"))
}

async fn list(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    Ok(Json(state.auth.db.replication_rules().await?).into_response())
}

async fn create(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(mut i): Json<ReplicationInput>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    validate(&state, &mut i).await?;
    let r = state.auth.db.create_replication_rule(&i, p.name()).await?;
    state.audit.record(&p, "replication_rule_created", None, None, None, Some(r.name.clone()));
    Ok((StatusCode::CREATED, Json(r)).into_response())
}

async fn update(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(mut i): Json<ReplicationInput>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    rule(&state, id).await?;
    validate(&state, &mut i).await?;
    state.auth.db.update_replication_rule(id, &i).await?;
    state.audit.record(&p, "replication_rule_updated", None, None, None, Some(i.name.clone()));
    Ok(Json(rule(&state, id).await?).into_response())
}

async fn delete(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let r = rule(&state, id).await?;
    state.auth.db.delete_replication_rule(id).await?;
    state.audit.record(&p, "replication_rule_deleted", None, None, None, Some(r.name));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Replicate everything the rule covers, in the background; the run shows in its history.
async fn run_now(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let r = rule(&state, id).await?;
    if !r.is_enabled {
        return Err(RegistryError::with_message(Code::Conflict, "the rule is paused"));
    }
    let actor = p.name().to_string();
    let st = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::replicate::run(&st, &r, "manual", &actor, None).await {
            tracing::warn!(rule = r.id, error = %format!("{e:#}"), "replication failed");
        }
    });
    Ok(StatusCode::ACCEPTED.into_response())
}

async fn runs(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    rule(&state, id).await?;
    Ok(Json(state.auth.db.task_runs(&format!("replication/{id}"), 50).await?).into_response())
}
