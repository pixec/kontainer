//! Namespace webhooks: managed by the namespace's admins (org admins, or the user themselves).

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::database::webhooks::{Webhook, WebhookInput};

use super::namespaces::require_ns_admin;
use crate::auth::Principal;
use crate::error::{RegistryError, Result};
use crate::state::AppState;
use crate::webhook::{check_target, EVENTS, FORMATS};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/webhook-events", get(event_list))
        .route("/api/v1/namespaces/{ns}/webhooks", get(list).post(create))
        .route("/api/v1/namespaces/{ns}/webhooks/{id}", put(update).delete(delete))
        .route("/api/v1/namespaces/{ns}/webhooks/{id}/test", post(test))
        .route("/api/v1/namespaces/{ns}/webhooks/{id}/deliveries", get(deliveries))
        .route("/api/v1/namespaces/{ns}/webhooks/{id}/deliveries/{delivery}/redeliver", post(redeliver))
}

/// What hooks can subscribe to and the formats they can use, for the UI.
async fn event_list() -> Response {
    Json(serde_json::json!({ "events": EVENTS, "formats": FORMATS })).into_response()
}

async fn view(state: &AppState, h: &Webhook) -> Result<serde_json::Value> {
    let mut v = serde_json::to_value(h).unwrap_or_default();
    v["has_secret"] = h.secret.is_some().into();
    v["has_auth_header"] = h.auth_header.is_some().into();
    let last = state.auth.db.deliveries(h.id, 1).await?.into_iter().next();
    v["last_delivery"] = last.map(|d| serde_json::json!({ "status": d.status, "event": d.event, "response_code": d.response_code, "at": d.delivered_at.unwrap_or(d.created_at).to_rfc3339() })).into();
    Ok(v)
}

async fn validate(state: &AppState, i: &WebhookInput) -> Result<()> {
    let bad = |m: &str| Err(RegistryError::bad_request(m.to_string()));
    if i.name.trim().is_empty() || i.name.len() > 64 {
        return bad("name: 1 to 64 characters");
    }
    if !FORMATS.contains(&i.format.as_str()) {
        return bad("format must be default, cloudevents or slack");
    }
    if let Some(e) = i.events.iter().find(|e| !EVENTS.contains(&e.as_str())) {
        return Err(RegistryError::bad_request(format!("unknown event `{e}`")));
    }
    if i.repositories.len() > 20 || i.repositories.iter().any(|r| r.is_empty() || r.len() > 200) {
        return bad("at most 20 repository patterns");
    }
    if i.secret.as_deref().is_some_and(|s| s.len() > 256) || i.auth_header.as_deref().is_some_and(|s| s.len() > 1024) {
        return bad("secret or authorization header too long");
    }
    let url = url::Url::parse(i.url.trim()).map_err(|_| RegistryError::bad_request("url: not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return bad("url: only http:// and https://");
    }
    // Say now, not at the first delivery, when the target is off limits.
    if !state.config.policy.is_webhooks_allow_private_targets {
        check_target(i.url.trim()).await.map_err(|e| RegistryError::bad_request(format!("url: {e:#}")))?;
    }
    Ok(())
}

async fn hook_in(state: &AppState, ns: &str, id: i64) -> Result<Webhook> {
    state.auth.db.webhook(id).await?.filter(|h| h.namespace == ns).ok_or_else(|| RegistryError::not_found("webhook"))
}

async fn list(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    let mut out = vec![];
    for h in state.auth.db.webhooks(&ns).await? {
        out.push(view(&state, &h).await?);
    }
    Ok(Json(out).into_response())
}

async fn create(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>, Json(i): Json<WebhookInput>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    validate(&state, &i).await?;
    let h = state.auth.db.create_webhook(&ns, &i, p.name()).await?;
    state.webhooks.reload().await?;
    state.audit.record_org(&p, "webhook_created", &ns, Some(format!("{} → {}", h.name, h.url)));
    Ok((StatusCode::CREATED, Json(view(&state, &h).await?)).into_response())
}

async fn update(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>, Json(i): Json<WebhookInput>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    hook_in(&state, &ns, id).await?;
    validate(&state, &i).await?;
    state.auth.db.update_webhook(id, &i).await?;
    state.webhooks.reload().await?;
    state.audit.record_org(&p, "webhook_updated", &ns, Some(i.name.clone()));
    let h = hook_in(&state, &ns, id).await?;
    Ok(Json(view(&state, &h).await?).into_response())
}

async fn delete(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    let h = hook_in(&state, &ns, id).await?;
    state.auth.db.delete_webhook(id).await?;
    state.webhooks.reload().await?;
    state.audit.record_org(&p, "webhook_deleted", &ns, Some(h.name));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn test(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    let h = hook_in(&state, &ns, id).await?;
    let d = state.webhooks.test(&h, p.name()).await.map_err(RegistryError::internal)?;
    Ok(Json(d).into_response())
}

async fn deliveries(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id)): Path<(String, i64)>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    hook_in(&state, &ns, id).await?;
    Ok(Json(state.auth.db.deliveries(id, 50).await?).into_response())
}

async fn redeliver(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((ns, id, delivery)): Path<(String, i64, i64)>) -> Result<Response> {
    require_ns_admin(&state, &p, &ns).await?;
    let h = hook_in(&state, &ns, id).await?;
    let past = state.auth.db.delivery(delivery).await?.filter(|d| d.webhook_id == id).ok_or_else(|| RegistryError::not_found("delivery"))?;
    let d = state.webhooks.redeliver(&h, &past).await.map_err(RegistryError::internal)?;
    Ok(Json(d).into_response())
}
