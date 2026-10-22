//! Tag history and the Time Machine, tag expiration, and repository state.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use kontainer_core::perm::Action;
use crate::auth::{require, Principal};
use crate::database::tags::TagEvent;
use kontainer_core::digest::Digest;
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;


#[derive(Serialize)]
struct HistoryEntry {
    #[serde(flatten)]
    event: TagEvent,
    /// The tag can be put back to `previous` (deleted or moved within the window, image kept).
    is_restorable: bool,
}

#[derive(Serialize)]
struct History {
    time_machine_secs: i64,
    events: Vec<HistoryEntry>,
}

/// `GET .../history?tag=`: newest first.
pub async fn history(state: AppState, p: Principal, name: String, tag: Option<&str>) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let window = crate::tags::time_machine(&state, &name).await.map_err(RegistryError::internal)?;
    let since = chrono::Utc::now() - window;
    let can_write = p.allowed(Action::Push, &name);
    let events = state.auth.db.tag_events(&name, tag, 300).await?;
    // The tag's current digest, to hide "restore" when it already points there.
    let current: std::collections::HashMap<String, String> =
        state.storage.list_tags_resolved(&name).await?.into_iter().map(|t| (t.tag, t.digest.to_string())).collect();
    let mut out = vec![];
    for e in events {
        let is_restorable = can_write
            && e.at >= since
            && e.previous.as_ref().is_some_and(|prev| current.get(&e.tag) != Some(prev))
            && match e.previous.as_deref().and_then(|d| d.parse::<Digest>().ok()) {
                Some(d) => state.storage.has_manifest(&name, &d).await?,
                None => false,
            };
        out.push(HistoryEntry { event: e, is_restorable });
    }
    Ok(Json(History { time_machine_secs: window.num_seconds(), events: out }).into_response())
}

#[derive(Deserialize)]
struct RestoreBody {
    digest: String,
}

/// `POST .../tags/{tag}/restore {digest}`: point the tag back at an image it had.
pub async fn restore(state: AppState, p: Principal, name: String, tag: String, body: &[u8]) -> Result<Response> {
    require(&state, &p, Action::Push, &name)?;
    state.require_writable(&name).await?;
    if !kontainer_core::names::is_valid_tag(&tag) {
        return Err(RegistryError::bad_request("invalid tag"));
    }
    if state.tag_is_immutable(&name, &tag) && state.storage.resolve_tag(&name, &tag).await?.is_some() {
        return Err(RegistryError::conflict(format!("tag {tag} is immutable")));
    }
    let b: RestoreBody = serde_json::from_slice(body).map_err(|e| RegistryError::bad_request(format!("{e}")))?;
    let digest: Digest = b.digest.parse().map_err(|_| RegistryError::bad_request("invalid digest"))?;
    let window = crate::tags::time_machine(&state, &name).await.map_err(RegistryError::internal)?;
    let since = chrono::Utc::now() - window;
    let known = state.auth.db.tag_events(&name, Some(&tag), 1000).await?.iter().any(|e| e.at >= since && e.previous.as_deref() == Some(b.digest.as_str()));
    if !known {
        return Err(RegistryError::bad_request(format!("{tag} did not point at {} within the Time Machine window", digest)));
    }
    if !state.storage.has_manifest(&name, &digest).await? {
        return Err(RegistryError::new(Code::ManifestUnknown));
    }
    crate::tags::set(&state, &name, &tag, &digest, "restore", p.name()).await.map_err(RegistryError::internal)?;
    state.reindex(&name).await;
    state.audit.record(&p, "restore_tag", Some(&name), Some(&tag), Some(&digest.to_string()), None);
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct ExpirationBody {
    /// RFC 3339; `null` clears it.
    expires_at: Option<String>,
}

/// `PUT .../tags/{tag}/expiration {expires_at}`.
pub async fn set_expiration(state: AppState, p: Principal, name: String, tag: String, body: &[u8]) -> Result<Response> {
    require(&state, &p, Action::Push, &name)?;
    state.require_writable(&name).await?;
    if state.storage.resolve_tag(&name, &tag).await?.is_none() {
        return Err(RegistryError::new(Code::ManifestUnknown));
    }
    let b: ExpirationBody = serde_json::from_slice(body).map_err(|e| RegistryError::bad_request(format!("{e}")))?;
    let at = match b.expires_at.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => {
            let t = chrono::DateTime::parse_from_rfc3339(s).map_err(|_| RegistryError::bad_request("expires_at must be an RFC 3339 time"))?.to_utc();
            if t <= chrono::Utc::now() {
                return Err(RegistryError::bad_request("expires_at must be in the future"));
            }
            if state.tag_is_immutable(&name, &tag) {
                return Err(RegistryError::conflict(format!("tag {tag} is immutable")));
            }
            Some(t)
        }
        None => None,
    };
    state.auth.db.set_tag_expiration(&name, &tag, at, p.name()).await?;
    let at = at.map(|t| t.to_rfc3339());
    state.audit.record(&p, "tag_expiration", Some(&name), Some(&tag), None, Some(at.clone().unwrap_or_else(|| "cleared".into())));
    Ok(Json(serde_json::json!({ "expires_at": at })).into_response())
}

#[derive(Deserialize)]
struct StateBody {
    state: String,
    #[serde(default)]
    reason: Option<String>,
}

/// `GET|PUT .../state`: `normal`, `read_only` or `mirror`.
pub async fn repo_state(state: AppState, p: Principal, name: String, body: Option<&[u8]>) -> Result<Response> {
    match body {
        None => {
            require(&state, &p, Action::Pull, &name)?;
            let s = state.auth.db.repo_state(&name).await?;
            Ok(Json(serde_json::json!({ "state": s.as_ref().map(|s| s.state.as_str()).unwrap_or("normal"), "reason": s.as_ref().and_then(|s| s.reason.clone()), "set_by": s.as_ref().map(|s| s.set_by.clone()), "set_at": s.as_ref().map(|s| s.set_at.to_rfc3339()) })).into_response())
        }
        Some(body) => {
            require(&state, &p, Action::State, &name)?;
            let b: StateBody = serde_json::from_slice(body).map_err(|e| RegistryError::bad_request(format!("{e}")))?;
            if !matches!(b.state.as_str(), "normal" | "read_only" | "mirror") {
                return Err(RegistryError::bad_request("state: normal, read_only or mirror"));
            }
            let reason = b.reason.as_deref().map(str::trim).filter(|r| !r.is_empty()).map(|r| r.chars().take(200).collect::<String>());
            state.auth.db.set_repo_state(&name, &b.state, reason.as_deref(), p.name()).await?;
            state.audit.record(&p, "repo_state", Some(&name), None, None, Some(b.state.clone()));
            Ok(StatusCode::NO_CONTENT.into_response())
        }
    }
}
