//! Keyless robot logins: manage a robot's trusted OIDC issuers, and exchange a CI OIDC token
//! for a short-lived robot token (`/oauth2/federation/robot/token`).

use axum::extract::{Extension, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::federation::{self, FederationRule};
use kontainer_core::perm::Global;
use crate::auth::{AuthMethod, Principal};
use crate::database::User;
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;

/// How long an exchanged token lives.
const EXCHANGED_TTL: chrono::Duration = chrono::Duration::hours(1);

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/robots/{id}/federation", get(get_rules).put(put_rules))
        .route("/api/v1/auth/federation/token", get(exchange).post(exchange))
        .route("/oauth2/federation/robot/token", get(exchange))
}


/// The robot, if the caller may manage it: its owner, an admin of its organization, or an
/// instance administrator.
async fn manageable_robot(state: &AppState, p: &Principal, id: i64) -> Result<User> {
    let robot = state.auth.db.user_by_id(id).await?.filter(|u| u.is_robot).ok_or_else(|| RegistryError::not_found("robot"))?;
    let allowed = p.has_global(Global::UsersWrite)
        || (robot.owner_id.is_some() && robot.owner_id == p.user_id)
        || match robot.org_id {
            Some(oid) => state.auth.db.org_by_id(oid).await?.is_some_and(|o| p.is_org_admin(&o.name)),
            None => false,
        };
    if !allowed || p.method == AuthMethod::Federated {
        return Err(state.auth.denied(p, None));
    }
    Ok(robot)
}

async fn get_rules(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let robot = manageable_robot(&state, &p, id).await?;
    Ok(Json(federation::rules(&state.auth.db, robot.id).await?).into_response())
}

#[derive(Deserialize)]
struct RulesBody {
    rules: Vec<FederationRule>,
}

async fn put_rules(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(body): Json<RulesBody>) -> Result<Response> {
    let robot = manageable_robot(&state, &p, id).await?;
    if body.rules.len() > 20 {
        return Err(RegistryError::bad_request("at most 20 rules"));
    }
    for r in &body.rules {
        let iss = r.issuer.trim();
        if !(iss.starts_with("https://") || iss.starts_with("http://localhost") || iss.starts_with("http://127.0.0.1")) || iss.len() > 300 {
            return Err(RegistryError::bad_request("issuer must be an https:// URL"));
        }
        let sub = r.subject.trim();
        if sub.is_empty() || sub.len() > 300 {
            return Err(RegistryError::bad_request("subject: 1-300 characters"));
        }
        // A bare `*` would let anyone the issuer serves (e.g. every GitHub repository) push.
        if sub.chars().all(|c| c == '*') {
            return Err(RegistryError::bad_request("subject must name something (a repository, project or branch), not just *"));
        }
    }
    federation::set_rules(&state.auth.db, robot.id, &body.rules).await?;
    state.audit.record(&p, "robot_federation", None, None, None, Some(format!("{}: {} rules", robot.username, body.rules.len())));
    Ok(Json(federation::rules(&state.auth.db, robot.id).await?).into_response())
}

/// Sign in as the robot with the OIDC token (Basic auth: robot name, token) and get a robot
/// access token valid for an hour.
async fn exchange(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    if p.method != AuthMethod::Federated {
        return Err(RegistryError::with_message(Code::Unauthorized, "authenticate with Basic auth: the robot name and an OIDC token from a trusted issuer")
            .header("WWW-Authenticate", "Basic realm=\"kontainer\""));
    }
    let uid = p.user_id.ok_or_else(|| state.auth.denied(&p, None))?;
    let expires = chrono::Utc::now() + EXCHANGED_TTL;
    let (token, _) = state.auth.create_access_token(uid, "oidc exchange", None, Some(expires)).await?;
    state.audit.record(&p, "robot_token_exchanged", None, None, None, None);
    Ok(Json(serde_json::json!({ "token": token, "username": p.name(), "expires_at": expires.to_rfc3339(), "expires_in": EXCHANGED_TTL.num_seconds() })).into_response())
}
