//! Administration: users, roles and the permission catalogue.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::database::User;
use kontainer_core::perm::{valid_role_name, valid_username, Action, Global, Role, Rule};
use crate::auth::{require_global, Principal};
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/permissions", get(permissions))
        .route("/api/v1/roles", get(list_roles).post(create_role))
        .route("/api/v1/roles/{name}", get(get_role).put(update_role).delete(delete_role))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{id}", get(get_user).patch(update_user).delete(delete_user))
        .route("/api/v1/users/{id}/password", axum::routing::post(reset_password))
        .route("/api/v1/users/{id}/mfa", axum::routing::delete(reset_mfa))
        .route("/api/v1/users/{id}/sessions", axum::routing::delete(revoke_sessions))
        .route("/api/v1/admin/scanning", get(scanning_status))
        .route("/api/v1/admin/scanning/override", axum::routing::post(scanning_override))
}

// Scan budget
/// The automatic-scan budget and the queue, cluster-wide (skips also for this instance).
#[derive(Serialize)]
struct ScanningStatus {
    /// A scanner is configured.
    enabled: bool,
    /// `scanner.max_auto_per_hour`; 0: unlimited.
    limit: u64,
    /// Automatic scans queued in the current window.
    used: i64,
    /// When the current window ends (`None`: no window open, the full budget is available).
    window_resets_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Scans skipped (budget spent or queue full) in the current window, on every instance.
    skipped_in_window: i64,
    /// Scans this instance skipped since it started, by reason (`budget`, `queue_full`).
    skipped_since_start: std::collections::BTreeMap<&'static str, u64>,
    /// Scans waiting or running.
    queue_depth: i64,
    /// `scanner.max_queue`; 0: unlimited.
    max_queue: u64,
    /// The budget is lifted until then, by whom.
    override_until: Option<chrono::DateTime<chrono::Utc>>,
    override_by: Option<String>,
}

async fn scanning_status(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    require_global(&state, &p, Global::Gc)?;
    let row = state.auth.db.scan_budget().await?;
    let budget = state.scans.as_ref().map(|q| q.budget).unwrap_or_else(|| crate::scan::queue::Budget::from_config(&state.config.scanner));
    Ok(Json(ScanningStatus {
        enabled: state.scans.is_some(),
        limit: budget.per_hour,
        used: row.used,
        window_resets_at: row.window_start.map(|t| t + chrono::Duration::hours(1)),
        skipped_in_window: row.skipped,
        skipped_since_start: crate::metrics::global().scans_skipped(),
        queue_depth: state.auth.db.scan_queue_depth().await?,
        max_queue: budget.max_queue,
        override_until: row.override_until,
        override_by: row.override_by,
    })
    .into_response())
}

#[derive(Deserialize)]
struct OverrideBody {
    /// Lift the budget for this many hours from now; 0 ends an override.
    hours: u32,
}

/// Lift the automatic-scan budget for a while (e.g. to rescan everything after a scanner
/// database update). `scanner.max_queue` still applies.
async fn scanning_override(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<OverrideBody>) -> Result<Response> {
    require_global(&state, &p, Global::Gc)?;
    if body.hours > 24 * 31 {
        return Err(RegistryError::bad_request("hours: at most 744 (31 days)"));
    }
    let until = state.auth.db.override_scan_budget(body.hours, p.name()).await?;
    let detail = match until {
        Some(t) => format!("scan budget lifted for {}h, until {}", body.hours, t.to_rfc3339()),
        None => "scan budget override ended".to_string(),
    };
    state.audit.record(&p, "scan_budget_override", None, None, None, Some(detail));
    Ok(Json(serde_json::json!({ "override_until": until })).into_response())
}



async fn permissions() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "actions": Action::ALL.iter().map(|a| serde_json::json!({ "name": a.as_str(), "description": a.describe() })).collect::<Vec<_>>(),
        "global": Global::ALL.iter().map(|g| serde_json::json!({ "name": g.as_str(), "description": g.describe() })).collect::<Vec<_>>(),
    }))
}

async fn list_roles(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    // Any signed-in user may see role names (needed to create robots); details need users:read.
    let roles = state.auth.db.list_roles().await?;
    if p.has_global(Global::UsersRead) || p.has_global(Global::RolesWrite) {
        return Ok(Json(roles).into_response());
    }
    let mine: Vec<&Role> = roles.iter().filter(|r| p.roles.iter().any(|m| m.name == r.name)).collect();
    Ok(Json(mine).into_response())
}

async fn get_role(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    require_global(&state, &p, Global::UsersRead)?;
    Ok(Json(state.auth.db.get_role(&name).await?.ok_or_else(|| RegistryError::not_found("role"))?).into_response())
}

#[derive(Deserialize)]
struct RoleBody {
    name: Option<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    global: Vec<Global>,
}

fn validate_rules(rules: &[Rule]) -> Result<()> {
    for r in rules {
        if r.repositories.is_empty() || r.actions.is_empty() {
            return Err(RegistryError::bad_request("each rule needs at least one repository pattern and one action"));
        }
    }
    Ok(())
}

/// Nobody can hand out permissions they do not hold themselves.
fn check_escalation(p: &Principal, role: &Role) -> Result<()> {
    if p.is_admin() {
        return Ok(());
    }
    for g in &role.global {
        if !p.has_global(*g) {
            return Err(RegistryError::bad_request(format!("you cannot grant `{}`", g.as_str())));
        }
    }
    for r in &role.rules {
        for repo in &r.repositories {
            for a in &r.actions {
                // The pattern itself must be covered: `team-a/**` needs a pattern of ours that
                // matches every name it could (see `kontainer_core::perm::covers`).
                if !p.covers(*a, repo) {
                    return Err(RegistryError::bad_request(format!("you cannot grant `{}` on `{repo}`", a.as_str())));
                }
            }
        }
    }
    Ok(())
}

/// Managing another account (changing, disabling or deleting it, resetting its password or
/// MFA, signing it out) is as good as holding its roles, so it needs everything they grant.
async fn check_target(state: &AppState, p: &Principal, target: &User) -> Result<()> {
    if p.is_admin() {
        return Ok(());
    }
    let known = state.auth.roles().await;
    for name in state.auth.db.user_roles(target.id).await? {
        if let Some(role) = known.get(&name) {
            check_escalation(p, role).map_err(|_| RegistryError::with_message(Code::Denied, format!("{} has role `{name}`, which grants more than you hold", target.username)))?;
        }
    }
    Ok(())
}

async fn create_role(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<RoleBody>) -> Result<Response> {
    require_global(&state, &p, Global::RolesWrite)?;
    let name = body.name.unwrap_or_default();
    if !valid_role_name(&name) {
        return Err(RegistryError::bad_request("invalid role name"));
    }
    if state.auth.db.get_role(&name).await?.is_some() {
        return Err(RegistryError::conflict("role already exists"));
    }
    validate_rules(&body.rules)?;
    let role = Role { name, description: body.description, rules: body.rules, global: body.global, is_managed: false };
    check_escalation(&p, &role)?;
    state.auth.db.upsert_role(&role).await?;
    state.auth.reload_roles().await?;
    state.audit.record(&p, "role_created", None, None, None, Some(role.name.clone()));
    Ok((StatusCode::CREATED, Json(role)).into_response())
}

async fn update_role(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>, Json(body): Json<RoleBody>) -> Result<Response> {
    require_global(&state, &p, Global::RolesWrite)?;
    let existing = state.auth.db.get_role(&name).await?.ok_or_else(|| RegistryError::not_found("role"))?;
    if existing.is_managed {
        return Err(RegistryError::bad_request("this role is defined in the configuration file"));
    }
    validate_rules(&body.rules)?;
    let role = Role { name: name.clone(), description: body.description, rules: body.rules, global: body.global, is_managed: false };
    check_escalation(&p, &role)?;
    state.auth.db.upsert_role(&role).await?;
    state.auth.reload_roles().await?;
    state.audit.record(&p, "role_updated", None, None, None, Some(name));
    Ok(Json(role).into_response())
}

async fn delete_role(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    require_global(&state, &p, Global::RolesWrite)?;
    let existing = state.auth.db.get_role(&name).await?.ok_or_else(|| RegistryError::not_found("role"))?;
    if existing.is_managed {
        return Err(RegistryError::bad_request("this role is defined in the configuration file"));
    }
    state.auth.db.delete_role(&name).await?;
    state.auth.reload_roles().await?;
    state.audit.record(&p, "role_deleted", None, None, None, Some(name));
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Serialize)]
struct UserView {
    #[serde(flatten)]
    user: User,
    roles: Vec<String>,
    identities: Vec<String>,
    owner: Option<String>,
}

async fn view(state: &AppState, u: User) -> Result<UserView> {
    let roles = state.auth.db.user_roles(u.id).await?;
    let identities = state.auth.db.user_identities(u.id).await?.into_iter().map(|i| i.provider).collect();
    let owner = match u.owner_id {
        Some(o) => state.auth.db.user_by_id(o).await?.map(|o| o.username),
        None => None,
    };
    Ok(UserView { user: u, roles, identities, owner })
}

async fn list_users(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    require_global(&state, &p, Global::UsersRead)?;
    let mut out = vec![];
    for u in state.auth.db.list_users().await? {
        out.push(view(&state, u).await?);
    }
    Ok(Json(out).into_response())
}

async fn get_user(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersRead)?;
    let u = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    Ok(Json(view(&state, u).await?).into_response())
}

#[derive(Deserialize)]
struct CreateUserBody {
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    is_robot: bool,
}

async fn check_roles_exist(state: &AppState, p: &Principal, roles: &[String]) -> Result<()> {
    let known = state.auth.roles().await;
    for r in roles {
        let Some(role) = known.get(r) else { return Err(RegistryError::bad_request(format!("unknown role `{r}`"))) };
        check_escalation(p, role).map_err(|_| RegistryError::bad_request(format!("you cannot assign `{r}`: it grants more than you hold")))?;
    }
    Ok(())
}

async fn create_user(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<CreateUserBody>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    if !valid_username(&body.username) {
        return Err(RegistryError::bad_request("invalid username (letters, digits, `-`, `_`, `.`; robots as `owner+name`)"));
    }
    if state.auth.db.name_taken(&body.username).await? {
        return Err(RegistryError::conflict("that name is already used by a user or organization"));
    }
    check_roles_exist(&state, &p, &body.roles).await?;
    let hash = match &body.password {
        Some(pw) if !body.is_robot => {
            crate::auth::password::check_strength(pw).map_err(RegistryError::bad_request)?;
            Some(crate::auth::password::hash_async(pw).await.map_err(RegistryError::internal)?)
        }
        _ => None,
    };
    let owner = if body.is_robot { body.username.split_once('+').map(|(o, _)| o.to_string()) } else { None };
    let owner_id = match owner {
        Some(o) => state.auth.db.user_by_name(&o).await?.map(|u| u.id),
        None => None,
    };
    let u = state.auth.db.create_user(&body.username, hash.as_deref(), body.email.as_deref(), body.display_name.as_deref(), body.is_robot, owner_id, false).await?;
    state.auth.db.set_user_roles(u.id, &body.roles).await?;
    let token = if body.is_robot { Some(state.auth.create_access_token(u.id, "robot credential", None, None).await?.0) } else { None };
    state.audit.record(&p, "user_created", None, None, None, Some(body.username.clone()));
    let mut v = serde_json::to_value(view(&state, u).await?).unwrap_or_default();
    if let Some(t) = token {
        v["token"] = serde_json::Value::String(t);
    }
    Ok((StatusCode::CREATED, Json(v)).into_response())
}

#[derive(Deserialize)]
struct UpdateUserBody {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    is_disabled: Option<bool>,
    #[serde(default)]
    roles: Option<Vec<String>>,
}

async fn update_user(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(body): Json<UpdateUserBody>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let u = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    check_target(&state, &p, &u).await?;
    if u.is_managed && body.roles.is_some() {
        return Err(RegistryError::bad_request("this account's roles are defined in the configuration file"));
    }
    if Some(id) == p.user_id && body.is_disabled == Some(true) {
        return Err(RegistryError::bad_request("you cannot disable your own account"));
    }
    if let Some(roles) = &body.roles {
        check_roles_exist(&state, &p, roles).await?;
        state.auth.db.set_user_roles(id, roles).await?;
    }
    state.auth.db.update_user(id, body.email.as_deref(), body.display_name.as_deref(), body.is_disabled).await?;
    if body.is_disabled == Some(true) {
        state.auth.db.delete_user_sessions(id).await?;
    }
    state.audit.record(&p, "user_updated", None, None, None, Some(u.username.clone()));
    let u = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    Ok(Json(view(&state, u).await?).into_response())
}

async fn delete_user(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let u = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    check_target(&state, &p, &u).await?;
    if u.is_managed {
        return Err(RegistryError::bad_request("this account is defined in the configuration file"));
    }
    if Some(id) == p.user_id {
        return Err(RegistryError::bad_request("you cannot delete your own account"));
    }
    state.auth.db.delete_user(id).await?;
    state.audit.record(&p, "user_deleted", None, None, None, Some(u.username));
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct ResetPasswordBody {
    password: String,
}

async fn reset_password(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(body): Json<ResetPasswordBody>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let u = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    check_target(&state, &p, &u).await?;
    if u.is_managed || u.is_robot {
        return Err(RegistryError::bad_request("cannot set a password for this account"));
    }
    crate::auth::password::check_strength(&body.password).map_err(RegistryError::bad_request)?;
    let hash = crate::auth::password::hash_async(&body.password).await.map_err(RegistryError::internal)?;
    state.auth.db.set_password(id, Some(&hash)).await?;
    state.auth.db.delete_user_sessions(id).await?;
    state.audit.record(&p, "password_reset", None, None, None, Some(u.username));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn reset_mfa(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let u = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    check_target(&state, &p, &u).await?;
    state.auth.db.disable_mfa(id).await?;
    state.audit.record(&p, "mfa_reset", None, None, None, Some(u.username));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn revoke_sessions(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let u = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    check_target(&state, &p, &u).await?;
    state.auth.db.delete_user_sessions(id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
