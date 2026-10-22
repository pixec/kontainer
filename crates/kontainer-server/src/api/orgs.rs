//! Organizations: a namespace (`org/...`) with teams, members, org admins and org robots.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use kontainer_core::perm::{valid_org_name, valid_username, Global, Level, TeamRole};
use crate::auth::{require_global, require_user, Principal};
use crate::database::{Organization, Team, User};
use crate::error::{RegistryError, Result};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/orgs", get(list_orgs).post(create_org))
        .route("/api/v1/orgs/{org}", get(get_org).patch(update_org).delete(delete_org))
        .route("/api/v1/orgs/{org}/teams", axum::routing::post(create_team))
        .route("/api/v1/orgs/{org}/teams/{team}", axum::routing::put(update_team).delete(delete_team))
        .route("/api/v1/orgs/{org}/teams/{team}/members", axum::routing::post(add_member))
        .route("/api/v1/orgs/{org}/teams/{team}/sync", axum::routing::put(set_team_sync).delete(clear_team_sync))
        .route("/api/v1/orgs/{org}/sso", get(get_sso).put(put_sso).delete(delete_sso))
        .route("/api/v1/orgs/{org}/teams/{team}/members/{user}", axum::routing::delete(remove_member))
        .route("/api/v1/orgs/{org}/robots", axum::routing::post(create_robot))
        .route("/api/v1/orgs/{org}/robots/{id}", axum::routing::delete(delete_robot).patch(update_robot))
        .route("/api/v1/orgs/{org}/robots/{id}/rotate", axum::routing::post(rotate_robot))
}


async fn org(state: &AppState, name: &str) -> Result<Organization> {
    state.auth.db.org_by_name(name).await?.ok_or_else(|| RegistryError::not_found("organization"))
}

fn require_org_admin(state: &AppState, p: &Principal, org: &str) -> Result<()> {
    if p.is_org_admin(org) { Ok(()) } else { Err(state.auth.denied(p, None)) }
}

#[derive(Serialize)]
struct OrgSummary {
    #[serde(flatten)]
    org: Organization,
    teams: usize,
    is_admin: bool,
    is_member: bool,
    /// The caller is on one of its teams (registry admins see every organization without it).
    is_joined: bool,
    /// The organization's own sign-in provider, by display name.
    sso: Option<String>,
}

async fn list_orgs(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    let db = &state.auth.db;
    let orgs = if p.has_global(Global::UsersRead) {
        db.list_orgs().await?
    } else if let Some(uid) = p.user_id {
        db.orgs_for_user(uid).await?
    } else {
        vec![]
    };
    let mut out = vec![];
    for o in orgs {
        let sso = db.org_sso(o.id).await?.map(|s| s.display_name);
        out.push(OrgSummary { teams: db.list_teams(o.id).await?.len(), is_admin: p.is_org_admin(&o.name), is_member: p.org_member(&o.name), is_joined: p.is_on_org_team(&o.name), sso, org: o });
    }
    Ok(Json(out).into_response())
}

#[derive(Deserialize)]
struct CreateOrgBody {
    name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: String,
}

async fn create_org(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<CreateOrgBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    require_global(&state, &p, Global::OrgsCreate)?;
    if !valid_org_name(&body.name) {
        return Err(RegistryError::bad_request("invalid organization name (letters, digits, `-`, `_`, `.`)"));
    }
    if state.auth.db.name_taken(&body.name).await? {
        return Err(RegistryError::conflict("that name is already used by a user or organization"));
    }
    let db = &state.auth.db;
    let o = db.create_org(&body.name, body.display_name.as_deref(), &body.description).await?;
    // The creator becomes the first org admin through an `owners` team.
    let owners = db.create_team(o.id, "owners", "Organization administrators", TeamRole::Admin, None).await?;
    db.add_team_member(owners.id, uid).await?;
    state.audit.record_org(&p, "org_created", &o.name, None);
    Ok((StatusCode::CREATED, Json(o)).into_response())
}

#[derive(Serialize)]
struct TeamView {
    #[serde(flatten)]
    team: Team,
    members: Vec<MemberView>,
    repositories: Vec<RepoLevel>,
    /// Membership comes from this directory group (and cannot be edited by hand).
    sync: Option<crate::database::sso::TeamSync>,
}

#[derive(Serialize)]
struct RepoLevel {
    repository: String,
    level: Level,
}

#[derive(Serialize)]
struct MemberView {
    id: i64,
    username: String,
    is_robot: bool,
}

#[derive(Serialize)]
struct OrgDetail {
    #[serde(flatten)]
    org: Organization,
    is_admin: bool,
    teams: Vec<TeamView>,
    robots: Vec<super::auth::RobotView>,
    repositories: Vec<String>,
    /// This organization's Time Machine window; `None` uses `default_time_machine_secs`.
    time_machine_secs: Option<i64>,
    default_time_machine_secs: u64,
}

async fn get_org(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    let o = org(&state, &name).await?;
    if !p.org_member(&name) {
        return Err(state.auth.denied(&p, None));
    }
    let db = &state.auth.db;
    let mut teams = vec![];
    for t in db.list_teams(o.id).await? {
        let members = db.team_members(t.id).await?.into_iter().map(|u| MemberView { id: u.id, username: u.username, is_robot: u.is_robot }).collect();
        let repositories = db.team_repo_grants(t.id).await?.into_iter().map(|(repository, level)| RepoLevel { repository, level }).collect();
        let sync = db.team_sync(t.id).await?;
        teams.push(TeamView { team: t, members, repositories, sync });
    }
    let mut robots = vec![];
    for r in db.org_robots(o.id).await? {
        robots.push(super::auth::robot_view(&state, r).await?);
    }
    let prefix = format!("{name}/");
    let repositories = state.repository_names().await?.into_iter().filter(|r| r.starts_with(&prefix) && p.can_see(r)).collect();
    let time_machine_secs = db.time_machine_secs(&name).await?;
    Ok(Json(OrgDetail { is_admin: p.is_org_admin(&name), org: o, teams, robots, repositories, time_machine_secs, default_time_machine_secs: state.config.policy.time_machine.as_secs() }).into_response())
}

#[derive(Deserialize)]
struct UpdateOrgBody {
    /// New namespace; moves every repository under it.
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    /// Absent: unchanged. `null`: the instance default. A number: seconds.
    #[serde(default, deserialize_with = "present")]
    time_machine_secs: Option<Option<i64>>,
}

/// Tells a JSON `null` (`Some(None)`) apart from a missing field (`None`, via `default`).
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> std::result::Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

async fn update_org(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>, Json(body): Json<UpdateOrgBody>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    state.auth.db.update_org(o.id, body.display_name.as_deref(), body.description.as_deref()).await?;
    if let Some(secs) = body.time_machine_secs {
        if secs.is_some_and(|s| !(0..=90 * 86400).contains(&s)) {
            return Err(RegistryError::bad_request("time_machine_secs: 0 to 90 days"));
        }
        state.auth.db.set_time_machine_secs(&name, secs).await?;
        state.audit.record_org(&p, "org_time_machine", &name, Some(secs.map(|s| format!("{s}s")).unwrap_or_else(|| "default".into())));
    }
    state.audit.record_org(&p, "org_updated", &name, None);
    let mut current = name.clone();
    if let Some(new) = body.name.as_deref().map(str::trim).filter(|n| *n != name) {
        if !valid_org_name(new) {
            return Err(RegistryError::bad_request("invalid organization name (letters, digits, `-`, `_`, `.`)"));
        }
        rename_namespace(&state, &name, new, Some(o.id), None).await?;
        state.audit.record_org(&p, "org_renamed", new, Some(format!("{name} -> {new}")));
        current = new.to_string();
    }
    Ok(Json(org(&state, &current).await?).into_response())
}

/// Move a namespace (organization or user) to a new name: every repository under it (its
/// manifests, tags and blob links), its robots, metadata, stars and grants, in one database
/// transaction. Blobs are content addressed and not tied to a name: nothing moves in storage.
pub async fn rename_namespace(state: &AppState, old: &str, new: &str, org_id: Option<i64>, user_id: Option<i64>) -> Result<()> {
    let new_lc = new.to_ascii_lowercase();
    if new != new_lc {
        return Err(RegistryError::bad_request("namespaces must be lowercase (image references are)"));
    }
    if state.auth.db.name_taken(new).await? {
        return Err(RegistryError::conflict("that name is already used by a user or organization"));
    }
    if state.storage.namespace_has_repositories(new).await? || state.auth.db.catalogue_has_namespace(new).await? {
        return Err(RegistryError::conflict("repositories already exist under that name"));
    }
    // Announces the change to the other instances' repository sets and search indexes.
    state.auth.db.rename_namespace(old, new, org_id, user_id).await?;
    state.auth.refresh_public_repos().await?;
    state.auth.set_known_repos(state.repository_names().await?).await;
    state.rebuild_search().await?;
    tracing::info!(%old, %new, "namespace renamed");
    Ok(())
}

/// Deleting an organization removes its teams and robots. Repositories under `org/` stay in
/// storage but become reachable only through global roles; use the repository delete first.
async fn delete_org(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_global(&state, &p, Global::UsersWrite)?;
    state.auth.db.delete_org(o.id).await?;
    state.audit.record_org(&p, "org_deleted", &name, None);
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct TeamBody {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "member")]
    role: TeamRole,
    /// Access to every repository in the org.
    #[serde(default)]
    base_permission: Option<Level>,
}

fn member() -> TeamRole {
    TeamRole::Member
}

async fn create_team(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>, Json(body): Json<TeamBody>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    if !valid_org_name(&body.name) {
        return Err(RegistryError::bad_request("invalid team name"));
    }
    if state.auth.db.team_by_name(o.id, &body.name).await?.is_some() {
        return Err(RegistryError::conflict("team already exists"));
    }
    let t = state.auth.db.create_team(o.id, &body.name, &body.description, body.role, body.base_permission).await?;
    state.audit.record_org(&p, "team_created", &name, Some(body.name.clone()));
    Ok((StatusCode::CREATED, Json(t)).into_response())
}

async fn team(state: &AppState, o: &Organization, name: &str) -> Result<Team> {
    state.auth.db.team_by_name(o.id, name).await?.ok_or_else(|| RegistryError::not_found("team"))
}

async fn update_team(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, tname)): Path<(String, String)>, Json(body): Json<TeamBody>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let t = team(&state, &o, &tname).await?;
    let db = &state.auth.db;
    if t.is_admin() && body.role != TeamRole::Admin {
        // Don't let the last admin team drop its admin role.
        let others: i64 = db.list_teams(o.id).await?.iter().filter(|x| x.is_admin() && x.id != t.id).count() as i64;
        if others == 0 {
            return Err(RegistryError::bad_request("the organization needs at least one admin team"));
        }
    }
    db.update_team(t.id, &body.description, body.role, body.base_permission).await?;
    state.audit.record_org(&p, "team_updated", &name, Some(tname.clone()));
    Ok(Json(db.team_by_id(t.id).await?.ok_or_else(|| RegistryError::not_found("team"))?).into_response())
}

async fn delete_team(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, tname)): Path<(String, String)>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let t = team(&state, &o, &tname).await?;
    let db = &state.auth.db;
    if t.is_admin() && db.list_teams(o.id).await?.iter().filter(|x| x.is_admin() && x.id != t.id).count() == 0 {
        return Err(RegistryError::bad_request("cannot delete the last admin team"));
    }
    db.delete_team(t.id).await?;
    state.audit.record_org(&p, "team_deleted", &name, Some(tname.clone()));
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct MemberBody {
    username: String,
}

async fn add_member(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, tname)): Path<(String, String)>, Json(body): Json<MemberBody>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let t = team(&state, &o, &tname).await?;
    let db = &state.auth.db;
    let u = db.user_by_name(&body.username).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    // Robots may only join teams of their own org (or be user robots of a member).
    if u.is_robot && u.org_id.is_some() && u.org_id != Some(o.id) {
        return Err(RegistryError::bad_request("that robot belongs to another organization"));
    }
    if db.team_sync(t.id).await?.is_some() && !u.is_robot {
        return Err(RegistryError::bad_request("this team's members come from a directory group; stop syncing to add people by hand"));
    }
    db.add_team_member(t.id, u.id).await?;
    state.audit.record_org(&p, "team_member_added", &name, Some(format!("{tname} += {}", u.username)));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn remove_member(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, tname, user)): Path<(String, String, String)>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let t = team(&state, &o, &tname).await?;
    let db = &state.auth.db;
    let u = db.user_by_name(&user).await?.ok_or_else(|| RegistryError::not_found("user"))?;
    if t.is_admin() && !u.is_robot && db.org_admin_count(o.id).await? <= 1 {
        return Err(RegistryError::bad_request("the organization needs at least one admin"));
    }
    db.remove_team_member(t.id, u.id).await?;
    state.audit.record_org(&p, "team_member_removed", &name, Some(format!("{tname} -= {}", u.username)));
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct RobotBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    /// Teams the robot joins.
    #[serde(default)]
    teams: Vec<String>,
    /// 0 = never; default: `policy.robot_expiry_days`.
    #[serde(default)]
    expires_in_days: Option<u32>,
}

async fn create_robot(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>, Json(body): Json<RobotBody>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let username = format!("{name}+{}", body.name.trim());
    if !valid_username(&username) {
        return Err(RegistryError::bad_request("invalid robot name"));
    }
    let db = &state.auth.db;
    if db.name_taken(&username).await? {
        return Err(RegistryError::conflict("a robot with that name already exists"));
    }
    let expires = super::auth::robot_expiry(&state, body.expires_in_days)?;
    let robot = db.create_org_robot(o.id, &username, body.description.as_deref()).await?;
    for t in &body.teams {
        let t = team(&state, &o, t).await?;
        db.add_team_member(t.id, robot.id).await?;
    }
    let (plain, _) = state.auth.create_access_token(robot.id, "robot credential", None, expires).await?;
    state.audit.record_org(&p, "robot_created", &name, Some(username.clone()));
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": robot.id, "username": username, "token": plain }))).into_response())
}

async fn org_robot(state: &AppState, p: &Principal, name: &str, id: i64) -> Result<User> {
    let o = org(state, name).await?;
    require_org_admin(state, p, name)?;
    match state.auth.db.user_by_id(id).await? {
        Some(u) if u.is_robot && u.org_id == Some(o.id) => Ok(u),
        _ => Err(RegistryError::not_found("robot")),
    }
}

async fn delete_robot(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, id)): Path<(String, i64)>) -> Result<Response> {
    let r = org_robot(&state, &p, &name, id).await?;
    state.auth.db.delete_user(r.id).await?;
    state.audit.record_org(&p, "robot_deleted", &name, Some(r.username));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn update_robot(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, id)): Path<(String, i64)>, Json(body): Json<super::auth::RobotUpdate>) -> Result<Response> {
    let r = org_robot(&state, &p, &name, id).await?;
    super::auth::apply_robot_update(&state, &r, &body).await?;
    state.audit.record_org(&p, "robot_updated", &name, Some(r.username.clone()));
    let r = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("robot"))?;
    Ok(Json(super::auth::robot_view(&state, r).await?).into_response())
}

async fn rotate_robot(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, id)): Path<(String, i64)>, body: Option<Json<super::auth::RotateBody>>) -> Result<Response> {
    let r = org_robot(&state, &p, &name, id).await?;
    let plain = super::auth::reissue_robot_credential(&state, &r, body.and_then(|b| b.0.expires_in_days)).await?;
    state.audit.record_org(&p, "robot_rotated", &name, Some(r.username.clone()));
    Ok(Json(serde_json::json!({ "username": r.username, "token": plain })).into_response())
}

// Single sign-on and directory-synced teams
/// Where synced team membership can come from, for this organization.
async fn sync_sources(state: &AppState, org_id: i64) -> Result<Vec<serde_json::Value>> {
    let mut out = vec![];
    if state.auth.ldap.is_some() {
        out.push(serde_json::json!({ "id": "ldap", "label": "LDAP group" }));
    }
    if let Some(o) = state.auth.oidc.as_ref().filter(|o| o.config().groups_claim.is_some()) {
        out.push(serde_json::json!({ "id": "oidc", "label": format!("{} group", o.config().display_name) }));
    }
    if let Some(s) = state.auth.db.org_sso(org_id).await?.filter(|s| s.groups_claim.is_some()) {
        out.push(serde_json::json!({ "id": "org-oidc", "label": format!("{} group (this organization)", s.display_name) }));
    }
    Ok(out)
}

async fn get_sso(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let base = state.auth.public_url.trim_end_matches('/').to_string();
    Ok(Json(serde_json::json!({
        "provider": state.auth.db.org_sso(o.id).await?,
        "callback_url": format!("{base}/auth/oidc/orgs/{name}/callback"),
        "login_url": format!("{base}/auth/oidc/orgs/{name}/login"),
        "sync_sources": sync_sources(&state, o.id).await?,
    }))
    .into_response())
}

async fn put_sso(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>, Json(body): Json<crate::database::sso::OrgSsoInput>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let issuer = body.issuer.trim().trim_end_matches('/');
    check_issuer(&state, issuer).await?;
    if body.client_id.trim().is_empty() {
        return Err(RegistryError::bad_request("client_id is required"));
    }
    let existing = state.auth.db.org_sso(o.id).await?;
    if existing.is_none() && body.client_secret.as_deref().is_none_or(str::is_empty) {
        return Err(RegistryError::bad_request("client_secret is required"));
    }
    // Fail now rather than at someone's sign-in.
    let discovery = format!("{issuer}/.well-known/openid-configuration");
    // No redirects: they could lead anywhere, past the checks above.
    let ok = reqwest::Client::builder().user_agent(kontainer_core::USER_AGENT).redirect(reqwest::redirect::Policy::none()).build().map_err(|e| RegistryError::internal(anyhow::anyhow!(e)))?.get(&discovery).timeout(std::time::Duration::from_secs(10)).send().await.ok().is_some_and(|r| r.status().is_success());
    if !ok {
        return Err(RegistryError::bad_request(format!("could not read {discovery}")));
    }
    state.auth.db.set_org_sso(o.id, &body).await?;
    state.audit.record_org(&p, "org_sso_updated", &name, Some(issuer.to_string()));
    get_sso(State(state), Extension(p), Path(name)).await
}

/// An organization's issuer is fetched by this server, so org admins must not be able to point it
/// at internal services: https only, no query, fragment or credentials, and a host that resolves
/// to public addresses only. The exception is a loopback issuer (`localhost`, `127.0.0.1`,
/// `[::1]`, plain http allowed) on a server that is itself bound to loopback, i.e. a developer's
/// machine.
async fn check_issuer(state: &AppState, issuer: &str) -> Result<()> {
    let bad = |m: &str| Err(RegistryError::bad_request(format!("issuer: {m}")));
    let Ok(u) = url::Url::parse(issuer) else { return bad("not a valid URL") };
    if u.query().is_some() || u.fragment().is_some() || !u.username().is_empty() || u.password().is_some() {
        return bad("must not have a query, fragment or credentials");
    }
    let is_loopback = match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        None => return bad("has no host"),
    };
    if is_loopback {
        if !matches!(u.scheme(), "https" | "http") {
            return bad("must be an https:// URL");
        }
        if !kontainer_core::config::is_loopback_bind(&state.config.server.bind) {
            return bad("a loopback issuer is only allowed when the server is bound to loopback");
        }
        return Ok(());
    }
    if u.scheme() != "https" {
        return bad("must be an https:// URL");
    }
    let host = u.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']').to_string();
    let port = u.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(a) => a.collect(),
        Err(_) => return bad(&format!("cannot resolve {host}")),
    };
    if addrs.is_empty() {
        return bad(&format!("cannot resolve {host}"));
    }
    if let Some(a) = addrs.iter().find(|a| !is_public_ip(a.ip())) {
        return bad(&format!("{host} resolves to a non-public address ({})", a.ip()));
    }
    Ok(())
}

/// Not loopback, private, link-local, shared (CGNAT), unspecified, multicast or otherwise
/// reserved.
fn is_public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast() || v.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v.segments();
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x64 && s[1] == 0xff9b)
                || (s[0] == 0x2001 && s[1] == 0xdb8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_public_ip;

    #[test]
    fn non_public_addresses() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "::ffff:169.254.169.254"] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}

async fn delete_sso(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    state.auth.db.delete_org_sso(o.id).await?;
    state.audit.record_org(&p, "org_sso_removed", &name, None);
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct TeamSyncBody {
    source: String,
    group: String,
}

async fn set_team_sync(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, tname)): Path<(String, String)>, Json(body): Json<TeamSyncBody>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let t = team(&state, &o, &tname).await?;
    let sources = sync_sources(&state, o.id).await?;
    if !sources.iter().any(|s| s["id"] == body.source.as_str()) {
        return Err(RegistryError::bad_request(format!("{} is not available here", body.source)));
    }
    let group = body.group.trim();
    if group.is_empty() || group.len() > 256 {
        return Err(RegistryError::bad_request("group: 1-256 characters"));
    }
    state.auth.db.set_team_sync(t.id, Some((&body.source, group))).await?;
    state.audit.record_org(&p, "team_sync_set", &name, Some(format!("{tname} <- {}:{group}", body.source)));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn clear_team_sync(State(state): State<AppState>, Extension(p): Extension<Principal>, Path((name, tname)): Path<(String, String)>) -> Result<Response> {
    let o = org(&state, &name).await?;
    require_org_admin(&state, &p, &name)?;
    let t = team(&state, &o, &tname).await?;
    state.auth.db.set_team_sync(t.id, None).await?;
    state.audit.record_org(&p, "team_sync_cleared", &name, Some(tname));
    Ok(StatusCode::NO_CONTENT.into_response())
}
