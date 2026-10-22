//! Repository catalogue: description, README, visibility, topics, and the public Explore list.

use std::collections::HashMap;

use axum::extract::{Extension, Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use kontainer_core::perm::Action;
use crate::auth::{require, require_user, Principal};
use crate::database::{RepoMeta, Visibility};
use crate::database::remote::{Mirror, ProxyCache, Registry};
use crate::database::repos::{RepoImport, RepoMetaUpdate};
use crate::database::Db;
use crate::error::{Code, RegistryError, Result};
use kontainer_core::names;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/explore", get(explore))
        .route("/api/v1/search", get(search))
        .route("/api/v1/repositories", axum::routing::post(create_repository))
        .route("/api/v1/repository-meta/{*name}", get(get_meta).patch(update_meta))
        .route("/api/v1/repository-permissions/{*name}", get(get_permissions).put(set_permission))
        .route("/api/v1/directory", get(directory))
        .route("/api/v1/stars", get(list_stars))
        .route("/api/v1/stars/{*name}", axum::routing::put(star).delete(unstar))
        .route("/api/v1/delete-plans/{id}/execute", axum::routing::post(execute_delete_plan))
}

#[derive(Serialize)]
pub struct ExploreEntry {
    pub name: String,
    pub description: String,
    pub topics: Vec<String>,
    pub tags: usize,
    pub updated_at: String,
    pub created_at: String,
    pub org: Option<String>,
    pub stars: i64,
    pub latest: super::ext::LatestTag,
}

#[derive(Deserialize)]
struct ExploreQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    topic: Option<String>,
}

/// Public repositories, browsable by anyone.
async fn explore(State(state): State<AppState>, Query(q): Query<ExploreQuery>) -> Result<Response> {
    let db = &state.auth.db;
    let mut out = vec![];
    let needle = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    // With a query, tantivy decides what matches and in which order.
    let ranked: Option<std::collections::HashMap<String, usize>> = match needle {
        Some(n) => Some(state.search.search(n, true, 1000).map_err(RegistryError::internal)?.into_iter().enumerate().map(|(i, h)| (h.name, i)).collect()),
        None => None,
    };
    let topic = q.topic.as_deref().map(str::trim).filter(|t| !t.is_empty());
    let stars = db.star_counts().await?;
    for m in db.all_repo_meta().await? {
        if m.visibility != Visibility::Public {
            continue;
        }
        let topics = m.topic_list();
        if let Some(t) = topic {
            if !topics.iter().any(|x| x == t) {
                continue;
            }
        }
        if ranked.as_ref().is_some_and(|r| !r.contains_key(&m.name)) {
            continue;
        }
        let tags = state.storage.list_tags(&m.name).await?.len();
        let org = m.name.split_once('/').map(|(o, _)| o.to_string()).filter(|o| !o.is_empty());
        let org = match org {
            Some(o) if db.org_by_name(&o).await?.is_some() => Some(o),
            _ => None,
        };
        out.push(ExploreEntry { name: m.name.clone(), description: m.description.clone(), topics, tags, updated_at: m.updated_at.to_rfc3339(), created_at: m.created_at.to_rfc3339(), org, stars: stars.get(&m.name).copied().unwrap_or(0), latest: super::ext::latest_tag(&state, &m.name).await? });
    }
    if let Some(r) = &ranked {
        out.sort_by_key(|e| r.get(&e.name).copied().unwrap_or(usize::MAX));
    }
    let mut all_topics: Vec<String> = out.iter().flat_map(|e| e.topics.clone()).collect();
    all_topics.sort();
    all_topics.dedup();
    Ok(Json(serde_json::json!({ "repositories": out, "topics": all_topics })).into_response())
}

#[derive(Serialize)]
struct MetaView {
    #[serde(flatten)]
    meta: RepoMeta,
    /// What the caller may do here (`admin` expanded), so the UI shows only those controls.
    actions: Vec<Action>,
    stars: i64,
    is_starred: bool,
    origin: Option<Origin>,
    owner: Option<Owner>,
    /// `read_only` or `mirror` when writes are blocked.
    state: Option<crate::database::tags::RepoState>,
    /// A runner serves this repository's namespace, so it can be built from Git.
    builds: bool,
}

/// Can `name` be built: builds are on and a runner serves its namespace?
async fn builds_available(state: &AppState, name: &str) -> Result<bool> {
    Ok(state.config.builds.is_enabled && state.auth.db.has_runner_for(names::namespace(name)).await?)
}

/// The namespace's owner, for the repository page's Details card.
#[derive(Serialize)]
struct Owner {
    /// `user` or `org`.
    kind: &'static str,
    name: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
}

async fn owner(state: &AppState, repo: &str) -> Result<Option<Owner>> {
    let Some((ns, _)) = repo.split_once('/') else { return Ok(None) };
    let db = &state.auth.db;
    if let Some(o) = db.org_by_name(ns).await? {
        return Ok(Some(Owner { kind: "org", name: o.name, display_name: o.display_name.filter(|d| !d.is_empty()), avatar_url: None }));
    }
    let Some(u) = db.user_by_name(ns).await? else { return Ok(None) };
    let avatar_url = db.profile(u.id).await?.and_then(|p| p.gravatar_email).map(|e| super::auth::gravatar_url(&e));
    Ok(Some(Owner { kind: "user", name: u.username, display_name: u.display_name.filter(|d| !d.is_empty()), avatar_url }))
}

/// Where a repository's content comes from, when it was not pushed here.
#[derive(Serialize)]
pub struct Origin {
    /// `cache`, `mirror` or `import`.
    kind: &'static str,
    /// Registry name and URL, when the origin is another registry.
    registry: Option<String>,
    registry_url: Option<String>,
    /// Upstream repository (`library/alpine`), `repo:tag`, or an archive's file name.
    source: String,
    /// `registry` or `archive`, for imports.
    via: Option<String>,
    at: Option<String>,
    status: Option<String>,
    message: Option<String>,
    actor: Option<String>,
    /// Mirror id, for a link to manage it.
    mirror_id: Option<i64>,
}

/// Everything needed to answer "where did this repository come from", loaded once.
pub struct Origins {
    registries: HashMap<i64, Registry>,
    caches: HashMap<String, ProxyCache>,
    mirrors: HashMap<String, Mirror>,
    imports: HashMap<String, RepoImport>,
}

impl Origins {
    pub async fn load(db: &Db) -> anyhow::Result<Self> {
        Ok(Self {
            registries: db.registries().await?.into_iter().map(|r| (r.id, r)).collect(),
            caches: db.proxy_caches().await?.into_iter().map(|c| (c.namespace.clone(), c)).collect(),
            mirrors: db.mirrors().await?.into_iter().rev().map(|m| (m.target.clone(), m)).collect(),
            imports: db.repo_imports().await?.into_iter().map(|i| (i.repository.clone(), i)).collect(),
        })
    }

    pub fn get(&self, name: &str) -> Option<Origin> {
        let reg = |id: i64| self.registries.get(&id);
        if let Some(c) = name.split_once('/').and_then(|(ns, _)| self.caches.get(ns)) {
            let r = reg(c.registry_id);
            return Some(Origin {
                kind: "cache", registry: r.map(|r| r.name.clone()), registry_url: r.map(|r| r.url.clone()), source: name[c.namespace.len() + 1..].to_string(),
                via: None, at: None, status: None, message: Some(format!("tags re-checked every {} min", c.ttl_secs / 60)), actor: None, mirror_id: None,
            });
        }
        if let Some(m) = self.mirrors.get(name) {
            let r = reg(m.registry_id);
            return Some(Origin {
                kind: "mirror", registry: r.map(|r| r.name.clone()), registry_url: r.map(|r| r.url.clone()), source: m.source.clone(),
                via: None, at: m.last_sync_at.map(|t| t.to_rfc3339()), status: m.last_status.clone(), message: m.last_message.clone(), actor: None, mirror_id: Some(m.id),
            });
        }
        let i = self.imports.get(name)?;
        let url = i.registry.as_ref().and_then(|n| self.registries.values().find(|r| &r.name == n)).map(|r| r.url.clone());
        Some(Origin {
            kind: "import", registry: i.registry.clone(), registry_url: url, source: i.source.clone(),
            via: Some(i.kind.clone()), at: Some(i.imported_at.to_rfc3339()), status: None, message: None, actor: Some(i.actor.clone()), mirror_id: None,
        })
    }
}

async fn origin(state: &AppState, name: &str) -> Result<Option<Origin>> {
    Ok(Origins::load(&state.auth.db).await?.get(name))
}

fn default_meta(name: &str) -> RepoMeta {
    RepoMeta {
        name: name.to_string(),
        description: String::new(),
        readme: String::new(),
        visibility: Visibility::Private,
        topics: "[]".into(),
        // Placeholders: `get_meta` shows them as null.
        created_at: chrono::DateTime::UNIX_EPOCH,
        updated_at: chrono::DateTime::UNIX_EPOCH,
    }
}

async fn get_meta(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    require(&state, &p, Action::Pull, &name)?;
    let stored = state.auth.db.repo_meta(&name).await?;
    let is_stored = stored.is_some();
    let meta = stored.unwrap_or_else(|| default_meta(&name));
    let (stars, is_starred) = star_state(&state, &p, &name).await?;
    let origin = origin(&state, &name).await?;
    let owner = owner(&state, &name).await?;
    let repo_state = state.auth.db.repo_state(&name).await?;
    let builds = builds_available(&state, &name).await?;
    let mut view = serde_json::to_value(MetaView { actions: p.actions_on(&name), meta, stars, is_starred, origin, owner, state: repo_state, builds }).map_err(RegistryError::internal)?;
    if !is_stored {
        // A repository in storage without a catalogue row: never created or updated here.
        view["created_at"] = serde_json::Value::Null;
        view["updated_at"] = serde_json::Value::Null;
    }
    Ok(Json(view).into_response())
}

async fn update_meta(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>, Json(body): Json<RepoMetaUpdate>) -> Result<Response> {
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    // An empty update still needs one of the two.
    if body.description.is_some() || body.readme.is_some() || body.topics.is_some() || body.visibility.is_none() {
        require(&state, &p, Action::Metadata, &name)?;
    }
    if body.visibility.is_some() {
        require(&state, &p, Action::Visibility, &name)?;
    }
    if let Some(t) = &body.topics {
        validate_topics(t)?;
    }
    if body.readme.as_ref().is_some_and(|r| r.len() > 256 * 1024) {
        return Err(RegistryError::bad_request("readme too large (256 KiB max)"));
    }
    let meta = state.auth.db.upsert_repo_meta(&name, &body, Visibility::Private).await?;
    state.auth.refresh_public_repos().await?;
    state.reindex(&name).await;
    state.audit.record(&p, "repository_updated", Some(&name), None, None, body.visibility.map(|v| format!("visibility={v:?}").to_lowercase()));
    Ok(Json(meta_view(&state, &p, meta).await?).into_response())
}

/// The `GET /api/v1/repository-meta/{name}` view of a stored catalogue entry.
async fn meta_view(state: &AppState, p: &Principal, meta: RepoMeta) -> Result<MetaView> {
    let name = meta.name.clone();
    let (stars, is_starred) = star_state(state, p, &name).await?;
    let origin = origin(state, &name).await?;
    let owner = owner(state, &name).await?;
    let repo_state = state.auth.db.repo_state(&name).await?;
    let builds = builds_available(state, &name).await?;
    Ok(MetaView { actions: p.actions_on(&name), meta, stars, is_starred, origin, owner, state: repo_state, builds })
}

fn validate_topics(t: &[String]) -> Result<()> {
    if t.len() > 20 || t.iter().any(|x| x.is_empty() || x.len() > 32 || !x.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')) {
        return Err(RegistryError::bad_request("topics: up to 20 of lowercase letters, digits and `-`"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct CreateRepository {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    visibility: Option<Visibility>,
    #[serde(default)]
    topics: Vec<String>,
}

/// `POST /api/v1/repositories`: create an empty repository, so it can be set up (a build
/// trigger, permissions, a README) before anything is pushed. Whoever may push a repository
/// into existence may create it here, and a Creator team member becomes its admin, as with a
/// first push. 201 with the `repository-meta` view; 409 if it already exists.
async fn create_repository(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<CreateRepository>) -> Result<Response> {
    let name = body.name.trim().to_string();
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid).detail(serde_json::json!({ "name": name })));
    }
    validate_topics(&body.topics)?;
    let ns = names::namespace(&name);
    if name.contains('/') && state.auth.proxies_contains(ns).await {
        return Err(RegistryError::bad_request(format!("{ns} is a pull-through cache; its repositories come from the upstream")));
    }
    // A repository belongs to a user or an organization. Even a superuser, who may push anywhere,
    // gets no ownerless `nobody/app` from the UI: the namespace must exist first.
    if name.contains('/') {
        let db = &state.auth.db;
        let owned = db.user_by_name(ns).await?.is_some_and(|u| !u.is_robot) || db.org_by_name(ns).await?.is_some();
        if !owned {
            return Err(RegistryError::bad_request(format!("{ns} is not a user or organization; create the organization first, or use your own namespace")));
        }
    } else {
        return Err(RegistryError::bad_request("a repository name needs a namespace: <user or organization>/<name>"));
    }
    // The first push's rule: decided on what storage and the catalogue hold now (see
    // `confirm_new_repo`), so an existing repository is never passed off as new.
    let mut p = p;
    state.auth.confirm_new_repo(&mut p, &name).await?;
    if state.repository_known(&name).await? {
        if p.can_see(&name) {
            return Err(RegistryError::conflict(format!("repository {name} already exists")));
        }
        return Err(state.auth.denied(&p, Some(format!("repository:{name}:pull,push"))));
    }
    require(&state, &p, Action::Push, &name)?;
    let visibility = body.visibility.unwrap_or(Visibility::Private);
    // Making it public takes the visibility right, which a Creator gets with the admin grant.
    if visibility == Visibility::Public && !p.creates(&name) && !p.allowed(Action::Visibility, &name) {
        return Err(state.auth.denied(&p, None));
    }
    let Some(meta) = state.auth.db.create_repo_meta(&name, body.description.trim(), visibility, &body.topics).await? else {
        return Err(RegistryError::conflict(format!("repository {name} already exists")));
    };
    // Grant before the repository counts as existing: `creates` asks whether it does.
    if state.auth.grant_creator(&p, &name).await? {
        let mut grants = (*p.repo_grants).clone();
        grants.insert(name.clone(), kontainer_core::perm::Level::ADMIN);
        p.repo_grants = std::sync::Arc::new(grants);
    }
    state.auth.note_repo(&name, true).await;
    let mut known = (*p.known_repos).clone();
    known.insert(name.clone());
    p.known_repos = std::sync::Arc::new(known);
    if visibility == Visibility::Public {
        state.auth.refresh_public_repos().await?;
    }
    state.reindex(&name).await;
    state.audit.record(&p, "repository_created", Some(&name), None, None, Some(format!("visibility={visibility:?}").to_lowercase()));
    Ok((axum::http::StatusCode::CREATED, Json(meta_view(&state, &p, meta).await?)).into_response())
}

async fn star_state(state: &AppState, p: &Principal, name: &str) -> Result<(i64, bool)> {
    let db = &state.auth.db;
    let stars = db.star_count(name).await?;
    let is_starred = match p.user_id {
        Some(uid) => db.starred_by(uid).await?.iter().any(|r| r == name),
        None => false,
    };
    Ok((stars, is_starred))
}

#[derive(Serialize)]
struct StarView {
    stars: i64,
    is_starred: bool,
}

async fn set_star(state: AppState, p: Principal, name: String, starred: bool) -> Result<Response> {
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    let uid = require_user(&state, &p)?;
    require(&state, &p, Action::Pull, &name)?;
    state.auth.db.set_star(uid, &name, starred).await?;
    let (stars, is_starred) = star_state(&state, &p, &name).await?;
    Ok(Json(StarView { stars, is_starred }).into_response())
}

async fn star(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    set_star(state, p, name, true).await
}

async fn unstar(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    set_star(state, p, name, false).await
}

#[derive(Serialize)]
struct StarredRepo {
    name: String,
    description: String,
    visibility: Visibility,
    tags: usize,
    stars: i64,
    updated_at: Option<String>,
}

/// The caller's starred repositories that still exist and that they can still pull.
async fn list_stars(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    let db = &state.auth.db;
    let counts = db.star_counts().await?;
    let existing = state.repository_names().await?;
    let mut out = vec![];
    for name in db.starred_by(uid).await? {
        if !existing.contains(&name) || !p.allowed(Action::Pull, &name) {
            continue;
        }
        let meta = db.repo_meta(&name).await?;
        let (tags, pushed) = state.storage.tag_summary(&name).await?;
        out.push(StarredRepo {
            tags,
            stars: counts.get(&name).copied().unwrap_or(0),
            description: meta.as_ref().map(|m| m.description.clone()).unwrap_or_default(),
            visibility: meta.as_ref().map(|m| m.visibility).unwrap_or(Visibility::Private),
            // Last push; the catalogue entry's own timestamp only if nothing is tagged.
            updated_at: pushed.or(meta.map(|m| m.updated_at)).map(|t| t.to_rfc3339()),
            name,
        });
    }
    Ok(Json(out).into_response())
}

#[derive(Serialize)]
struct InheritedAccess {
    /// Why the access applies, e.g. "Admin team" or "Base permission".
    source: String,
    team: String,
    level: kontainer_core::perm::Level,
}

#[derive(Serialize)]
struct PermissionsView {
    /// The namespace is an organization (teams can be granted).
    org: Option<String>,
    grants: Vec<crate::database::RepoGrant>,
    /// Org-wide access that applies without a grant: admin teams and base permissions.
    inherited: Vec<InheritedAccess>,
}

/// Explicit grants on a repository plus the org-wide access that also applies. Repo admins only.
async fn get_permissions(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>) -> Result<Response> {
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    require(&state, &p, Action::Permissions, &name)?;
    let db = &state.auth.db;
    let ns = kontainer_core::names::namespace(&name);
    let org = db.org_by_name(ns).await?;
    let mut inherited = vec![];
    if let Some(o) = &org {
        for t in db.list_teams(o.id).await? {
            if t.is_admin() {
                inherited.push(InheritedAccess { source: "Admin team".into(), team: t.name.clone(), level: kontainer_core::perm::Level::ADMIN });
            } else if let Some(l) = t.base_permission {
                inherited.push(InheritedAccess { source: "Base permission".into(), team: t.name.clone(), level: l });
            }
        }
    }
    Ok(Json(PermissionsView { org: org.map(|o| o.name), grants: db.repo_grants(&name).await?, inherited }).into_response())
}

#[derive(Deserialize)]
struct SetPermissionBody {
    /// `user` (people and robots) or `team`.
    kind: String,
    name: String,
    /// `None` removes the grant.
    level: Option<kontainer_core::perm::Level>,
}

async fn set_permission(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(name): Path<String>, Json(body): Json<SetPermissionBody>) -> Result<Response> {
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    require(&state, &p, Action::Permissions, &name)?;
    let db = &state.auth.db;
    let bad = |m: &str| RegistryError::bad_request(m);
    let ns = kontainer_core::names::namespace(&name);
    let org = db.org_by_name(ns).await?;
    match body.kind.as_str() {
        "team" => {
            let o = org.as_ref().ok_or_else(|| bad("teams can only be granted on organization repositories"))?;
            let t = db.team_by_name(o.id, &body.name).await?.ok_or_else(|| bad("no such team in this organization"))?;
            db.set_team_grant(&name, t.id, body.level).await?;
        }
        "user" => {
            let u = db.user_by_name(&body.name).await?.ok_or_else(|| bad("no such user or robot"))?;
            // Robots only get access inside their own namespace: org robots on their org's
            // repositories, personal robots on their owner's.
            if u.is_robot {
                let home = match (u.org_id, u.owner_id) {
                    (Some(oid), _) => db.org_by_id(oid).await?.map(|o| o.name),
                    (_, Some(uid)) => db.user_by_id(uid).await?.map(|o| o.username),
                    _ => None,
                };
                if home.as_deref() != Some(ns) {
                    return Err(bad("robots can only be granted access to repositories in their own namespace"));
                }
            }
            db.set_user_grant(&name, u.id, body.level).await?;
        }
        _ => return Err(bad("kind must be `user` or `team`")),
    }
    state.audit.record(&p, "permission_changed", Some(&name), None, None, Some(format!("{} {} = {}", body.kind, body.name, body.level.map_or("none".to_string(), |l| l.as_string()))));
    Ok(Json(PermissionsView { org: org.map(|o| o.name), grants: db.repo_grants(&name).await?, inherited: vec![] }).into_response())
}

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct SearchResult {
    name: String,
    description: String,
    visibility: Visibility,
    tags: usize,
    score: f32,
}

/// Ranked full-text search over every repository the caller can see.
async fn search(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(q): Query<SearchQuery>) -> Result<Response> {
    let limit = q.limit.unwrap_or(10).clamp(1, 50);
    // Over-fetch, then drop what the caller may not see, so private hits do not eat the limit.
    let hits = state.search.search(&q.q, false, 500).map_err(RegistryError::internal)?;
    let mut out = vec![];
    for h in hits.into_iter().filter(|h| p.can_see(&h.name)).take(limit) {
        let meta = state.auth.db.repo_meta(&h.name).await?;
        out.push(SearchResult {
            tags: state.storage.list_tags(&h.name).await?.len(),
            description: meta.as_ref().map(|m| m.description.clone()).unwrap_or_default(),
            visibility: meta.map(|m| m.visibility).unwrap_or(Visibility::Private),
            name: h.name,
            score: h.score,
        });
    }
    Ok(Json(out).into_response())
}

#[derive(Deserialize)]
struct DirectoryQuery {
    /// `user`, `robot` or `team`.
    kind: String,
    #[serde(default)]
    q: String,
    /// For robots and teams: whose (a user's or an organization's namespace).
    #[serde(default)]
    namespace: Option<String>,
}

#[derive(Serialize)]
struct DirectoryEntry {
    name: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
}

/// Who can be granted access, for pickers. People: anyone signed in can search them by username
/// or name (at most 10). Robots and teams: only the namespace's owner, the organization's
/// members, and superusers see them.
async fn directory(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(q): Query<DirectoryQuery>) -> Result<Response> {
    require_user(&state, &p)?;
    let db = &state.auth.db;
    let needle = q.q.trim().to_lowercase();
    let hit = |name: &str, display: Option<&str>| needle.is_empty() || name.to_lowercase().contains(&needle) || display.is_some_and(|d| d.to_lowercase().contains(&needle));
    let entries: Vec<DirectoryEntry> = match q.kind.as_str() {
        "user" => {
            if needle.is_empty() {
                vec![]
            } else {
                db.search_people(&needle, 10).await?.into_iter().map(|(name, display_name, email)| DirectoryEntry {
                    name,
                    display_name: display_name.filter(|d| !d.is_empty()),
                    avatar_url: email.map(|e| super::auth::gravatar_url(&e)),
                }).collect()
            }
        }
        "robot" | "team" => {
            let ns = q.namespace.as_deref().ok_or_else(|| RegistryError::bad_request("namespace is required for robots and teams"))?;
            let org = db.org_by_name(ns).await?;
            let visible = p.is_superuser || match &org {
                Some(o) => p.teams.iter().any(|t| t.org == o.name),
                None => p.name() == ns,
            };
            if !visible {
                return Err(state.auth.denied(&p, None));
            }
            match (q.kind.as_str(), &org) {
                ("team", Some(o)) => db.list_teams(o.id).await?.into_iter().filter(|t| hit(&t.name, None)).map(|t| DirectoryEntry { name: t.name, display_name: (!t.description.is_empty()).then_some(t.description), avatar_url: None }).collect(),
                ("team", None) => vec![],
                (_, Some(o)) => db.org_robots(o.id).await?.into_iter().filter(|r| hit(&r.username, r.display_name.as_deref())).map(|r| DirectoryEntry { name: r.username, display_name: r.display_name, avatar_url: None }).collect(),
                (_, None) => {
                    let uid = p.user_id.ok_or_else(|| state.auth.denied(&p, None))?;
                    let owner = if p.name() == ns { uid } else { db.user_by_name(ns).await?.map(|u| u.id).ok_or_else(|| RegistryError::not_found("namespace"))? };
                    db.list_robots(owner).await?.into_iter().filter(|r| hit(&r.username, r.display_name.as_deref())).map(|r| DirectoryEntry { name: r.username, display_name: r.display_name, avatar_url: None }).collect()
                }
            }
        }
        _ => return Err(RegistryError::bad_request("kind must be user, robot or team")),
    };
    Ok(Json(entries).into_response())
}

// Deletion safeguards
//
// Deleting a repository, or several tags at once, takes two requests: a plan (what would go,
// shown to the user) and its execution, by the same user within five minutes, with the
// repository's name typed back. Deleting one tag still works directly (`DELETE
// /v2/<name>/manifests/<tag>`); the web UI shows its preview and asks for the name too.

/// How long a deletion plan may be executed.
const PLAN_TTL: chrono::Duration = chrono::Duration::minutes(5);
/// The most tags one plan deletes.
pub const MAX_PLAN_TAGS: usize = 100;

/// What deleting one tag affects.
#[derive(Serialize)]
pub struct TagDeletePreview {
    pub tag: String,
    pub digest: String,
    /// Other tags pointing at the same manifest: they stay, and keep it.
    pub other_tags: Vec<String>,
    /// Indexes in this repository listing the manifest as a platform image.
    pub index_parents: Vec<String>,
    /// Signatures, SBOMs and other artifacts attached to the manifest.
    pub referrers: i64,
    pub is_immutable: bool,
}

async fn tag_preview(state: &AppState, name: &str, tag: &str) -> Result<TagDeletePreview> {
    let db = &state.auth.db;
    let digest = state.storage.resolve_tag(name, tag).await?.ok_or_else(|| RegistryError::with_message(Code::ManifestUnknown, format!("no tag {tag} in {name}")))?;
    let other_tags = db.tags_pointing_at(name, &digest).await?.into_iter().filter(|t| t != tag).collect();
    Ok(TagDeletePreview {
        tag: tag.to_string(),
        other_tags,
        index_parents: db.index_parents(name, &digest).await?,
        referrers: db.referrer_count(name, &digest).await?,
        is_immutable: state.tag_is_immutable(name, tag),
        digest: digest.to_string(),
    })
}

/// `GET /api/v1/repositories/{name}/tags/{tag}/delete-preview`.
pub async fn tag_delete_preview(state: AppState, p: Principal, name: String, tag: String) -> Result<Response> {
    require(&state, &p, Action::Delete, &name)?;
    Ok(Json(tag_preview(&state, &name, &tag).await?).into_response())
}

/// A replication rule or mirror that touches the repository, and the tags it covers.
#[derive(Serialize)]
pub struct SyncedTags {
    pub id: i64,
    pub name: String,
    pub tags: Vec<String>,
}

/// What deleting a whole repository affects.
#[derive(Serialize)]
pub struct RepoDeletePreview {
    #[serde(flatten)]
    pub stats: crate::database::registry::RepoDeleteStats,
    /// Manifests and linked blobs together (shared blobs are only freed once nothing uses them).
    pub bytes: i64,
    pub immutable_tags: Vec<String>,
    /// Push replication rules covering this repository: deleted tags are also deleted on the
    /// target only where the rule replicates deletions.
    pub replication: Vec<SyncedTags>,
    /// Mirrors copying into this repository: they bring their tags back on the next sync.
    pub mirrors: Vec<SyncedTags>,
}

async fn repo_preview(state: &AppState, name: &str) -> Result<RepoDeletePreview> {
    let db = &state.auth.db;
    if !state.repository_known(name).await? {
        return Err(RegistryError::new(Code::NameUnknown));
    }
    let tags = state.storage.list_tags(name).await?;
    let globs = |json: &str| serde_json::from_str::<Vec<String>>(json).unwrap_or_default();
    let covered = |patterns: &[String]| -> Vec<String> { tags.iter().filter(|t| patterns.is_empty() || kontainer_core::glob::any_matches(patterns.iter(), t)).cloned().collect() };
    let mut replication = vec![];
    for r in db.enabled_replication_rules().await? {
        if kontainer_core::glob::any_matches(globs(&r.repositories).iter(), name) {
            replication.push(SyncedTags { id: r.id, tags: covered(&globs(&r.tags)), name: r.name });
        }
    }
    let mirrors = db.enabled_mirrors_into(name).await?.into_iter().map(|m| SyncedTags { id: m.id, tags: covered(&globs(&m.tags)), name: m.name }).collect();
    let stats = db.repository_delete_stats(name).await?;
    Ok(RepoDeletePreview {
        bytes: stats.manifest_bytes + stats.blob_bytes,
        stats,
        immutable_tags: tags.iter().filter(|t| state.tag_is_immutable(name, t)).cloned().collect(),
        replication,
        mirrors,
    })
}

/// `GET /api/v1/repositories/{name}/delete-preview`.
pub async fn repo_delete_preview(state: AppState, p: Principal, name: String) -> Result<Response> {
    require(&state, &p, Action::DeleteRepository, &name)?;
    Ok(Json(repo_preview(&state, &name).await?).into_response())
}

/// What a plan deletes.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum PlanTargets {
    Repository { repository: bool },
    Tags { tags: Vec<String> },
}

/// `POST /api/v1/repositories/{name}/delete-plan` with `{"repository": true}` or `{"tags": [...]}`:
/// stores a plan and returns its id with the preview.
pub async fn create_delete_plan(state: AppState, p: Principal, name: String, body: &[u8]) -> Result<Response> {
    let targets: PlanTargets = serde_json::from_slice(body).map_err(|e| RegistryError::bad_request(format!("expected {{\"repository\": true}} or {{\"tags\": [...]}}: {e}")))?;
    if !state.config.features.is_delete {
        return Err(RegistryError::new(Code::Unsupported));
    }
    let preview = match &targets {
        PlanTargets::Repository { repository: true } => {
            require(&state, &p, Action::DeleteRepository, &name)?;
            serde_json::to_value(repo_preview(&state, &name).await?).map_err(RegistryError::internal)?
        }
        PlanTargets::Repository { repository: false } => return Err(RegistryError::bad_request("nothing to delete")),
        PlanTargets::Tags { tags } => {
            require(&state, &p, Action::Delete, &name)?;
            let mut seen = std::collections::HashSet::new();
            if tags.is_empty() || tags.len() > MAX_PLAN_TAGS || !tags.iter().all(|t| seen.insert(t.as_str())) {
                return Err(RegistryError::bad_request(format!("tags: 1-{MAX_PLAN_TAGS} different tags")));
            }
            let mut previews = vec![];
            for t in tags {
                previews.push(tag_preview(&state, &name, t).await?);
            }
            serde_json::json!({ "tags": previews })
        }
    };
    let targets_json = serde_json::to_string(&targets).map_err(RegistryError::internal)?;
    let plan = state.auth.db.create_delete_plan(p.user_id, p.name(), &name, &targets_json, PLAN_TTL).await?;
    state.audit.record(&p, "delete_plan_created", Some(&name), None, None, Some(plan_summary(&targets)));
    Ok((axum::http::StatusCode::CREATED, Json(serde_json::json!({ "id": plan.id, "repository": name, "targets": targets, "expires_at": plan.expires_at.to_rfc3339(), "preview": preview }))).into_response())
}

fn plan_summary(t: &PlanTargets) -> String {
    match t {
        PlanTargets::Repository { .. } => "repository".to_string(),
        PlanTargets::Tags { tags } if tags.len() <= 5 => format!("tags {}", tags.join(", ")),
        PlanTargets::Tags { tags } => format!("{} tags ({}, ...)", tags.len(), tags[..5].join(", ")),
    }
}

#[derive(Deserialize)]
struct ExecuteBody {
    confirm: String,
}

/// `POST /api/v1/delete-plans/{id}/execute` with `{"confirm": "<repository name>"}`: runs the plan
/// once, for the user who made it, before it expires.
async fn execute_delete_plan(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<String>, Json(body): Json<ExecuteBody>) -> Result<Response> {
    let db = &state.auth.db;
    let plan = db.delete_plan(&id).await?.filter(|plan| plan.actor_id == p.user_id && (p.user_id.is_some() || plan.actor == p.name()));
    // Someone else's plan is as unknown as a missing one.
    let Some(plan) = plan else { return Err(RegistryError::not_found("deletion plan")) };
    if plan.used_at.is_some() {
        return Err(RegistryError::conflict("this deletion plan was already used; make a new one"));
    }
    if plan.expires_at <= chrono::Utc::now() {
        return Err(RegistryError::conflict("this deletion plan expired; make a new one"));
    }
    if body.confirm.trim() != plan.repository {
        return Err(RegistryError::bad_request(format!("type the repository name ({}) to confirm", plan.repository)));
    }
    let targets: PlanTargets = serde_json::from_str(&plan.targets).map_err(RegistryError::internal)?;
    let name = plan.repository.clone();
    // Permissions and protections as they are now, not as they were when it was planned.
    if !state.config.features.is_delete {
        return Err(RegistryError::new(Code::Unsupported));
    }
    state.require_writable(&name).await?;
    match &targets {
        PlanTargets::Repository { .. } => require(&state, &p, Action::DeleteRepository, &name)?,
        PlanTargets::Tags { tags } => {
            require(&state, &p, Action::Delete, &name)?;
            if let Some(t) = tags.iter().find(|t| state.tag_is_immutable(&name, t)) {
                return Err(RegistryError::conflict(format!("tag {t} is immutable")));
            }
        }
    }
    if !db.claim_delete_plan(&id).await? {
        return Err(RegistryError::conflict("this deletion plan was already used or expired; make a new one"));
    }
    let deleted = match &targets {
        PlanTargets::Repository { .. } => {
            delete_repository(&state, &p, &name).await?;
            serde_json::json!({ "repository": name })
        }
        PlanTargets::Tags { tags } => {
            let mut gone = vec![];
            for t in tags {
                if let Some(digest) = crate::tags::remove(&state, &name, t, "delete", p.name()).await? {
                    state.webhooks.fire(crate::webhook::Event::delete(&name, Some(t), &digest, p.name()));
                    state.audit.record(&p, "delete_tag", Some(&name), Some(t), Some(&digest.to_string()), Some(format!("plan {}", plan.id)));
                    gone.push(t.clone());
                }
            }
            state.reindex(&name).await;
            serde_json::json!({ "tags": gone })
        }
    };
    state.audit.record(&p, "delete_plan_executed", Some(&name), None, None, Some(format!("{} ({})", plan_summary(&targets), plan.id)));
    Ok(Json(serde_json::json!({ "id": plan.id, "deleted": deleted })).into_response())
}

/// Delete repository `name` with everything in it. Callers check permissions and confirmation.
pub async fn delete_repository(state: &AppState, p: &Principal, name: &str) -> Result<()> {
    state.require_writable(name).await?;
    for t in state.storage.list_tags(name).await? {
        if state.tag_is_immutable(name, &t) {
            return Err(RegistryError::conflict(format!("tag {t} is immutable")));
        }
    }
    state.storage.delete_repository(name).await?;
    // Also removes the repository's grants, in the same transaction.
    state.auth.db.delete_repo_meta(name).await?;
    state.auth.note_repo(name, false).await;
    if let Err(e) = state.search.remove(name) {
        tracing::warn!(repository = %name, error = %e, "removing from the search index");
    }
    state.auth.refresh_public_repos().await?;
    state.audit.record(p, "delete_repository", Some(name), None, None, None);
    Ok(())
}

