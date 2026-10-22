//! Authentication and authorization.
//!
//! Every request resolves to a [`Principal`]: who is calling, through which credential, with
//! which roles, and (for scoped bearer tokens and access tokens) which restriction applies on
//! top of the roles. Credentials are tried in this order:
//!
//! 1. session cookie (web UI)
//! 2. `Authorization: Bearer <jwt>` issued by `/auth/token` (docker login flow)
//! 3. `Authorization: Basic` with a password or a personal access token
//! 4. anonymous
//!
//! Users, roles, sessions and tokens live in PostgreSQL ([`database`](crate::database)). Roles and users from the config
//! file are synced into the database on start and marked managed.
//!
//! Every request's authorization reads four things kept in memory: role definitions, public
//! repositories, pull-through cache namespaces and the repositories that have content. With
//! several instances on one database each holds its own copy, so every change is announced with
//! a `NOTIFY` ([`database::notify`](crate::database::notify)) that makes each instance reload
//! what changed; all four are also reloaded on a timer, in case a notification was lost. A
//! repository missing from the local set is looked up in storage before a push may count as
//! creating it.

pub mod client_ip;
pub mod federation;
mod jwks;
pub mod ldap;
pub(crate) mod limits;
pub mod mfa;
pub mod oidc;
pub mod passkey;
pub mod password;
pub mod sso;
pub mod token;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
use tokio::sync::RwLock;

use kontainer_core::config::{AuthMode, Config};
use crate::error::{Code, RegistryError};
use crate::state::AppState;
use crate::database::notify::{Listener, Topic};
use crate::database::{sha256_hex, Db, User};
use kontainer_core::glob;
use kontainer_core::perm::{Action, Global, Level, Role, Rule, TeamGrant, TeamRole};

pub const SESSION_COOKIE: &str = "kontainer_session";

/// How often the caches are reloaded whatever the notifications say.
const CACHE_RELOAD: Duration = Duration::from_secs(60);
/// The set of repositories with content is rebuilt from a full storage listing every this many
/// reloads (the listing reads every object key). In between, a repository missing from the set
/// is looked up in storage when it matters (see [`Authenticator::confirm_new_repo`]), and one
/// in it wrongly only refuses a creation.
const KNOWN_REPOS_EVERY: u32 = 10;
pub const TOKEN_PREFIX: &str = "kontainer_";
/// Prefixes of tokens issued before the rename; still accepted, never issued.
const LEGACY_TOKEN_PREFIXES: &[&str] = &["sauh_"];

fn is_access_token(secret: &str) -> bool {
    secret.starts_with(TOKEN_PREFIX) || LEGACY_TOKEN_PREFIXES.iter().any(|p| secret.starts_with(p))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Anonymous,
    Session,
    Bearer,
    Password,
    AccessToken,
    /// A robot signed in with an OIDC token from a trusted issuer (keyless).
    Federated,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: Option<i64>,
    pub username: Option<String>,
    /// For personal robots: the user who owns them. Robots never inherit their owner's access.
    pub owner: Option<String>,
    pub is_robot: bool,
    pub is_mfa_enabled: bool,
    pub is_managed: bool,
    pub method: AuthMethod,
    pub session_id: Option<String>,
    pub roles: Vec<Arc<Role>>,
    /// Team memberships: role and base permission inside the team's organization.
    pub teams: Vec<TeamGrant>,
    /// Explicit repository grants (direct or through a team), strongest level per repository.
    pub repo_grants: Arc<HashMap<String, Level>>,
    /// Repositories that have content; Creator teams may push only to repositories not in it.
    pub known_repos: Arc<HashSet<String>>,
    /// Pull-through cache namespaces and whether anonymous pulls are allowed.
    pub proxies: Arc<HashMap<String, bool>>,
    /// Scoped credentials (bearer tokens, scoped access tokens) can only do what both the
    /// roles and this restriction allow.
    pub restrict: Option<Vec<Rule>>,
    pub restrict_global: Option<Vec<Global>>,
    /// Auth is_disabled: everything is allowed.
    pub is_superuser: bool,
    /// Globs from the config file.
    pub public_repositories: Arc<Vec<String>>,
    /// Repositories marked public in the catalogue.
    pub public_repos: Arc<HashSet<String>>,
}

impl Principal {
    pub fn name(&self) -> &str {
        self.username.as_deref().unwrap_or("anonymous")
    }

    pub fn allowed(&self, action: Action, repository: &str) -> bool {
        if self.is_superuser {
            return true;
        }
        if let Some(r) = &self.restrict {
            if !kontainer_core::perm::rules_grant(r, action, repository) {
                return false;
            }
        }
        if action == Action::Pull && (self.public_repos.contains(repository) || glob::any_matches(self.public_repositories.iter(), repository)) {
            return true;
        }
        // Pull-through caches: anyone signed in pulls (everyone if public); only instance
        // roles may do more, since the content belongs to the upstream.
        if let Some(is_public) = repository.split_once('/').and_then(|(ns, _)| self.proxies.get(ns)) {
            if action == Action::Pull && (*is_public || self.is_authenticated()) {
                return true;
            }
            return self.roles.iter().any(|r| r.allows(action, repository));
        }
        if self.in_personal_namespace(repository) {
            return true;
        }
        self.roles.iter().any(|r| r.allows(action, repository))
            || self.teams.iter().any(|t| t.allows(action, repository))
            || self.repo_grants.get(repository).is_some_and(|l| l.grants(action))
            || self.may_create(action, repository)
    }

    /// May do `action` on every repository the glob `pattern` could match: what it takes to hand
    /// that permission out. Counts roles, teams, the personal namespace and repository grants;
    /// public repositories and pull-through caches give nothing to grant.
    pub fn covers(&self, action: Action, pattern: &str) -> bool {
        if self.is_superuser {
            return true;
        }
        if let Some(r) = &self.restrict {
            if !kontainer_core::perm::rules_cover(r, action, pattern) {
                return false;
            }
        }
        let personal = match self.username.as_ref() {
            Some(u) if !self.is_robot => kontainer_core::perm::covers(&format!("{u}/**"), pattern),
            _ => false,
        };
        personal
            || self.roles.iter().any(|r| r.global.contains(&Global::System) || kontainer_core::perm::rules_cover(&r.rules, action, pattern))
            || self.teams.iter().any(|t| (t.role == TeamRole::Admin || t.base.is_some_and(|l| l.grants(action))) && kontainer_core::perm::covers(&format!("{}/**", t.org), pattern))
            || self.repo_grants.iter().any(|(repo, l)| l.grants(action) && kontainer_core::perm::covers(repo, pattern))
    }

    /// Creator (and admin) teams may push a repository into existence in their org.
    fn may_create(&self, action: Action, repository: &str) -> bool {
        action == Action::Push
            && !self.known_repos.contains(repository)
            && self.teams.iter().any(|t| t.role >= TeamRole::Creator && t.covers(repository))
    }

    /// True when a push to this repository is allowed only because it creates it; the
    /// pusher then becomes the repository's admin.
    pub fn creates(&self, repository: &str) -> bool {
        !self.known_repos.contains(repository)
            && !self.in_personal_namespace(repository)
            && self.teams.iter().any(|t| t.role == TeamRole::Creator && t.covers(repository))
    }

    /// Every human user owns the `<username>/` namespace. Robots own nothing.
    pub fn in_personal_namespace(&self, repository: &str) -> bool {
        match self.username.as_ref() {
            Some(u) if !self.is_robot => repository.strip_prefix(u.as_str()).is_some_and(|r| r.starts_with('/')),
            _ => false,
        }
    }

    /// May manage the organization's teams, members and robots.
    pub fn is_org_admin(&self, org: &str) -> bool {
        self.has_global(Global::UsersWrite) || self.teams.iter().any(|t| t.org == org && t.role == TeamRole::Admin)
    }

    pub fn org_member(&self, org: &str) -> bool {
        self.has_global(Global::UsersRead) || self.is_on_org_team(org)
    }

    /// On one of the organization's teams; unlike [`Self::org_member`], admin roles don't count.
    pub fn is_on_org_team(&self, org: &str) -> bool {
        self.teams.iter().any(|t| t.org == org)
    }

    pub fn has_global(&self, g: Global) -> bool {
        if self.is_superuser {
            return true;
        }
        // Personal robots are repository credentials only; they never manage users or roles.
        if self.owner.is_some() && !matches!(g, Global::Catalog) {
            return false;
        }
        if let Some(r) = &self.restrict_global {
            if !r.contains(&g) && !r.contains(&Global::System) {
                return false;
            }
        }
        self.roles.iter().any(|r| r.has_global(g))
    }

    pub fn is_admin(&self) -> bool {
        self.has_global(Global::System)
    }

    /// Repositories visible to this principal (catalog, UI listing).
    pub fn can_see(&self, repository: &str) -> bool {
        self.allowed(Action::Pull, repository) || self.has_global(Global::Catalog)
    }

    pub fn actions_on(&self, repository: &str) -> Vec<Action> {
        Action::ALL.into_iter().filter(|a| self.allowed(*a, repository)).collect()
    }

    pub fn globals(&self) -> Vec<Global> {
        Global::ALL.into_iter().filter(|g| self.has_global(*g)).collect()
    }

    pub fn is_authenticated(&self) -> bool {
        self.user_id.is_some()
    }
}

pub struct Authenticator {
    pub db: Db,
    pub mode: AuthMode,
    pub realm: String,
    pub service: String,
    pub public_url: String,
    pub session_ttl: chrono::Duration,
    pub token_ttl: chrono::Duration,
    pub oidc: Option<oidc::Oidc>,
    pub federation: federation::Federation,
    pub ldap: Option<kontainer_core::config::LdapConfig>,
    /// Passkey sign-in; `None` when `public_url` cannot be a WebAuthn relying party.
    pub passkeys: Option<passkey::Passkeys>,
    /// Organizations' own providers, rebuilt when their settings change.
    org_oidc: tokio::sync::Mutex<HashMap<i64, OrgOidc>>,
    anonymous_roles: Vec<String>,
    public_repositories: Arc<Vec<String>>,
    caches: Arc<Caches>,
    /// This process's `LISTEN` connection; the caches follow its notifications.
    listener: Listener,
    /// Applies notifications and periodic reloads to `caches`; stopped when dropped.
    _watcher: AbortOnDrop,
    enc: EncodingKey,
    dec: DecodingKey,
    /// Keys recovery-code hashes to this instance's secret.
    pub recovery_key: mfa::RecoveryKey,
    limiter: limits::LoginLimiter,
    basic_cache: limits::BasicCache,
}

impl Authenticator {
    pub async fn new(cfg: &Config) -> Result<Self> {
        let db = Db::open(cfg.auth.database_url.expose(), cfg.auth.database_pool).await?;
        let secret = match &cfg.auth.secret {
            Some(s) => s.expose().to_string(),
            None => match db.meta_get("jwt_secret").await? {
                Some(s) => s,
                // Instances booting together each propose one; the first written wins for all.
                None => db.meta_init("jwt_secret", &kontainer_core::random_token(32)).await?,
            },
        };
        // Listening before the caches are first loaded, so no change in between is missed.
        let listener = Listener::start(cfg.auth.database_url.expose()).await?;
        let caches = Arc::new(Caches::new(db.clone()));
        let watcher = AbortOnDrop(tokio::spawn(watch(caches.clone(), listener.subscribe())));
        if cfg.auth.mode == AuthMode::None {
            tracing::warn!(bind = %cfg.server.bind, "auth.mode = \"none\": every request is treated as a superuser");
        }
        let oidc = if cfg.auth.oidc.is_enabled { Some(oidc::Oidc::new(&cfg.auth.oidc, &cfg.public_url())?) } else { None };
        let passkeys = match passkey::Passkeys::new(&cfg.public_url(), &cfg.auth.realm, secret.as_bytes()) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "passkeys are unavailable");
                None
            }
        };
        let me = Self {
            db: db.clone(),
            mode: cfg.auth.mode,
            realm: cfg.auth.realm.clone(),
            service: cfg.service_name(),
            public_url: cfg.public_url(),
            session_ttl: chrono::Duration::from_std(cfg.auth.session_ttl)?,
            token_ttl: chrono::Duration::from_std(cfg.auth.token_ttl)?,
            oidc,
            federation: federation::Federation::new(cfg.service_name())?,
            ldap: cfg.auth.ldap.is_enabled.then(|| cfg.auth.ldap.clone()),
            passkeys,
            org_oidc: tokio::sync::Mutex::new(HashMap::new()),
            anonymous_roles: cfg.auth.anonymous_roles.clone(),
            public_repositories: Arc::new(cfg.auth.public_repositories.clone()),
            caches,
            listener,
            _watcher: watcher,
            enc: EncodingKey::from_secret(secret.as_bytes()),
            dec: DecodingKey::from_secret(secret.as_bytes()),
            recovery_key: mfa::RecoveryKey::derive(secret.as_bytes()),
            limiter: limits::LoginLimiter::new(db.clone()),
            basic_cache: limits::BasicCache::default(),
        };
        me.sync_config(cfg).await?;
        me.reload_roles().await?;
        me.refresh_public_repos().await?;
        me.refresh_proxies().await?;
        Ok(me)
    }

    /// Sync config-defined roles and users into the database; bootstrap an admin if needed.
    async fn sync_config(&self, cfg: &Config) -> Result<()> {
        let names: Vec<String> = cfg.auth.roles.iter().map(|r| r.name.clone()).collect();
        for r in &cfg.auth.roles {
            self.db.upsert_role(&Role { is_managed: true, ..r.clone() }).await?;
        }
        self.db.prune_managed_roles(&names).await?;
        for u in &cfg.auth.users {
            let hash = match (&u.password_hash, &u.password) {
                (Some(h), _) => h.clone(),
                (None, Some(p)) => password::hash_async(p.expose()).await?,
                (None, None) => unreachable!("validated"),
            };
            let user = match self.db.user_by_name(&u.username).await? {
                Some(existing) => {
                    self.db.set_password(existing.id, Some(&hash)).await?;
                    self.db.set_managed(existing.id, true).await?;
                    self.db.update_user(existing.id, u.email.as_deref(), None, None).await?;
                    existing
                }
                None => self.db.create_user(&u.username, Some(&hash), u.email.as_deref(), None, u.is_robot, None, true).await?,
            };
            self.db.set_user_roles(user.id, &u.roles).await?;
        }
        if self.db.count_users().await? == 0 {
            if let Some(b) = &cfg.auth.bootstrap_admin {
                self.ensure_system_role().await?;
                let user = self.db.create_user(&b.username, Some(&password::hash_async(b.password.expose()).await?), None, Some("Administrator"), false, None, false).await?;
                self.db.set_user_roles(user.id, &["system".to_string()]).await?;
                tracing::warn!(username = %b.username, "created bootstrap admin account; change its password");
            } else if cfg.auth.mode != AuthMode::None {
                tracing::warn!("auth enabled but no users exist: set auth.bootstrap_admin or run `kontainer user create --system <name>`");
            }
        }
        Ok(())
    }

    /// The built-in `system` role (is_superuser). Created on demand.
    pub async fn ensure_system_role(&self) -> Result<()> {
        if self.db.get_role("system").await?.is_none() {
            self.db
                .upsert_role(&Role {
                    name: "system".into(),
                    description: "Superuser: every permission on everything".into(),
                    rules: vec![],
                    global: vec![Global::System],
                    is_managed: false,
                })
                .await?;
            self.reload_roles().await?;
        }
        Ok(())
    }

    /// Reload role definitions here. (The write that changed them notified every instance.)
    pub async fn reload_roles(&self) -> Result<()> {
        self.caches.reload_roles().await
    }

    pub async fn refresh_public_repos(&self) -> Result<()> {
        self.caches.refresh_public_repos().await
    }

    pub async fn proxies_contains(&self, namespace: &str) -> bool {
        self.caches.proxies.read().await.contains_key(namespace)
    }

    pub async fn refresh_proxies(&self) -> Result<()> {
        self.caches.refresh_proxies().await
    }

    /// The storage the set of repositories with content is checked against. Set once, at
    /// startup; without it, the set is only what [`Self::set_known_repos`] and
    /// [`Self::note_repo`] say.
    pub fn set_storage(&self, storage: kontainer_store::Storage) {
        let _ = self.caches.storage.set(storage);
    }

    /// Replace the set of repositories that have content (startup, namespace renames).
    pub async fn set_known_repos(&self, repos: impl IntoIterator<Item = String>) {
        *self.caches.known_repos.write().await = Arc::new(repos.into_iter().collect());
    }

    /// Record a repository's first manifest or its deletion, and tell the other instances.
    pub async fn note_repo(&self, repository: &str, exists: bool) {
        if self.caches.set_known(repository, exists).await {
            self.db.notify(&Topic::Repo(repository.to_string())).await;
        }
    }

    /// Before deciding that a push creates `repository` (a Creator team's right, which also
    /// makes the pusher its admin): if it is missing from this instance's set, look in storage,
    /// so a set that has not caught up with another instance yet cannot pass an existing
    /// repository off as new. Updates `p` (and the set) when it does exist.
    pub async fn confirm_new_repo(&self, p: &mut Principal, repository: &str) -> Result<()> {
        if p.known_repos.contains(repository) || !p.teams.iter().any(|t| t.role >= TeamRole::Creator && t.covers(repository)) {
            return Ok(());
        }
        if self.caches.recheck_repo(repository).await? == Some(true) {
            p.known_repos = self.caches.known_repos.read().await.clone();
        }
        Ok(())
    }

    /// Changes announced by any instance ([`Topic`]s), for other in-memory state that follows
    /// them (the search index).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Topic> {
        self.listener.subscribe()
    }

    /// Build log chunks appended on any instance (see [`crate::build::logs`]).
    pub fn subscribe_build_logs(&self) -> tokio::sync::broadcast::Receiver<crate::database::notify::LogNote> {
        self.listener.subscribe_build_logs()
    }

    async fn public_repos(&self) -> Arc<HashSet<String>> {
        self.caches.public_repos.read().await.clone()
    }

    pub async fn roles(&self) -> Arc<HashMap<String, Arc<Role>>> {
        self.caches.roles.read().await.clone()
    }

    async fn resolve_roles(&self, names: &[String]) -> Vec<Arc<Role>> {
        let map = self.roles().await;
        names.iter().filter_map(|n| map.get(n).cloned()).collect()
    }

    /// The principal for unauthenticated requests: `anonymous_roles`, public repositories.
    pub async fn anonymous(&self) -> Principal {
        Principal {
            user_id: None,
            username: None,
            owner: None,
            is_robot: false,
            is_mfa_enabled: false,
            is_managed: false,
            method: AuthMethod::Anonymous,
            session_id: None,
            roles: self.resolve_roles(&self.anonymous_roles).await,
            teams: vec![],
            repo_grants: Arc::default(),
            known_repos: self.caches.known_repos.read().await.clone(),
            proxies: self.caches.proxies.read().await.clone(),
            restrict: None,
            restrict_global: None,
            is_superuser: self.mode == AuthMode::None && self.anonymous_roles.is_empty(),
            public_repositories: self.public_repositories.clone(),
            public_repos: self.public_repos().await,
        }
    }

    pub async fn principal_for(&self, user: &User, method: AuthMethod) -> Result<Principal> {
        // Robots (personal `alice+ci` or org `acme+ci`) have only what was granted to them:
        // repository grants and team memberships. They never inherit their owner's access.
        let owner = match (user.is_robot, user.owner_id) {
            (true, Some(oid)) => self.db.user_by_id(oid).await?,
            _ => None,
        };
        let roles = self.db.user_roles(user.id).await?;
        let teams = self.db.team_grants(user.id).await?;
        let repo_grants = Arc::new(self.db.effective_repo_grants(user.id).await?);
        Ok(Principal {
            user_id: Some(user.id),
            username: Some(user.username.clone()),
            owner: owner.map(|o| o.username),
            is_robot: user.is_robot,
            is_mfa_enabled: user.is_mfa_enabled,
            is_managed: user.is_managed,
            method,
            session_id: None,
            roles: self.resolve_roles(&roles).await,
            teams,
            repo_grants,
            known_repos: self.caches.known_repos.read().await.clone(),
            proxies: self.caches.proxies.read().await.clone(),
            restrict: None,
            restrict_global: None,
            is_superuser: false,
            public_repositories: self.public_repositories.clone(),
            public_repos: self.public_repos().await,
        })
    }

    /// 401 with the right `WWW-Authenticate` for the configured mode. `scope` is the
    /// `repository:<name>:<action>` the client should request a token for.
    pub fn unauthorized(&self, scope: Option<String>) -> RegistryError {
        let challenge = match self.mode {
            AuthMode::Token => {
                let mut c = format!("Bearer realm=\"{}/auth/token\",service=\"{}\"", self.public_url, self.service);
                if let Some(s) = scope {
                    c.push_str(&format!(",scope=\"{s}\""));
                }
                c
            }
            _ => format!("Basic realm=\"{}\"", self.realm),
        };
        RegistryError::new(Code::Unauthorized).header("WWW-Authenticate", challenge)
    }

    /// Failed authorization: 401 for anonymous callers (so clients prompt for credentials),
    /// 403 for authenticated ones.
    pub fn denied(&self, principal: &Principal, scope: Option<String>) -> RegistryError {
        if !principal.is_authenticated() && self.mode != AuthMode::None {
            self.unauthorized(scope)
        } else if principal.method == AuthMethod::Bearer && principal.restrict.is_some() && scope.is_some() {
            // A scoped token that lacks this scope: 401 naming it, as the token auth spec and
            // distribution do, so the client fetches a wider token. A user who really lacks the
            // permission gets a token without that scope and fails the same way on the retry.
            self.unauthorized(scope)
        } else {
            RegistryError::new(Code::Denied)
        }
    }

    /// Resolve the principal for a request from its headers. `ip`: the client's address, for
    /// brute-force limits.
    pub async fn authenticate(&self, headers: &HeaderMap, ip: Option<&str>) -> Result<Principal, RegistryError> {
        if let Some(sid) = cookie(headers, SESSION_COOKIE) {
            if let Some(session) = self.db.session(&sid).await? {
                if let Some(user) = self.db.user_by_id(session.user_id).await? {
                    if !user.is_disabled {
                        let mut p = self.principal_for(&user, AuthMethod::Session).await?;
                        p.session_id = Some(sid);
                        return Ok(p);
                    }
                }
            }
            // A stale cookie is simply ignored.
        }
        let Some(authz) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
            return Ok(self.anonymous().await);
        };
        if let Some(t) = authz.strip_prefix("Bearer ").or_else(|| authz.strip_prefix("bearer ")) {
            return self.authenticate_bearer(t.trim()).await;
        }
        self.authenticate_basic_header(authz, ip).await
    }

    /// `ip`: the client's address, for brute-force limits.
    pub async fn authenticate_basic_header(&self, authz: &str, ip: Option<&str>) -> Result<Principal, RegistryError> {
        let Some(encoded) = authz.strip_prefix("Basic ").or_else(|| authz.strip_prefix("basic ")) else {
            return Err(self.unauthorized(None));
        };
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).map_err(|_| self.unauthorized(None))?;
        let decoded = String::from_utf8(decoded).map_err(|_| self.unauthorized(None))?;
        let (user, secret) = decoded.split_once(':').ok_or_else(|| self.unauthorized(None))?;
        self.authenticate_basic(user, secret, ip).await
    }

    /// Username + password, or username + personal access token. `ip`: the client's address,
    /// for brute-force limits.
    pub async fn authenticate_basic(&self, username: &str, secret: &str, ip: Option<&str>) -> Result<Principal, RegistryError> {
        let unauthorized = || self.unauthorized(None);
        if is_access_token(secret) {
            let Some(tok) = self.db.token_by_hash(&sha256_hex(secret)).await? else { return Err(unauthorized()) };
            if tok.expired() {
                return Err(RegistryError::with_message(Code::Unauthorized, "access token expired").header("WWW-Authenticate", self.unauthorized(None).headers[0].1.clone()));
            }
            let Some(user) = self.db.user_by_id(tok.user_id).await? else { return Err(unauthorized()) };
            if user.is_disabled || (user.username != username && !username.is_empty() && username != "$token") {
                return Err(unauthorized());
            }
            self.db.touch_token(tok.id).await?;
            let mut p = self.principal_for(&user, AuthMethod::AccessToken).await?;
            // Scopes that cannot be read deny the token; they never mean "unrestricted".
            p.restrict = match tok.scope_rules() {
                Ok(rules) => rules,
                Err(e) => {
                    tracing::warn!(token = tok.id, error = %e, "refusing an access token whose scopes cannot be read");
                    return Err(unauthorized());
                }
            };
            return Ok(p);
        }
        // Keyless robot login: the CI's OIDC token in place of the credential.
        if federation::looks_like_jwt(secret) {
            let robot = self.db.user_by_name(username).await?.filter(|u| u.is_robot && !u.is_disabled).ok_or_else(unauthorized)?;
            return match self.federation.verify(&self.db, robot.id, secret).await {
                Ok(claims) => {
                    tracing::info!(robot = %robot.username, iss = %claims.iss, sub = %claims.sub, "federated robot login");
                    self.principal_for(&robot, AuthMethod::Federated).await.map_err(Into::into)
                }
                Err(e) => {
                    tracing::info!(robot = %robot.username, error = %e, "federated robot login refused");
                    Err(RegistryError::with_message(Code::Unauthorized, format!("OIDC token refused: {e}")).header("WWW-Authenticate", self.unauthorized(None).headers[0].1.clone()))
                }
            };
        }
        let user = self.verify_password(username, secret, ip).await?.ok_or_else(unauthorized)?;
        if user.is_mfa_enabled {
            return Err(RegistryError::with_message(
                Code::Unauthorized,
                "this account has two-factor authentication enabled: sign in with a personal access token instead of your password",
            )
            .header("WWW-Authenticate", self.unauthorized(None).headers[0].1.clone()));
        }
        self.principal_for(&user, AuthMethod::Password).await.map_err(Into::into)
    }

    /// Check a password, within the brute-force limits for `username` and `ip` (the client's
    /// address). Returns the user when correct and not disabled; a correct password clears the
    /// account's failures.
    pub async fn verify_password(&self, username: &str, password: &str, ip: Option<&str>) -> Result<Option<User>, RegistryError> {
        let user = self.check_password_limited(username, password, ip).await?;
        if user.is_some() {
            self.limiter.succeed(username).await?;
        }
        Ok(user)
    }

    /// [`verify_password`](Self::verify_password) for the first step of a sign-in that may still
    /// need a second factor: a correct password does not clear the account's failures, so wrong
    /// one-time codes keep counting. Call [`login_succeeded`](Self::login_succeeded) once every
    /// step has passed.
    pub async fn verify_password_step(&self, username: &str, password: &str, ip: Option<&str>) -> Result<Option<User>, RegistryError> {
        self.check_password_limited(username, password, ip).await
    }

    /// 429 while the account (when known) or `ip` is locked out: for sign-ins that may not name
    /// an account up front (passkeys).
    pub async fn throttle_login(&self, username: Option<&str>, ip: Option<&str>) -> Result<(), RegistryError> {
        self.limiter.check_any(username, ip).await?.map_err(|wait| {
            tracing::info!(username, ip, "sign-in refused: too many failed attempts");
            RegistryError::with_message(Code::TooManyRequests, "too many failed sign-in attempts; try again later").header("Retry-After", wait.as_secs().max(1).to_string())
        })
    }

    /// Count a failed sign-in against the account (when known) and `ip`.
    pub async fn login_failed(&self, username: Option<&str>, ip: Option<&str>) -> Result<()> {
        self.limiter.fail_any(username, ip).await
    }

    /// A complete sign-in: clear `username`'s failed attempts.
    pub async fn login_succeeded(&self, username: &str) -> Result<()> {
        self.limiter.succeed(username).await
    }

    async fn check_password_limited(&self, username: &str, password: &str, ip: Option<&str>) -> Result<Option<User>, RegistryError> {
        if let Some((id, hash)) = self.basic_cache.get(username, password) {
            // Still the same account with the same password, and not disabled since.
            if let Some(user) = self.db.user_by_name(username).await?.filter(|u| u.id == id && u.password_hash.as_deref() == Some(hash.as_str()) && !u.is_disabled) {
                return Ok(Some(user));
            }
        }
        self.throttle(username, ip).await?;
        let user = self.check_password(username, password).await?;
        match &user {
            Some(u) => {
                if let Some(hash) = &u.password_hash {
                    self.basic_cache.insert(username, password, u.id, hash);
                }
            }
            None => self.limiter.fail(username, ip).await?,
        }
        Ok(user)
    }

    /// 429 while `username` or `ip` is locked out after too many failed attempts.
    async fn throttle(&self, username: &str, ip: Option<&str>) -> Result<(), RegistryError> {
        self.throttle_login(Some(username), ip).await
    }

    /// Check a one-time code from `user`'s authenticator app (each code works once), within the
    /// brute-force limits. A wrong code counts as a failed attempt; a right one clears them.
    pub async fn verify_otp(&self, user: &User, code: &str, ip: Option<&str>) -> Result<bool, RegistryError> {
        let Some(secret) = self.db.user_mfa_secret(user)? else {
            self.throttle(&user.username, ip).await?;
            return Ok(false);
        };
        self.verify_otp_with(user, &secret, code, ip).await
    }

    /// [`Self::verify_otp`] against `secret` rather than the account's own: the one being set up.
    pub async fn verify_otp_with(&self, user: &User, secret: &str, code: &str, ip: Option<&str>) -> Result<bool, RegistryError> {
        self.throttle(&user.username, ip).await?;
        let ok = mfa::verify_once(&self.db, user.id, secret, &self.realm, &user.username, code).await?;
        if ok { self.limiter.succeed(&user.username).await? } else { self.limiter.fail(&user.username, ip).await? }
        Ok(ok)
    }

    /// Consume one of `user`'s recovery codes, within the brute-force limits.
    pub async fn use_recovery_code(&self, user: &User, code: &str, ip: Option<&str>) -> Result<bool, RegistryError> {
        self.throttle(&user.username, ip).await?;
        let ok = mfa::use_recovery_code(&self.db, &self.recovery_key, user.id, code).await?;
        if ok { self.limiter.succeed(&user.username).await? } else { self.limiter.fail(&user.username, ip).await? }
        Ok(ok)
    }

    async fn check_password(&self, username: &str, password: &str) -> Result<Option<User>> {
        let user = self.db.user_by_name(username).await?;
        // Directory accounts: anyone without a local password (and never robots).
        if let Some(cfg) = &self.ldap {
            if user.as_ref().is_none_or(|u| u.password_hash.is_none() && !u.is_robot) {
                return self.verify_ldap(cfg, username, password).await;
            }
        }
        // Always run a hash so missing users / passwordless accounts are not distinguishable
        // by latency.
        let ok = password::verify_async(password, user.as_ref().and_then(|u| u.password_hash.clone())).await?;
        Ok(user.filter(|u| ok && u.password_hash.is_some() && !u.is_disabled))
    }

    /// The OIDC client for an organization's own provider, if it has one.
    pub async fn org_oidc(&self, org_id: i64, org: &str) -> Result<Option<Arc<oidc::Oidc>>> {
        let Some(s) = self.db.org_sso(org_id).await? else { return Ok(None) };
        let mut cache = self.org_oidc.lock().await;
        if let Some((at, o)) = cache.get(&org_id) {
            if *at == s.updated_at {
                return Ok(Some(o.clone()));
            }
        }
        let cfg = kontainer_core::config::OidcConfig {
            is_enabled: true,
            display_name: s.display_name.clone(),
            issuer: s.issuer.clone(),
            client_id: s.client_id.clone(),
            client_secret: s.client_secret.clone().into(),
            redirect_url: Some(format!("{}/auth/oidc/orgs/{org}/callback", self.public_url.trim_end_matches('/'))),
            groups_claim: s.groups_claim.clone(),
            ..Default::default()
        };
        let o = Arc::new(oidc::Oidc::new(&cfg, &self.public_url)?);
        cache.insert(org_id, (s.updated_at, o.clone()));
        Ok(Some(o))
    }

    async fn verify_ldap(&self, cfg: &kontainer_core::config::LdapConfig, username: &str, password: &str) -> Result<Option<User>> {
        let lu = match ldap::authenticate(cfg, username, password).await {
            Ok(Some(lu)) => lu,
            Ok(None) => return Ok(None),
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "LDAP sign-in failed");
                return Ok(None);
            }
        };
        let id = sso::Identity { provider: "ldap", subject: &lu.dn, username: &lu.username, email: lu.email.as_deref(), name: lu.name.as_deref() };
        let Some(user) = sso::provision(&self.db, &id, sso::Matching::ByUsername, true, &cfg.default_roles, None).await? else { return Ok(None) };
        if user.is_disabled {
            return Ok(None);
        }
        sso::sync_roles(&self.db, user.id, &cfg.group_roles, &lu.groups).await?;
        sso::sync_teams(&self.db, user.id, "ldap", None, &lu.groups).await?;
        Ok(Some(user))
    }

    async fn authenticate_bearer(&self, jwt: &str) -> Result<Principal, RegistryError> {
        let mut v = Validation::default();
        v.set_audience(&[self.service.as_str()]);
        v.set_issuer(&[self.public_url.as_str()]);
        let claims = jsonwebtoken::decode::<token::Claims>(jwt, &self.dec, &v)?.claims;
        let (rules, globals) = token::restriction(&claims.access);
        let mut p = if claims.svc.as_deref() == Some(token::SVC_SCANNER) && claims.uid == 0 {
            // The scanner may pull exactly what `access` lists: a role granting pull everywhere,
            // cut down by the restriction below.
            let mut p = self.anonymous().await;
            p.username = Some(token::SVC_SCANNER.to_string());
            p.is_superuser = false;
            p.roles = vec![Arc::new(Role { name: token::SVC_SCANNER.into(), description: "internal scanner".into(), rules: vec![Rule { repositories: vec!["**".into()], actions: vec![Action::Pull] }], global: vec![], is_managed: true })];
            p
        } else if claims.uid == 0 {
            self.anonymous().await
        } else {
            let Some(user) = self.db.user_by_id(claims.uid).await? else { return Err(self.unauthorized(None)) };
            if user.is_disabled {
                return Err(self.unauthorized(None));
            }
            self.principal_for(&user, AuthMethod::Bearer).await?
        };
        p.restrict = Some(rules);
        p.restrict_global = Some(globals);
        Ok(p)
    }

    pub fn issue_token(&self, principal: &Principal, service: &str, access: Vec<token::Access>) -> Result<(String, u64, String)> {
        let now = Utc::now();
        let claims = token::Claims {
            iss: self.public_url.clone(),
            sub: principal.name().to_string(),
            aud: service.to_string(),
            exp: (now + self.token_ttl).timestamp(),
            nbf: now.timestamp() - 5,
            iat: now.timestamp(),
            jti: kontainer_core::random_token(8),
            uid: principal.user_id.unwrap_or(0),
            access,
            svc: None,
        };
        let jwt = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &self.enc).context("signing token")?;
        Ok((jwt, self.token_ttl.num_seconds() as u64, now.to_rfc3339()))
    }

    /// A short-lived token for the bundled scanner to pull one repository: no account behind it,
    /// so there is nothing to configure, leak or lock out.
    pub fn issue_scanner_token(&self, repository: &str) -> Result<String> {
        let now = Utc::now();
        let claims = token::Claims {
            iss: self.public_url.clone(),
            sub: token::SVC_SCANNER.to_string(),
            aud: self.service.clone(),
            exp: (now + self.token_ttl).timestamp(),
            nbf: now.timestamp() - 5,
            iat: now.timestamp(),
            jti: kontainer_core::random_token(8),
            uid: 0,
            access: vec![token::Access { kind: "repository".into(), name: repository.to_string(), actions: vec!["pull".into()] }],
            svc: Some(token::SVC_SCANNER.to_string()),
        };
        jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &self.enc).context("signing scanner token")
    }

    /// `ip`: the client's address ([`client_ip::ClientIp`]), shown in the session list.
    pub async fn create_session(&self, user: &User, headers: &HeaderMap, ip: Option<&str>) -> Result<crate::database::Session> {
        let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|s| s.chars().take(200).collect::<String>());
        self.db.touch_login(user.id).await?;
        self.db.create_session(user.id, self.session_ttl, ua.as_deref(), ip).await
    }

    /// The session cookie: `SameSite=Strict`, so no request another site starts (a link, a
    /// form, a top-level navigation) carries it. Single sign-on still works: the callback that
    /// sets it is reached cross-site, but the browser then goes on to `/...`, whose API calls
    /// are same-site. Linking an identity, the one callback that needs the signed-in account,
    /// uses [`Self::oidc_link_cookie`] instead.
    pub fn session_cookie(&self, id: &str) -> String {
        let secure = if self.public_url.starts_with("https://") { "; Secure" } else { "" };
        format!("{SESSION_COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}", self.session_ttl.num_seconds())
    }

    pub fn clear_cookie(&self) -> String {
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
    }

    /// The cookie binding an OIDC login to this browser ([`oidc::LOGIN_COOKIE`]). Lax, so the
    /// provider's top-level redirect back carries it; it lives as long as a login state does.
    pub fn oidc_login_cookie(&self, nonce: &str) -> String {
        let secure = if self.public_url.starts_with("https://") { "; Secure" } else { "" };
        format!("{}={nonce}; Path=/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=900{secure}", oidc::LOGIN_COOKIE)
    }

    pub fn clear_oidc_login_cookie(&self) -> String {
        format!("{}=; Path=/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=0", oidc::LOGIN_COOKIE)
    }

    /// The cookie proving, at a link's callback, that this browser holds the session that
    /// started the link ([`oidc::LINK_COOKIE`]). Lax and scoped to `/auth/oidc` like the login
    /// cookie; it lives as long as a login state does.
    pub fn oidc_link_cookie(&self, token: &str) -> String {
        let secure = if self.public_url.starts_with("https://") { "; Secure" } else { "" };
        format!("{}={token}; Path=/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=900{secure}", oidc::LINK_COOKIE)
    }

    pub fn clear_oidc_link_cookie(&self) -> String {
        format!("{}=; Path=/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=0", oidc::LINK_COOKIE)
    }

    /// Generate a personal access token for `user`. Returns the plaintext (shown once).
    pub async fn create_access_token(&self, user_id: i64, name: &str, scopes: Option<&[Rule]>, expires_at: Option<chrono::DateTime<Utc>>) -> Result<(String, crate::database::AccessToken)> {
        let plain = format!("{TOKEN_PREFIX}{}", kontainer_core::random_token(24));
        let tok = self.db.create_token(user_id, name, &plain[..12], &sha256_hex(&plain), scopes, expires_at).await?;
        Ok((plain, tok))
    }
}

/// Aborts a task when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The in-memory state authorization reads on every request (see the module docs).
struct Caches {
    db: Db,
    roles: RwLock<Arc<HashMap<String, Arc<Role>>>>,
    public_repos: RwLock<Arc<HashSet<String>>>,
    proxies: RwLock<Arc<HashMap<String, bool>>>,
    /// Repositories that have content.
    known_repos: RwLock<Arc<HashSet<String>>>,
    storage: OnceLock<kontainer_store::Storage>,
}

impl Caches {
    fn new(db: Db) -> Self {
        Self { db, roles: RwLock::default(), public_repos: RwLock::default(), proxies: RwLock::default(), known_repos: RwLock::default(), storage: OnceLock::new() }
    }

    async fn reload_roles(&self) -> Result<()> {
        let map: HashMap<String, Arc<Role>> = self.db.list_roles().await?.into_iter().map(|r| (r.name.clone(), Arc::new(r))).collect();
        *self.roles.write().await = Arc::new(map);
        Ok(())
    }

    async fn refresh_public_repos(&self) -> Result<()> {
        let set: HashSet<String> = self.db.public_repos().await?.into_iter().collect();
        *self.public_repos.write().await = Arc::new(set);
        Ok(())
    }

    async fn refresh_proxies(&self) -> Result<()> {
        let map: HashMap<String, bool> = self.db.proxy_caches().await?.into_iter().map(|p| (p.namespace, p.is_public)).collect();
        *self.proxies.write().await = Arc::new(map);
        Ok(())
    }

    /// Rebuild the set of repositories with content from the registry tables (when known).
    async fn reload_known_repos(&self) -> Result<()> {
        let Some(storage) = self.storage.get() else { return Ok(()) };
        let current = self.known_repos.read().await.clone();
        let with_manifests: HashSet<String> = storage.repositories_with_manifests().await?.into_iter().collect();
        let mut repos = HashSet::new();
        for name in storage.list_repositories().await? {
            // The listing also has repositories with layers but no manifest yet: one being
            // pushed into existence right now must not turn "known" (and refuse its creator's
            // manifest) before that manifest arrives.
            if current.contains(&name) || with_manifests.contains(&name) {
                repos.insert(name);
            }
        }
        *self.known_repos.write().await = Arc::new(repos);
        Ok(())
    }

    /// Ask storage whether `repository` has content, and record the answer. `None` without
    /// storage to ask.
    async fn recheck_repo(&self, repository: &str) -> Result<Option<bool>> {
        let Some(storage) = self.storage.get() else { return Ok(None) };
        let exists = storage.repository_exists(repository).await?;
        self.set_known(repository, exists).await;
        Ok(Some(exists))
    }

    /// Record whether `repository` has content; `true` when that changed the set.
    async fn set_known(&self, repository: &str, exists: bool) -> bool {
        let mut g = self.known_repos.write().await;
        if g.contains(repository) == exists {
            return false;
        }
        let mut next = (**g).clone();
        if exists { next.insert(repository.to_string()); } else { next.remove(repository); }
        *g = Arc::new(next);
        true
    }

    /// Reload what `topic` says changed.
    async fn apply(&self, topic: &Topic) {
        let result = match topic {
            Topic::Roles => self.reload_roles().await,
            Topic::PublicRepos => self.refresh_public_repos().await,
            Topic::Proxies => self.refresh_proxies().await,
            // Created, deleted, or its visibility changed.
            Topic::Repo(name) => match self.refresh_public_repos().await {
                Ok(()) => self.recheck_repo(name).await.map(|_| ()),
                Err(e) => Err(e),
            },
            Topic::Repos => match self.refresh_public_repos().await {
                Ok(()) => self.reload_known_repos().await,
                Err(e) => Err(e),
            },
            Topic::Resync => self.reload(true).await,
        };
        if let Err(e) = result {
            tracing::warn!(topic = %topic.payload(), error = %format!("{e:#}"), "reloading a cache after a change on another instance");
        }
    }

    /// Reload everything (the set of repositories with content only `with_known_repos`).
    async fn reload(&self, with_known_repos: bool) -> Result<()> {
        self.reload_roles().await?;
        self.refresh_public_repos().await?;
        self.refresh_proxies().await?;
        if with_known_repos {
            self.reload_known_repos().await?;
        }
        Ok(())
    }
}

/// Keep `caches` current: apply each notification, and reload on a timer as a safety net.
async fn watch(caches: Arc<Caches>, mut rx: tokio::sync::broadcast::Receiver<Topic>) {
    use tokio::sync::broadcast::error::RecvError;
    let mut tick = tokio::time::interval(CACHE_RELOAD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    let mut ticks = 0u32;
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Ok(topic) => caches.apply(&topic).await,
                // Too far behind to know what changed.
                Err(RecvError::Lagged(_)) => caches.apply(&Topic::Resync).await,
                Err(RecvError::Closed) => return,
            },
            _ = tick.tick() => {
                ticks = ticks.wrapping_add(1);
                if let Err(e) = caches.reload(ticks.is_multiple_of(KNOWN_REPOS_EVERY)).await {
                    tracing::warn!(error = %format!("{e:#}"), "reloading the authorization caches");
                }
            }
        }
    }
}

/// An organization's OIDC client, and the `org_sso.updated_at` it was built from.
type OrgOidc = (chrono::DateTime<Utc>, Arc<oidc::Oidc>);

/// The value of the request cookie `name`.
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

/// Middleware: authenticates the request and stores the [`Principal`] in request extensions.
pub async fn middleware(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let ip = req.extensions().get::<client_ip::ClientIp>().and_then(|c| c.0.clone());
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).map(str::to_string);
    let resp = match state.auth.authenticate(req.headers(), ip.as_deref()).await {
        Ok(principal) => {
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        Err(e) => axum::response::IntoResponse::into_response(e),
    };
    scanner_realm(&state, host.as_deref(), resp)
}

/// The host the bundled scanner reaches this registry at (`scanner.registry_host`, else
/// `127.0.0.1:<bind port>`, as the scanner module computes it).
pub fn scanner_host(state: &AppState) -> String {
    state.config.scanner.registry_host.clone().unwrap_or_else(|| format!("127.0.0.1:{}", state.config.server.bind.rsplit(':').next().unwrap_or("5000")))
}

/// A `401` answered to the bundled scanner names the scanner's own host in the token realm
/// rather than `public_url`. Trivy and grype refuse a realm on a loopback or private IP that
/// differs from the host they contacted (an SSRF guard), which is exactly the case when
/// `public_url` is an IP address or another port, so the challenge is rewritten for that one
/// client. Tokens are the same whichever realm issued them.
fn scanner_realm(state: &AppState, host: Option<&str>, mut resp: Response) -> Response {
    let Some(host) = host else { return resp };
    if resp.status() != StatusCode::UNAUTHORIZED || host != scanner_host(state) {
        return resp;
    }
    let scheme = if state.config.scanner.is_insecure { "http" } else { "https" };
    let public_realm = format!("realm=\"{}/auth/token\"", state.auth.public_url);
    let local_realm = format!("realm=\"{scheme}://{host}/auth/token\"");
    if let Some(v) = resp.headers().get(header::WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()) {
        if v.contains(&public_realm) {
            if let Ok(hv) = HeaderValue::from_str(&v.replace(&public_realm, &local_realm)) {
                resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
            }
        }
    }
    resp
}

/// Ensure the principal may perform `action` on `repository`.
pub fn require(state: &AppState, principal: &Principal, action: Action, repository: &str) -> Result<(), RegistryError> {
    if principal.allowed(action, repository) {
        Ok(())
    } else {
        tracing::debug!(user = principal.name(), ?action, repository, "access denied");
        let scope = format!("repository:{repository}:{}", match action {
            Action::Pull => "pull",
            Action::Push => "pull,push",
            Action::Delete | Action::DeleteRepository => "delete",
            _ => "pull",
        });
        Err(state.auth.denied(principal, Some(scope)))
    }
}

pub fn require_global(state: &AppState, principal: &Principal, g: Global) -> Result<(), RegistryError> {
    if principal.has_global(g) {
        Ok(())
    } else {
        Err(state.auth.denied(principal, None))
    }
}

/// Require a signed-in human account (not anonymous, not a robot).
pub fn require_user(state: &AppState, principal: &Principal) -> Result<i64, RegistryError> {
    match principal.user_id {
        Some(id) if !principal.is_robot => Ok(id),
        _ => Err(state.auth.denied(principal, None)),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kontainer_core::config::{AuthMode, Config};
    use kontainer_core::perm::{Action, Role, Rule};

    use super::Authenticator;
    use crate::database::test_support::fresh_database_url;

    #[test]
    fn access_token_prefixes() {
        assert!(super::is_access_token("kontainer_abc") && super::is_access_token("sauh_abc"));
        assert!(!super::is_access_token("hunter2") && !super::is_access_token("eyJhbGciOi.x.y"));
    }

    fn config(url: &str) -> Config {
        let mut cfg = Config::default();
        cfg.auth.database_url = url.to_string().into();
        cfg.auth.database_pool = 4;
        cfg.auth.mode = AuthMode::Token;
        cfg.server.public_url = Some("http://registry.test".into());
        cfg
    }

    /// Poll `check` for up to five seconds.
    async fn eventually<F, Fut>(mut check: F) -> bool
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        for _ in 0..250 {
            if check().await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_role_edited_on_one_instance_applies_on_the_other() {
        let url = fresh_database_url();
        let cfg = config(&url);
        let a = Authenticator::new(&cfg).await.unwrap();
        let b = Authenticator::new(&cfg).await.unwrap();
        let mut role = Role { name: "ci".into(), description: String::new(), rules: vec![Rule { repositories: vec!["team/**".into()], actions: vec![Action::Pull] }], global: vec![], is_managed: false };
        // What the roles API does: write, then reload on the instance that served the request.
        a.db.upsert_role(&role).await.unwrap();
        a.reload_roles().await.unwrap();
        assert!(eventually(|| async { b.roles().await.contains_key("ci") }).await, "a new role reaches the other instance");
        role.rules[0].actions.push(Action::Push);
        a.db.upsert_role(&role).await.unwrap();
        assert!(eventually(|| async { b.roles().await.get("ci").is_some_and(|r| r.allows(Action::Push, "team/app")) }).await, "and so does an edit");
        a.db.delete_role("ci").await.unwrap();
        assert!(eventually(|| async { !b.roles().await.contains_key("ci") }).await, "and a deletion");
    }

    #[tokio::test]
    async fn proxies_and_public_repositories_follow_other_instances() {
        let url = fresh_database_url();
        let cfg = config(&url);
        let (a, b) = (Authenticator::new(&cfg).await.unwrap(), Authenticator::new(&cfg).await.unwrap());
        let reg = a.db.create_registry(&crate::database::remote::RegistryInput { name: "hub".into(), url: "https://registry-1.docker.io".into(), username: None, password: None, is_insecure: false }).await.unwrap();
        a.db.set_proxy_cache("hub", reg.id, 60, true).await.unwrap();
        assert!(eventually(|| async { b.proxies_contains("hub").await }).await);
        let public = crate::database::repos::RepoMetaUpdate { visibility: Some(crate::database::Visibility::Public), ..Default::default() };
        a.db.upsert_repo_meta("acme/app", &public, crate::database::Visibility::Private).await.unwrap();
        assert!(eventually(|| async { b.anonymous().await.allowed(Action::Pull, "acme/app") }).await, "made public on a, pullable anonymously on b");
        a.db.delete_registry(reg.id).await.unwrap();
        assert!(eventually(|| async { !b.proxies_contains("hub").await }).await);
    }

    #[tokio::test]
    async fn instances_booting_together_agree_on_the_signing_secret() {
        let url = fresh_database_url();
        let cfg = config(&url);
        // An empty but migrated database, so no start waits for another's migrations: they all
        // find no secret and propose their own, at the same time.
        crate::database::Db::open(&url, 1).await.unwrap();
        let started = futures::future::join_all((0..6).map(|_| Authenticator::new(&cfg))).await;
        let instances: Vec<Authenticator> = started.into_iter().map(Result::unwrap).collect();
        let anon = instances[0].anonymous().await;
        for (i, signer) in instances.iter().enumerate() {
            let (jwt, _, _) = signer.issue_token(&anon, &signer.service, vec![]).unwrap();
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(axum::http::header::AUTHORIZATION, format!("Bearer {jwt}").parse().unwrap());
            for (j, verifier) in instances.iter().enumerate() {
                assert!(verifier.authenticate(&headers, None).await.is_ok(), "a token signed by instance {i} is refused by instance {j}");
            }
        }

        // The race itself, step by step, as `new` takes it: two instances have both looked and
        // found no secret; each now proposes its own.
        let url = fresh_database_url();
        let (x, y) = (crate::database::Db::open(&url, 1).await.unwrap(), crate::database::Db::open(&url, 1).await.unwrap());
        assert!(x.meta_get("jwt_secret").await.unwrap().is_none() && y.meta_get("jwt_secret").await.unwrap().is_none());
        let (sx, sy) = tokio::join!(x.meta_init("jwt_secret", "proposed-by-x"), y.meta_init("jwt_secret", "proposed-by-y"));
        let (sx, sy) = (sx.unwrap(), sy.unwrap());
        assert_eq!(sx, sy, "both use the secret that was stored first");
        assert_eq!(x.meta_get("jwt_secret").await.unwrap(), Some(sx));
    }
}
