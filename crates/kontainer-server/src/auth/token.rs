//! Docker-style bearer tokens (the `docker login` flow).
//!
//! Clients hitting `/v2/` get `WWW-Authenticate: Bearer realm=".../auth/token",service=...`.
//! They then call the realm with Basic credentials and the scopes they want
//! (`repository:<name>:pull,push`), and we return a short-lived JWT listing what was actually
//! granted. Requests to `/v2/` carrying that JWT are restricted to those grants.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use kontainer_core::perm::{Action, Global, Rule};
use super::Principal;
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Access {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub actions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    pub jti: String,
    /// Registry user id; 0 for anonymous.
    pub uid: i64,
    pub access: Vec<Access>,
    /// Internal service the registry minted this token for (`scanner`): no account, only
    /// `access`. Only the registry can mint it, since it alone holds the signing secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svc: Option<String>,
}

/// The internal scanner: pulls what its token names and nothing else.
pub const SVC_SCANNER: &str = "scanner";

/// Parse `repository:<name>:<actions>` / `registry:catalog:*` scopes.
pub fn parse_scope(scope: &str) -> Option<(String, String, Vec<String>)> {
    let mut parts = scope.splitn(3, ':');
    let kind = parts.next()?.to_string();
    let name = parts.next()?.to_string();
    let actions = parts.next().unwrap_or("").split(',').filter(|a| !a.is_empty()).map(str::to_string).collect();
    Some((kind, name, actions))
}

fn map_action(a: &str) -> Vec<Action> {
    match a {
        "pull" => vec![Action::Pull],
        "push" => vec![Action::Push],
        "delete" => vec![Action::Delete],
        "*" => vec![Action::Pull, Action::Push, Action::Delete],
        _ => vec![],
    }
}

/// Intersect requested scopes with what the principal may do.
pub fn grant(principal: &Principal, scopes: &[String]) -> Vec<Access> {
    let mut out = vec![];
    for s in scopes {
        let Some((kind, name, actions)) = parse_scope(s) else { continue };
        match kind.as_str() {
            "repository" => {
                let mut granted = vec![];
                for a in actions {
                    let ok = map_action(&a).iter().all(|act| principal.allowed(*act, &name)) && !map_action(&a).is_empty();
                    if ok {
                        granted.push(a);
                    }
                }
                if !granted.is_empty() {
                    out.push(Access { kind, name, actions: granted });
                }
            }
            "registry" if name == "catalog" && principal.has_global(Global::Catalog) => {
                out.push(Access { kind, name, actions: vec!["*".into()] });
            }
            _ => {}
        }
    }
    out
}

/// Convert JWT grants back into a restriction for the request principal.
pub fn restriction(access: &[Access]) -> (Vec<Rule>, Vec<Global>) {
    let mut rules = vec![];
    let mut globals = vec![];
    for a in access {
        match a.kind.as_str() {
            "repository" => rules.push(Rule {
                repositories: vec![a.name.clone()],
                actions: a.actions.iter().flat_map(|s| map_action(s)).collect(),
            }),
            "registry" if a.name == "catalog" => globals.push(Global::Catalog),
            _ => {}
        }
    }
    (rules, globals)
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    access_token: String,
    expires_in: u64,
    issued_at: String,
}

/// `GET|POST /auth/token?service=...&scope=...&scope=...`
pub async fn token_endpoint(State(state): State<AppState>, client: super::client_ip::ClientIp, headers: HeaderMap, Query(raw): Query<Vec<(String, String)>>, body: String) -> Result<Response> {
    let mut params: Vec<(String, String)> = raw;
    let is_form = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
    if is_form {
        params.extend(url::form_urlencoded::parse(body.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())));
    }
    // Repeated `scope` parameters, or (OAuth2 form) several in one, separated by spaces.
    let scopes: Vec<String> = params.iter().filter(|(k, _)| k == "scope").flat_map(|(_, v)| v.split_whitespace().map(str::to_string)).collect();
    let service = params.iter().find(|(k, _)| k == "service").map(|(_, v)| v.clone()).unwrap_or_else(|| state.config.service_name());

    let auth = &state.auth;
    let param = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    // The OAuth2 form of the request (what Docker sends to a POST realm) carries the credentials
    // in the body: `grant_type=password&username=...&password=...`.
    let ip = client.0;
    let principal = match (param("grant_type"), param("username"), param("password")) {
        (Some("password"), Some(user), Some(secret)) => auth.authenticate_basic(user, secret, ip.as_deref()).await?,
        _ => match headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
            Some(h) => auth.authenticate_basic_header(h, ip.as_deref()).await?,
            None => auth.anonymous().await,
        },
    };
    let mut principal = principal;
    for s in &scopes {
        if let Some(("repository", name, actions)) = parse_scope(s).as_ref().map(|(k, n, a)| (k.as_str(), n, a)) {
            if actions.iter().any(|a| a == "push" || a == "*") {
                auth.confirm_new_repo(&mut principal, name).await?;
            }
        }
    }
    let access = grant(&principal, &scopes);
    let (token, expires_in, issued_at) = auth.issue_token(&principal, &service, access)?;
    state.audit.record(&principal, "token_issued", None, None, None, Some(format!("service={service} scopes={}", scopes.join(" "))));
    Ok(Json(TokenResponse { access_token: token.clone(), token, expires_in, issued_at }).into_response())
}

impl From<jsonwebtoken::errors::Error> for RegistryError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        RegistryError::with_message(Code::Unauthorized, format!("invalid token: {e}"))
    }
}
