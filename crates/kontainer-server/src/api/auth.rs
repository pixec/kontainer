//! Account endpoints: login/logout, profile, password, MFA, personal access tokens, robot
//! accounts, sessions and OIDC single sign-on.

use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::database::{AccessToken, Profile, User};
use kontainer_core::perm::{valid_username, Global, Rule};
use crate::auth::client_ip::ClientIp;
use crate::auth::{require_user, AuthMethod, Principal};
use crate::auth::{mfa, oidc, sso};
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/me", get(me))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/profile", get(get_profile).put(update_profile))
        .route("/api/v1/auth/username", post(change_username))
        .route("/api/v1/auth/password", post(change_password))
        .route("/api/v1/auth/mfa/setup", post(mfa_setup))
        .route("/api/v1/auth/mfa/enable", post(mfa_enable))
        .route("/api/v1/auth/mfa/disable", post(mfa_disable))
        .route("/api/v1/auth/mfa/recovery-codes", post(mfa_recovery_codes))
        .route("/api/v1/auth/tokens", get(list_tokens).post(create_token))
        .route("/api/v1/auth/tokens/{id}", axum::routing::delete(delete_token))
        .route("/api/v1/auth/sessions", get(list_sessions))
        .route("/api/v1/auth/sessions/{id}", axum::routing::delete(delete_session))
        .route("/api/v1/auth/passkeys", get(list_passkeys))
        .route("/api/v1/auth/passkeys/{id}", axum::routing::delete(delete_passkey))
        .route("/api/v1/auth/passkeys/register/start", post(passkey_register_start))
        .route("/api/v1/auth/passkeys/register/finish", post(passkey_register_finish))
        .route("/api/v1/auth/passkeys/login/start", post(passkey_login_start))
        .route("/api/v1/auth/passkeys/login/finish", post(passkey_login_finish))
        .route("/api/v1/auth/robots", get(list_robots).post(create_robot))
        .route("/api/v1/auth/robots/{id}", axum::routing::delete(delete_robot).patch(update_robot))
        .route("/api/v1/auth/robots/{id}/rotate", post(rotate_robot))
        .route("/auth/token", get(crate::auth::token::token_endpoint).post(crate::auth::token::token_endpoint))
        .route("/auth/oidc/login", get(oidc_login))
        .route("/auth/oidc/callback", get(oidc_callback))
        .route("/auth/oidc/orgs/{org}/login", get(org_oidc_login))
        .route("/api/v1/auth/oidc/orgs/{org}/link", post(org_oidc_link))
        .route("/auth/oidc/orgs/{org}/callback", get(org_oidc_callback))
}


#[derive(Serialize)]
pub struct Me {
    pub username: Option<String>,
    pub user_id: Option<i64>,
    pub is_robot: bool,
    pub admin: bool,
    pub method: AuthMethod,
    pub is_mfa_enabled: bool,
    pub is_managed: bool,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub roles: Vec<String>,
    pub globals: Vec<Global>,
    pub auth_mode: kontainer_core::config::AuthMode,
    pub oidc: Option<String>,
    /// Passkey sign-in is available.
    pub passkeys: bool,
    /// Image builds from Git are enabled.
    pub builds: bool,
    pub features: kontainer_core::config::FeatureConfig,
    pub scanner: Option<&'static str>,
}

pub async fn me(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Json<Me>> {
    let user = match p.user_id {
        Some(id) => state.auth.db.user_by_id(id).await?,
        None => None,
    };
    let profile = match p.user_id {
        Some(id) => state.auth.db.profile(id).await?,
        None => None,
    };
    Ok(Json(Me {
        username: p.username.clone(),
        user_id: p.user_id,
        is_robot: p.is_robot,
        admin: p.is_admin(),
        method: p.method,
        is_mfa_enabled: p.is_mfa_enabled,
        is_managed: p.is_managed,
        email: user.as_ref().and_then(|u| u.email.clone()),
        display_name: user.as_ref().and_then(|u| u.display_name.clone()),
        avatar_url: profile.and_then(|p| p.gravatar_email).map(|e| gravatar_url(&e)),
        roles: p.roles.iter().map(|r| r.name.clone()).collect(),
        globals: p.globals(),
        auth_mode: state.config.auth.mode,
        oidc: state.auth.oidc.as_ref().map(|o| o.config().display_name.clone()),
        passkeys: state.auth.passkeys.is_some(),
        builds: state.config.builds.is_enabled,
        features: state.config.features.clone(),
        scanner: state.scans.as_ref().map(|q| q.scanner_name),
    }))
}

/// Gravatar accepts the SHA-256 of the trimmed, lowercased address. `d=404` lets the UI
/// fall back to initials when no Gravatar exists.
pub fn gravatar_url(email: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(email.trim().to_lowercase().as_bytes()));
    format!("https://gravatar.com/avatar/{hash}?s=160&d=404")
}

#[derive(Deserialize)]
struct UsernameBody {
    username: String,
}

/// Rename your account, which also moves your personal namespace and personal robots.
async fn change_username(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<UsernameBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if p.method != AuthMethod::Session {
        return Err(RegistryError::bad_request("change your username from a browser session"));
    }
    if p.is_robot || p.is_managed {
        return Err(RegistryError::bad_request("this account's name is managed elsewhere and cannot be changed here"));
    }
    let new = body.username.trim();
    if !valid_username(new) || new.contains('+') {
        return Err(RegistryError::bad_request("invalid username (letters, digits, `-`, `_`, `.`)"));
    }
    let old = p.name().to_string();
    if new == old {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    super::orgs::rename_namespace(&state, &old, new, None, Some(uid)).await?;
    state.audit.record(&p, "username_changed", None, None, None, Some(format!("{old} -> {new}")));
    Ok(Json(serde_json::json!({ "username": new })).into_response())
}

async fn get_profile(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Json<Profile>> {
    let uid = require_user(&state, &p)?;
    Ok(Json(state.auth.db.profile(uid).await?.unwrap_or_default()))
}

async fn update_profile(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<Profile>) -> Result<Json<Profile>> {
    let uid = require_user(&state, &p)?;
    if p.is_robot {
        return Err(RegistryError::bad_request("robot accounts have no profile"));
    }
    fn clean(v: Option<String>, field: &str, max: usize) -> Result<Option<String>> {
        let v = v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if v.as_ref().is_some_and(|s| s.chars().count() > max) {
            return Err(RegistryError::bad_request(format!("{field} must be at most {max} characters")));
        }
        Ok(v)
    }
    let profile = Profile {
        display_name: clean(body.display_name, "full name", 100)?,
        company: clean(body.company, "company", 100)?,
        location: clean(body.location, "location", 100)?,
        website: clean(body.website, "website", 255)?,
        gravatar_email: clean(body.gravatar_email, "gravatar email", 255)?,
    };
    if let Some(w) = &profile.website {
        let ok = url::Url::parse(w).is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some());
        if !ok {
            return Err(RegistryError::bad_request("website must be an http(s) URL"));
        }
    }
    if let Some(e) = &profile.gravatar_email {
        if !e.contains('@') || e.contains(char::is_whitespace) {
            return Err(RegistryError::bad_request("gravatar email is not a valid email address"));
        }
    }
    state.auth.db.set_profile(uid, &profile).await?;
    state.audit.record(&p, "profile_updated", None, None, None, None);
    Ok(Json(profile))
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
    #[serde(default)]
    otp: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

async fn login(State(state): State<AppState>, client: ClientIp, headers: HeaderMap, Json(body): Json<LoginBody>) -> Result<Response> {
    let auth = &state.auth;
    let ip = client.0;
    let anon = auth.anonymous().await;
    // Failed attempts are cleared only once every step (password, then code) has passed, so a
    // known password does not reset the count of wrong codes.
    let Some(user) = auth.verify_password_step(&body.username, &body.password, ip.as_deref()).await? else {
        state.audit.record(&anon, "login_failed", None, None, None, Some(body.username.clone()));
        return Err(RegistryError::with_message(Code::Unauthorized, "invalid username or password"));
    };
    if user.is_robot {
        return Err(RegistryError::with_message(Code::Unauthorized, "robot accounts cannot sign in to the UI"));
    }
    if user.is_mfa_enabled {
        let ok = match (&body.otp, &body.recovery_code) {
            (Some(code), _) if !code.is_empty() => auth.verify_otp(&user, code, ip.as_deref()).await?,
            (_, Some(rc)) if !rc.is_empty() => auth.use_recovery_code(&user, rc, ip.as_deref()).await?,
            _ => {
                return Ok((StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "mfa_required": true }))).into_response());
            }
        };
        if !ok {
            state.audit.record(&anon, "login_failed", None, None, None, Some(format!("{} (bad otp)", user.username)));
            return Err(RegistryError::with_message(Code::Unauthorized, "invalid one-time code"));
        }
    }
    auth.login_succeeded(&body.username).await?;
    finish_login(&state, &user, &headers, ip.as_deref(), "password").await
}

/// A `Set-Cookie` value. The cookie is built from our own settings and a random session id, so
/// a failure is a bug (500), not a panic.
fn cookie(value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value).map_err(RegistryError::internal)
}

async fn finish_login(state: &AppState, user: &User, headers: &HeaderMap, ip: Option<&str>, how: &str) -> Result<Response> {
    let session = state.auth.create_session(user, headers, ip).await?;
    let p = state.auth.principal_for(user, AuthMethod::Session).await?;
    state.audit.record(&p, "login", None, None, None, Some(how.to_string()));
    let mut resp = Json(serde_json::json!({ "ok": true, "username": user.username })).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie(&state.auth.session_cookie(&session.id))?);
    Ok(resp)
}

async fn logout(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    if let Some(sid) = &p.session_id {
        state.auth.db.delete_session(sid).await?;
        state.audit.record(&p, "logout", None, None, None, None);
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie(&state.auth.clear_cookie())?);
    Ok(resp)
}

#[derive(Deserialize)]
struct PasswordBody {
    current_password: String,
    new_password: String,
}

async fn change_password(State(state): State<AppState>, Extension(p): Extension<Principal>, client: ClientIp, Json(body): Json<PasswordBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if p.is_managed {
        return Err(RegistryError::bad_request("this account is defined in the configuration file; change its password there"));
    }
    let user = state.auth.db.user_by_id(uid).await?.ok_or_else(|| RegistryError::new(Code::Unauthorized))?;
    if state.auth.verify_password(&user.username, &body.current_password, None).await?.is_none() {
        return Err(RegistryError::with_message(Code::Unauthorized, "current password is incorrect"));
    }
    crate::auth::password::check_strength(&body.new_password).map_err(RegistryError::bad_request)?;
    let hash = crate::auth::password::hash_async(&body.new_password).await.map_err(RegistryError::internal)?;
    state.auth.db.set_password(uid, Some(&hash)).await?;
    // Revoke every other session.
    state.auth.db.delete_user_sessions(uid).await?;
    state.audit.record(&p, "password_changed", None, None, None, None);
    let session = state.auth.create_session(&user, &HeaderMap::new(), client.as_deref()).await?;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie(&state.auth.session_cookie(&session.id))?);
    Ok(resp)
}

async fn mfa_setup(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if p.is_mfa_enabled {
        return Err(RegistryError::bad_request("two-factor authentication is already enabled"));
    }
    let e = mfa::enroll(&state.auth.realm, p.name()).map_err(RegistryError::internal)?;
    // Pending until a code from it reaches `enable` within `mfa::SETUP_TTL`; a new setup
    // replaces it.
    state.auth.db.start_mfa_setup(uid, &e.secret, mfa::SETUP_TTL).await?;
    Ok(Json(serde_json::json!({ "secret": e.secret, "otpauth_url": e.otpauth_url, "qr_svg": e.qr_svg })).into_response())
}

#[derive(Deserialize)]
struct CodeBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    password: Option<String>,
}

async fn mfa_enable(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<CodeBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    let user = state.auth.db.user_by_id(uid).await?.ok_or_else(|| RegistryError::new(Code::Unauthorized))?;
    if user.is_mfa_enabled {
        return Err(RegistryError::bad_request("two-factor authentication is already enabled"));
    }
    let Some(secret) = state.auth.db.pending_mfa_secret(uid).await? else {
        return Err(RegistryError::bad_request("no two-factor setup in progress (or it expired): call /mfa/setup first"));
    };
    if !state.auth.verify_otp_with(&user, &secret, &body.code, None).await? {
        return Err(RegistryError::with_message(Code::Unauthorized, "invalid one-time code"));
    }
    let (plain, hashed) = mfa::recovery_codes(&state.auth.recovery_key);
    if !state.auth.db.complete_mfa_setup(uid, &secret, &hashed).await? {
        return Err(RegistryError::bad_request("the two-factor setup expired or was restarted: call /mfa/setup again"));
    }
    state.audit.record(&p, "is_mfa_enabled", None, None, None, None);
    Ok(Json(serde_json::json!({ "recovery_codes": plain })).into_response())
}

async fn mfa_disable(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<CodeBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    let user = state.auth.db.user_by_id(uid).await?.ok_or_else(|| RegistryError::new(Code::Unauthorized))?;
    let ok = match (user.is_mfa_enabled, &body.password) {
        (true, _) if !body.code.is_empty() => state.auth.verify_otp(&user, &body.code, None).await?,
        (_, Some(pw)) => state.auth.verify_password(&user.username, pw, None).await?.is_some(),
        _ => false,
    };
    if !ok {
        return Err(RegistryError::with_message(Code::Unauthorized, "verification failed"));
    }
    state.auth.db.disable_mfa(uid).await?;
    state.audit.record(&p, "mfa_disabled", None, None, None, None);
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn mfa_recovery_codes(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<CodeBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    let user = state.auth.db.user_by_id(uid).await?.ok_or_else(|| RegistryError::new(Code::Unauthorized))?;
    if !user.is_mfa_enabled {
        return Err(RegistryError::bad_request("two-factor authentication is not enabled"));
    }
    if !state.auth.verify_otp(&user, &body.code, None).await? {
        return Err(RegistryError::with_message(Code::Unauthorized, "invalid one-time code"));
    }
    let (plain, hashed) = mfa::recovery_codes(&state.auth.recovery_key);
    state.auth.db.replace_recovery_codes(uid, &hashed).await?;
    Ok(Json(serde_json::json!({ "recovery_codes": plain })).into_response())
}

fn passkeys(state: &AppState) -> Result<&crate::auth::passkey::Passkeys> {
    state.auth.passkeys.as_ref().ok_or_else(|| RegistryError::bad_request("passkeys are unavailable: server.public_url must name the registry by domain"))
}

/// An account's passkeys as webauthn-rs reads them, with their rows.
async fn user_passkeys(state: &AppState, uid: i64) -> Result<Vec<(crate::database::users::PasskeyRow, webauthn_rs::prelude::Passkey)>> {
    let mut out = vec![];
    for row in state.auth.db.list_passkeys(uid).await? {
        match serde_json::from_str(&row.credential) {
            Ok(pk) => out.push((row, pk)),
            Err(e) => tracing::warn!(passkey = row.id, error = %e, "skipping a passkey that cannot be read"),
        }
    }
    Ok(out)
}

async fn list_passkeys(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    Ok(Json(state.auth.db.list_passkeys(uid).await?).into_response())
}

async fn delete_passkey(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    let Some(name) = state.auth.db.delete_passkey(uid, id).await? else { return Err(RegistryError::not_found("passkey")) };
    state.audit.record(&p, "passkey_removed", None, None, None, Some(name));
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
struct PasskeyRegisterStart {
    name: String,
}

/// `POST /api/v1/auth/passkeys/register/start`: options for `navigator.credentials.create`, and
/// the id of the ceremony to finish. Only from a browser session.
async fn passkey_register_start(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<PasskeyRegisterStart>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if p.method != AuthMethod::Session {
        return Err(RegistryError::bad_request("add passkeys from a browser session"));
    }
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(RegistryError::bad_request("passkey name must be 1-64 characters"));
    }
    let pk = passkeys(&state)?;
    let user = state.auth.db.user_by_id(uid).await?.ok_or_else(|| RegistryError::new(Code::Unauthorized))?;
    let existing: Vec<_> = user_passkeys(&state, uid).await?.into_iter().map(|(_, k)| k).collect();
    let display = user.display_name.clone().filter(|d| !d.is_empty()).unwrap_or_else(|| user.username.clone());
    let (options, reg) = pk.start_registration(uid, &user.username, &display, &existing).map_err(RegistryError::internal)?;
    let id = state.auth.db.create_webauthn_challenge("register", Some(uid), &reg, Some(name), crate::auth::passkey::CHALLENGE_TTL).await?;
    Ok(Json(serde_json::json!({ "challenge_id": id, "options": options })).into_response())
}

#[derive(Deserialize)]
struct PasskeyRegisterFinish {
    challenge_id: String,
    credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
}

async fn passkey_register_finish(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<PasskeyRegisterFinish>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if p.method != AuthMethod::Session {
        return Err(RegistryError::bad_request("add passkeys from a browser session"));
    }
    let pk = passkeys(&state)?;
    let ch = state.auth.db.take_webauthn_challenge(&body.challenge_id, &["register"]).await?;
    let Some(ch) = ch.filter(|c| c.user_id == Some(uid)) else { return Err(RegistryError::bad_request("no passkey registration in progress (or it expired): start again")) };
    let passkey = pk.finish_registration(&ch.state, &body.credential).map_err(|e| {
        tracing::info!(user = p.name(), error = %format!("{e:#}"), "passkey registration refused");
        RegistryError::bad_request("the passkey could not be verified")
    })?;
    let name = ch.name.unwrap_or_else(|| "passkey".to_string());
    let json = serde_json::to_string(&passkey).map_err(RegistryError::internal)?;
    let Some(row) = state.auth.db.add_passkey(uid, passkey.cred_id().as_ref(), &json, &name, 0).await? else {
        return Err(RegistryError::conflict("this passkey is already registered"));
    };
    state.audit.record(&p, "passkey_added", None, None, None, Some(name));
    Ok((StatusCode::CREATED, Json(row)).into_response())
}

#[derive(Deserialize, Default)]
struct PasskeyLoginStart {
    #[serde(default)]
    username: Option<String>,
}

/// `POST /api/v1/auth/passkeys/login/start`: options for `navigator.credentials.get`. With a
/// username, that account's passkeys are offered; without one (or for an account without
/// passkeys, so the answer does not tell which accounts exist), any discoverable credential.
async fn passkey_login_start(State(state): State<AppState>, client: ClientIp, body: Option<Json<PasskeyLoginStart>>) -> Result<Response> {
    let pk = passkeys(&state)?;
    let username = body.and_then(|b| b.0.username).map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    state.auth.throttle_login(username.as_deref(), client.as_deref()).await?;
    let user = match &username {
        Some(u) => state.auth.db.user_by_name(u).await?.filter(|u| !u.is_robot),
        None => None,
    };
    let creds: Vec<_> = match &user {
        Some(u) => user_passkeys(&state, u.id).await?.into_iter().map(|(_, k)| k).collect(),
        None => vec![],
    };
    let (options, kind, st) = pk.start_login(&creds).map_err(RegistryError::internal)?;
    let user_id = if kind == "login" { user.map(|u| u.id) } else { None };
    let id = state.auth.db.create_webauthn_challenge(kind, user_id, &st, None, crate::auth::passkey::CHALLENGE_TTL).await?;
    Ok(Json(serde_json::json!({ "challenge_id": id, "options": options })).into_response())
}

#[derive(Deserialize)]
struct PasskeyLoginFinish {
    challenge_id: String,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

/// `POST /api/v1/auth/passkeys/login/finish`: verify the assertion and start a session. A
/// passkey verifies the user on the authenticator, so it is both factors: no one-time code is
/// asked even when the account has two-factor authentication on.
async fn passkey_login_finish(State(state): State<AppState>, client: ClientIp, headers: HeaderMap, Json(body): Json<PasskeyLoginFinish>) -> Result<Response> {
    let pk = passkeys(&state)?;
    let auth = &state.auth;
    let ip = client.0;
    let anon = auth.anonymous().await;
    let refused = || RegistryError::with_message(Code::Unauthorized, "passkey sign-in failed");
    let Some(ch) = auth.db.take_webauthn_challenge(&body.challenge_id, &["login", "discoverable"]).await? else {
        return Err(RegistryError::with_message(Code::Unauthorized, "no passkey sign-in in progress (or it expired): start again"));
    };
    // The credential the response names, and so the account.
    let row = auth.db.passkey_by_credential_id(body.credential.get_credential_id()).await?;
    let user = match &row {
        Some(r) => auth.db.user_by_id(r.user_id).await?,
        None => None,
    };
    auth.throttle_login(user.as_ref().map(|u| u.username.as_str()), ip.as_deref()).await?;
    let verified = match (&row, &user) {
        // A started sign-in for one account accepts only that account's passkeys; a discoverable
        // one, a passkey whose user handle is its owner's.
        (Some(row), Some(user)) if ch.user_id.is_none_or(|id| id == user.id) => {
            let handle_ok = ch.kind != "discoverable" || pk.identify(&body.credential).is_ok_and(|(h, _)| h == pk.user_handle(user.id));
            match serde_json::from_str::<webauthn_rs::prelude::Passkey>(&row.credential) {
                Ok(stored) if handle_ok => pk.finish_login(&ch.kind, &ch.state, &body.credential, &stored).map_err(|e| tracing::info!(user = %user.username, error = %format!("{e:#}"), "passkey sign-in refused")).ok(),
                _ => None,
            }
        }
        _ => None,
    };
    let who = user.as_ref().map(|u| u.username.clone());
    let (Some(row), Some(user), Some((updated, changed, counter))) = (row, user, verified) else {
        auth.login_failed(who.as_deref(), ip.as_deref()).await?;
        state.audit.record(&anon, "login_failed", None, None, None, Some("passkey".into()));
        return Err(refused());
    };
    if user.is_robot || user.is_disabled {
        auth.login_failed(Some(&user.username), ip.as_deref()).await?;
        state.audit.record(&anon, "login_failed", None, None, None, Some(format!("{} (passkey, account disabled)", user.username)));
        return Err(refused());
    }
    let json = if changed { Some(serde_json::to_string(&updated).map_err(RegistryError::internal)?) } else { None };
    auth.db.touch_passkey(row.id, json.as_deref(), i64::from(counter)).await?;
    auth.login_succeeded(&user.username).await?;
    finish_login(&state, &user, &headers, ip.as_deref(), &format!("passkey {}", row.name)).await
}

#[derive(Serialize)]
struct TokenView {
    #[serde(flatten)]
    token: AccessToken,
    scopes: Option<Vec<Rule>>,
}

async fn list_tokens(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    let tokens = state.auth.db.list_tokens(uid).await?;
    Ok(Json(tokens.into_iter().map(|t| TokenView { scopes: t.scope_rules().unwrap_or_else(|_| Some(vec![])), token: t }).collect::<Vec<_>>()).into_response())
}

#[derive(Deserialize)]
struct CreateTokenBody {
    name: String,
    #[serde(default)]
    expires_in_days: Option<u32>,
    /// No longer supported; present only to reject old clients clearly.
    #[serde(default)]
    scopes: Option<Vec<Rule>>,
}

const NO_SCOPES: &str = "scoped credentials were removed: a token acts as you. For narrower access, create a robot account and grant it access to specific repositories";

async fn create_token(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<CreateTokenBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if p.method != AuthMethod::Session {
        return Err(RegistryError::bad_request("tokens can only be created from a browser session"));
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(RegistryError::bad_request("token name must be 1-64 characters"));
    }
    if body.scopes.as_ref().is_some_and(|s| !s.is_empty()) {
        return Err(RegistryError::bad_request(NO_SCOPES));
    }
    let expires = body.expires_in_days.filter(|d| *d > 0).map(|d| chrono::Utc::now() + chrono::Duration::days(d as i64));
    let (plain, tok) = state.auth.create_access_token(uid, name, None, expires).await?;
    state.audit.record(&p, "token_created", None, None, None, Some(name.to_string()));
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "token": plain, "id": tok.id, "hint": tok.hint, "expires_at": tok.expires_at.map(|t| t.to_rfc3339()) }))).into_response())
}

async fn delete_token(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if !state.auth.db.delete_token(uid, id).await? {
        return Err(RegistryError::not_found("token"));
    }
    state.audit.record(&p, "token_revoked", None, None, None, Some(id.to_string()));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn list_sessions(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    let sessions = state.auth.db.list_sessions(uid).await?;
    let current = p.session_id.clone();
    let view: Vec<_> = sessions
        .into_iter()
        .map(|s| serde_json::json!({ "id": &s.id[..8], "created_at": s.created_at.to_rfc3339(), "expires_at": s.expires_at.to_rfc3339(), "user_agent": s.user_agent, "ip": s.ip, "is_current": Some(&s.id) == current.as_ref() }))
        .collect();
    Ok(Json(view).into_response())
}

async fn delete_session(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<String>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if id == "all" {
        state.auth.db.delete_user_sessions(uid).await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    // Every session except the one making this request.
    if id == "others" {
        for s in state.auth.db.list_sessions(uid).await? {
            if Some(&s.id) != p.session_id.as_ref() {
                state.auth.db.delete_session(&s.id).await?;
            }
        }
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    for s in state.auth.db.list_sessions(uid).await? {
        if s.id.starts_with(&id) {
            state.auth.db.delete_session(&s.id).await?;
        }
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Serialize)]
pub struct RobotView {
    #[serde(flatten)]
    pub user: User,
    /// Repositories the robot was granted; robots have no other access.
    pub repositories: Vec<RepoAccess>,
    /// When its credential stops working; `None` never.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When its credential was last used.
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize)]
pub struct RepoAccess {
    pub repository: String,
    pub level: kontainer_core::perm::Level,
}

pub async fn robot_view(state: &AppState, user: User) -> Result<RobotView> {
    let repositories = state.auth.db.user_repo_grants(user.id).await?.into_iter().map(|(repository, level)| RepoAccess { repository, level }).collect();
    let tokens = state.auth.db.list_tokens(user.id).await?;
    // A robot normally has one credential; with several, it works until the last one expires.
    let expires_at = if tokens.iter().any(|t| t.expires_at.is_none()) { None } else { tokens.iter().filter_map(|t| t.expires_at).max() };
    let last_used_at = tokens.iter().filter_map(|t| t.last_used_at).max();
    Ok(RobotView { user, repositories, expires_at, last_used_at })
}

/// When a new robot credential expires: `days` from now (0 = never), else the configured default.
pub fn robot_expiry(state: &AppState, days: Option<u32>) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let days = days.or(state.config.policy.robot_expiry_days).unwrap_or(0);
    if days > 3650 {
        return Err(RegistryError::bad_request("expires_in_days: at most 3650"));
    }
    Ok((days > 0).then(|| chrono::Utc::now() + chrono::Duration::days(days.into())))
}

/// Replace a robot's credentials with a new one. Without `days`, the new one lasts as long as
/// the old one did. Returns the plain credential.
pub async fn reissue_robot_credential(state: &AppState, robot: &User, days: Option<u32>) -> Result<String> {
    let mut scopes = None;
    let mut lifetime = None;
    for t in state.auth.db.list_tokens(robot.id).await? {
        // Legacy robots may still carry scopes from before repository grants; keep them so a
        // rotated credential is never broader than the old one.
        if scopes.is_none() {
            scopes = t.scope_rules()?;
        }
        if let Some(exp) = t.expires_at {
            // Rounded: the expiry was computed a moment before the token was stamped.
            lifetime = Some((((exp - t.created_at).num_seconds() + 43_200) / 86_400).max(1) as u32);
        }
        state.auth.db.delete_token(robot.id, t.id).await?;
    }
    let expires = robot_expiry(state, days.or(lifetime))?;
    let (plain, _) = state.auth.create_access_token(robot.id, "robot credential", scopes.as_deref(), expires).await?;
    Ok(plain)
}

#[derive(Deserialize, Default)]
pub struct RobotUpdate {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_disabled: Option<bool>,
}

#[derive(Deserialize, Default)]
pub struct RotateBody {
    /// 0 = never; default: as long as the old credential lasted.
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

async fn list_robots(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    let mut out = vec![];
    for r in state.auth.db.list_robots(uid).await? {
        out.push(robot_view(&state, r).await?);
    }
    Ok(Json(out).into_response())
}

#[derive(Deserialize)]
struct CreateRobotBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    /// No longer supported; robots get access through repository grants.
    #[serde(default)]
    scopes: Option<Vec<Rule>>,
    /// 0 = never; default: `policy.robot_expiry_days`.
    #[serde(default)]
    expires_in_days: Option<u32>,
}

async fn create_robot(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<CreateRobotBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if body.scopes.as_ref().is_some_and(|s| !s.is_empty()) {
        return Err(RegistryError::bad_request(NO_SCOPES));
    }
    let username = format!("{}+{}", p.name(), body.name.trim());
    if !valid_username(&username) {
        return Err(RegistryError::bad_request("invalid robot name"));
    }
    if state.auth.db.user_by_name(&username).await?.is_some() {
        return Err(RegistryError::conflict("a robot with that name already exists"));
    }
    let expires = robot_expiry(&state, body.expires_in_days)?;
    let robot = state.auth.db.create_user(&username, None, None, body.description.as_deref(), true, Some(uid), false).await?;
    let (plain, _) = state.auth.create_access_token(robot.id, "robot credential", None, expires).await?;
    state.audit.record(&p, "robot_created", None, None, None, Some(username.clone()));
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": robot.id, "username": username, "token": plain }))).into_response())
}

async fn owned_robot(state: &AppState, p: &Principal, id: i64) -> Result<User> {
    let uid = require_user(state, p)?;
    match state.auth.db.user_by_id(id).await? {
        Some(u) if u.is_robot && (u.owner_id == Some(uid) || p.has_global(Global::UsersWrite)) => Ok(u),
        _ => Err(RegistryError::not_found("robot")),
    }
}

async fn delete_robot(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let robot = owned_robot(&state, &p, id).await?;
    state.auth.db.delete_user(robot.id).await?;
    state.audit.record(&p, "robot_deleted", None, None, None, Some(robot.username));
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn update_robot(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(body): Json<RobotUpdate>) -> Result<Response> {
    let robot = owned_robot(&state, &p, id).await?;
    apply_robot_update(&state, &robot, &body).await?;
    state.audit.record(&p, "robot_updated", None, None, None, Some(robot.username.clone()));
    let robot = state.auth.db.user_by_id(id).await?.ok_or_else(|| RegistryError::not_found("robot"))?;
    Ok(Json(robot_view(&state, robot).await?).into_response())
}

/// Change a robot's description or enabled state.
pub async fn apply_robot_update(state: &AppState, robot: &User, body: &RobotUpdate) -> Result<()> {
    if body.description.as_deref().is_some_and(|d| d.len() > 200) {
        return Err(RegistryError::bad_request("description: at most 200 characters"));
    }
    state.auth.db.update_user(robot.id, None, body.description.as_deref().map(str::trim), body.is_disabled).await?;
    Ok(())
}

async fn rotate_robot(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, body: Option<Json<RotateBody>>) -> Result<Response> {
    let robot = owned_robot(&state, &p, id).await?;
    let plain = reissue_robot_credential(&state, &robot, body.and_then(|b| b.0.expires_in_days)).await?;
    state.audit.record(&p, "robot_rotated", None, None, None, Some(robot.username.clone()));
    Ok(Json(serde_json::json!({ "username": robot.username, "token": plain })).into_response())
}

#[derive(Deserialize)]
struct OidcLoginQuery {
    #[serde(default)]
    redirect: Option<String>,
}

/// A post-login destination, if it is a path on this site. Anything a browser could read as
/// another origin is refused: `//host`, `/\host` (browsers treat `\` as `/`), and control
/// characters or whitespace, which browsers strip before resolving.
fn safe_redirect(r: Option<String>) -> Option<String> {
    r.filter(|r| r.starts_with('/') && !r.starts_with("//") && !r.contains('\\') && !r.chars().any(|c| c.is_control() || c.is_whitespace()))
}

/// Redirect the browser to the provider, with the cookie that binds the login to it.
fn to_provider(state: &AppState, begin: oidc::Begin) -> Result<Response> {
    let mut resp = Redirect::to(&begin.url).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie(&state.auth.oidc_login_cookie(&begin.browser_nonce))?);
    Ok(resp)
}

async fn oidc_login(State(state): State<AppState>, Query(q): Query<OidcLoginQuery>) -> Result<Response> {
    let Some(oidc) = &state.auth.oidc else { return Err(RegistryError::bad_request("single sign-on is not configured")) };
    let redirect = safe_redirect(q.redirect);
    let begin = oidc.begin(&state.auth.db, redirect.as_deref()).await.map_err(RegistryError::internal)?;
    to_provider(&state, begin)
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

fn login_error(msg: &str) -> Response {
    Redirect::to(&format!("/login?error={}", urlenc(msg))).into_response()
}

async fn oidc_callback(State(state): State<AppState>, client: ClientIp, headers: HeaderMap, Query(q): Query<OidcCallbackQuery>) -> Result<Response> {
    let Some(oidc) = &state.auth.oidc else { return Err(RegistryError::bad_request("single sign-on is not configured")) };
    let (claims, st) = match callback_claims(&state, oidc, &headers, q).await? {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    // A state minted for an organization's provider is only good on that organization's callback.
    if st.org.is_some() {
        return with_cleared_login_cookie(&state, Err(RegistryError::bad_request("login state belongs to another provider")));
    }
    let cfg = oidc.config();
    let login = SsoLogin {
        provider: cfg.issuer.trim_end_matches('/').to_string(),
        username_claim: &cfg.username_claim,
        groups_claim: cfg.groups_claim.as_deref(),
        matching: sso::Matching::ByUsername,
        may_create: cfg.is_auto_create_users,
        default_roles: &cfg.default_roles,
        group_roles: &cfg.group_roles,
        team_source: "oidc",
        team_org: None,
    };
    with_cleared_login_cookie(&state, finish_sso(&state, &headers, client.as_deref(), &claims, &st, &login).await)
}

/// The login and link cookies are single use: clear them on whatever the callback answers.
fn with_cleared_login_cookie(state: &AppState, r: Result<Response>) -> Result<Response> {
    let clear = [cookie(&state.auth.clear_oidc_login_cookie())?, cookie(&state.auth.clear_oidc_link_cookie())?];
    let mut resp = match r {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    };
    for c in clear {
        resp.headers_mut().append(header::SET_COOKIE, c);
    }
    Ok(resp)
}

/// Exchange the code (or relay the provider's error to the login page). The callback must come
/// from the browser that started the login (its [`oidc::LOGIN_COOKIE`]).
async fn callback_claims(state: &AppState, oidc: &oidc::Oidc, headers: &HeaderMap, q: OidcCallbackQuery) -> Result<std::result::Result<(oidc::IdClaims, crate::database::OidcState), Response>> {
    let fail = |resp: Response| with_cleared_login_cookie(state, Ok(resp)).map(Err);
    if let Some(e) = q.error {
        return fail(login_error(&format!("{e}: {}", q.error_description.unwrap_or_default())));
    }
    let (Some(code), Some(st)) = (q.code, q.state) else { return Err(RegistryError::bad_request("missing code or state")) };
    let browser = crate::auth::cookie(headers, oidc::LOGIN_COOKIE);
    match oidc.complete(&state.auth.db, &code, &st, browser.as_deref()).await {
        Ok(v) => Ok(Ok(v)),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "oidc login failed");
            fail(login_error("single sign-on failed"))
        }
    }
}

struct SsoLogin<'a> {
    provider: String,
    username_claim: &'a str,
    groups_claim: Option<&'a str>,
    matching: sso::Matching,
    may_create: bool,
    default_roles: &'a [String],
    group_roles: &'a std::collections::HashMap<String, Vec<String>>,
    team_source: &'a str,
    team_org: Option<i64>,
}

/// Find or create the account, sync roles and teams from groups, and start a session; or, for a
/// login started to link the identity, link it to the signed-in account and return there.
///
/// A link is honored only from the browser that started it with a signed-in POST: the one
/// holding that POST's [`oidc::LINK_COOKIE`]. The session cookie itself is `SameSite=Strict` and
/// does not come along on the provider's cross-site redirect; the link cookie stands in for it,
/// for this one link. So a link can never be planted in someone else's account.
async fn finish_sso(state: &AppState, headers: &HeaderMap, ip: Option<&str>, claims: &oidc::IdClaims, st: &crate::database::OidcState, l: &SsoLogin<'_>) -> Result<Response> {
    let db = &state.auth.db;
    let mut linker = None;
    if let Some(uid) = st.link_user_id {
        let token = crate::auth::cookie(headers, oidc::LINK_COOKIE);
        let user = match db.user_by_id(uid).await? {
            Some(u) if !u.is_robot && !u.is_disabled && oidc::browser_matches(st.link_hash.as_deref(), token.as_deref()) => u,
            _ => return Ok(login_error("sign in to the account you are linking, then try again")),
        };
        linker = Some(state.auth.principal_for(&user, AuthMethod::Session).await?);
    }
    // Unverified addresses are not trusted: the provider must say it checked the address.
    let email = claims.email.clone().filter(|_| claims.is_email_verified.unwrap_or(false));
    let wanted = claims.claim_str(l.username_claim).or_else(|| email.clone()).unwrap_or_else(|| claims.sub.clone());
    let id = sso::Identity { provider: &l.provider, subject: &claims.sub, username: &wanted, email: email.as_deref(), name: claims.name.as_deref() };
    let Some(user) = sso::provision(db, &id, l.matching, l.may_create, l.default_roles, st.link_user_id).await? else {
        return Ok(login_error("no registry account for this identity; ask an administrator"));
    };
    let dest = st.redirect_to.clone().unwrap_or_else(|| "/".to_string());
    if let Some(linker) = &linker {
        // Linking: the browser already has a session; no new one is issued.
        if Some(user.id) != linker.user_id {
            return Ok(Redirect::to(&format!("{dest}{}error={}", if dest.contains('?') { '&' } else { '?' }, urlenc("this identity is already linked to another account"))).into_response());
        }
        state.audit.record(linker, "identity_linked", None, None, None, Some(format!("oidc {}", l.provider)));
        return Ok(Redirect::to(&dest).into_response());
    }
    if user.is_disabled {
        return Ok(login_error("account disabled"));
    }
    let principal = state.auth.principal_for(&user, AuthMethod::Session).await?;
    // An organization's provider is run by that organization, not by this instance, so it may not
    // sign in to an account that is protected by a second factor or holds instance-wide
    // permissions: those sign in with their password (and code) or the instance's provider. Other
    // accounts reach an org provider only by being created by it or linked by their owner (a
    // signed-in POST, then a callback in that owner's session), so the owner consented. The
    // instance's own provider is trusted like the instance and keeps signing anyone in.
    if l.matching == sso::Matching::NewAccountOnly && (user.is_mfa_enabled || !principal.globals().is_empty() || principal.is_admin()) {
        return Ok(login_error("this account cannot sign in through an organization's single sign-on; sign in with your password"));
    }
    // Groups are applied on every sign-in, so removals in the directory take effect.
    if let Some(gc) = l.groups_claim {
        let groups = claims.groups(gc);
        sso::sync_roles(db, user.id, l.group_roles, &groups).await?;
        sso::sync_teams(db, user.id, l.team_source, l.team_org, &groups).await?;
    }
    let session = state.auth.create_session(&user, headers, ip).await?;
    state.audit.record(&principal, "login", None, None, None, Some(format!("oidc {}", l.provider)));
    let mut resp = Redirect::to(&dest).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie(&state.auth.session_cookie(&session.id))?);
    Ok(resp)
}

#[derive(Deserialize)]
struct OrgSsoLoginQuery {
    #[serde(default)]
    redirect: Option<String>,
}

/// `GET /auth/oidc/orgs/{org}/login`: sign in with an organization's own provider. Never links:
/// a GET can be triggered cross-site, so linking goes through [`org_oidc_link`].
async fn org_oidc_login(State(state): State<AppState>, Path(org): Path<String>, Query(q): Query<OrgSsoLoginQuery>) -> Result<Response> {
    let Some(o) = state.auth.db.org_by_name(&org).await? else { return Ok(login_error(&format!("no organization named {org}"))) };
    let Some(oidc) = state.auth.org_oidc(o.id, &o.name).await? else { return Ok(login_error(&format!("{org} has no single sign-on"))) };
    let redirect = safe_redirect(q.redirect).unwrap_or_else(|| format!("/orgs/{org}"));
    let begin = oidc.begin_for(&state.auth.db, Some(&redirect), Some(&o.name), None).await.map_err(RegistryError::internal)?;
    to_provider(&state, begin)
}

#[derive(Deserialize)]
struct OrgSsoLinkBody {
    #[serde(default)]
    redirect: Option<String>,
}

/// `POST /api/v1/auth/oidc/orgs/{org}/link`: start linking an organization's identity to the
/// signed-in account. A JSON body (which a cross-site form cannot send) and a browser session
/// are required. Returns the provider URL for the browser to go to, and sets the login cookie
/// and the link cookie that stands in for the (Strict) session at the callback.
async fn org_oidc_link(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(org): Path<String>, Json(body): Json<OrgSsoLinkBody>) -> Result<Response> {
    let uid = require_user(&state, &p)?;
    if p.method != AuthMethod::Session {
        return Err(RegistryError::bad_request("link identities from a browser session"));
    }
    let o = state.auth.db.org_by_name(&org).await?.ok_or_else(|| RegistryError::not_found("organization"))?;
    let Some(oidc) = state.auth.org_oidc(o.id, &o.name).await? else { return Err(RegistryError::bad_request(format!("{org} has no single sign-on"))) };
    let redirect = safe_redirect(body.redirect).unwrap_or_else(|| "/settings/security".to_string());
    let begin = oidc.begin_for(&state.auth.db, Some(&redirect), Some(&o.name), Some(uid)).await.map_err(RegistryError::internal)?;
    let link_token = begin.link_token.as_deref().ok_or_else(|| RegistryError::internal("a link started without a link token"))?;
    let mut resp = Json(serde_json::json!({ "url": begin.url })).into_response();
    resp.headers_mut().append(header::SET_COOKIE, cookie(&state.auth.oidc_login_cookie(&begin.browser_nonce))?);
    resp.headers_mut().append(header::SET_COOKIE, cookie(&state.auth.oidc_link_cookie(link_token))?);
    Ok(resp)
}

async fn org_oidc_callback(State(state): State<AppState>, client: ClientIp, headers: HeaderMap, Path(org): Path<String>, Query(q): Query<OidcCallbackQuery>) -> Result<Response> {
    let o = state.auth.db.org_by_name(&org).await?.ok_or_else(|| RegistryError::bad_request(format!("no organization {org}")))?;
    let Some(oidc) = state.auth.org_oidc(o.id, &o.name).await? else { return Err(RegistryError::bad_request(format!("{org} has no single sign-on"))) };
    let (claims, st) = match callback_claims(&state, &oidc, &headers, q).await? {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if st.org.as_deref() != Some(o.name.as_str()) {
        return with_cleared_login_cookie(&state, Err(RegistryError::bad_request("login state belongs to another provider")));
    }
    let empty = std::collections::HashMap::new();
    let login = SsoLogin {
        // Scoped to the org: its provider cannot claim identities from anywhere else.
        provider: format!("org:{}:{}", o.id, oidc.config().issuer.trim_end_matches('/')),
        username_claim: &oidc.config().username_claim,
        groups_claim: oidc.config().groups_claim.as_deref(),
        matching: sso::Matching::NewAccountOnly,
        may_create: true,
        default_roles: &[],
        group_roles: &empty,
        team_source: "org-oidc",
        team_org: Some(o.id),
    };
    with_cleared_login_cookie(&state, finish_sso(&state, &headers, client.as_deref(), &claims, &st, &login).await)
}

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::safe_redirect;

    #[test]
    fn redirects_stay_on_site() {
        let ok = |r: &str| safe_redirect(Some(r.to_string())).is_some();
        assert!(ok("/") && ok("/orgs/acme?tab=sso"));
        for bad in ["//evil.example", "/\\evil.example", "/\\/evil.example", "https://evil.example", "evil", "/ /evil", "/\t/evil.example", "/x\ny", ""] {
            assert!(!ok(bad), "{bad:?} must be refused");
        }
        assert!(safe_redirect(None).is_none());
    }
}

