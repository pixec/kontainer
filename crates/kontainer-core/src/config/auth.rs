//! Authentication: local accounts, roles, OIDC and LDAP.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{humantime_serde, DatabaseUrl, Secret};
use crate::perm::Role;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// `none`: no authentication, everything allowed. `basic`: HTTP Basic challenge.
    /// `token` (default): Docker-style bearer token flow (`docker login` obtains a JWT from
    /// `/auth/token`). Sessions, Basic auth and access tokens work in both `basic` and `token`.
    pub mode: AuthMode,
    /// `mode = "none"` makes every caller a superuser, so it is refused unless the server
    /// binds to a loopback address or this is set.
    pub allow_insecure_none: bool,
    pub realm: String,
    /// PostgreSQL database holding users, roles, sessions, tokens and the rest of the registry's
    /// metadata: a `postgres://user:password@host:port/database` URL (`KONTAINER_DATABASE_URL`).
    /// Its password is never printed.
    pub database_url: DatabaseUrl,
    /// Most connections to the database at once.
    pub database_pool: u32,
    /// Secret for signing bearer tokens (at least 32 bytes). Generated and stored in the database when unset.
    pub secret: Option<Secret>,
    /// Key for the secrets the registry stores in its database (upstream passwords, webhook
    /// secrets, Git tokens, SSO client secrets, its own signing secret), 32+ bytes
    /// (`KONTAINER_ENCRYPTION_KEY`). Unset, a key is derived from `secret`; with neither, they
    /// are stored unencrypted. See docs/operations.md, "Secrets at rest".
    pub encryption_key: Option<Secret>,
    /// Keys stored secrets may still be encrypted with, during a rotation: they decrypt, never
    /// encrypt (`KONTAINER_PREVIOUS_ENCRYPTION_KEYS`, comma-separated).
    pub previous_encryption_keys: Vec<Secret>,
    /// Audience / `service` name in bearer tokens. Defaults to the host of `public_url`.
    pub service: Option<String>,
    #[serde(with = "humantime_serde")]
    pub session_ttl: Duration,
    #[serde(with = "humantime_serde")]
    pub token_ttl: Duration,
    /// Created on first start when the database has no users. Change the password afterwards.
    pub bootstrap_admin: Option<BootstrapAdmin>,
    /// Roles granted to unauthenticated requests.
    pub anonymous_roles: Vec<String>,
    /// Repositories (globs) anyone may pull from, even unauthenticated.
    pub public_repositories: Vec<String>,
    /// Roles defined here are synced into the database on start and are read-only in the UI.
    pub roles: Vec<Role>,
    /// Users defined here are synced into the database on start.
    pub users: Vec<User>,
    pub oidc: OidcConfig,
    pub ldap: LdapConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Token,
            allow_insecure_none: false,
            realm: "kontainer".into(),
            database_url: DatabaseUrl::default(),
            database_pool: 16,
            secret: None,
            encryption_key: None,
            previous_encryption_keys: vec![],
            service: None,
            session_ttl: Duration::from_secs(7 * 24 * 3600),
            token_ttl: Duration::from_secs(3600),
            bootstrap_admin: None,
            anonymous_roles: vec![],
            public_repositories: vec![],
            roles: vec![],
            users: vec![],
            oidc: OidcConfig::default(),
            ldap: LdapConfig::default(),
        }
    }
}

/// Sign in with directory (LDAP / Active Directory) passwords. Accounts are created on first
/// sign-in; directory groups map to roles and to synced organization teams.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LdapConfig {
    #[serde(rename = "enabled")]
    pub is_enabled: bool,
    /// `ldap://host:389` or `ldaps://host:636`.
    pub url: String,
    /// Upgrade `ldap://` with StartTLS.
    #[serde(rename = "start_tls")]
    pub is_start_tls: bool,
    /// Allow plain `ldap://` without StartTLS: passwords then cross the network in clear text.
    pub allow_insecure: bool,
    /// Service account used to find users and their groups. Empty: anonymous bind.
    pub bind_dn: String,
    pub bind_password: Secret,
    pub user_base_dn: String,
    /// `{username}` is replaced (escaped). Active Directory: `(sAMAccountName={username})`.
    pub user_filter: String,
    pub username_attr: String,
    pub email_attr: String,
    pub name_attr: String,
    /// Empty: read group names from the user's `memberOf` instead.
    pub group_base_dn: String,
    /// `{dn}` and `{username}` are replaced (escaped).
    pub group_filter: String,
    pub group_name_attr: String,
    /// Directory group -> roles, applied on every sign-in.
    pub group_roles: HashMap<String, Vec<String>>,
    /// Roles every directory user gets.
    pub default_roles: Vec<String>,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            is_enabled: false,
            url: String::new(),
            is_start_tls: false,
            allow_insecure: false,
            bind_dn: String::new(),
            bind_password: Secret::default(),
            user_base_dn: String::new(),
            user_filter: "(uid={username})".into(),
            username_attr: "uid".into(),
            email_attr: "mail".into(),
            name_attr: "cn".into(),
            group_base_dn: String::new(),
            group_filter: "(|(member={dn})(memberUid={username}))".into(),
            group_name_attr: "cn".into(),
            group_roles: HashMap::new(),
            default_roles: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    None,
    Basic,
    Token,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapAdmin {
    pub username: String,
    pub password: Secret,
}

/// Why `password` is not acceptable for a new or changed password, if it isn't. The single
/// rule for every password this server sets: the API (through `kontainer_server::auth::password`) and
/// passwords given in the configuration.
pub fn check_password_strength(password: &str) -> Result<(), &'static str> {
    if password.chars().count() < 8 {
        return Err("password must be at least 8 characters");
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub username: String,
    /// Argon2id hash (generate with `kontainer hash-password`); bcrypt hashes (htpasswd-style)
    /// are also accepted.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// Plain-text password. Only for development.
    #[serde(default)]
    pub password: Option<Secret>,
    #[serde(default)]
    pub roles: Vec<String>,
    /// Robot accounts are machine credentials (CI, deploy keys), conventionally named
    /// `<owner>+<name>`. They cannot log in to the UI.
    #[serde(default, rename = "robot")]
    pub is_robot: bool,
    #[serde(default)]
    pub email: Option<String>,
}

/// OpenID Connect single sign-on (Google, Okta, Keycloak, Entra ID, Authentik...).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcConfig {
    #[serde(rename = "enabled")]
    pub is_enabled: bool,
    /// Label shown on the sign-in button.
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Secret,
    /// Defaults to `<public_url>/auth/oidc/callback`.
    pub redirect_url: Option<String>,
    pub scopes: Vec<String>,
    /// Claim used for the registry username.
    pub username_claim: String,
    /// Claim containing group names, mapped to roles through `group_roles`.
    pub groups_claim: Option<String>,
    pub group_roles: HashMap<String, Vec<String>>,
    /// Roles every SSO user gets.
    pub default_roles: Vec<String>,
    /// Create registry accounts for unknown SSO users. When false, only pre-created users
    /// (matched by username/email) may sign in.
    #[serde(rename = "auto_create_users")]
    pub is_auto_create_users: bool,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            is_enabled: false,
            display_name: "SSO".into(),
            issuer: String::new(),
            client_id: String::new(),
            client_secret: Secret::default(),
            redirect_url: None,
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            username_claim: "preferred_username".into(),
            groups_claim: None,
            group_roles: HashMap::new(),
            default_roles: vec![],
            is_auto_create_users: true,
        }
    }
}
