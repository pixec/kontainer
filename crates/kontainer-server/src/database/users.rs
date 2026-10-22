//! Accounts, roles, sessions, access tokens, SSO identities, MFA recovery codes.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::{now, random_token, Db};
use kontainer_core::perm::{Role, Rule};

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip)]
    pub password_hash: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_robot: bool,
    pub owner_id: Option<i64>,
    pub is_disabled: bool,
    pub is_managed: bool,
    /// The TOTP secret as stored (sealed, see [`super::secrets`]): set exactly when two-factor
    /// authentication is on; [`Db::user_mfa_secret`] opens it. A secret being set up lives in
    /// `mfa_setups` until a code confirms it.
    #[serde(skip)]
    pub mfa_secret: Option<String>,
    /// `mfa_secret.is_some()`, derived when the row is read.
    pub is_mfa_enabled: bool,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub last_login_at: Option<DateTime<Utc>>,
    pub org_id: Option<i64>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for User {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> sqlx::Result<Self> {
        use sqlx::Row;
        let mfa_secret: Option<String> = row.try_get("mfa_secret")?;
        Ok(Self {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            password_hash: row.try_get("password_hash")?,
            email: row.try_get("email")?,
            display_name: row.try_get("display_name")?,
            is_robot: row.try_get("is_robot")?,
            owner_id: row.try_get("owner_id")?,
            is_disabled: row.try_get("is_disabled")?,
            is_managed: row.try_get("is_managed")?,
            is_mfa_enabled: mfa_secret.is_some(),
            mfa_secret,
            created_at: row.try_get("created_at")?,
            last_login_at: row.try_get("last_login_at")?,
            org_id: row.try_get("org_id")?,
        })
    }
}

/// Public profile shown to other users. Empty fields are stored as NULL.
#[derive(Debug, Clone, Default, Serialize, Deserialize, sqlx::FromRow)]
pub struct Profile {
    pub display_name: Option<String>,
    pub company: Option<String>,
    pub location: Option<String>,
    pub website: Option<String>,
    pub gravatar_email: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339")]
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AccessToken {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    /// The plaintext token's first characters, to tell tokens apart in the UI.
    pub hint: String,
    #[serde(skip)]
    pub token_hash: String,
    #[serde(skip)]
    pub scopes: Option<String>,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "super::rfc3339::option")]
    pub last_used_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    /// The rules restricting this token: `None` means unrestricted. Scopes that cannot be read
    /// are an error, never "unrestricted": callers must refuse the token.
    pub fn scope_rules(&self) -> Result<Option<Vec<Rule>>> {
        self.scopes.as_deref().map(|s| serde_json::from_str(s).with_context(|| format!("access token {} has unreadable scopes", self.id))).transpose()
    }
    pub fn expired(&self) -> bool {
        self.expires_at.is_some_and(|t| t < Utc::now())
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Identity {
    pub provider: String,
    pub subject: String,
    pub user_id: i64,
    pub email: Option<String>,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OidcState {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub redirect_to: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Set for an organization's own provider.
    pub org: Option<String>,
    /// A signed-in user linking this identity to their account.
    pub link_user_id: Option<i64>,
    /// SHA-256 of the nonce in the browser cookie that started the login; `None` for states
    /// created before browser binding, which are refused.
    pub browser_hash: Option<String>,
    /// For a link: SHA-256 of the token in the browser's link cookie
    /// ([`crate::auth::oidc::LINK_COOKIE`]), which stands in for the session at the callback.
    pub link_hash: Option<String>,
}

/// A registered passkey, as listed to its owner.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PasskeyRow {
    pub id: i64,
    pub user_id: i64,
    #[serde(skip)]
    pub credential_id: Vec<u8>,
    /// json `webauthn_rs::prelude::Passkey`.
    #[serde(skip)]
    pub credential: String,
    pub name: String,
    pub sign_count: i64,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub last_used_at: Option<DateTime<Utc>>,
}

/// A WebAuthn ceremony waiting for its finish request.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebauthnChallenge {
    pub id: String,
    /// `register`, `login` or `discoverable`.
    pub kind: String,
    pub user_id: Option<i64>,
    /// json webauthn-rs ceremony state.
    pub state: String,
    pub name: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct RoleRow {
    name: String,
    description: String,
    rules: String,
    global: String,
    is_managed: bool,
}

impl RoleRow {
    fn into_role(self) -> Role {
        Role {
            name: self.name,
            description: self.description,
            rules: serde_json::from_str(&self.rules).unwrap_or_default(),
            global: serde_json::from_str(&self.global).unwrap_or_default(),
            is_managed: self.is_managed,
        }
    }
}

impl Db {
    pub async fn user_by_name(&self, username: &str) -> Result<Option<User>> {
        Ok(sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1").bind(username).fetch_optional(&self.pool).await?)
    }

    pub async fn user_by_id(&self, id: i64) -> Result<Option<User>> {
        Ok(sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1").bind(id).fetch_optional(&self.pool).await?)
    }

    pub async fn profile(&self, id: i64) -> Result<Option<Profile>> {
        Ok(sqlx::query_as::<_, Profile>("SELECT display_name, company, location, website, gravatar_email FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn set_profile(&self, id: i64, p: &Profile) -> Result<()> {
        sqlx::query("UPDATE users SET display_name = $1, company = $2, location = $3, website = $4, gravatar_email = $5 WHERE id = $6")
            .bind(&p.display_name)
            .bind(&p.company)
            .bind(&p.location)
            .bind(&p.website)
            .bind(&p.gravatar_email)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// People (not robots, not disabled) whose username or display name contains `q`,
    /// best matches first: (username, display name, gravatar email).
    pub async fn search_people(&self, q: &str, limit: i64) -> Result<Vec<(String, Option<String>, Option<String>)>> {
        let like = format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
        let prefix = format!("{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
        Ok(sqlx::query_as(
            "SELECT username, display_name, gravatar_email FROM users
             WHERE is_robot = false AND is_disabled = false AND (username ILIKE $1 ESCAPE '\\' OR display_name ILIKE $1 ESCAPE '\\')
             ORDER BY username = $3 DESC, username ILIKE $2 ESCAPE '\\' DESC, username LIMIT $4",
        )
        .bind(&like)
        .bind(&prefix)
        .bind(q)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        Ok(sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY is_robot, username").fetch_all(&self.pool).await?)
    }

    pub async fn list_robots(&self, owner_id: i64) -> Result<Vec<User>> {
        Ok(sqlx::query_as::<_, User>("SELECT * FROM users WHERE owner_id = $1 ORDER BY username").bind(owner_id).fetch_all(&self.pool).await?)
    }

    pub async fn count_users(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_robot = false").fetch_one(&self.pool).await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_user(
        &self,
        username: &str,
        password_hash: Option<&str>,
        email: Option<&str>,
        display_name: Option<&str>,
        is_robot: bool,
        owner_id: Option<i64>,
        is_managed: bool,
    ) -> Result<User> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO users(username, password_hash, email, display_name, is_robot, owner_id, is_managed, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        )
        .bind(username)
        .bind(password_hash)
        .bind(email)
        .bind(display_name)
        .bind(is_robot)
        .bind(owner_id)
        .bind(is_managed)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        Ok(self.user_by_id(id).await?.expect("just inserted"))
    }

    pub async fn set_password(&self, id: i64, hash: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2").bind(hash).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn set_managed(&self, id: i64, is_managed: bool) -> Result<()> {
        sqlx::query("UPDATE users SET is_managed = $1 WHERE id = $2").bind(is_managed).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn update_user(&self, id: i64, email: Option<&str>, display_name: Option<&str>, is_disabled: Option<bool>) -> Result<()> {
        sqlx::query(
            "UPDATE users SET email = COALESCE($1, email), display_name = COALESCE($2, display_name), is_disabled = COALESCE($3, is_disabled) WHERE id = $4",
        )
        .bind(email)
        .bind(display_name)
        .bind(is_disabled)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn touch_login(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE users SET last_login_at = $1 WHERE id = $2").bind(now()).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn delete_user(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn user_roles(&self, id: i64) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT role FROM user_roles WHERE user_id = $1 ORDER BY role").bind(id).fetch_all(&self.pool).await?)
    }

    pub async fn set_user_roles(&self, id: i64, roles: &[String]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM user_roles WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
        for r in roles {
            sqlx::query("INSERT INTO user_roles(user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(id).bind(r).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Start (or restart) setting up two-factor authentication with `secret`, which stays
    /// pending for `ttl`.
    pub async fn start_mfa_setup(&self, id: i64, secret: &str, ttl: Duration) -> Result<()> {
        let created = now();
        sqlx::query(
            "INSERT INTO mfa_setups(user_id, secret, created_at, expires_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at, expires_at = excluded.expires_at",
        )
        .bind(id)
        .bind(self.seal_secret(secret))
        .bind(created)
        .bind(created + ttl)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The secret being set up for `id`, unless the setup expired.
    pub async fn pending_mfa_secret(&self, id: i64) -> Result<Option<String>> {
        let stored: Option<String> = sqlx::query_scalar("SELECT secret FROM mfa_setups WHERE user_id = $1 AND expires_at > now()").bind(id).fetch_optional(&self.pool).await?;
        self.open_secret_opt("mfa_setups.secret", id, stored)
    }

    /// `user`'s TOTP secret in plaintext, if two-factor authentication is on.
    pub fn user_mfa_secret(&self, user: &User) -> Result<Option<String>> {
        self.open_secret_opt("users.mfa_secret", user.id, user.mfa_secret.clone())
    }

    /// Finish setting up: the pending `secret` becomes the account's, with new recovery codes.
    /// Returns false, changing nothing, when that setup is no longer pending (expired, or
    /// replaced by a newer one).
    pub async fn complete_mfa_setup(&self, id: i64, secret: &str, recovery_hashes: &[String]) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        // Sealed values carry random nonces: compare the plaintext, under the row lock.
        let stored: Option<String> = sqlx::query_scalar("SELECT secret FROM mfa_setups WHERE user_id = $1 AND expires_at > now() FOR UPDATE").bind(id).fetch_optional(&mut *tx).await?;
        if self.open_secret_opt("mfa_setups.secret", id, stored)?.as_deref() != Some(secret) {
            return Ok(false);
        }
        sqlx::query("DELETE FROM mfa_setups WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
        sqlx::query("UPDATE users SET mfa_secret = $1 WHERE id = $2").bind(self.seal_secret(secret)).bind(id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
        for h in recovery_hashes {
            sqlx::query("INSERT INTO recovery_codes(user_id, code_hash) VALUES ($1, $2)").bind(id).bind(h).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Turn two-factor authentication off: no secret, no setup in progress, no recovery codes.
    pub async fn disable_mfa(&self, id: i64) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET mfa_secret = NULL WHERE id = $1").bind(id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM mfa_setups WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn replace_recovery_codes(&self, id: i64, hashes: &[String]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
        for h in hashes {
            sqlx::query("INSERT INTO recovery_codes(user_id, code_hash) VALUES ($1, $2)").bind(id).bind(h).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Consume a recovery code. Returns true if it was valid and unused.
    pub async fn use_recovery_code(&self, id: i64, hash: &str) -> Result<bool> {
        let n = sqlx::query("UPDATE recovery_codes SET is_used = true WHERE user_id = $1 AND code_hash = $2 AND is_used = false")
            .bind(id)
            .bind(hash)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n == 1)
    }

    /// Record that a one-time code from TOTP time step `step` was accepted. Returns false, and
    /// records nothing, when this step or a later one was already used (a replay).
    pub async fn claim_totp_step(&self, id: i64, step: u64) -> Result<bool> {
        let step = i64::try_from(step)?;
        let n = sqlx::query("UPDATE users SET last_totp_step = $1 WHERE id = $2 AND (last_totp_step IS NULL OR last_totp_step < $3)")
            .bind(step)
            .bind(id)
            .bind(step)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n == 1)
    }

    pub async fn list_roles(&self) -> Result<Vec<Role>> {
        let rows = sqlx::query_as::<_, RoleRow>("SELECT name, description, rules, global, is_managed FROM roles ORDER BY name").fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(RoleRow::into_role).collect())
    }

    pub async fn get_role(&self, name: &str) -> Result<Option<Role>> {
        let row = sqlx::query_as::<_, RoleRow>("SELECT name, description, rules, global, is_managed FROM roles WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(RoleRow::into_role))
    }

    pub async fn upsert_role(&self, role: &Role) -> Result<()> {
        sqlx::query(
            "INSERT INTO roles(name, description, rules, global, is_managed, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(name) DO UPDATE SET description = excluded.description, rules = excluded.rules,
             global = excluded.global, is_managed = excluded.is_managed, updated_at = excluded.updated_at",
        )
        .bind(&role.name)
        .bind(&role.description)
        .bind(serde_json::to_string(&role.rules)?)
        .bind(serde_json::to_string(&role.global)?)
        .bind(role.is_managed)
        .bind(now())
        .bind(now())
        .execute(&self.pool)
        .await?;
        self.notify(&super::notify::Topic::Roles).await;
        Ok(())
    }

    pub async fn delete_role(&self, name: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM user_roles WHERE role = $1").bind(name).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM roles WHERE name = $1").bind(name).execute(&mut *tx).await?;
        tx.commit().await?;
        self.notify(&super::notify::Topic::Roles).await;
        Ok(())
    }

    /// Drop managed roles that are no longer in the config.
    pub async fn prune_managed_roles(&self, keep: &[String]) -> Result<()> {
        let rows: Vec<String> = sqlx::query_scalar("SELECT name FROM roles WHERE is_managed = true").fetch_all(&self.pool).await?;
        for name in rows {
            if !keep.contains(&name) {
                self.delete_role(&name).await?;
            }
        }
        Ok(())
    }

    pub async fn create_session(&self, user_id: i64, ttl: Duration, user_agent: Option<&str>, ip: Option<&str>) -> Result<Session> {
        let id = random_token(32);
        let created = Utc::now();
        sqlx::query("INSERT INTO sessions(id, user_id, created_at, expires_at, user_agent, ip) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(&id)
            .bind(user_id)
            .bind(created)
            .bind(created + ttl)
            .bind(user_agent)
            .bind(ip)
            .execute(&self.pool)
            .await?;
        Ok(self.session(&id).await?.expect("just inserted"))
    }

    pub async fn session(&self, id: &str) -> Result<Option<Session>> {
        let s = sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = $1").bind(id).fetch_optional(&self.pool).await?;
        Ok(s.filter(|s| s.expires_at > Utc::now()))
    }

    pub async fn list_sessions(&self, user_id: i64) -> Result<Vec<Session>> {
        Ok(sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY created_at DESC")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn delete_session(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn delete_user_sessions(&self, user_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn purge_expired(&self) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE expires_at < now()").execute(&self.pool).await?;
        sqlx::query("DELETE FROM oidc_states WHERE created_at < now() - interval '15 minutes'").execute(&self.pool).await?;
        sqlx::query("DELETE FROM mfa_setups WHERE expires_at < now()").execute(&self.pool).await?;
        sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at < now()").execute(&self.pool).await?;
        // Deletion plans: kept a day past expiry, so a late `execute` says "expired", not "unknown".
        sqlx::query("DELETE FROM delete_plans WHERE expires_at < now() - interval '1 day'").execute(&self.pool).await?;
        // Hour-long tokens from keyless robot logins pile up otherwise.
        sqlx::query("DELETE FROM access_tokens WHERE name = 'oidc exchange' AND expires_at < now()").execute(&self.pool).await?;
        // Failed sign-ins whose window is over and that lock nothing out any more.
        let window = chrono::Duration::from_std(crate::auth::limits::WINDOW).unwrap_or_default();
        sqlx::query("DELETE FROM login_failures WHERE window_started_at < $1 AND (locked_until IS NULL OR locked_until < now())").bind(Utc::now() - window).execute(&self.pool).await?;
        // Background jobs: a week of history.
        sqlx::query("DELETE FROM jobs WHERE status <> 'running' AND finished_at < now() - interval '7 days'").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn create_token(&self, user_id: i64, name: &str, hint: &str, hash: &str, scopes: Option<&[Rule]>, expires_at: Option<DateTime<Utc>>) -> Result<AccessToken> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO access_tokens(user_id, name, hint, token_hash, scopes, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(user_id)
        .bind(name)
        .bind(hint)
        .bind(hash)
        .bind(scopes.map(serde_json::to_string).transpose()?)
        .bind(now())
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(sqlx::query_as::<_, AccessToken>("SELECT * FROM access_tokens WHERE id = $1").bind(id).fetch_one(&self.pool).await?)
    }

    pub async fn token_by_hash(&self, hash: &str) -> Result<Option<AccessToken>> {
        Ok(sqlx::query_as::<_, AccessToken>("SELECT * FROM access_tokens WHERE token_hash = $1").bind(hash).fetch_optional(&self.pool).await?)
    }

    pub async fn touch_token(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE access_tokens SET last_used_at = $1 WHERE id = $2").bind(now()).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn list_tokens(&self, user_id: i64) -> Result<Vec<AccessToken>> {
        Ok(sqlx::query_as::<_, AccessToken>("SELECT * FROM access_tokens WHERE user_id = $1 ORDER BY created_at DESC").bind(user_id).fetch_all(&self.pool).await?)
    }

    pub async fn delete_token(&self, user_id: i64, id: i64) -> Result<bool> {
        let n = sqlx::query("DELETE FROM access_tokens WHERE id = $1 AND user_id = $2").bind(id).bind(user_id).execute(&self.pool).await?.rows_affected();
        Ok(n == 1)
    }

    pub async fn identity(&self, provider: &str, subject: &str) -> Result<Option<Identity>> {
        Ok(sqlx::query_as::<_, Identity>("SELECT * FROM identities WHERE provider = $1 AND subject = $2")
            .bind(provider)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn link_identity(&self, provider: &str, subject: &str, user_id: i64, email: Option<&str>) -> Result<()> {
        sqlx::query("INSERT INTO identities(provider, subject, user_id, email, created_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (provider, subject) DO UPDATE SET email = excluded.email")
            .bind(provider)
            .bind(subject)
            .bind(user_id)
            .bind(email)
            .bind(now())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn user_identities(&self, user_id: i64) -> Result<Vec<Identity>> {
        Ok(sqlx::query_as::<_, Identity>("SELECT * FROM identities WHERE user_id = $1").bind(user_id).fetch_all(&self.pool).await?)
    }

    /// A new OIDC login state bound to a browser: `browser_hash` is the SHA-256 of the nonce in
    /// that browser's login cookie; for a link, `link` is the linking user and the SHA-256 of the
    /// token in that browser's link cookie. Returns the state value.
    pub async fn create_oidc_state_bound(&self, nonce: &str, verifier: &str, redirect_to: Option<&str>, org: Option<&str>, link: Option<(i64, &str)>, browser_hash: &str) -> Result<String> {
        let state = super::random_token(24);
        sqlx::query("INSERT INTO oidc_states(state, nonce, pkce_verifier, redirect_to, created_at, org, link_user_id, browser_hash, link_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
            .bind(&state)
            .bind(nonce)
            .bind(verifier)
            .bind(redirect_to)
            .bind(now())
            .bind(org)
            .bind(link.map(|l| l.0))
            .bind(browser_hash)
            .bind(link.map(|l| l.1))
            .execute(&self.pool)
            .await?;
        Ok(state)
    }

    /// Fetch and delete an OIDC state (single use).
    pub async fn take_oidc_state(&self, state: &str) -> Result<Option<OidcState>> {
        let row = sqlx::query_as::<_, OidcState>("DELETE FROM oidc_states WHERE state = $1 RETURNING *").bind(state).fetch_optional(&self.pool).await?;
        Ok(row.filter(|r| r.created_at > Utc::now() - Duration::minutes(15)))
    }

    pub async fn list_passkeys(&self, user_id: i64) -> Result<Vec<PasskeyRow>> {
        Ok(sqlx::query_as::<_, PasskeyRow>("SELECT * FROM passkeys WHERE user_id = $1 ORDER BY created_at, id").bind(user_id).fetch_all(&self.pool).await?)
    }

    pub async fn passkey_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<PasskeyRow>> {
        Ok(sqlx::query_as::<_, PasskeyRow>("SELECT * FROM passkeys WHERE credential_id = $1").bind(credential_id).fetch_optional(&self.pool).await?)
    }

    /// Store a new passkey. `None` when its credential id is already registered (to anyone).
    pub async fn add_passkey(&self, user_id: i64, credential_id: &[u8], credential: &str, name: &str, sign_count: i64) -> Result<Option<PasskeyRow>> {
        Ok(sqlx::query_as::<_, PasskeyRow>(
            "INSERT INTO passkeys(user_id, credential_id, credential, name, sign_count, created_at) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (credential_id) DO NOTHING RETURNING *",
        )
        .bind(user_id)
        .bind(credential_id)
        .bind(credential)
        .bind(name)
        .bind(sign_count)
        .bind(now())
        .fetch_optional(&self.pool)
        .await?)
    }

    /// After a sign-in with passkey `id`: its updated credential (counter, backup state), if it
    /// changed, and when it was used.
    pub async fn touch_passkey(&self, id: i64, credential: Option<&str>, sign_count: i64) -> Result<()> {
        sqlx::query("UPDATE passkeys SET credential = COALESCE($1, credential), sign_count = GREATEST(sign_count, $2), last_used_at = $3 WHERE id = $4")
            .bind(credential)
            .bind(sign_count)
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_passkey(&self, user_id: i64, id: i64) -> Result<Option<String>> {
        Ok(sqlx::query_scalar("DELETE FROM passkeys WHERE id = $1 AND user_id = $2 RETURNING name").bind(id).bind(user_id).fetch_optional(&self.pool).await?)
    }

    /// Store a ceremony's state for `ttl`; returns its id.
    pub async fn create_webauthn_challenge(&self, kind: &str, user_id: Option<i64>, state: &str, name: Option<&str>, ttl: Duration) -> Result<String> {
        let id = random_token(24);
        let created = now();
        sqlx::query("INSERT INTO webauthn_challenges(id, kind, user_id, state, name, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(&id)
            .bind(kind)
            .bind(user_id)
            .bind(state)
            .bind(name)
            .bind(created)
            .bind(created + ttl)
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    /// Take (fetch and delete) an unexpired ceremony of one of `kinds`: each works once.
    pub async fn take_webauthn_challenge(&self, id: &str, kinds: &[&str]) -> Result<Option<WebauthnChallenge>> {
        let kinds: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
        Ok(sqlx::query_as::<_, WebauthnChallenge>("DELETE FROM webauthn_challenges WHERE id = $1 AND kind = ANY($2) AND expires_at > now() RETURNING id, kind, user_id, state, name")
            .bind(id)
            .bind(&kinds)
            .fetch_optional(&self.pool)
            .await?)
    }
}
