//! Keyless robot logins (OIDC federation): CI systems mint
//! short-lived OIDC tokens; a robot trusts tokens from configured issuers whose subject matches
//! a pattern. The token is checked against the issuer's published keys (discovery + JWKS).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation};

use crate::auth::jwks;
use serde::{Deserialize, Serialize};

use crate::database::Db;

const JWKS_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FederationRule {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub robot_id: i64,
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub audience: Option<String>,
    /// Set by the server; ignored in requests.
    #[serde(default, with = "crate::database::rfc3339")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct Unverified {
    iss: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
}

pub struct Federation {
    http: reqwest::Client,
    /// Expected `aud` when a rule names none: the registry's service name.
    audience: String,
    /// Per issuer: its keys and when they were fetched.
    jwks: Mutex<HashMap<String, (JwkSet, Instant)>>,
}

/// Does `secret` look like a JWT (three base64url parts) rather than a password or token?
pub fn looks_like_jwt(secret: &str) -> bool {
    secret.starts_with("ey") && secret.split('.').count() == 3
}

impl Federation {
    /// `audience`: what tokens must be issued for when a rule sets no audience (the
    /// registry's service name).
    pub fn new(audience: String) -> Result<Self> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(10)).user_agent(kontainer_core::USER_AGENT).build().context("building HTTP client")?;
        Ok(Self { http, audience, jwks: Mutex::new(HashMap::new()) })
    }

    /// The issuer's keys. `refresh`: refetch even if cached (a token named an unknown key),
    /// but not more than once per [`jwks::FORCED_REFRESH_COOLDOWN`].
    async fn keys(&self, issuer: &str, refresh: bool) -> Result<JwkSet> {
        if let Some((set, at)) = self.jwks.lock().unwrap_or_else(|e| e.into_inner()).get(issuer) {
            let fresh_for = if refresh { jwks::FORCED_REFRESH_COOLDOWN } else { JWKS_TTL };
            if at.elapsed() < fresh_for {
                return Ok(set.clone());
            }
        }
        let discovery = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let doc: serde_json::Value = self.http.get(&discovery).send().await.with_context(|| format!("fetching {discovery}"))?.error_for_status()?.json().await?;
        let jwks_uri = doc["jwks_uri"].as_str().ok_or_else(|| anyhow!("{discovery} has no jwks_uri"))?;
        let set: JwkSet = self.http.get(jwks_uri).send().await.with_context(|| format!("fetching {jwks_uri}"))?.error_for_status()?.json().await?;
        self.jwks.lock().unwrap_or_else(|e| e.into_inner()).insert(issuer.to_string(), (set.clone(), Instant::now()));
        Ok(set)
    }

    /// Verify `jwt` for `robot_id`: some rule must name its issuer, its signature must check
    /// out against that issuer's keys, and its subject and audience (the rule's, else the
    /// registry's service name) must match. Returns the claims.
    pub async fn verify(&self, db: &Db, robot_id: i64, jwt: &str) -> Result<Claims> {
        let payload = jwt.split('.').nth(1).ok_or_else(|| anyhow!("malformed token"))?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).context("malformed token")?;
        let iss = serde_json::from_slice::<Unverified>(&raw).ok().and_then(|u| u.iss).ok_or_else(|| anyhow!("token has no issuer"))?;
        let rules: Vec<FederationRule> = rules(db, robot_id).await?.into_iter().filter(|r| r.issuer.trim_end_matches('/') == iss.trim_end_matches('/')).collect();
        if rules.is_empty() {
            bail!("this robot does not trust tokens from {iss}");
        }
        let header = jsonwebtoken::decode_header(jwt)?;
        let jwk = match jwks::find_key(&self.keys(&iss, false).await?, &header)? {
            Some(k) => k,
            // Keys rotate: refetch (rate-limited) before giving up.
            None => jwks::find_key(&self.keys(&iss, true).await?, &header)?.ok_or_else(|| anyhow!("{iss} has no key {:?}", header.kid))?,
        };
        let alg = jwks::algorithm(&jwk, &header)?;
        let key = DecodingKey::from_jwk(&jwk)?;
        let mut last_err = anyhow!("no rule matched");
        for rule in &rules {
            let mut v = Validation::new(alg);
            v.set_issuer(&[iss.as_str()]);
            v.leeway = 30;
            v.set_audience(&[rule.audience.as_deref().unwrap_or(&self.audience)]);
            match jsonwebtoken::decode::<Claims>(jwt, &key, &v) {
                Ok(data) if kontainer_core::glob::matches(&rule.subject, &data.claims.sub) => return Ok(data.claims),
                Ok(data) => last_err = anyhow!("subject {} does not match {}", data.claims.sub, rule.subject),
                Err(e) => last_err = anyhow!("{e}"),
            }
        }
        Err(last_err)
    }
}

/// A robot's trusted issuers.
pub async fn rules(db: &Db, robot_id: i64) -> Result<Vec<FederationRule>> {
    Ok(sqlx::query_as::<_, FederationRule>("SELECT * FROM robot_federations WHERE robot_id = $1 ORDER BY id").bind(robot_id).fetch_all(db.pool()).await?)
}

/// Replace a robot's rules.
pub async fn set_rules(db: &Db, robot_id: i64, rules: &[FederationRule]) -> Result<()> {
    let mut tx = db.pool().begin().await?;
    sqlx::query("DELETE FROM robot_federations WHERE robot_id = $1").bind(robot_id).execute(&mut *tx).await?;
    for r in rules {
        sqlx::query("INSERT INTO robot_federations (robot_id, issuer, subject, audience, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(robot_id)
            .bind(r.issuer.trim())
            .bind(r.subject.trim())
            .bind(r.audience.as_deref().map(str::trim).filter(|a| !a.is_empty()))
            .bind(chrono::Utc::now())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
