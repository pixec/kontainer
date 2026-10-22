//! OpenID Connect login (authorization code flow with PKCE).

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::{OnceCell, RwLock};

use crate::auth::jwks;
use kontainer_core::random_token;
use crate::database::Db;
use kontainer_core::config::OidcConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct IdClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, rename = "email_verified")]
    pub is_email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl IdClaims {
    pub fn claim_str(&self, name: &str) -> Option<String> {
        match name {
            "sub" => Some(self.sub.clone()),
            "email" => self.email.clone(),
            "name" => self.name.clone(),
            "preferred_username" => self.preferred_username.clone(),
            other => self.extra.get(other).and_then(|v| v.as_str()).map(str::to_string),
        }
    }

    pub fn groups(&self, claim: &str) -> Vec<String> {
        self.extra
            .get(claim)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|g| g.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    }
}

/// The cookie binding a login to the browser that started it. Scoped to `/auth/oidc`, where the
/// callbacks live.
pub const LOGIN_COOKIE: &str = "kontainer_oidc";

/// The cookie that stands in for the session when a link's callback arrives. The session cookie
/// is `SameSite=Strict`, so the provider's (cross-site) redirect back does not carry it; this one
/// is `Lax`, scoped to `/auth/oidc`, set only by the signed-in POST that starts a link, and lives
/// as long as a login state does.
pub const LINK_COOKIE: &str = "kontainer_oidc_link";

/// A login just started.
pub struct Begin {
    /// The provider's authorization URL.
    pub url: String,
    /// Goes in the browser's [`LOGIN_COOKIE`]; only its hash is stored with the state.
    pub browser_nonce: String,
    /// For a link: goes in the browser's [`LINK_COOKIE`]; only its hash is stored with the state.
    pub link_token: Option<String>,
}

/// Whether the callback's cookie is the one the login was started with. States without a
/// binding (created before it existed) never match.
pub(crate) fn browser_matches(stored_hash: Option<&str>, cookie: Option<&str>) -> bool {
    match (stored_hash, cookie) {
        (Some(h), Some(c)) if !c.is_empty() => {
            let got = crate::database::sha256_hex(c);
            // Constant-time: both are 64 hex characters.
            got.len() == h.len() && got.bytes().zip(h.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        }
        _ => false,
    }
}

pub struct Oidc {
    cfg: OidcConfig,
    redirect_url: String,
    http: reqwest::Client,
    discovery: OnceCell<Discovery>,
    jwks: RwLock<Option<(Instant, Arc<JwkSet>)>>,
}

impl Oidc {
    /// The provider's settings. `client_secret` is a [`kontainer_core::config::Secret`], so this is safe
    /// to log.
    pub fn config(&self) -> &OidcConfig {
        &self.cfg
    }

    pub fn new(cfg: &OidcConfig, public_url: &str) -> Result<Self> {
        Ok(Self {
            cfg: cfg.clone(),
            redirect_url: cfg.redirect_url.clone().unwrap_or_else(|| format!("{public_url}/auth/oidc/callback")),
            http: reqwest::Client::builder().user_agent(kontainer_core::USER_AGENT).timeout(Duration::from_secs(15)).build().context("building HTTP client")?,
            discovery: OnceCell::new(),
            jwks: RwLock::new(None),
        })
    }

    async fn discovery(&self) -> Result<&Discovery> {
        self.discovery
            .get_or_try_init(|| async {
                let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer.trim_end_matches('/'));
                self.http.get(&url).send().await?.error_for_status()?.json::<Discovery>().await.with_context(|| format!("fetching {url}"))
            })
            .await
    }

    /// The provider's keys. `force`: refetch even if cached (a token named an unknown key),
    /// but not more than once per [`jwks::FORCED_REFRESH_COOLDOWN`].
    async fn jwks(&self, force: bool) -> Result<Arc<JwkSet>> {
        if let Some((at, set)) = self.jwks.read().await.as_ref() {
            let fresh_for = if force { jwks::FORCED_REFRESH_COOLDOWN } else { Duration::from_secs(3600) };
            if at.elapsed() < fresh_for {
                return Ok(set.clone());
            }
        }
        let d = self.discovery().await?;
        let set: JwkSet = self.http.get(&d.jwks_uri).send().await?.error_for_status()?.json().await.context("fetching jwks")?;
        let set = Arc::new(set);
        *self.jwks.write().await = Some((Instant::now(), set.clone()));
        Ok(set)
    }

    /// Start a login: returns the provider URL to redirect the browser to, and the nonce to put
    /// in that browser's login cookie ([`LOGIN_COOKIE`]).
    pub async fn begin(&self, db: &Db, redirect_to: Option<&str>) -> Result<Begin> {
        self.begin_for(db, redirect_to, None, None).await
    }

    /// `org`: an organization's own provider. `link_user_id`: a signed-in user linking the
    /// identity to their account (the callback must come from that user's session).
    pub async fn begin_for(&self, db: &Db, redirect_to: Option<&str>, org: Option<&str>, link_user_id: Option<i64>) -> Result<Begin> {
        let d = self.discovery().await?;
        let nonce = random_token(16);
        let verifier = random_token(32);
        let browser_nonce = random_token(32);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
        let link_token = link_user_id.map(|_| random_token(32));
        let link_hash = link_token.as_deref().map(crate::database::sha256_hex);
        let link = link_user_id.zip(link_hash.as_deref());
        let state = db.create_oidc_state_bound(&nonce, &verifier, redirect_to, org, link, &crate::database::sha256_hex(&browser_nonce)).await?;
        let mut url = url::Url::parse(&d.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("scope", &self.cfg.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(Begin { url: url.to_string(), browser_nonce, link_token })
    }

    /// Finish a login: exchange the code, verify the ID token, return its claims and the
    /// post-login redirect. `browser_nonce`: the login cookie of the browser making the
    /// callback, which must be the one that started the login.
    pub async fn complete(&self, db: &Db, code: &str, state: &str, browser_nonce: Option<&str>) -> Result<(IdClaims, crate::database::OidcState)> {
        let st = db.take_oidc_state(state).await?.ok_or_else(|| anyhow!("unknown or expired login state"))?;
        if !browser_matches(st.browser_hash.as_deref(), browser_nonce) {
            anyhow::bail!("login state was started in another browser");
        }
        let d = self.discovery().await?;
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let resp = self
            .http
            .post(&d.token_endpoint)
            .basic_auth(&self.cfg.client_id, Some(self.cfg.client_secret.expose()))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_url.as_str()),
                ("client_id", self.cfg.client_id.as_str()),
                ("client_secret", self.cfg.client_secret.expose()),
                ("code_verifier", st.pkce_verifier.as_str()),
            ])
            .send()
            .await?;
        if !resp.status().is_success() {
            // The body may echo the code or other details: log it, keep it out of the error.
            let status = resp.status();
            let body: String = resp.text().await.unwrap_or_default().chars().take(1024).collect();
            tracing::warn!(issuer = %self.cfg.issuer, %status, body = %body, "OIDC token endpoint refused the code exchange");
            anyhow::bail!("token endpoint returned {status}");
        }
        let tr: TokenResponse = resp.json().await.context("parsing token response")?;
        let claims = self.verify_id_token(&tr.id_token).await?;
        if claims.nonce.as_deref() != Some(st.nonce.as_str()) {
            anyhow::bail!("id token nonce mismatch");
        }
        Ok((claims, st))
    }

    async fn verify_id_token(&self, token: &str) -> Result<IdClaims> {
        let header = decode_header(token)?;
        let d = self.discovery().await?;
        let jwk = match jwks::find_key(&*self.jwks(false).await?, &header)? {
            Some(j) => j,
            None => jwks::find_key(&*self.jwks(true).await?, &header)?.ok_or_else(|| anyhow!("no matching signing key"))?,
        };
        let alg = jwks::algorithm(&jwk, &header)?;
        let key = DecodingKey::from_jwk(&jwk)?;
        let mut v = Validation::new(alg);
        v.set_audience(&[self.cfg.client_id.as_str()]);
        v.set_issuer(&[d.issuer.as_str(), self.cfg.issuer.trim_end_matches('/')]);
        Ok(decode::<IdClaims>(token, &key, &v)?.claims)
    }
}

use sha2::Digest as _;

#[cfg(test)]
mod tests {
    #[test]
    fn browser_binding() {
        let h = crate::database::sha256_hex("nonce");
        assert!(super::browser_matches(Some(&h), Some("nonce")));
        assert!(!super::browser_matches(Some(&h), Some("other")));
        assert!(!super::browser_matches(Some(&h), None));
        assert!(!super::browser_matches(Some(&h), Some("")));
        assert!(!super::browser_matches(None, Some("nonce")), "unbound states are refused");
    }
}
