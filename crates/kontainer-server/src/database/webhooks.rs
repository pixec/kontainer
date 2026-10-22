//! Namespace webhooks and their delivery history.

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{now, Db};

/// Finished deliveries kept per webhook (pending ones are never dropped).
const KEEP_DELIVERIES: i64 = 50;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Webhook {
    pub id: i64,
    pub namespace: String,
    pub name: String,
    pub url: String,
    pub format: String,
    #[serde(serialize_with = "json_list")]
    pub events: String,
    #[serde(serialize_with = "json_list")]
    pub repositories: String,
    #[serde(skip)]
    pub secret: Option<String>,
    #[serde(skip)]
    pub auth_header: Option<String>,
    pub is_verify_tls: bool,
    pub is_enabled: bool,
    pub created_by: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
}

fn json_list<S: serde::Serializer>(raw: &str, s: S) -> Result<S::Ok, S::Error> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default().serialize(s)
}

impl Webhook {
    pub fn event_list(&self) -> Vec<String> {
        serde_json::from_str(&self.events).unwrap_or_default()
    }
    pub fn repository_list(&self) -> Vec<String> {
        serde_json::from_str(&self.repositories).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookInput {
    pub name: String,
    pub url: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
    /// `None` keeps the stored value on an update; `""` clears it.
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default = "yes")]
    pub is_verify_tls: bool,
    #[serde(default = "yes")]
    pub is_enabled: bool,
}

fn default_format() -> String {
    "default".into()
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Delivery {
    pub id: i64,
    pub webhook_id: i64,
    pub event: String,
    pub payload: String,
    pub status: String,
    pub attempts: i64,
    pub response_code: Option<i64>,
    pub response_body: Option<String>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub delivered_at: Option<DateTime<Utc>>,
}

/// The outcome of one delivery attempt.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub ok: bool,
    pub response_code: Option<u16>,
    pub response_body: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// A delivery claimed from the queue: to a namespace hook (`webhook_id`) or a `[[webhooks]]` hook
/// from the config file (`config_hook`, by name).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QueuedDelivery {
    pub id: i64,
    pub webhook_id: Option<i64>,
    pub config_hook: Option<String>,
    pub event: String,
    pub payload: String,
    pub content_type: Option<String>,
    /// Attempts made before this one.
    pub attempts: i64,
    pub max_attempts: i32,
}

/// Whether two URLs share an origin: scheme, host and port (the default port for the scheme
/// when none is given), compared case-insensitively. User info and paths are ignored. URLs that
/// don't parse only match themselves.
pub(crate) fn same_origin(a: &str, b: &str) -> bool {
    fn origin(url: &str) -> Option<(String, String, u16)> {
        let (scheme, rest) = url.trim().split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        let authority = rest.split(['/', '?', '#']).next()?;
        let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        // `[::1]:8443`, `host:8443`, `host`
        let (host, port) = match authority.rfind(':') {
            Some(i) if !authority[i..].contains(']') => (&authority[..i], Some(authority[i + 1..].parse::<u16>().ok()?)),
            _ => (authority, None),
        };
        let port = port.or(match scheme.as_str() {
            "http" => Some(80),
            "https" => Some(443),
            "ssh" => Some(22),
            _ => None,
        })?;
        (!host.is_empty()).then(|| (scheme, host.trim_end_matches('.').to_ascii_lowercase(), port))
    }
    match (origin(a), origin(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a.trim() == b.trim(),
    }
}

fn blank_to_none(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|s| !s.is_empty())
}

impl Db {
    /// `h` with its secret and auth header decrypted (see [`super::secrets`]).
    fn open_webhook(&self, mut h: Webhook) -> Result<Webhook> {
        h.secret = self.open_secret_opt("webhooks.secret", h.id, h.secret.take())?;
        h.auth_header = self.open_secret_opt("webhooks.auth_header", h.id, h.auth_header.take())?;
        Ok(h)
    }

    pub async fn all_webhooks(&self) -> Result<Vec<Webhook>> {
        sqlx::query_as::<_, Webhook>("SELECT * FROM webhooks ORDER BY namespace, id").fetch_all(self.pool()).await?.into_iter().map(|h| self.open_webhook(h)).collect()
    }

    pub async fn webhooks(&self, namespace: &str) -> Result<Vec<Webhook>> {
        sqlx::query_as::<_, Webhook>("SELECT * FROM webhooks WHERE namespace = $1 ORDER BY id").bind(namespace).fetch_all(self.pool()).await?.into_iter().map(|h| self.open_webhook(h)).collect()
    }

    pub async fn webhook(&self, id: i64) -> Result<Option<Webhook>> {
        sqlx::query_as::<_, Webhook>("SELECT * FROM webhooks WHERE id = $1").bind(id).fetch_optional(self.pool()).await?.map(|h| self.open_webhook(h)).transpose()
    }

    pub async fn create_webhook(&self, namespace: &str, i: &WebhookInput, by: &str) -> Result<Webhook> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO webhooks (namespace, name, url, format, events, repositories, secret, auth_header, is_verify_tls, is_enabled, created_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
        )
        .bind(namespace)
        .bind(i.name.trim())
        .bind(i.url.trim())
        .bind(&i.format)
        .bind(serde_json::to_string(&i.events)?)
        .bind(serde_json::to_string(&i.repositories)?)
        .bind(self.seal_secret_opt(blank_to_none(i.secret.as_deref())))
        .bind(self.seal_secret_opt(blank_to_none(i.auth_header.as_deref())))
        .bind(i.is_verify_tls)
        .bind(i.is_enabled)
        .bind(by)
        .bind(now())
        .fetch_one(self.pool())
        .await?;
        Ok(self.webhook(id).await?.expect("just created"))
    }

    /// `None` for `secret` or `auth_header` keeps the stored one, unless the URL now points at
    /// another origin (scheme, host, port): then it is cleared, so a credential meant for one
    /// receiver is never sent (or used to sign deliveries) to another.
    pub async fn update_webhook(&self, id: i64, i: &WebhookInput) -> Result<()> {
        let keep = self.webhook(id).await?.is_some_and(|old| same_origin(&old.url, i.url.trim()));
        sqlx::query(
            "UPDATE webhooks SET name = $1, url = $2, format = $3, events = $4, repositories = $5, is_verify_tls = $6, is_enabled = $7, \
             secret = CASE WHEN $8 THEN $9 WHEN $10 THEN secret END, auth_header = CASE WHEN $11 THEN $12 WHEN $13 THEN auth_header END WHERE id = $14",
        )
        .bind(i.name.trim())
        .bind(i.url.trim())
        .bind(&i.format)
        .bind(serde_json::to_string(&i.events)?)
        .bind(serde_json::to_string(&i.repositories)?)
        .bind(i.is_verify_tls)
        .bind(i.is_enabled)
        .bind(i.secret.is_some())
        .bind(self.seal_secret_opt(blank_to_none(i.secret.as_deref())))
        .bind(keep)
        .bind(i.auth_header.is_some())
        .bind(self.seal_secret_opt(blank_to_none(i.auth_header.as_deref())))
        .bind(keep)
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn delete_webhook(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM webhooks WHERE id = $1").bind(id).execute(self.pool()).await?;
        Ok(())
    }

    /// Queue (or, with `holder`, start delivering right away) a delivery to a namespace hook
    /// (`Ok(id)`) or a config-file hook (`Err(name)`). Finished deliveries beyond the history
    /// are dropped.
    pub async fn insert_delivery(&self, target: Result<i64, &str>, event: &str, payload: &str, content_type: &str, max_attempts: u32, holder: Option<&str>) -> Result<i64> {
        let (webhook_id, config_hook) = match target {
            Ok(id) => (Some(id), None),
            Err(name) => (None, Some(name)),
        };
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO webhook_deliveries (webhook_id, config_hook, event, payload, content_type, status, max_attempts, next_at, locked_by, locked_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, 'pending', $6, now(), $7, CASE WHEN $7 IS NULL THEN NULL ELSE now() END, $8) RETURNING id",
        )
        .bind(webhook_id)
        .bind(config_hook)
        .bind(event)
        .bind(payload)
        .bind(content_type)
        .bind(max_attempts.max(1) as i32)
        .bind(holder)
        .bind(now())
        .fetch_one(self.pool())
        .await?;
        let prune = match target {
            Ok(_) => "DELETE FROM webhook_deliveries WHERE webhook_id = $1 AND status <> 'pending' AND id NOT IN (SELECT id FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY id DESC LIMIT $2)",
            Err(_) => "DELETE FROM webhook_deliveries WHERE config_hook = $1 AND status <> 'pending' AND id NOT IN (SELECT id FROM webhook_deliveries WHERE config_hook = $1 ORDER BY id DESC LIMIT $2)",
        };
        let q = sqlx::query(prune);
        let q = match target {
            Ok(id) => q.bind(id),
            Err(name) => q.bind(name),
        };
        q.bind(KEEP_DELIVERIES).execute(self.pool()).await?;
        Ok(id)
    }

    /// Take the oldest due delivery no live worker holds, for `holder`. A claim older than
    /// `lease` was abandoned mid-attempt: that attempt counts.
    pub async fn claim_delivery(&self, holder: &str, lease: Duration) -> Result<Option<QueuedDelivery>> {
        Ok(sqlx::query_as::<_, QueuedDelivery>(
            "UPDATE webhook_deliveries SET locked_by = $1, locked_at = now(), attempts = attempts + CASE WHEN locked_at IS NULL THEN 0 ELSE 1 END \
             WHERE id = (SELECT id FROM webhook_deliveries \
                         WHERE status = 'pending' AND next_at <= now() AND (locked_at IS NULL OR locked_at < now() - make_interval(secs => $2)) \
                         ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) \
             RETURNING id, webhook_id, config_hook, event, payload, content_type, attempts, max_attempts",
        )
        .bind(holder)
        .bind(lease.as_secs_f64())
        .fetch_optional(self.pool())
        .await?)
    }

    /// Record an attempt by `holder`, and release the delivery: done when it succeeded or was the
    /// last attempt, otherwise due again after `retry_in`. Returns the new status (`None`: the
    /// delivery is no longer `holder`'s).
    pub async fn record_attempt(&self, id: i64, holder: &str, a: &Attempt, retry_in: Duration) -> Result<Option<String>> {
        Ok(sqlx::query_scalar(
            "UPDATE webhook_deliveries SET attempts = attempts + 1, response_code = $1, response_body = $2, error = $3, duration_ms = $4, \
             status = CASE WHEN $5 THEN 'succeeded' WHEN attempts + 1 >= max_attempts THEN 'failed' ELSE 'pending' END, \
             next_at = CASE WHEN NOT $5 AND attempts + 1 < max_attempts THEN now() + make_interval(secs => $6) END, \
             delivered_at = CASE WHEN $5 OR attempts + 1 >= max_attempts THEN $7 ELSE delivered_at END, \
             locked_by = NULL, locked_at = NULL \
             WHERE id = $8 AND locked_by = $9 RETURNING status",
        )
        .bind(a.response_code.map(i64::from))
        .bind(a.response_body.as_deref())
        .bind(a.error.as_deref())
        .bind(a.duration_ms as i64)
        .bind(a.ok)
        .bind(retry_in.as_secs_f64())
        .bind(now())
        .bind(id)
        .bind(holder)
        .fetch_optional(self.pool())
        .await?)
    }

    /// Give up on a delivery `holder` claimed without attempting it (its hook is gone, or its
    /// last attempt was interrupted).
    pub async fn abandon_delivery(&self, id: i64, holder: &str, error: &str) -> Result<()> {
        sqlx::query("UPDATE webhook_deliveries SET status = 'failed', error = $1, next_at = NULL, locked_by = NULL, locked_at = NULL, delivered_at = $2 WHERE id = $3 AND locked_by = $4")
            .bind(error)
            .bind(now())
            .bind(id)
            .bind(holder)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn deliveries(&self, webhook_id: i64, limit: i64) -> Result<Vec<Delivery>> {
        Ok(sqlx::query_as::<_, Delivery>("SELECT * FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY id DESC LIMIT $2").bind(webhook_id).bind(limit).fetch_all(self.pool()).await?)
    }

    pub async fn delivery(&self, id: i64) -> Result<Option<Delivery>> {
        Ok(sqlx::query_as::<_, Delivery>("SELECT * FROM webhook_deliveries WHERE id = $1 AND webhook_id IS NOT NULL").bind(id).fetch_optional(self.pool()).await?)
    }
}

#[cfg(test)]
mod origin_tests {
    use super::same_origin;

    #[test]
    fn origins() {
        assert!(same_origin("https://hooks.example.com/a", "https://HOOKS.example.com:443/b?x=1"));
        assert!(same_origin("https://user:pw@git.example.com/a.git", "https://git.example.com/b.git"));
        assert!(same_origin("http://[::1]:8080/a", "http://[::1]:8080/b"));
        assert!(!same_origin("https://hooks.example.com/a", "http://hooks.example.com/a"));
        assert!(!same_origin("https://hooks.example.com/a", "https://hooks.example.com:8443/a"));
        assert!(!same_origin("https://hooks.example.com/a", "https://evil.example/a"));
        assert!(!same_origin("https://hooks.example.com@evil.example/a", "https://hooks.example.com/a"));
        assert!(!same_origin("not a url", "https://hooks.example.com/a"));
    }
}
