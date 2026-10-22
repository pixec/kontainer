//! Per-namespace pull policies and CVE allowlists.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{now, Db};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SecurityPolicy {
    pub namespace: String,
    pub block_severity: Option<String>,
    pub is_block_unscanned: bool,
    pub is_require_signature: bool,
    #[serde(serialize_with = "json_list")]
    pub signing_keys: String,
    pub updated_by: String,
    #[serde(with = "super::rfc3339")]
    pub updated_at: DateTime<Utc>,
}

fn json_list<S: serde::Serializer>(raw: &str, s: S) -> Result<S::Ok, S::Error> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default().serialize(s)
}

impl SecurityPolicy {
    /// The trusted signing keys (PEM). An empty list means "any cosign signature", so stored
    /// keys that don't parse are an error, never an empty list.
    pub fn keys(&self) -> Result<Vec<String>, serde_json::Error> {
        serde_json::from_str(&self.signing_keys)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityPolicyInput {
    #[serde(default)]
    pub block_severity: Option<String>,
    #[serde(default)]
    pub is_block_unscanned: bool,
    #[serde(default)]
    pub is_require_signature: bool,
    #[serde(default)]
    pub signing_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AllowedCve {
    pub id: i64,
    pub namespace: Option<String>,
    pub cve: String,
    pub reason: String,
    #[serde(with = "super::rfc3339::option")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
}

impl AllowedCve {
    pub fn is_active(&self) -> bool {
        self.expires_at.is_none_or(|t| t > Utc::now())
    }
}

impl Db {
    pub async fn security_policy(&self, namespace: &str) -> Result<Option<SecurityPolicy>> {
        Ok(sqlx::query_as::<_, SecurityPolicy>("SELECT * FROM security_policies WHERE namespace = $1").bind(namespace).fetch_optional(self.pool()).await?)
    }

    pub async fn set_security_policy(&self, namespace: &str, p: &SecurityPolicyInput, by: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO security_policies (namespace, block_severity, is_block_unscanned, is_require_signature, signing_keys, updated_by, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT(namespace) DO UPDATE SET block_severity = excluded.block_severity, is_block_unscanned = excluded.is_block_unscanned, \
             is_require_signature = excluded.is_require_signature, signing_keys = excluded.signing_keys, updated_by = excluded.updated_by, updated_at = excluded.updated_at",
        )
        .bind(namespace)
        .bind(p.block_severity.as_deref())
        .bind(p.is_block_unscanned)
        .bind(p.is_require_signature)
        .bind(serde_json::to_string(&p.signing_keys)?)
        .bind(by)
        .bind(now())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// A namespace's allowlist (`Some`), or the registry-wide one (`None`).
    pub async fn cve_allowlist(&self, namespace: Option<&str>) -> Result<Vec<AllowedCve>> {
        Ok(match namespace {
            Some(ns) => sqlx::query_as::<_, AllowedCve>("SELECT * FROM cve_allowlist WHERE namespace = $1 ORDER BY cve").bind(ns).fetch_all(self.pool()).await?,
            None => sqlx::query_as::<_, AllowedCve>("SELECT * FROM cve_allowlist WHERE namespace IS NULL ORDER BY cve").fetch_all(self.pool()).await?,
        })
    }

    /// CVE ids that don't count for `namespace` right now: its own and the registry-wide ones.
    pub async fn allowed_cves(&self, namespace: &str) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, AllowedCve>("SELECT * FROM cve_allowlist WHERE namespace = $1 OR namespace IS NULL").bind(namespace).fetch_all(self.pool()).await?;
        Ok(rows.into_iter().filter(AllowedCve::is_active).map(|r| r.cve).collect())
    }

    /// Add (or update the reason and expiry of) an allowlisted CVE.
    pub async fn allow_cve(&self, namespace: Option<&str>, cve: &str, reason: &str, expires_at: Option<DateTime<Utc>>, by: &str) -> Result<AllowedCve> {
        let existing = self.cve_allowlist(namespace).await?.into_iter().find(|r| r.cve == cve);
        let id: i64 = match existing {
            Some(r) => {
                sqlx::query("UPDATE cve_allowlist SET reason = $1, expires_at = $2 WHERE id = $3").bind(reason).bind(expires_at).bind(r.id).execute(self.pool()).await?;
                r.id
            }
            None => sqlx::query_scalar("INSERT INTO cve_allowlist (namespace, cve, reason, expires_at, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id")
                .bind(namespace)
                .bind(cve)
                .bind(reason)
                .bind(expires_at)
                .bind(by)
                .bind(now())
                .fetch_one(self.pool())
                .await?,
        };
        Ok(sqlx::query_as::<_, AllowedCve>("SELECT * FROM cve_allowlist WHERE id = $1").bind(id).fetch_one(self.pool()).await?)
    }

    pub async fn disallow_cve(&self, namespace: Option<&str>, id: i64) -> Result<bool> {
        let r = match namespace {
            Some(ns) => sqlx::query("DELETE FROM cve_allowlist WHERE id = $1 AND namespace = $2").bind(id).bind(ns).execute(self.pool()).await?,
            None => sqlx::query("DELETE FROM cve_allowlist WHERE id = $1 AND namespace IS NULL").bind(id).execute(self.pool()).await?,
        };
        Ok(r.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::SecurityPolicy;

    fn policy(keys: &str) -> SecurityPolicy {
        SecurityPolicy { namespace: "ns".into(), block_severity: None, is_block_unscanned: false, is_require_signature: true, signing_keys: keys.into(), updated_by: "a".into(), updated_at: chrono::Utc::now() }
    }

    #[test]
    fn corrupt_keys_are_an_error_not_an_empty_list() {
        assert_eq!(policy("[]").keys().unwrap(), Vec::<String>::new());
        assert_eq!(policy("[\"k\"]").keys().unwrap(), vec!["k".to_string()]);
        assert!(policy("[\"k\"").keys().is_err());
        assert!(policy("").keys().is_err());
    }
}
