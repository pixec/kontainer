//! Organization identity providers and directory-synced teams.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{now, Db};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OrgSso {
    pub org_id: i64,
    pub issuer: String,
    pub client_id: String,
    #[serde(skip)]
    pub client_secret: String,
    pub display_name: String,
    pub groups_claim: Option<String>,
    #[serde(with = "super::rfc3339")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrgSsoInput {
    pub issuer: String,
    pub client_id: String,
    /// Empty keeps the stored secret.
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub groups_claim: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TeamSync {
    pub team_id: i64,
    pub source: String,
    pub group_name: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
}

impl Db {
    pub async fn org_sso(&self, org_id: i64) -> Result<Option<OrgSso>> {
        let Some(mut s) = sqlx::query_as::<_, OrgSso>("SELECT * FROM org_sso WHERE org_id = $1").bind(org_id).fetch_optional(self.pool()).await? else { return Ok(None) };
        s.client_secret = self.open_secret("org_sso.client_secret", s.org_id, &s.client_secret)?;
        Ok(Some(s))
    }

    pub async fn set_org_sso(&self, org_id: i64, i: &OrgSsoInput) -> Result<()> {
        let secret = match i.client_secret.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => s.to_string(),
            None => self.org_sso(org_id).await?.map(|s| s.client_secret).unwrap_or_default(),
        };
        sqlx::query(
            "INSERT INTO org_sso (org_id, issuer, client_id, client_secret, display_name, groups_claim, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(org_id) DO UPDATE SET issuer = excluded.issuer, client_id = excluded.client_id, client_secret = excluded.client_secret,
               display_name = excluded.display_name, groups_claim = excluded.groups_claim, updated_at = excluded.updated_at",
        )
        .bind(org_id)
        .bind(i.issuer.trim().trim_end_matches('/'))
        .bind(i.client_id.trim())
        .bind(self.seal_secret(&secret))
        .bind(i.display_name.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or("SSO"))
        .bind(i.groups_claim.as_deref().map(str::trim).filter(|s| !s.is_empty()))
        .bind(now())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn delete_org_sso(&self, org_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM org_sso WHERE org_id = $1").bind(org_id).execute(self.pool()).await?;
        sqlx::query("DELETE FROM team_syncs WHERE source = 'org-oidc' AND team_id IN (SELECT id FROM teams WHERE org_id = $1)").bind(org_id).execute(self.pool()).await?;
        Ok(())
    }

    pub async fn team_sync(&self, team_id: i64) -> Result<Option<TeamSync>> {
        Ok(sqlx::query_as::<_, TeamSync>("SELECT * FROM team_syncs WHERE team_id = $1").bind(team_id).fetch_optional(self.pool()).await?)
    }

    pub async fn set_team_sync(&self, team_id: i64, sync: Option<(&str, &str)>) -> Result<()> {
        match sync {
            Some((source, group)) => {
                sqlx::query(
                    "INSERT INTO team_syncs (team_id, source, group_name, created_at) VALUES ($1, $2, $3, $4)
                     ON CONFLICT(team_id) DO UPDATE SET source = excluded.source, group_name = excluded.group_name",
                )
                .bind(team_id)
                .bind(source)
                .bind(group.trim())
                .bind(now())
                .execute(self.pool())
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM team_syncs WHERE team_id = $1").bind(team_id).execute(self.pool()).await?;
            }
        }
        Ok(())
    }

    /// Synced teams fed by `source`; `org_id` narrows to one organization (for `org-oidc`).
    pub async fn team_syncs_for(&self, source: &str, org_id: Option<i64>) -> Result<Vec<(TeamSync, i64)>> {
        let rows = sqlx::query_as::<_, (i64, String, String, DateTime<Utc>, i64)>(
            "SELECT s.team_id, s.source, s.group_name, s.created_at, t.org_id FROM team_syncs s JOIN teams t ON t.id = s.team_id WHERE s.source = $1 AND ($2::bigint IS NULL OR t.org_id = $3)",
        )
        .bind(source)
        .bind(org_id)
        .bind(org_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|(team_id, source, group_name, created_at, org)| (TeamSync { team_id, source, group_name, created_at }, org)).collect())
    }

    pub async fn create_oidc_state_for(&self, nonce: &str, verifier: &str, redirect_to: Option<&str>, org: Option<&str>, link_user_id: Option<i64>) -> Result<String> {
        let state = super::random_token(24);
        sqlx::query("INSERT INTO oidc_states(state, nonce, pkce_verifier, redirect_to, created_at, org, link_user_id) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(&state)
            .bind(nonce)
            .bind(verifier)
            .bind(redirect_to)
            .bind(now())
            .bind(org)
            .bind(link_user_id)
            .execute(self.pool())
            .await?;
        Ok(state)
    }
}
