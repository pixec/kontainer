//! Repository catalogue entries: description, README, visibility and topics. The registry
//! content (manifests, tags, blob links) is in [`super::registry`], blobs in object storage.

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{now, Db};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RepoMeta {
    pub name: String,
    pub description: String,
    pub readme: String,
    pub visibility: Visibility,
    /// json array of strings
    #[serde(serialize_with = "topics_json")]
    pub topics: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339")]
    pub updated_at: DateTime<Utc>,
}

fn topics_json<S: serde::Serializer>(raw: &str, s: S) -> Result<S::Ok, S::Error> {
    let v: Vec<String> = serde_json::from_str(raw).unwrap_or_default();
    v.serialize(s)
}

impl RepoMeta {
    pub fn topic_list(&self) -> Vec<String> {
        serde_json::from_str(&self.topics).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RepoImport {
    pub repository: String,
    pub kind: String,
    pub registry: Option<String>,
    pub source: String,
    pub actor: String,
    #[serde(with = "super::rfc3339")]
    pub imported_at: DateTime<Utc>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct RepoMetaUpdate {
    pub description: Option<String>,
    pub readme: Option<String>,
    pub visibility: Option<Visibility>,
    pub topics: Option<Vec<String>>,
}

impl Db {
    pub async fn repo_meta(&self, name: &str) -> Result<Option<RepoMeta>> {
        Ok(sqlx::query_as::<_, RepoMeta>("SELECT * FROM repositories WHERE name = $1").bind(name).fetch_optional(&self.pool).await?)
    }

    pub async fn all_repo_meta(&self) -> Result<Vec<RepoMeta>> {
        Ok(sqlx::query_as::<_, RepoMeta>("SELECT * FROM repositories ORDER BY name").fetch_all(&self.pool).await?)
    }

    pub async fn public_repos(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT name FROM repositories WHERE visibility = 'public' ORDER BY name").fetch_all(&self.pool).await?)
    }

    /// Create or update the catalogue entry; unspecified fields are kept.
    pub async fn upsert_repo_meta(&self, name: &str, u: &RepoMetaUpdate, default_visibility: Visibility) -> Result<RepoMeta> {
        let topics = u.topics.as_ref().map(|t| serde_json::to_string(t).unwrap_or_else(|_| "[]".into()));
        sqlx::query(
            "INSERT INTO repositories(name, description, readme, visibility, topics, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(name) DO UPDATE SET
               description = COALESCE($8, repositories.description),
               readme = COALESCE($9, repositories.readme),
               visibility = COALESCE($10, repositories.visibility),
               topics = COALESCE($11, repositories.topics),
               updated_at = excluded.updated_at",
        )
        .bind(name)
        .bind(u.description.clone().unwrap_or_default())
        .bind(u.readme.clone().unwrap_or_default())
        .bind(u.visibility.unwrap_or(default_visibility))
        .bind(topics.clone().unwrap_or_else(|| "[]".into()))
        .bind(now())
        .bind(now())
        .bind(&u.description)
        .bind(&u.readme)
        .bind(u.visibility)
        .bind(&topics)
        .execute(&self.pool)
        .await?;
        // Its visibility may have changed.
        self.notify(&super::notify::Topic::Repo(name.to_string())).await;
        Ok(self.repo_meta(name).await?.expect("just upserted"))
    }

    /// Forget everything the database keeps about a repository (metadata, stars, tag history,
    /// build triggers, user and team grants), in one transaction. Build history stays, as does
    /// namespace-wide configuration (webhooks, mirrors, policies).
    pub async fn delete_repo_meta(&self, name: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for sql in [
            "DELETE FROM repositories WHERE name = $1",
            "DELETE FROM stars WHERE repository = $1",
            "DELETE FROM repo_imports WHERE repository = $1",
            "DELETE FROM tag_expirations WHERE repository = $1",
            "DELETE FROM repo_states WHERE repository = $1",
            "DELETE FROM tag_events WHERE repository = $1",
            "DELETE FROM build_triggers WHERE repository = $1",
            "DELETE FROM repo_user_permissions WHERE repository = $1",
            "DELETE FROM repo_team_permissions WHERE repository = $1",
        ] {
            sqlx::query(sql).bind(name).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.notify(&super::notify::Topic::Repo(name.to_string())).await;
        Ok(())
    }

    pub async fn record_import(&self, repository: &str, kind: &str, registry: Option<&str>, source: &str, actor: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO repo_imports (repository, kind, registry, source, actor, imported_at) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT(repository) DO UPDATE SET kind = excluded.kind, registry = excluded.registry, source = excluded.source, actor = excluded.actor, imported_at = excluded.imported_at",
        )
        .bind(repository)
        .bind(kind)
        .bind(registry)
        .bind(source)
        .bind(actor)
        .bind(now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn repo_imports(&self) -> Result<Vec<RepoImport>> {
        Ok(sqlx::query_as::<_, RepoImport>("SELECT * FROM repo_imports").fetch_all(&self.pool).await?)
    }

    pub async fn set_star(&self, user_id: i64, repo: &str, starred: bool) -> Result<()> {
        if starred {
            sqlx::query("INSERT INTO stars(user_id, repository, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(user_id)
                .bind(repo)
                .bind(now())
                .execute(&self.pool)
                .await?;
        } else {
            sqlx::query("DELETE FROM stars WHERE user_id = $1 AND repository = $2").bind(user_id).bind(repo).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn star_count(&self, repo: &str) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM stars WHERE repository = $1").bind(repo).fetch_one(&self.pool).await?)
    }

    /// Star counts for every starred repository.
    pub async fn star_counts(&self) -> Result<HashMap<String, i64>> {
        let rows: Vec<(String, i64)> = sqlx::query_as("SELECT repository, COUNT(*) FROM stars GROUP BY repository").fetch_all(&self.pool).await?;
        Ok(rows.into_iter().collect())
    }

    /// Repositories the user starred, most recent first.
    pub async fn starred_by(&self, user_id: i64) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT repository FROM stars WHERE user_id = $1 ORDER BY created_at DESC")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?)
    }
}
