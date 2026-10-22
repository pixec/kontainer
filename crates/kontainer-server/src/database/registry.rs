//! Registry metadata ([`kontainer_store::metadata::Metadata`]) in PostgreSQL: manifests with
//! their bodies, tags and repository blob links (tables `manifests`, `tags`, `blob_links`), so
//! every instance in every region sees a push as soon as it commits. One statement per method
//! where possible; operations that change several rows (a manifest push with its tag, a
//! manifest delete with its tags, a repository delete) are one transaction, and a repository is
//! read for garbage collection and usage from one `REPEATABLE READ` snapshot.
//!
//! A blob link and a garbage collection sweep of the same digest exclude each other with a
//! transaction-scoped advisory lock (shared for links, exclusive for the sweep; see
//! [`kontainer_store::gc`]).

use std::collections::HashSet;

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use sqlx::{Postgres, Transaction};

use kontainer_core::digest::Digest;
use kontainer_store::metadata::{BlobLink, Metadata, PutManifest, RepoSnapshot, StoredManifest};
use kontainer_store::TagEntry;

use super::Db;

/// The first key of the advisory locks taken per blob digest (`'kb'`); the second is the
/// digest's hash. Two-key advisory locks never collide with the one-key locks of [`super::locks`].
pub(super) const BLOB_LOCK: i32 = 0x6b62;

macro_rules! manifest_columns {
    () => {
        "digest, media_type, body, subject_digest, artifact_type, pushed_at"
    };
}

#[derive(sqlx::FromRow)]
struct ManifestRow {
    digest: String,
    media_type: String,
    body: Vec<u8>,
    subject_digest: Option<String>,
    artifact_type: Option<String>,
    pushed_at: DateTime<Utc>,
}

fn digest(s: &str) -> Result<Digest> {
    s.parse().with_context(|| format!("corrupt digest {s:?} in the registry tables"))
}

impl TryFrom<ManifestRow> for StoredManifest {
    type Error = anyhow::Error;

    fn try_from(r: ManifestRow) -> Result<Self> {
        Ok(Self {
            digest: digest(&r.digest)?,
            media_type: r.media_type,
            body: Bytes::from(r.body),
            subject: r.subject_digest.as_deref().map(digest).transpose()?,
            artifact_type: r.artifact_type,
            pushed_at: r.pushed_at,
        })
    }
}

fn manifests(rows: Vec<ManifestRow>) -> Result<Vec<StoredManifest>> {
    rows.into_iter().map(TryInto::try_into).collect()
}

#[derive(sqlx::FromRow)]
struct TagRow {
    tag: String,
    digest: String,
    updated_at: DateTime<Utc>,
}

fn tags(rows: Vec<TagRow>) -> Result<Vec<TagEntry>> {
    rows.into_iter().map(|r| Ok(TagEntry { digest: digest(&r.digest)?, tag: r.tag, pushed_at: Some(r.updated_at) })).collect()
}

#[derive(sqlx::FromRow)]
struct LinkRow {
    digest: String,
    size: i64,
    linked_at: DateTime<Utc>,
}

fn links(rows: Vec<LinkRow>) -> Result<Vec<BlobLink>> {
    rows.into_iter().map(|r| Ok(BlobLink { digest: digest(&r.digest)?, size: u64::try_from(r.size).unwrap_or(0), linked_at: r.linked_at })).collect()
}

fn size(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| anyhow::anyhow!("size {n} out of range"))
}

fn strings(ds: &[Digest]) -> Vec<String> {
    let mut seen = HashSet::new();
    ds.iter().map(Digest::to_string).filter(|d| seen.insert(d.clone())).collect()
}

/// `LIKE` pattern for every name under `prefix/`.
fn under(prefix: &str) -> String {
    let mut p = String::with_capacity(prefix.len() + 2);
    for c in prefix.chars() {
        if matches!(c, '\\' | '%' | '_') {
            p.push('\\');
        }
        p.push(c);
    }
    p.push_str("/%");
    p
}

fn is_foreign_key_violation(e: &sqlx::Error) -> bool {
    e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23503")
}

async fn insert_manifest(tx: &mut Transaction<'_, Postgres>, repo: &str, m: &StoredManifest, on_conflict: &'static str) -> Result<u64> {
    let sql = match on_conflict {
        "update" => {
            "INSERT INTO manifests (repository, digest, media_type, size, body, subject_digest, artifact_type, pushed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (repository, digest) DO UPDATE SET media_type = excluded.media_type, pushed_at = excluded.pushed_at"
        }
        _ => {
            "INSERT INTO manifests (repository, digest, media_type, size, body, subject_digest, artifact_type, pushed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (repository, digest) DO NOTHING"
        }
    };
    Ok(sqlx::query(sql)
        .bind(repo)
        .bind(m.digest.to_string())
        .bind(&m.media_type)
        .bind(size(m.size())?)
        .bind(m.body.as_ref())
        .bind(m.subject.as_ref().map(Digest::to_string))
        .bind(&m.artifact_type)
        .bind(m.pushed_at)
        .execute(&mut **tx)
        .await?
        .rows_affected())
}

#[async_trait::async_trait]
impl Metadata for Db {
    async fn put_manifest(&self, repo: &str, m: &StoredManifest, blobs: &[Digest], children: &[Digest], tag: Option<&str>) -> Result<PutManifest> {
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        // Refresh the links the manifest references, so garbage collection keeps them (its
        // removal is conditional on the link's time; whichever commits first wins).
        let wanted = strings(blobs);
        let touched: HashSet<String> = sqlx::query_scalar("UPDATE blob_links SET linked_at = $3 WHERE repository = $1 AND digest = ANY($2) RETURNING digest")
            .bind(repo)
            .bind(&wanted)
            .bind(now)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
        let children = strings(children);
        let present: HashSet<String> = sqlx::query_scalar("SELECT digest FROM manifests WHERE repository = $1 AND digest = ANY($2) FOR KEY SHARE")
            .bind(repo)
            .bind(&children)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
        let missing: Vec<String> = wanted.into_iter().filter(|d| !touched.contains(d)).chain(children.into_iter().filter(|d| !present.contains(d))).collect();
        if !missing.is_empty() {
            tx.rollback().await?;
            return Ok(PutManifest::Missing(missing.iter().map(|d| digest(d)).collect::<Result<_>>()?));
        }
        insert_manifest(&mut tx, repo, &StoredManifest { pushed_at: now, ..m.clone() }, "update").await?;
        let previous_tag = match tag {
            Some(t) => {
                let previous: Option<String> = sqlx::query_scalar("SELECT digest FROM tags WHERE repository = $1 AND tag = $2 FOR UPDATE").bind(repo).bind(t).fetch_optional(&mut *tx).await?;
                sqlx::query(
                    "INSERT INTO tags (repository, tag, digest, updated_at) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (repository, tag) DO UPDATE SET digest = excluded.digest, updated_at = excluded.updated_at",
                )
                .bind(repo)
                .bind(t)
                .bind(m.digest.to_string())
                .bind(now)
                .execute(&mut *tx)
                .await?;
                previous.as_deref().map(digest).transpose()?
            }
            None => None,
        };
        tx.commit().await?;
        Ok(PutManifest::Stored { previous_tag })
    }

    async fn manifest(&self, repo: &str, d: &Digest) -> Result<Option<StoredManifest>> {
        let row: Option<ManifestRow> = sqlx::query_as(concat!("SELECT ", manifest_columns!(), " FROM manifests WHERE repository = $1 AND digest = $2"))
            .bind(repo)
            .bind(d.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn has_manifest(&self, repo: &str, d: &Digest) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM manifests WHERE repository = $1 AND digest = $2)").bind(repo).bind(d.to_string()).fetch_one(&self.pool).await?)
    }

    async fn manifest_digests(&self, repo: &str) -> Result<Vec<Digest>> {
        let rows: Vec<String> = sqlx::query_scalar("SELECT digest FROM manifests WHERE repository = $1 ORDER BY digest").bind(repo).fetch_all(&self.pool).await?;
        rows.iter().map(|d| digest(d)).collect()
    }

    async fn manifests(&self, repo: &str) -> Result<Vec<StoredManifest>> {
        manifests(sqlx::query_as(concat!("SELECT ", manifest_columns!(), " FROM manifests WHERE repository = $1 ORDER BY digest")).bind(repo).fetch_all(&self.pool).await?)
    }

    async fn delete_manifest(&self, repo: &str, d: &Digest) -> Result<Option<Vec<String>>> {
        let mut tx = self.pool.begin().await?;
        let removed: Vec<String> = sqlx::query_scalar("DELETE FROM tags WHERE repository = $1 AND digest = $2 RETURNING tag").bind(repo).bind(d.to_string()).fetch_all(&mut *tx).await?;
        let n = sqlx::query("DELETE FROM manifests WHERE repository = $1 AND digest = $2").bind(repo).bind(d.to_string()).execute(&mut *tx).await?.rows_affected();
        if n == 0 {
            tx.rollback().await?;
            return Ok(None);
        }
        tx.commit().await?;
        Ok(Some(removed))
    }

    async fn collect_manifest(&self, repo: &str, d: &Digest, cutoff: DateTime<Utc>) -> Result<bool> {
        let deleted = sqlx::query(
            "DELETE FROM manifests m WHERE repository = $1 AND digest = $2 AND pushed_at <= $3
             AND NOT EXISTS (SELECT 1 FROM tags t WHERE t.repository = m.repository AND t.digest = m.digest)",
        )
        .bind(repo)
        .bind(d.to_string())
        .bind(cutoff)
        .execute(&self.pool)
        .await;
        match deleted {
            Ok(r) => Ok(r.rows_affected() > 0),
            // Tagged by a push that committed while the delete waited for the row.
            Err(e) if is_foreign_key_violation(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn referrers(&self, repo: &str, subject: &Digest, artifact_type: Option<&str>) -> Result<Vec<StoredManifest>> {
        manifests(
            sqlx::query_as(concat!(
                "SELECT ",
                manifest_columns!(),
                " FROM manifests WHERE repository = $1 AND subject_digest = $2 AND ($3::text IS NULL OR artifact_type = $3) ORDER BY digest"
            ))
            .bind(repo)
            .bind(subject.to_string())
            .bind(artifact_type)
            .fetch_all(&self.pool)
            .await?,
        )
    }

    async fn resolve_tag(&self, repo: &str, tag: &str) -> Result<Option<Digest>> {
        let d: Option<String> = sqlx::query_scalar("SELECT digest FROM tags WHERE repository = $1 AND tag = $2").bind(repo).bind(tag).fetch_optional(&self.pool).await?;
        d.as_deref().map(digest).transpose()
    }

    async fn put_tag(&self, repo: &str, tag: &str, d: &Digest) -> Result<Option<Digest>> {
        let mut tx = self.pool.begin().await?;
        let previous: Option<String> = sqlx::query_scalar("SELECT digest FROM tags WHERE repository = $1 AND tag = $2 FOR UPDATE").bind(repo).bind(tag).fetch_optional(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO tags (repository, tag, digest, updated_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (repository, tag) DO UPDATE SET digest = excluded.digest, updated_at = excluded.updated_at",
        )
        .bind(repo)
        .bind(tag)
        .bind(d.to_string())
        .bind(Utc::now())
        .execute(&mut *tx)
        .await
        .map_err(|e| if is_foreign_key_violation(&e) { anyhow::anyhow!("{repo} has no manifest {d} to tag") } else { e.into() })?;
        tx.commit().await?;
        previous.as_deref().map(digest).transpose()
    }

    async fn delete_tag(&self, repo: &str, tag: &str) -> Result<Option<Digest>> {
        let d: Option<String> = sqlx::query_scalar("DELETE FROM tags WHERE repository = $1 AND tag = $2 RETURNING digest").bind(repo).bind(tag).fetch_optional(&self.pool).await?;
        d.as_deref().map(digest).transpose()
    }

    async fn tags(&self, repo: &str, last: Option<&str>, limit: Option<usize>) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT tag FROM tags WHERE repository = $1 AND ($2::text IS NULL OR tag > $2) ORDER BY tag LIMIT $3")
            .bind(repo)
            .bind(last)
            .bind(limit.map(|n| i64::try_from(n).unwrap_or(i64::MAX)))
            .fetch_all(&self.pool)
            .await?)
    }

    async fn tags_resolved(&self, repo: &str) -> Result<Vec<TagEntry>> {
        tags(sqlx::query_as("SELECT tag, digest, updated_at FROM tags WHERE repository = $1 ORDER BY tag").bind(repo).fetch_all(&self.pool).await?)
    }

    async fn tag_summary(&self, repo: &str) -> Result<(usize, Option<DateTime<Utc>>)> {
        let (n, last): (i64, Option<DateTime<Utc>>) = sqlx::query_as("SELECT count(*), max(updated_at) FROM tags WHERE repository = $1").bind(repo).fetch_one(&self.pool).await?;
        Ok((usize::try_from(n).unwrap_or(0), last))
    }

    async fn link_blob(&self, repo: &str, d: &Digest, n: u64) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // Waits for a sweep of this digest in progress (see the module docs).
        sqlx::query("SELECT pg_advisory_xact_lock_shared($1, hashtext($2))").bind(BLOB_LOCK).bind(d.to_string()).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO blob_links (repository, digest, size, linked_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (repository, digest) DO UPDATE SET size = excluded.size, linked_at = excluded.linked_at",
        )
        .bind(repo)
        .bind(d.to_string())
        .bind(size(n)?)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn blob_link(&self, repo: &str, d: &Digest) -> Result<Option<BlobLink>> {
        let row: Option<LinkRow> = sqlx::query_as("SELECT digest, size, linked_at FROM blob_links WHERE repository = $1 AND digest = $2").bind(repo).bind(d.to_string()).fetch_optional(&self.pool).await?;
        Ok(links(row.into_iter().collect())?.pop())
    }

    async fn unlink_blob(&self, repo: &str, d: &Digest) -> Result<bool> {
        Ok(sqlx::query("DELETE FROM blob_links WHERE repository = $1 AND digest = $2").bind(repo).bind(d.to_string()).execute(&self.pool).await?.rows_affected() > 0)
    }

    async fn collect_blob_link(&self, repo: &str, d: &Digest, cutoff: DateTime<Utc>) -> Result<bool> {
        Ok(sqlx::query("DELETE FROM blob_links WHERE repository = $1 AND digest = $2 AND linked_at <= $3")
            .bind(repo)
            .bind(d.to_string())
            .bind(cutoff)
            .execute(&self.pool)
            .await?
            .rows_affected()
            > 0)
    }

    async fn blob_links(&self, repo: &str) -> Result<Vec<BlobLink>> {
        links(sqlx::query_as("SELECT digest, size, linked_at FROM blob_links WHERE repository = $1 ORDER BY digest").bind(repo).fetch_all(&self.pool).await?)
    }

    async fn sweep_blob(&self, d: &Digest, delete: BoxFuture<'_, Result<()>>) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))").bind(BLOB_LOCK).bind(d.to_string()).execute(&mut *tx).await?;
        let used: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM blob_links WHERE digest = $1) OR EXISTS (SELECT 1 FROM blob_uploads WHERE digest = $1)")
            .bind(d.to_string())
            .fetch_one(&mut *tx)
            .await?;
        if used {
            tx.rollback().await?;
            return Ok(false);
        }
        // Links of this digest wait until the transaction ends.
        delete.await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn repositories(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT repository FROM manifests UNION SELECT repository FROM blob_links ORDER BY 1").fetch_all(&self.pool).await?)
    }

    async fn repositories_with_manifests(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT DISTINCT repository FROM manifests ORDER BY 1").fetch_all(&self.pool).await?)
    }

    async fn repository_exists(&self, repo: &str) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM manifests WHERE repository = $1)").bind(repo).fetch_one(&self.pool).await?)
    }

    async fn namespace_has_repositories(&self, namespace: &str) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM manifests WHERE repository = $1 OR repository LIKE $2)
                 OR EXISTS (SELECT 1 FROM blob_links WHERE repository = $1 OR repository LIKE $2)",
        )
        .bind(namespace)
        .bind(under(namespace))
        .fetch_one(&self.pool)
        .await?)
    }

    async fn delete_repository(&self, repo: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for sql in ["DELETE FROM tags WHERE repository = $1", "DELETE FROM manifests WHERE repository = $1", "DELETE FROM blob_links WHERE repository = $1"] {
            sqlx::query(sql).bind(repo).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn snapshot(&self, repo: &str) -> Result<RepoSnapshot> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await?;
        let m = manifests(sqlx::query_as(concat!("SELECT ", manifest_columns!(), " FROM manifests WHERE repository = $1 ORDER BY digest")).bind(repo).fetch_all(&mut *tx).await?)?;
        let t = tags(sqlx::query_as("SELECT tag, digest, updated_at FROM tags WHERE repository = $1 ORDER BY tag").bind(repo).fetch_all(&mut *tx).await?)?;
        let l = links(sqlx::query_as("SELECT digest, size, linked_at FROM blob_links WHERE repository = $1 ORDER BY digest").bind(repo).fetch_all(&mut *tx).await?)?;
        tx.commit().await?;
        Ok(RepoSnapshot { manifests: m, tags: t, links: l })
    }

    async fn is_empty(&self) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM manifests) AND NOT EXISTS (SELECT 1 FROM blob_links)").fetch_one(&self.pool).await?)
    }

    async fn restore_manifest(&self, repo: &str, m: &StoredManifest) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let n = insert_manifest(&mut tx, repo, m, "nothing").await?;
        tx.commit().await?;
        Ok(n > 0)
    }

    async fn restore_tag(&self, repo: &str, tag: &str, d: &Digest, updated_at: DateTime<Utc>) -> Result<bool> {
        Ok(sqlx::query("INSERT INTO tags (repository, tag, digest, updated_at) VALUES ($1, $2, $3, $4) ON CONFLICT (repository, tag) DO NOTHING")
            .bind(repo)
            .bind(tag)
            .bind(d.to_string())
            .bind(updated_at)
            .execute(&self.pool)
            .await
            .map_err(|e| if is_foreign_key_violation(&e) { anyhow::anyhow!("{repo} has no manifest {d} to tag") } else { e.into() })?
            .rows_affected()
            > 0)
    }

    async fn restore_blob_link(&self, repo: &str, l: &BlobLink) -> Result<bool> {
        Ok(sqlx::query("INSERT INTO blob_links (repository, digest, size, linked_at) VALUES ($1, $2, $3, $4) ON CONFLICT (repository, digest) DO NOTHING")
            .bind(repo)
            .bind(l.digest.to_string())
            .bind(size(l.size)?)
            .bind(l.linked_at)
            .execute(&self.pool)
            .await?
            .rows_affected()
            > 0)
    }
}

/// What deleting a repository takes with it ([`Db::repository_delete_stats`]).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RepoDeleteStats {
    pub tags: i64,
    pub manifests: i64,
    /// Manifest bodies.
    pub manifest_bytes: i64,
    /// Blobs linked to the repository (layers and configs; shared ones stay for other
    /// repositories until garbage collection finds them unused).
    pub blob_bytes: i64,
}

/// An enabled replication rule or mirror, for deletion previews.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SyncRuleRow {
    pub id: i64,
    /// The rule's name, or the mirror's upstream repository.
    pub name: String,
    /// json globs of local repositories (replication rules; empty for mirrors).
    pub repositories: String,
    /// json tag globs; empty = every tag.
    pub tags: String,
}

/// Read-only queries for deletion previews.
impl Db {
    /// The tags of `repo` pointing at `digest`, sorted.
    pub async fn tags_pointing_at(&self, repo: &str, digest: &Digest) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT tag FROM tags WHERE repository = $1 AND digest = $2 ORDER BY tag").bind(repo).bind(digest.to_string()).fetch_all(&self.pool).await?)
    }

    /// Indexes in `repo` that list `digest` among their manifests.
    pub async fn index_parents(&self, repo: &str, digest: &Digest) -> Result<Vec<String>> {
        let d = digest.to_string();
        // Narrowed by a byte search of the bodies, then confirmed by reading them.
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as("SELECT digest, body FROM manifests WHERE repository = $1 AND digest <> $2 AND position(convert_to($2, 'UTF8') IN body) > 0 ORDER BY digest")
            .bind(repo)
            .bind(&d)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .filter(|(_, body)| {
                serde_json::from_slice::<serde_json::Value>(body).ok().and_then(|v| v.get("manifests").and_then(|m| m.as_array()).map(|m| m.iter().any(|c| c.get("digest").and_then(|x| x.as_str()) == Some(d.as_str())))).unwrap_or(false)
            })
            .map(|(digest, _)| digest)
            .collect())
    }

    /// How many manifests in `repo` name `digest` as their subject (signatures, SBOMs, ...).
    pub async fn referrer_count(&self, repo: &str, digest: &Digest) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM manifests WHERE repository = $1 AND subject_digest = $2").bind(repo).bind(digest.to_string()).fetch_one(&self.pool).await?)
    }

    pub async fn repository_delete_stats(&self, repo: &str) -> Result<RepoDeleteStats> {
        let (tags, manifests, manifest_bytes, blob_bytes): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM tags WHERE repository = $1),
                    (SELECT count(*) FROM manifests WHERE repository = $1),
                    (SELECT COALESCE(sum(size), 0) FROM manifests WHERE repository = $1)::bigint,
                    (SELECT COALESCE(sum(size), 0) FROM blob_links WHERE repository = $1)::bigint",
        )
        .bind(repo)
        .fetch_one(&self.pool)
        .await?;
        Ok(RepoDeleteStats { tags, manifests, manifest_bytes, blob_bytes })
    }

    /// Enabled push replication rules (their repository globs are matched by the caller).
    pub async fn enabled_replication_rules(&self) -> Result<Vec<SyncRuleRow>> {
        Ok(sqlx::query_as::<_, SyncRuleRow>("SELECT id, name, repositories, tags FROM replication_rules WHERE is_enabled ORDER BY id").fetch_all(&self.pool).await?)
    }

    /// Enabled mirrors copying into `repo`.
    pub async fn enabled_mirrors_into(&self, repo: &str) -> Result<Vec<SyncRuleRow>> {
        Ok(sqlx::query_as::<_, SyncRuleRow>("SELECT id, source AS name, '[]' AS repositories, tags FROM mirrors WHERE is_enabled AND target = $1 ORDER BY id").bind(repo).fetch_all(&self.pool).await?)
    }
}

impl Db {
    /// Move the registry metadata of every repository named `old` or under `old/` to `new`,
    /// inside a namespace rename's transaction (tags follow their manifests by cascade).
    pub(super) async fn rename_registry_namespace(tx: &mut Transaction<'_, Postgres>, old: &str, new: &str) -> Result<()> {
        for sql in [
            "UPDATE manifests SET repository = $1 || substr(repository, $2::int) WHERE repository = $3 OR repository LIKE $4",
            "UPDATE blob_links SET repository = $1 || substr(repository, $2::int) WHERE repository = $3 OR repository LIKE $4",
        ] {
            sqlx::query(sql).bind(new).bind(old.len() as i64 + 1).bind(old).bind(under(old)).execute(&mut **tx).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn manifest(body: &str) -> StoredManifest {
        StoredManifest::new(Digest::sha256_of(body.as_bytes()), kontainer_core::manifest::OCI_MANIFEST, Bytes::from(body.to_string()))
    }

    #[test]
    fn like_patterns_escape_wildcards() {
        assert_eq!(under("a_b"), "a\\_b/%");
        assert_eq!(under("50%\\"), "50\\%\\\\/%");
    }

    #[tokio::test]
    async fn manifests_tags_links_and_listings() {
        let db = crate::database::test_support::fresh_db().await;
        let layer = Digest::sha256_of(b"layer");
        db.link_blob("acme/app", &layer, 5).await.unwrap();
        assert_eq!(db.repositories().await.unwrap(), vec!["acme/app".to_string()]);
        assert!(!db.repository_exists("acme/app").await.unwrap(), "links alone don't make a repository");

        let m = manifest(r#"{"schemaVersion":2,"a":1}"#);
        let child = Digest::sha256_of(b"child");
        let missing = db.put_manifest("acme/app", &m, &[layer.clone(), Digest::sha256_of(b"x")], std::slice::from_ref(&child), Some("v1")).await.unwrap();
        assert_eq!(missing, PutManifest::Missing(vec![Digest::sha256_of(b"x"), child]));
        assert!(db.manifest("acme/app", &m.digest).await.unwrap().is_none(), "rolled back");
        assert_eq!(db.put_manifest("acme/app", &m, std::slice::from_ref(&layer), &[], Some("v1")).await.unwrap(), PutManifest::Stored { previous_tag: None });
        let other = manifest(r#"{"schemaVersion":2,"a":2}"#);
        assert_eq!(db.put_manifest("acme/app", &other, &[], std::slice::from_ref(&m.digest), Some("v1")).await.unwrap(), PutManifest::Stored { previous_tag: Some(m.digest.clone()) });
        let got = db.manifest("acme/app", &m.digest).await.unwrap().unwrap();
        assert_eq!((got.body.clone(), got.media_type.as_str()), (m.body.clone(), kontainer_core::manifest::OCI_MANIFEST));

        // Tags sort bytewise and paginate after `last`.
        for t in ["b", "B", "a-1", "a_1"] {
            db.put_tag("acme/app", t, &m.digest).await.unwrap();
        }
        assert_eq!(db.tags("acme/app", None, None).await.unwrap(), ["B", "a-1", "a_1", "b", "v1"]);
        assert_eq!(db.tags("acme/app", Some("a-1"), Some(2)).await.unwrap(), ["a_1", "b"]);
        assert!(db.put_tag("acme/app", "nope", &Digest::sha256_of(b"none")).await.is_err());
        assert_eq!(db.tag_summary("acme/app").await.unwrap().0, 5);

        // Namespaces: the name itself and what is under it, `_` taken literally.
        db.link_blob("acme_x/app", &layer, 5).await.unwrap();
        assert!(db.namespace_has_repositories("acme").await.unwrap());
        assert!(!db.namespace_has_repositories("acm").await.unwrap());
        assert!(!db.namespace_has_repositories("acme_").await.unwrap());
        assert!(db.namespace_has_repositories("acme_x").await.unwrap());
        assert_eq!(db.repositories().await.unwrap(), ["acme/app", "acme_x/app"]);
        assert_eq!(db.repositories_with_manifests().await.unwrap(), ["acme/app"]);

        // Deleting a manifest takes its tags with it, in one go.
        let mut removed = db.delete_manifest("acme/app", &m.digest).await.unwrap().unwrap();
        removed.sort();
        assert_eq!(removed, ["B", "a-1", "a_1", "b"]);
        assert_eq!(db.tags("acme/app", None, None).await.unwrap(), ["v1"]);
        assert_eq!(db.delete_manifest("acme/app", &m.digest).await.unwrap(), None);

        // GC: tagged and freshly pushed manifests stay; unreferenced old links go.
        assert!(!db.collect_manifest("acme/app", &other.digest, Utc::now()).await.unwrap(), "tagged");
        db.delete_tag("acme/app", "v1").await.unwrap();
        assert!(!db.collect_manifest("acme/app", &other.digest, Utc::now() - chrono::Duration::hours(1)).await.unwrap(), "pushed after the cutoff");
        assert!(db.collect_manifest("acme/app", &other.digest, Utc::now()).await.unwrap());
        assert!(!db.collect_blob_link("acme/app", &layer, Utc::now() - chrono::Duration::hours(1)).await.unwrap());
        assert!(db.collect_blob_link("acme/app", &layer, Utc::now()).await.unwrap());
        db.delete_repository("acme_x/app").await.unwrap();
        assert!(db.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn referrers_by_subject_and_artifact_type() {
        let db = crate::database::test_support::fresh_db().await;
        let subject = manifest(r#"{"schemaVersion":2,"subject":"none"}"#);
        db.put_manifest("r", &subject, &[], &[], None).await.unwrap();
        let referrer = |kind: &str| manifest(&format!(r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"{kind}","config":{{"mediaType":"application/vnd.oci.empty.v1+json","digest":"{}","size":2}},"layers":[],"subject":{{"mediaType":"x","digest":"{}","size":1}}}}"#, Digest::sha256_of(b"{}"), subject.digest));
        let (sbom, sig) = (referrer("application/spdx+json"), referrer("application/vnd.dev.cosign"));
        for m in [&sbom, &sig] {
            assert_eq!(m.subject.as_ref(), Some(&subject.digest));
            db.put_manifest("r", m, &[], &[], None).await.unwrap();
        }
        let mut all: Vec<Digest> = db.referrers("r", &subject.digest, None).await.unwrap().into_iter().map(|m| m.digest).collect();
        all.sort_by_key(|d| d.to_string());
        let mut want = vec![sbom.digest.clone(), sig.digest.clone()];
        want.sort_by_key(|d| d.to_string());
        assert_eq!(all, want);
        let only = db.referrers("r", &subject.digest, Some("application/spdx+json")).await.unwrap();
        assert_eq!(only.iter().map(|m| &m.digest).collect::<Vec<_>>(), vec![&sbom.digest]);
        assert!(db.referrers("other", &subject.digest, None).await.unwrap().is_empty());
    }

    /// The race garbage collection must never lose: a blob linked by a push while its sweep is
    /// deleting it. The link waits for the sweep's lock, and then finds the blob gone (the
    /// caller stores it again); a link that committed first makes the sweep skip the blob.
    #[tokio::test]
    async fn a_link_and_a_sweep_of_the_same_blob_exclude_each_other() {
        let db = crate::database::test_support::fresh_db().await;
        let d = Digest::sha256_of(b"blob");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel::<()>();
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sweep = {
            let (db, d, deleted) = (db.clone(), d.clone(), deleted.clone());
            tokio::spawn(async move {
                let delete = Box::pin(async move {
                    started_tx.send(()).unwrap();
                    finish_rx.await.unwrap();
                    deleted.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                });
                db.sweep_blob(&d, delete).await.unwrap()
            })
        };
        started_rx.await.unwrap();
        let link = {
            let (db, d) = (db.clone(), d.clone());
            tokio::spawn(async move { db.link_blob("acme/app", &d, 4).await.unwrap() })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!link.is_finished(), "the link waits for the sweep");
        assert!(db.blob_link("acme/app", &d).await.unwrap().is_none());
        finish_tx.send(()).unwrap();
        assert!(sweep.await.unwrap());
        link.await.unwrap();
        assert!(deleted.load(std::sync::atomic::Ordering::SeqCst), "the delete ran before the link committed, so the linker sees the blob gone");
        assert!(db.blob_link("acme/app", &d).await.unwrap().is_some());

        // Linked now: a sweep leaves it alone.
        let ran = db.sweep_blob(&d, Box::pin(async { panic!("must not delete a linked blob") })).await.unwrap();
        assert!(!ran);
        // So does an upload being completed into it.
        db.unlink_blob("acme/app", &d).await.unwrap();
        use kontainer_store::uploads::UploadSessions;
        db.create("u1", "acme/app").await.unwrap();
        db.seal("u1", &d.to_string()).await.unwrap();
        assert!(!db.sweep_blob(&d, Box::pin(async { panic!("must not delete a blob being uploaded") })).await.unwrap());
    }
}
