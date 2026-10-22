//! Blob upload sessions ([`kontainer_store::uploads::UploadSessions`]) in PostgreSQL, so every
//! registry instance sees every session. Each method is one statement: the offset
//! compare-and-set and the seal are conditional `UPDATE`s, atomic under concurrent instances.

use anyhow::Result;
use chrono::{DateTime, Utc};

use kontainer_store::uploads::{UploadSession, UploadSessions};

use super::Db;

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    repository: String,
    upload_offset: i64,
    chunks: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    is_sealed: bool,
    digest: Option<String>,
}

impl From<Row> for UploadSession {
    fn from(r: Row) -> Self {
        Self {
            id: r.id,
            repository: r.repository,
            offset: u64::try_from(r.upload_offset).unwrap_or(0),
            chunks: r.chunks,
            created_at: r.created_at,
            updated_at: r.updated_at,
            sealed: r.is_sealed,
            digest: r.digest,
        }
    }
}

fn to_i64(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| anyhow::anyhow!("upload offset {n} out of range"))
}

#[async_trait::async_trait]
impl UploadSessions for Db {
    async fn create(&self, id: &str, repository: &str) -> Result<()> {
        let now = Utc::now();
        sqlx::query("INSERT INTO blob_uploads (id, repository, created_at, updated_at) VALUES ($1, $2, $3, $3)")
            .bind(id)
            .bind(repository)
            .bind(now)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<UploadSession>> {
        Ok(sqlx::query_as::<_, Row>("SELECT * FROM blob_uploads WHERE id = $1").bind(id).fetch_optional(self.pool()).await?.map(Into::into))
    }

    async fn advance(&self, id: &str, expected_offset: u64, len: u64, chunk: &str) -> Result<bool> {
        let expected = to_i64(expected_offset)?;
        let next = to_i64(expected_offset.checked_add(len).ok_or_else(|| anyhow::anyhow!("upload offset overflow"))?)?;
        let n = sqlx::query(
            "UPDATE blob_uploads SET upload_offset = $3, chunks = array_append(chunks, $4), updated_at = $5 \
             WHERE id = $1 AND upload_offset = $2 AND NOT is_sealed",
        )
        .bind(id)
        .bind(expected)
        .bind(next)
        .bind(chunk)
        .bind(Utc::now())
        .execute(self.pool())
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    async fn seal(&self, id: &str, digest: &str) -> Result<Option<UploadSession>> {
        Ok(sqlx::query_as::<_, Row>(
            "UPDATE blob_uploads SET is_sealed = true, digest = $2, updated_at = $3 \
             WHERE id = $1 AND (NOT is_sealed OR digest = $2) RETURNING *",
        )
        .bind(id)
        .bind(digest)
        .bind(Utc::now())
        .fetch_optional(self.pool())
        .await?
        .map(Into::into))
    }

    async fn delete(&self, id: &str) -> Result<bool> {
        Ok(sqlx::query("DELETE FROM blob_uploads WHERE id = $1").bind(id).execute(self.pool()).await?.rows_affected() > 0)
    }

    async fn list_expired(&self, cutoff: DateTime<Utc>) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar("SELECT id FROM blob_uploads WHERE updated_at < $1").bind(cutoff).fetch_all(self.pool()).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn upload_sessions_compare_and_set() {
        let db = crate::database::test_support::fresh_db().await;
        let id = uuid::Uuid::new_v4().to_string();
        db.create(&id, "acme/app").await.unwrap();
        let s = db.get(&id).await.unwrap().unwrap();
        assert_eq!((s.repository.as_str(), s.offset, s.chunks.len(), s.sealed), ("acme/app", 0, 0, false));

        assert!(db.advance(&id, 0, 5, "a").await.unwrap());
        assert!(!db.advance(&id, 0, 5, "b").await.unwrap(), "stale offset");
        assert!(db.advance(&id, 5, 3, "c").await.unwrap());
        let s = db.get(&id).await.unwrap().unwrap();
        assert_eq!((s.offset, s.chunks.clone()), (8, vec!["a".to_string(), "c".to_string()]));

        let sealed = db.seal(&id, "sha256:aa").await.unwrap().unwrap();
        assert!(sealed.sealed);
        assert_eq!(sealed.digest.as_deref(), Some("sha256:aa"));
        assert!(!db.advance(&id, 8, 1, "d").await.unwrap(), "sealed");
        assert!(db.seal(&id, "sha256:aa").await.unwrap().is_some(), "a retried PUT");
        assert!(db.seal(&id, "sha256:bb").await.unwrap().is_none());

        // Two racing chunks for the same offset: exactly one is recorded.
        let other = uuid::Uuid::new_v4().to_string();
        db.create(&other, "acme/app").await.unwrap();
        let (a, b) = tokio::join!(db.advance(&other, 0, 4, "x"), db.advance(&other, 0, 4, "y"));
        assert!(a.unwrap() ^ b.unwrap());
        assert_eq!(db.get(&other).await.unwrap().unwrap().chunks.len(), 1);

        assert!(db.list_expired(Utc::now() - chrono::Duration::hours(1)).await.unwrap().is_empty());
        tokio::time::sleep(Duration::from_millis(5)).await;
        let mut expired = db.list_expired(Utc::now()).await.unwrap();
        expired.sort();
        let mut want = vec![id.clone(), other.clone()];
        want.sort();
        assert_eq!(expired, want);
        assert!(db.delete(&id).await.unwrap());
        assert!(!db.delete(&id).await.unwrap());
        assert!(db.get(&id).await.unwrap().is_none());
    }
}
