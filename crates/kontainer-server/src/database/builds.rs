//! Build triggers and builds.

use std::collections::BTreeMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::notify::BUILD_LOG_CHANNEL;
use super::{now, Db};
use kontainer_core::build::protocol::LOG_TAIL_BYTES;

/// Advisory lock key serializing [`Db::claim_build`] (any fixed number; `kont` in ASCII).
const CLAIM_LOCK: i64 = 0x6b6f_6e74;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct BuildTrigger {
    pub id: i64,
    pub repository: String,
    pub name: String,
    pub git_url: String,
    pub git_username: Option<String>,
    #[serde(skip)]
    pub git_token: Option<String>,
    #[serde(serialize_with = "json_list")]
    pub branches: String,
    pub dockerfile: String,
    pub context: String,
    #[serde(serialize_with = "json_list")]
    pub tags: String,
    #[serde(skip)]
    pub secret: String,
    pub is_enabled: bool,
    pub created_by: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    /// Check Git for new commits this often (seconds); `None` waits for webhooks.
    pub poll_secs: Option<i64>,
    /// The commit each matching branch or tag was last seen at, by webhook or poll.
    #[serde(serialize_with = "json_map")]
    pub seen_refs: String,
    #[serde(with = "super::rfc3339::option")]
    pub checked_at: Option<DateTime<Utc>>,
    pub check_error: Option<String>,
}

fn json_map<S: serde::Serializer>(raw: &str, s: S) -> Result<S::Ok, S::Error> {
    serde_json::from_str::<BTreeMap<String, String>>(raw).unwrap_or_default().serialize(s)
}

fn json_list<S: serde::Serializer>(raw: &str, s: S) -> Result<S::Ok, S::Error> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default().serialize(s)
}

impl BuildTrigger {
    pub fn branch_list(&self) -> Vec<String> {
        serde_json::from_str(&self.branches).unwrap_or_default()
    }
    pub fn tag_list(&self) -> Vec<String> {
        serde_json::from_str(&self.tags).unwrap_or_default()
    }
    pub fn seen(&self) -> BTreeMap<String, String> {
        serde_json::from_str(&self.seen_refs).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TriggerInput {
    pub name: String,
    pub git_url: String,
    #[serde(default)]
    pub git_username: Option<String>,
    /// Empty keeps the stored token.
    #[serde(default)]
    pub git_token: Option<String>,
    #[serde(default)]
    pub branches: Vec<String>,
    #[serde(default)]
    pub dockerfile: Option<String>,
    #[serde(default)]
    pub context: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "yes")]
    pub is_enabled: bool,
    #[serde(default)]
    pub poll_secs: Option<i64>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Build {
    pub id: i64,
    pub trigger_id: Option<i64>,
    pub repository: String,
    pub git_url: String,
    pub git_ref: String,
    pub commit_sha: Option<String>,
    #[serde(serialize_with = "json_list")]
    pub tags: String,
    pub digest: Option<String>,
    pub status: String,
    pub message: Option<String>,
    pub actor: String,
    #[serde(skip)]
    pub log: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "super::rfc3339::option")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(with = "super::rfc3339::option")]
    pub finished_at: Option<DateTime<Utc>>,
    /// Who runs it: `local/<n>`, `kubernetes/<job>` or an external agent's name.
    pub agent: Option<String>,
    #[serde(skip)]
    pub agent_token_hash: Option<String>,
    #[serde(with = "super::rfc3339::option")]
    pub heartbeat_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub is_cancel_requested: bool,
    /// JSON tag templates overriding the trigger's, for a build started by hand.
    #[serde(skip)]
    pub tag_templates: Option<String>,
    /// The runner that claimed it.
    pub runner_id: Option<i64>,
}

impl Db {
    /// `t` with its Git token and webhook secret decrypted (see [`super::secrets`]).
    fn open_trigger(&self, mut t: BuildTrigger) -> Result<BuildTrigger> {
        t.git_token = self.open_secret_opt("build_triggers.git_token", t.id, t.git_token.take())?;
        t.secret = self.open_secret("build_triggers.secret", t.id, &t.secret)?;
        Ok(t)
    }

    pub async fn build_triggers(&self, repository: &str) -> Result<Vec<BuildTrigger>> {
        sqlx::query_as::<_, BuildTrigger>("SELECT * FROM build_triggers WHERE repository = $1 ORDER BY id").bind(repository).fetch_all(self.pool()).await?.into_iter().map(|t| self.open_trigger(t)).collect()
    }

    pub async fn build_trigger(&self, id: i64) -> Result<Option<BuildTrigger>> {
        sqlx::query_as::<_, BuildTrigger>("SELECT * FROM build_triggers WHERE id = $1").bind(id).fetch_optional(self.pool()).await?.map(|t| self.open_trigger(t)).transpose()
    }

    pub async fn create_build_trigger(&self, repository: &str, i: &TriggerInput, secret: &str, by: &str) -> Result<BuildTrigger> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO build_triggers (repository, name, git_url, git_username, git_token, branches, dockerfile, context, tags, secret, is_enabled, created_by, created_at, poll_secs)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id",
        )
        .bind(repository)
        .bind(i.name.trim())
        .bind(i.git_url.trim())
        .bind(i.git_username.as_deref().filter(|s| !s.is_empty()))
        .bind(self.seal_secret_opt(i.git_token.as_deref().filter(|s| !s.is_empty())))
        .bind(serde_json::to_string(&i.branches)?)
        .bind(i.dockerfile.as_deref().filter(|s| !s.is_empty()).unwrap_or("Dockerfile"))
        .bind(i.context.as_deref().filter(|s| !s.is_empty()).unwrap_or("."))
        .bind(serde_json::to_string(&i.tags)?)
        .bind(self.seal_secret(secret))
        .bind(i.is_enabled)
        .bind(by)
        .bind(now())
        .bind(i.poll_secs)
        .fetch_one(self.pool())
        .await?;
        Ok(self.build_trigger(id).await?.expect("just inserted"))
    }

    /// A blank `git_token` keeps the stored one, unless `git_url` now points at another origin
    /// (scheme, host, port): then it is cleared, so the token is never sent to a host it wasn't
    /// given for.
    pub async fn update_build_trigger(&self, id: i64, i: &TriggerInput) -> Result<()> {
        let keep = self.build_trigger(id).await?.is_some_and(|old| crate::database::webhooks::same_origin(&old.git_url, i.git_url.trim()));
        let token = self.seal_secret_opt(i.git_token.as_deref().filter(|s| !s.is_empty()));
        sqlx::query(
            "UPDATE build_triggers SET name = $1, git_url = $2, git_username = $3, git_token = CASE WHEN $4::text IS NOT NULL THEN $5 WHEN $6 THEN git_token END, branches = $7, dockerfile = $8, context = $9, tags = $10, is_enabled = $11, poll_secs = $12, \
             checked_at = CASE WHEN git_url = $13 THEN checked_at END, seen_refs = CASE WHEN git_url = $14 THEN seen_refs ELSE '{}' END WHERE id = $15",
        )
        .bind(i.name.trim())
        .bind(i.git_url.trim())
        .bind(i.git_username.as_deref().filter(|s| !s.is_empty()))
        .bind(&token)
        .bind(&token)
        .bind(keep)
        .bind(serde_json::to_string(&i.branches)?)
        .bind(i.dockerfile.as_deref().filter(|s| !s.is_empty()).unwrap_or("Dockerfile"))
        .bind(i.context.as_deref().filter(|s| !s.is_empty()).unwrap_or("."))
        .bind(serde_json::to_string(&i.tags)?)
        .bind(i.is_enabled)
        .bind(i.poll_secs)
        .bind(i.git_url.trim())
        .bind(i.git_url.trim())
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn set_build_trigger_secret(&self, id: i64, secret: &str) -> Result<()> {
        sqlx::query("UPDATE build_triggers SET secret = $1 WHERE id = $2").bind(self.seal_secret(secret)).bind(id).execute(self.pool()).await?;
        Ok(())
    }

    /// Enabled triggers that poll Git.
    pub async fn polling_build_triggers(&self) -> Result<Vec<BuildTrigger>> {
        sqlx::query_as::<_, BuildTrigger>("SELECT * FROM build_triggers WHERE is_enabled = true AND poll_secs IS NOT NULL ORDER BY id").fetch_all(self.pool()).await?.into_iter().map(|t| self.open_trigger(t)).collect()
    }

    /// `git_ref` was seen at `sha` (a push came in, or a poll found it).
    pub async fn see_build_ref(&self, id: i64, git_ref: &str, sha: &str) -> Result<()> {
        sqlx::query("UPDATE build_triggers SET seen_refs = (seen_refs::jsonb || jsonb_build_object($1::text, $2::text))::text WHERE id = $3").bind(git_ref).bind(sha).bind(id).execute(self.pool()).await?;
        Ok(())
    }

    /// Record a poll: what it saw (all matching refs) or why it failed.
    pub async fn record_build_poll(&self, id: i64, seen: Option<&BTreeMap<String, String>>, error: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE build_triggers SET checked_at = $1, check_error = $2, seen_refs = COALESCE($3, seen_refs) WHERE id = $4")
            .bind(now())
            .bind(error)
            .bind(seen.map(serde_json::to_string).transpose()?)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The trigger's most recent build, if any.
    pub async fn last_trigger_build(&self, trigger_id: i64) -> Result<Option<Build>> {
        Ok(sqlx::query_as::<_, Build>("SELECT * FROM builds WHERE trigger_id = $1 ORDER BY id DESC LIMIT 1").bind(trigger_id).fetch_optional(self.pool()).await?)
    }

    pub async fn delete_build_trigger(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM build_triggers WHERE id = $1").bind(id).execute(self.pool()).await?;
        Ok(())
    }

    pub async fn create_build(&self, trigger_id: Option<i64>, repository: &str, git_url: &str, git_ref: &str, actor: &str) -> Result<i64> {
        Ok(sqlx::query_scalar("INSERT INTO builds (trigger_id, repository, git_url, git_ref, status, actor, created_at) VALUES ($1, $2, $3, $4, 'queued', $5, $6) RETURNING id")
            .bind(trigger_id)
            .bind(repository)
            .bind(git_url)
            .bind(git_ref)
            .bind(actor)
            .bind(now())
            .fetch_one(self.pool())
            .await?)
    }

    pub async fn build(&self, id: i64) -> Result<Option<Build>> {
        Ok(sqlx::query_as::<_, Build>("SELECT * FROM builds WHERE id = $1").bind(id).fetch_optional(self.pool()).await?)
    }

    pub async fn builds(&self, repository: &str, limit: i64) -> Result<Vec<Build>> {
        Ok(sqlx::query_as::<_, Build>("SELECT * FROM builds WHERE repository = $1 ORDER BY id DESC LIMIT $2").bind(repository).bind(limit).fetch_all(self.pool()).await?)
    }

    pub async fn set_build_result(&self, id: i64, commit: Option<&str>, tags: &[String], digest: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE builds SET commit_sha = COALESCE($1, commit_sha), tags = $2, digest = COALESCE($3, digest) WHERE id = $4")
            .bind(commit)
            .bind(serde_json::to_string(tags)?)
            .bind(digest)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Hand the next queued build of `namespaces` (`None`: any) to runner `runner`, shown as
    /// `agent`, which will prove itself with the token behind `token_hash`. Atomic, so any
    /// number of runners can claim concurrently.
    ///
    /// Fair across namespaces: builds of namespaces with fewer builds running go first (oldest
    /// first among equals), and a namespace already running `max_per_namespace` (0: no limit)
    /// waits.
    pub async fn claim_build(&self, runner: Option<i64>, agent: &str, token_hash: &str, namespaces: Option<&[String]>, max_per_namespace: usize) -> Result<Option<i64>> {
        let ts = now();
        let limit = if max_per_namespace == 0 { i64::MAX } else { max_per_namespace as i64 };
        let scope = namespaces.map(serde_json::to_string).transpose()?;
        // Claims are serialized (a transaction-scoped advisory lock), so concurrent runners
        // neither pick the same build nor overrun `max_per_namespace` together.
        let mut tx = self.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(CLAIM_LOCK).execute(&mut *tx).await?;
        // A repository's namespace is its first path segment.
        let id = sqlx::query_scalar(
            "WITH running AS (SELECT substr(repository, 1, strpos(repository || '/', '/') - 1) AS ns, COUNT(*) AS n \
                              FROM builds WHERE status = 'running' GROUP BY ns) \
             UPDATE builds SET status = 'running', runner_id = $1, agent = $2, agent_token_hash = $3, heartbeat_at = $4, started_at = $5 \
             WHERE id = (SELECT b.id FROM builds b LEFT JOIN running r ON r.ns = substr(b.repository, 1, strpos(b.repository || '/', '/') - 1) \
                         WHERE b.status = 'queued' AND COALESCE(r.n, 0) < $6 \
                         AND ($7::text IS NULL OR substr(b.repository, 1, strpos(b.repository || '/', '/') - 1) IN (SELECT json_array_elements_text($8::json))) \
                         ORDER BY COALESCE(r.n, 0), b.id LIMIT 1) \
             AND status = 'queued' RETURNING id",
        )
        .bind(runner)
        .bind(agent)
        .bind(token_hash)
        .bind(ts)
        .bind(ts)
        .bind(limit)
        .bind(&scope)
        .bind(&scope)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Cancel `trigger`'s queued builds of `git_ref` older than build `newer`, which replaces
    /// them. Returns their ids.
    pub async fn supersede_builds(&self, trigger: i64, git_ref: &str, newer: i64) -> Result<Vec<i64>> {
        Ok(sqlx::query_scalar(
            "UPDATE builds SET status = 'cancelled', message = $1, finished_at = $2 \
             WHERE trigger_id = $3 AND git_ref = $4 AND status = 'queued' AND id < $5 RETURNING id",
        )
        .bind(format!("Superseded by build #{newer}"))
        .bind(now())
        .bind(trigger)
        .bind(git_ref)
        .bind(newer)
        .fetch_all(self.pool())
        .await?)
    }

    /// Where queued build `id` stands: queued builds older than it, and builds its namespace has
    /// running.
    pub async fn build_queue_position(&self, id: i64, repository: &str) -> Result<(i64, i64)> {
        let ahead: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE status = 'queued' AND id < $1").bind(id).fetch_one(self.pool()).await?;
        let ns = repository.split('/').next().unwrap_or_default();
        let running: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE status = 'running' AND substr(repository, 1, strpos(repository || '/', '/') - 1) = $1")
            .bind(ns)
            .fetch_one(self.pool())
            .await?;
        Ok((ahead, running))
    }

    /// Give a queued build its own tag templates.
    pub async fn set_build_tag_templates(&self, id: i64, templates: &[String]) -> Result<()> {
        sqlx::query("UPDATE builds SET tag_templates = $1 WHERE id = $2").bind(serde_json::to_string(templates)?).bind(id).execute(self.pool()).await?;
        Ok(())
    }

    /// Name the agent of a claimed build once it is known (e.g. the Kubernetes Job).
    pub async fn set_build_agent(&self, id: i64, agent: &str) -> Result<()> {
        sqlx::query("UPDATE builds SET agent = $1 WHERE id = $2").bind(agent).bind(id).execute(self.pool()).await?;
        Ok(())
    }

    /// A runner checking in: the heartbeat, and the log from where the server's copy ends (see
    /// [`LogInput`]). Logs past `max` bytes are truncated: the head stays, what follows is
    /// dropped, and only the last [`LOG_TAIL_BYTES`] come back at the end (a tail check-in),
    /// behind a marker line saying how much was left out.
    pub async fn append_build_log(&self, id: i64, input: LogInput<'_>, max: u64) -> Result<LogAppend> {
        let mut tx = self.pool().begin().await?;
        let row: Option<LogRow> = sqlx::query_as("SELECT status, is_cancel_requested, log_length, log_stored, log_seq, log_truncated_at, log_omitted FROM builds WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        // Gone: stop.
        let Some(row) = row else { return Ok(LogAppend { stop: true, length: 0, truncated: false }) };
        let mut w = LogWriter::new(id, &row);
        // Over already (cancelled while queued, failed by the reaper): stop, and keep the log.
        if row.status != "running" {
            return Ok(w.reply(true));
        }
        let (offset, data, tail) = match input {
            LogInput::At { offset, data, tail } => (i64::try_from(offset).unwrap_or(i64::MAX), data, tail),
            // The whole log: what we lack of it, if it still starts with what we have.
            LogInput::Whole(log) => (row.log_length, log.get(usize::try_from(row.log_length).unwrap_or(usize::MAX)..).unwrap_or_default(), false),
        };
        let len = data.len() as i64;
        match (row.log_truncated_at, row.log_omitted) {
            (None, _) if offset == row.log_length && !data.is_empty() => {
                let room = usize::try_from((max as i64 - w.stored).max(0)).unwrap_or(usize::MAX);
                if data.len() <= room {
                    w.push(&mut tx, data).await?;
                } else {
                    // The head ends at the last whole line that fits.
                    let fits = data.floor_char_boundary(room);
                    let keep = data[..fits].rfind('\n').map_or(fits, |i| i + 1);
                    w.push(&mut tx, &data[..keep]).await?;
                    w.truncated_at = Some(offset + keep as i64);
                }
                w.length = offset + len;
            }
            // The end of a truncated log: the marker, then the tail.
            (Some(cut), None) if tail && offset >= row.log_length && !data.is_empty() => {
                let start = data.ceil_char_boundary(data.len().saturating_sub(LOG_TAIL_BYTES));
                w.marker(&mut tx, offset + start as i64 - cut).await?;
                w.push(&mut tx, &data[start..]).await?;
                w.length = offset + len;
            }
            // Past the limit: counted, not stored.
            (Some(_), _) if offset == row.log_length => w.length = offset + len,
            // Anything else (a resend after a lost reply, a runner that restarted): the reply
            // tells the runner where the log stands.
            _ => {}
        }
        w.save(&mut tx, None).await?;
        tx.commit().await?;
        Ok(w.reply(row.is_cancel_requested))
    }

    /// Record how a running build ended, with a last `line` for its log (the outcome), and cache
    /// the whole log in `builds.log`. Returns false (and changes nothing) when it had already
    /// ended, e.g. cancelled or failed for going quiet.
    pub async fn finish_build(&self, id: i64, status: &str, message: &str, line: Option<&str>) -> Result<bool> {
        let mut tx = self.pool().begin().await?;
        let row: Option<LogRow> = sqlx::query_as("SELECT status, is_cancel_requested, log_length, log_stored, log_seq, log_truncated_at, log_omitted FROM builds WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row.filter(|r| r.status == "running") else { return Ok(false) };
        let mut w = LogWriter::new(id, &row);
        // Truncated, and the runner never sent the tail: say so all the same.
        if let (Some(cut), None) = (row.log_truncated_at, row.log_omitted) {
            w.marker(&mut tx, row.log_length - cut).await?;
        }
        if let Some(line) = line.filter(|l| !l.is_empty()) {
            let line = if line.ends_with('\n') { line.to_string() } else { format!("{line}\n") };
            w.push_line(&mut tx, &line).await?;
        }
        w.save(&mut tx, Some((status, message))).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// The log of build `id` so far, from its chunks (for a running build; an ended one has it in
    /// `builds.log`).
    pub async fn build_log_text(&self, id: i64) -> Result<String> {
        Ok(sqlx::query_scalar("SELECT (SELECT COALESCE(string_agg(data, '' ORDER BY seq), '') FROM build_log_chunks WHERE build_id = $1)").bind(id).fetch_one(self.pool()).await?)
    }

    /// Up to `limit` chunks of build `id`'s log after chunk `after`, in order.
    pub async fn build_log_chunks(&self, id: i64, after: i64, limit: i64) -> Result<Vec<LogChunk>> {
        Ok(sqlx::query_as::<_, LogChunk>("SELECT seq, data FROM build_log_chunks WHERE build_id = $1 AND seq > $2 ORDER BY seq LIMIT $3")
            .bind(id)
            .bind(after)
            .bind(limit)
            .fetch_all(self.pool())
            .await?)
    }

    /// Build `id`'s status and message, if it exists.
    pub async fn build_status(&self, id: i64) -> Result<Option<(String, Option<String>)>> {
        Ok(sqlx::query_as("SELECT status, message FROM builds WHERE id = $1").bind(id).fetch_optional(self.pool()).await?)
    }

    /// Wake whoever follows build `id`'s log, on every instance (it ended some other way than
    /// [`Db::finish_build`], which does this itself). Best effort, like [`Db::notify`].
    pub async fn notify_build_log(&self, id: i64) {
        if let Err(e) = sqlx::query("SELECT pg_notify($1, id::text || ':' || log_seq::text) FROM builds WHERE id = $2").bind(BUILD_LOG_CHANNEL).bind(id).execute(self.pool()).await {
            tracing::warn!(build = id, error = %e, "notifying followers of a build log");
        }
    }

    /// Keep a running build from counting as stale (its agent is still starting).
    pub async fn touch_build(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE builds SET heartbeat_at = $1 WHERE id = $2 AND status = 'running'").bind(now()).bind(id).execute(self.pool()).await?;
        Ok(())
    }

    /// Cancel a build: a queued one at once (returns true), a running one by asking its agent.
    pub async fn cancel_build(&self, id: i64) -> Result<bool> {
        let queued = sqlx::query("UPDATE builds SET status = 'cancelled', message = 'Cancelled', finished_at = $1 WHERE id = $2 AND status = 'queued'")
            .bind(now())
            .bind(id)
            .execute(self.pool())
            .await?
            .rows_affected();
        if queued == 0 {
            sqlx::query("UPDATE builds SET is_cancel_requested = true WHERE id = $1 AND status = 'running'").bind(id).execute(self.pool()).await?;
        }
        Ok(queued > 0)
    }

    /// Running builds held by agents whose name starts with `prefix`.
    pub async fn running_builds(&self, prefix: &str) -> Result<Vec<Build>> {
        Ok(sqlx::query_as::<_, Build>("SELECT * FROM builds WHERE status = 'running' AND agent LIKE $1 || '%' ORDER BY id")
            .bind(prefix)
            .fetch_all(self.pool())
            .await?)
    }

    /// Fail running builds whose agent has not checked in since `cutoff`.
    pub async fn fail_stale_builds(&self, cutoff: DateTime<Utc>) -> Result<Vec<i64>> {
        Ok(sqlx::query_scalar(
            "UPDATE builds SET status = 'failed', message = 'The build agent stopped responding', finished_at = $1, \
             log = (SELECT COALESCE(string_agg(data, '' ORDER BY seq), '') FROM build_log_chunks WHERE build_id = builds.id) \
             WHERE status = 'running' AND (heartbeat_at IS NULL OR heartbeat_at < $2) RETURNING id",
        )
        .bind(now())
        .bind(cutoff)
        .fetch_all(self.pool())
        .await?)
    }

    /// In-process builds left running by a restart can never finish. Queued builds stay queued
    /// and are picked up again.
    pub async fn fail_interrupted_builds(&self, agent_prefix: &str) -> Result<u64> {
        Ok(sqlx::query("UPDATE builds SET status = 'failed', message = 'Interrupted by a server restart', finished_at = $1, log = (SELECT COALESCE(string_agg(data, '' ORDER BY seq), '') FROM build_log_chunks WHERE build_id = builds.id) WHERE status = 'running' AND agent LIKE $2 || '%'")
            .bind(now())
            .bind(agent_prefix)
            .execute(self.pool())
            .await?
            .rows_affected())
    }
}

/// What a check-in brings.
#[derive(Debug, Clone, Copy)]
pub enum LogInput<'a> {
    /// The log from byte `offset` on (see `CheckIn`).
    At { offset: u64, data: &'a str, tail: bool },
    /// The whole log so far, from a runner that predates chunked logs.
    Whole(&'a str),
}

/// Where a build's log stands after a check-in: the reply to the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogAppend {
    /// The build is over or cancelled.
    pub stop: bool,
    /// Bytes of the runner's log accounted for: where its next check-in starts.
    pub length: u64,
    /// Past `builds.max_log_bytes`: send nothing more but the tail.
    pub truncated: bool,
}

/// A piece of a build's log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct LogChunk {
    pub seq: i64,
    pub data: String,
}

#[derive(sqlx::FromRow)]
struct LogRow {
    status: String,
    is_cancel_requested: bool,
    log_length: i64,
    log_stored: i64,
    log_seq: i64,
    log_truncated_at: Option<i64>,
    log_omitted: Option<i64>,
}

/// Appends chunks to a build's log within a transaction holding its row, then saves where the
/// log stands.
struct LogWriter {
    id: i64,
    length: i64,
    stored: i64,
    seq: i64,
    truncated_at: Option<i64>,
    omitted: Option<i64>,
    /// Whether the last chunk ends a line (`None`: not known yet).
    at_line_start: Option<bool>,
}

impl LogWriter {
    fn new(id: i64, row: &LogRow) -> Self {
        Self { id, length: row.log_length, stored: row.log_stored, seq: row.log_seq, truncated_at: row.log_truncated_at, omitted: row.log_omitted, at_line_start: None }
    }

    fn reply(&self, stop: bool) -> LogAppend {
        LogAppend { stop, length: self.length.max(0) as u64, truncated: self.truncated_at.is_some() }
    }

    /// Store `data` as the next chunk and tell every instance (`<build>:<seq>`, delivered when
    /// the transaction commits).
    async fn push(&mut self, tx: &mut sqlx::PgConnection, data: &str) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.seq += 1;
        sqlx::query("INSERT INTO build_log_chunks (build_id, seq, data, created_at) VALUES ($1, $2, $3, $4)").bind(self.id).bind(self.seq).bind(data).bind(now()).execute(&mut *tx).await?;
        sqlx::query("SELECT pg_notify($1, $2)").bind(BUILD_LOG_CHANNEL).bind(format!("{}:{}", self.id, self.seq)).execute(&mut *tx).await?;
        self.stored += data.len() as i64;
        self.at_line_start = Some(data.ends_with('\n'));
        Ok(())
    }

    /// Store `line` on a line of its own.
    async fn push_line(&mut self, tx: &mut sqlx::PgConnection, line: &str) -> Result<()> {
        let fresh = match self.at_line_start {
            Some(f) => f,
            None => sqlx::query_scalar::<_, String>("SELECT right(data, 1) FROM build_log_chunks WHERE build_id = $1 ORDER BY seq DESC LIMIT 1")
                .bind(self.id)
                .fetch_optional(&mut *tx)
                .await?
                .is_none_or(|last| last == "\n"),
        };
        if fresh {
            self.push(tx, line).await
        } else {
            self.push(tx, &format!("\n{line}")).await
        }
    }

    /// Say that `omitted` bytes were left out here.
    async fn marker(&mut self, tx: &mut sqlx::PgConnection, omitted: i64) -> Result<()> {
        let omitted = omitted.max(0);
        self.push_line(tx, &format!("==> log truncated: {omitted} bytes omitted\n")).await?;
        self.omitted = Some(omitted);
        Ok(())
    }

    /// Save where the log stands (a check-in is also the heartbeat), or end the build with
    /// `(status, message)`, caching its whole log.
    async fn save(&self, tx: &mut sqlx::PgConnection, end: Option<(&str, &str)>) -> Result<()> {
        let mut q = sqlx::query(match end {
            None => "UPDATE builds SET log_length = $1, log_stored = $2, log_seq = $3, log_truncated_at = $4, log_omitted = $5, heartbeat_at = $6 WHERE id = $7",
            Some(_) => {
                "UPDATE builds SET log_length = $1, log_stored = $2, log_seq = $3, log_truncated_at = $4, log_omitted = $5, finished_at = $6, status = $8, message = $9, \
                 log = (SELECT COALESCE(string_agg(data, '' ORDER BY seq), '') FROM build_log_chunks WHERE build_id = $7) WHERE id = $7"
            }
        })
        .bind(self.length)
        .bind(self.stored)
        .bind(self.seq)
        .bind(self.truncated_at)
        .bind(self.omitted)
        .bind(now())
        .bind(self.id);
        if let Some((status, message)) = end {
            q = q.bind(status).bind(message);
        }
        q.execute(&mut *tx).await?;
        if end.is_some() {
            // Followers see the end even when nothing was added to the log.
            sqlx::query("SELECT pg_notify($1, $2)").bind(BUILD_LOG_CHANNEL).bind(format!("{}:{}", self.id, self.seq)).execute(&mut *tx).await?;
        }
        Ok(())
    }
}
