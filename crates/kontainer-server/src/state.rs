use std::sync::Arc;

use crate::audit::Audit;
use crate::auth::Authenticator;
use kontainer_core::config::Config;
use crate::scan::queue::ScanQueue;
use kontainer_store::Storage;
use crate::webhook::Webhooks;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub storage: Storage,
    pub auth: Arc<Authenticator>,
    pub scans: Option<ScanQueue>,
    pub webhooks: Webhooks,
    pub audit: Audit,
    pub search: Arc<crate::search::SearchIndex>,
    /// The storage report as last read from the database (where one instance at a time
    /// computes it), and whether this instance is computing or fetching one.
    pub usage: Arc<std::sync::Mutex<Option<Arc<kontainer_store::usage::UsageReport>>>>,
    pub usage_running: Arc<std::sync::atomic::AtomicBool>,
    /// Background jobs running on this instance, to cancel them. Every instance's jobs are
    /// listed from the database (`jobs`).
    pub jobs: Arc<std::sync::Mutex<std::collections::HashMap<String, tokio::task::AbortHandle>>>,
    /// Images known to be signed, for pull policies.
    pub signed: crate::policy::SignedCache,
    /// Maintenance and replication runs in progress.
    pub running: crate::maintenance::Running,
    /// Pull-through cache: upstream clients per registry and downloads in flight.
    pub proxy: crate::sync::ProxyState,
    /// Who follows which build's log on this instance.
    pub build_logs: Arc<crate::build::logs::BuildLogHub>,
}

/// The storage quota that applies to a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Quota {
    /// `None`: no limit.
    pub max_bytes: Option<u64>,
    /// `namespace` (its own, possibly unlimited), `default` (from the config) or `none`.
    pub source: &'static str,
}

/// A background job as the API shows it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub actor: String,
    /// `running`, `done`, `failed` or `cancelled`.
    pub status: String,
    /// Progress while running, the result when done, the error when failed.
    pub message: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    /// The instance running it.
    pub instance: String,
    pub is_cancel_requested: bool,
}

impl From<crate::database::jobs::JobRow> for Job {
    fn from(r: crate::database::jobs::JobRow) -> Self {
        Self {
            message: if r.status == "failed" { r.error.or(r.message) } else { r.message },
            id: r.id,
            kind: r.kind,
            title: r.subject,
            actor: r.actor,
            status: r.status,
            started_at: r.created_at.to_rfc3339(),
            finished_at: r.finished_at.map(|t| t.to_rfc3339()),
            instance: r.instance_id,
            is_cancel_requested: r.is_cancel_requested,
        }
    }
}

/// How often a running job records its progress, and looks for a cancel request.
const JOB_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(5);

/// A running job whose owner has not updated it for this long was interrupted.
pub const JOB_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(120);

tokio::task_local! {
    static JOB_PROGRESS: Arc<std::sync::Mutex<Option<String>>>;
}

/// Report progress from inside a background job ([`AppState::spawn_job`]); recorded with the
/// job's next heartbeat. Does nothing outside a job.
pub fn job_progress(message: impl Into<String>) {
    let _ = JOB_PROGRESS.try_with(|p| *p.lock().unwrap_or_else(|e| e.into_inner()) = Some(message.into()));
}

/// What [`AppState::cancel_job`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancel {
    /// It ran here and was stopped.
    Stopped,
    /// It runs on another instance, which will stop it within a heartbeat.
    Requested,
    /// It is not running.
    NotRunning,
}

/// Clears a flag when dropped, also when the task holding it panics.
struct ResetOnDrop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A namespace quota that applies to a user-initiated write.
pub struct QuotaCheck {
    pub namespace: String,
    pub quota: u64,
}

impl AppState {
    /// Run `work` in the background on this instance, tracked as a job that every instance
    /// lists. While it runs, its row is updated every [`JOB_HEARTBEAT`] with the progress the
    /// work reports ([`job_progress`]), and it is stopped if a cancel was requested elsewhere.
    pub async fn spawn_job<F>(&self, kind: &'static str, title: String, actor: String, work: F) -> anyhow::Result<String>
    where
        F: std::future::Future<Output = anyhow::Result<String>> + Send + 'static,
    {
        self.spawn_job_with(kind, title, actor, JOB_HEARTBEAT, work).await
    }

    async fn spawn_job_with<F>(&self, kind: &'static str, title: String, actor: String, heartbeat: std::time::Duration, work: F) -> anyhow::Result<String>
    where
        F: std::future::Future<Output = anyhow::Result<String>> + Send + 'static,
    {
        let id = kontainer_core::random_token(8);
        let db = self.auth.db.clone();
        db.create_job(&id, kind, &title, &actor).await?;
        let progress: Arc<std::sync::Mutex<Option<String>>> = Arc::default();
        // Its own task, so a panic marks the job failed instead of leaving it running forever.
        let mut task = tokio::spawn(JOB_PROGRESS.scope(progress.clone(), work));
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), task.abort_handle());
        let (jobs, jid) = (self.jobs.clone(), id.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(heartbeat);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            let result = loop {
                tokio::select! {
                    r = &mut task => break r,
                    _ = tick.tick() => {
                        let message = progress.lock().unwrap_or_else(|e| e.into_inner()).take();
                        match db.job_progress(&jid, message.as_deref()).await {
                            Ok(true) => {
                                tracing::info!(job = %jid, "cancelling a background job, as requested on another instance");
                                task.abort();
                            }
                            Ok(false) => {}
                            Err(e) => {
                                // Try again with the next heartbeat.
                                *progress.lock().unwrap_or_else(|e| e.into_inner()) = message;
                                tracing::warn!(job = %jid, error = %e, "recording a background job's progress");
                            }
                        }
                    }
                }
            };
            jobs.lock().unwrap_or_else(|e| e.into_inner()).remove(&jid);
            let (status, message, error) = match result {
                Ok(Ok(m)) => ("done", Some(m), None),
                Ok(Err(e)) => ("failed", None, Some(format!("{e:#}"))),
                Err(e) if e.is_cancelled() => ("cancelled", None, None),
                Err(e) => {
                    tracing::error!(job = %jid, error = %e, "background job panicked");
                    ("failed", None, Some("the job crashed".to_string()))
                }
            };
            if let Err(e) = db.finish_job(&jid, status, message.as_deref(), error.as_deref()).await {
                tracing::warn!(job = %jid, status, error = %e, "recording the end of a background job");
            }
        });
        Ok(id)
    }

    /// Cancel job `id`: here if it runs here, otherwise by asking the instance that runs it.
    pub async fn cancel_job(&self, id: &str) -> anyhow::Result<Cancel> {
        let local = self.jobs.lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned();
        if let Some(handle) = local {
            handle.abort();
            return Ok(Cancel::Stopped);
        }
        Ok(if self.auth.db.request_job_cancel(id).await? { Cancel::Requested } else { Cancel::NotRunning })
    }

    /// Recent jobs of every instance, newest first (only `actor`'s when given).
    pub async fn list_jobs(&self, actor: Option<&str>) -> anyhow::Result<Vec<Job>> {
        Ok(self.auth.db.list_jobs(actor, 100).await?.into_iter().map(Job::from).collect())
    }

    /// The configured default quota for an organization (`is_org`) or a user.
    pub fn default_quota(&self, is_org: bool) -> Option<u64> {
        let p = &self.config.policy;
        (if is_org { &p.default_org_quota } else { &p.default_user_quota }).as_deref().and_then(kontainer_core::config::parse_bytes).map(|b| b as u64)
    }

    /// The quota for namespace `ns`: its own if it has one (0 = unlimited), else the default for
    /// organizations or users. Robots and unknown namespaces have none.
    pub async fn quota_for(&self, ns: &str) -> anyhow::Result<Quota> {
        if let Some(own) = self.auth.db.quota(ns).await? {
            return Ok(Quota { max_bytes: (own > 0).then_some(own), source: "namespace" });
        }
        let is_org = if self.auth.db.org_by_name(ns).await?.is_some() {
            true
        } else if self.auth.db.user_by_name(ns).await?.is_some_and(|u| !u.is_robot) {
            false
        } else {
            return Ok(Quota { max_bytes: None, source: "none" });
        };
        Ok(match self.default_quota(is_org) {
            Some(b) => Quota { max_bytes: Some(b), source: "default" },
            None => Quota { max_bytes: None, source: "none" },
        })
    }

    /// The storage report as this instance last read it (it may be stale).
    pub fn usage_cached(&self) -> Option<Arc<kontainer_store::usage::UsageReport>> {
        self.usage.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn usage_age(u: &kontainer_store::usage::UsageReport) -> Option<std::time::Duration> {
        chrono::DateTime::parse_from_rfc3339(&u.computed_at).ok().map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).to_std().unwrap_or_default())
    }

    fn usage_is_fresh(&self, u: &kontainer_store::usage::UsageReport) -> bool {
        Self::usage_age(u).is_some_and(|age| age < self.config.retention.report_ttl)
    }

    /// The report every instance shares, read from the database (and cached here). Computing
    /// one walks all of storage, so one instance does it ([`Self::refresh_usage`]) and the
    /// others read its result.
    pub async fn shared_usage(&self) -> anyhow::Result<Option<Arc<kontainer_store::usage::UsageReport>>> {
        let Some((raw, _)) = self.auth.db.usage_report().await? else { return Ok(None) };
        let report: Arc<kontainer_store::usage::UsageReport> = Arc::new(serde_json::from_str(&raw)?);
        *self.usage.lock().unwrap_or_else(|e| e.into_inner()) = Some(report.clone());
        Ok(Some(report))
    }

    /// Compute a fresh report on this instance, store it for all, and cache it. Call with the
    /// cluster-wide `usage` lock held.
    async fn compute_usage(&self) -> anyhow::Result<Arc<kontainer_store::usage::UsageReport>> {
        let quotas = self.auth.db.all_quotas().await?;
        let mut report = kontainer_store::usage::compute(&self.storage, &quotas).await?;
        // Namespaces without a quota of their own get the default for their kind.
        for n in report.namespaces.iter_mut().filter(|n| n.quota.is_none()) {
            n.quota = self.quota_for(&n.namespace).await?.max_bytes;
        }
        self.auth.db.put_usage_report(&serde_json::to_string(&report)?, chrono::Utc::now()).await?;
        let report = Arc::new(report);
        *self.usage.lock().unwrap_or_else(|e| e.into_inner()) = Some(report.clone());
        Ok(report)
    }

    /// A report computed from now on: by this instance, or (if another is computing one at the
    /// moment) by that one, waited for.
    pub async fn refresh_usage(&self) -> anyhow::Result<Arc<kontainer_store::usage::UsageReport>> {
        let asked = chrono::Utc::now();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
        let lock = loop {
            if let Some(l) = self.auth.db.try_advisory_lock("usage").await? {
                break l;
            }
            anyhow::ensure!(tokio::time::Instant::now() < deadline, "another instance has been computing the storage report for over ten minutes");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        };
        // Someone may have finished one while we waited for the lock.
        let done = match self.auth.db.usage_report().await {
            Ok(Some((_, at))) if at >= asked => self.shared_usage().await,
            _ => Ok(None),
        };
        let result = match done {
            Ok(Some(r)) => Ok(r),
            _ => self.compute_usage().await,
        };
        lock.release().await;
        result
    }

    /// The shared report if fresh, otherwise a new one (`force`: a new one in any case).
    pub async fn usage_report(&self, force: bool) -> anyhow::Result<Arc<kontainer_store::usage::UsageReport>> {
        if !force {
            if let Some(u) = self.usage_cached().filter(|u| self.usage_is_fresh(u)) {
                return Ok(u);
            }
            if let Some(u) = self.shared_usage().await?.filter(|u| self.usage_is_fresh(u)) {
                return Ok(u);
            }
        }
        self.refresh_usage().await
    }

    /// Recompute the shared report in the background if it is stale: on one instance at a
    /// time across the cluster (the others skip while one holds the lock).
    pub fn refresh_usage_in_background(&self) {
        use std::sync::atomic::Ordering;
        if self.usage_cached().is_some_and(|u| self.usage_is_fresh(&u)) || self.usage_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let state = self.clone();
        tokio::spawn(async move {
            // Reset even if computing the report panics, or no report would ever run again.
            let _reset = ResetOnDrop(state.usage_running.clone());
            match state.shared_usage().await {
                Ok(Some(u)) if state.usage_is_fresh(&u) => return,
                Err(e) => tracing::warn!(error = %e, "reading the storage report"),
                _ => {}
            }
            let db = state.auth.db.clone();
            if let Some(Err(e)) = crate::database::locks::exclusive(&db, "usage", state.compute_usage()).await {
                tracing::warn!(error = %e, "computing the storage report");
            }
        });
    }

    /// Re-index one repository after something it is found by changed. Search is a convenience,
    /// so failures are logged rather than failing the request that caused them.
    pub async fn reindex(&self, repository: &str) {
        crate::search::reindex(&self.storage, &self.auth.db, &self.config.auth.public_repositories, &self.search, repository).await
    }

    /// Rebuild the whole search index from storage (startup, namespace renames).
    pub async fn rebuild_search(&self) -> anyhow::Result<usize> {
        crate::search::rebuild(&self.storage, &self.auth.db, &self.config.auth.public_repositories, &self.search).await
    }

    /// Refuse writes to read-only and mirrored repositories. Internal writers (mirror sync,
    /// retention, expiry) do not come through here.
    pub async fn require_writable(&self, repository: &str) -> Result<(), crate::error::RegistryError> {
        use crate::error::{Code, RegistryError};
        let Some(s) = self.auth.db.repo_state(repository).await.map_err(RegistryError::internal)? else { return Ok(()) };
        let why = s.reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default();
        let msg = match s.state.as_str() {
            "mirror" => format!("{repository} is a mirror; only its sync writes to it{why}"),
            _ => format!("{repository} is read-only{why}"),
        };
        Err(RegistryError::with_message(Code::Denied, msg).status(axum::http::StatusCode::METHOD_NOT_ALLOWED))
    }

    /// Read a small metadata blob (image config, signature payload) into memory: `None` when it
    /// is missing or larger than `server.max_manifest_size`, so a huge blob pushed as a
    /// "config" cannot make the server buffer it.
    pub async fn small_blob(&self, digest: &kontainer_core::digest::Digest) -> anyhow::Result<Option<bytes::Bytes>> {
        let max = self.config.server.max_manifest_size;
        match self.storage.blob_size(digest).await? {
            Some(n) if n <= max => self.storage.blob_bytes(digest).await,
            Some(n) => {
                tracing::debug!(%digest, size = n, max, "not reading an oversized metadata blob");
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// The namespace quota for a user-initiated write to `repository`, if one applies.
    pub async fn quota_check(&self, repository: &str) -> anyhow::Result<Option<QuotaCheck>> {
        let namespace = kontainer_core::names::namespace(repository);
        Ok(self.quota_for(namespace).await?.max_bytes.map(|quota| QuotaCheck { namespace: namespace.to_string(), quota }))
    }

    /// Admit a write to `repository` storing `blobs` (digest, size; those the namespace already
    /// holds cost nothing) plus `extra` bytes, or refuse it if it would exceed the quota. Fires
    /// the quota webhooks (refused, or crossing 90%) like a push does.
    pub async fn admit_write(&self, q: &QuotaCheck, repository: &str, blobs: Vec<(kontainer_core::digest::Digest, u64)>, extra: u64, actor: &str) -> Result<(), crate::error::RegistryError> {
        use crate::webhook::Event;
        use kontainer_store::usage::human;
        let sizes: std::collections::HashMap<kontainer_core::digest::Digest, u64> = blobs.into_iter().collect();
        let (used, missing) = kontainer_store::usage::namespace_missing(&self.storage, &q.namespace, sizes.keys().cloned().collect::<Vec<_>>()).await?;
        let adding: Vec<(kontainer_core::digest::Digest, u64)> = missing.into_iter().map(|d| { let n = sizes.get(&d).copied().unwrap_or(0); (d, n) }).collect();
        let added = adding.iter().map(|(_, n)| n).sum::<u64>() + extra;
        let quota = q.quota;
        if added > 0 && used + added > quota {
            self.webhooks.fire(Event::quota(true, repository, used, quota, added, actor));
            return Err(crate::error::RegistryError::with_message(
                crate::error::Code::Denied,
                format!("storage quota exceeded for {}: {} used of {}, this write adds {}", q.namespace, human(used), human(quota), human(added)),
            ));
        }
        if added > 0 && (used + added) * 10 > quota * 9 && used * 10 <= quota * 9 {
            self.webhooks.fire(Event::quota(false, repository, used, quota, added, actor));
        }
        kontainer_store::usage::record_namespace_blobs(&self.storage, &q.namespace, adding);
        Ok(())
    }

    /// Immutable tags cannot be re-pointed: refuse setting `tag` to `digest` when it is
    /// immutable and already points elsewhere.
    pub async fn check_tag_change(&self, repository: &str, tag: &str, digest: &kontainer_core::digest::Digest) -> Result<(), crate::error::RegistryError> {
        if !self.tag_is_immutable(repository, tag) {
            return Ok(());
        }
        match self.storage.resolve_tag(repository, tag).await? {
            Some(existing) if &existing != digest => Err(crate::error::RegistryError::with_message(crate::error::Code::Denied, format!("tag {tag} is immutable"))
                .status(axum::http::StatusCode::CONFLICT)),
            _ => Ok(()),
        }
    }

    pub fn tag_is_immutable(&self, repository: &str, tag: &str) -> bool {
        use kontainer_core::glob;
        self.config
            .policy
            .immutable_tags
            .iter()
            .any(|r| glob::any_matches(&r.repositories, repository) && glob::any_matches(&r.tags, tag))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kontainer_core::config::{Config, StorageDriver};

    use super::{AppState, Cancel};

    async fn instance(url: &str) -> AppState {
        let mut cfg = Config::default();
        cfg.storage.driver = StorageDriver::Memory;
        cfg.storage.upload_dir = tempfile::tempdir().unwrap().keep();
        cfg.auth.database_url = url.to_string().into();
        cfg.auth.database_pool = 4;
        crate::build_state(cfg).await.unwrap()
    }

    async fn status(s: &AppState, id: &str) -> String {
        s.list_jobs(None).await.unwrap().into_iter().find(|j| j.id == id).map(|j| j.status).unwrap_or_default()
    }

    #[tokio::test]
    async fn jobs_are_listed_and_cancelled_from_any_instance() {
        let url = crate::database::test_support::fresh_database_url();
        let (a, b) = (instance(&url).await, instance(&url).await);
        let heartbeat = Duration::from_millis(50);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let quick = a
            .spawn_job_with("import", "Import x".into(), "ann".into(), heartbeat, async move {
                super::job_progress("halfway");
                let _ = rx.await;
                Ok("imported".to_string())
            })
            .await
            .unwrap();
        let slow = a.spawn_job_with("mirror", "Sync y".into(), "ben".into(), heartbeat, async { std::future::pending::<anyhow::Result<String>>().await }).await.unwrap();

        // b runs neither, and lists both, with a's progress.
        let listed = b.list_jobs(None).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|j| j.status == "running" && j.instance == a.auth.db.instance_id()));
        let mut progressed = false;
        for _ in 0..100 {
            if b.list_jobs(Some("ann")).await.unwrap().first().and_then(|j| j.message.clone()).as_deref() == Some("halfway") {
                progressed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(progressed, "a's progress is visible on b");
        tx.send(()).unwrap();

        // Cancelling on b asks a, which stops the job at its next heartbeat.
        assert_eq!(b.cancel_job(&slow).await.unwrap(), Cancel::Requested);
        let mut cancelled = false;
        for _ in 0..100 {
            if status(&b, &slow).await == "cancelled" && status(&b, &quick).await == "done" {
                cancelled = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(cancelled, "the owner cancelled it");
        assert!(a.jobs.lock().unwrap().is_empty(), "and let go of its handles");
        assert_eq!(b.cancel_job(&slow).await.unwrap(), Cancel::NotRunning);
        let done = b.list_jobs(None).await.unwrap().into_iter().find(|j| j.id == quick).unwrap();
        assert_eq!(done.message.as_deref(), Some("imported"));

        // On its own instance a job is stopped at once.
        let local = a.spawn_job_with("mirror", "Sync z".into(), "ben".into(), heartbeat, async { std::future::pending::<anyhow::Result<String>>().await }).await.unwrap();
        assert_eq!(a.cancel_job(&local).await.unwrap(), Cancel::Stopped);
        let mut stopped = false;
        for _ in 0..100 {
            if status(&b, &local).await == "cancelled" {
                stopped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(stopped);

        // A job whose instance died is failed by the periodic check, and pruned after a week.
        let orphan = a.spawn_job_with("import", "Import w".into(), "ann".into(), Duration::from_secs(3600), async { std::future::pending::<anyhow::Result<String>>().await }).await.unwrap();
        sqlx::query("UPDATE jobs SET updated_at = now() - interval '10 minutes' WHERE id = $1").bind(&orphan).execute(b.auth.db.pool()).await.unwrap();
        assert_eq!(b.auth.db.fail_stale_jobs(super::JOB_STALE_AFTER).await.unwrap(), 1);
        assert_eq!(status(&b, &orphan).await, "failed");
        sqlx::query("UPDATE jobs SET finished_at = now() - interval '8 days' WHERE status <> 'running'").execute(b.auth.db.pool()).await.unwrap();
        b.auth.db.purge_expired().await.unwrap();
        assert!(b.list_jobs(None).await.unwrap().is_empty(), "finished a week ago: pruned");
    }
}
