//! Maintenance runs: garbage collection and scanning everything, by hand or on a schedule
//! (`gc.interval`, `scanner.rescan_interval`), each recorded in `task_runs` for the admin UI.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::Serialize;

use kontainer_core::digest::Digest;
use kontainer_core::manifest::Manifest;
use kontainer_store::gc::GcReport;

use crate::state::AppState;

/// What is running on this registry: at most one of each at a time.
#[derive(Clone, Default)]
pub struct Running {
    gc: Arc<AtomicBool>,
    scan_all: Arc<AtomicBool>,
    /// Replication rules with a full run in progress.
    pub replication: Arc<std::sync::Mutex<HashSet<i64>>>,
}

/// A run was refused because the same kind is still going.
#[derive(Debug)]
pub struct AlreadyRunning(pub &'static str);

impl std::fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is already running", self.0)
    }
}

impl std::error::Error for AlreadyRunning {}

/// Holds a run's slot until dropped.
struct Slot(Arc<AtomicBool>);

impl Slot {
    fn take(flag: &Arc<AtomicBool>, what: &'static str) -> Result<Self> {
        if flag.swap(true, Ordering::SeqCst) {
            return Err(AlreadyRunning(what).into());
        }
        Ok(Self(flag.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// The cluster-wide slot for `name`: with several instances on one database, a run of each kind
/// at a time across all of them. Dropped without release (an early return), its connection is
/// closed, which releases it too.
pub async fn cluster_slot(state: &AppState, name: &str, what: &'static str) -> Result<crate::database::locks::AdvisoryLock> {
    state.auth.db.try_advisory_lock(name).await?.ok_or_else(|| AlreadyRunning(what).into())
}

/// Like [`Slot`], for runs keyed by id (one at a time per replication rule).
pub struct KeyedSlot {
    set: Arc<std::sync::Mutex<HashSet<i64>>>,
    key: i64,
}

impl KeyedSlot {
    pub fn take(set: &Arc<std::sync::Mutex<HashSet<i64>>>, key: i64, what: &'static str) -> Result<Self> {
        if !set.lock().unwrap_or_else(|e| e.into_inner()).insert(key) {
            return Err(AlreadyRunning(what).into());
        }
        Ok(Self { set: set.clone(), key })
    }
}

impl Drop for KeyedSlot {
    fn drop(&mut self) {
        self.set.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.key);
    }
}

/// Collect garbage, recording the run. Dry runs are recorded too, so a preview shows up in the
/// history next to what was actually removed.
pub async fn gc(state: &AppState, trigger: &str, actor: &str, delete_untagged: bool, dry_run: bool, grace: Duration) -> Result<GcReport> {
    let _slot = Slot::take(&state.running.gc, "garbage collection")?;
    let lock = cluster_slot(state, "gc", "garbage collection").await?;
    let run = state.auth.db.start_task_run("gc", trigger, actor).await?;
    let result = async {
        let window = crate::tags::longest_time_machine(&state.auth.db, state.config.policy.time_machine).await?;
        let restorable = crate::tags::restorable(&state.auth.db, window).await?;
        kontainer_store::gc::run(&state.storage, delete_untagged, dry_run, grace, &restorable).await
    }
    .await;
    match &result {
        Ok(r) => {
            let verb = if dry_run { "would free" } else { "freed" };
            let summary = format!(
                "{}{verb} {} ({} blobs, {} manifests)",
                if dry_run { "Dry run: " } else { "" },
                kontainer_store::usage::human(r.bytes_freed),
                r.blobs_removed.len(),
                r.manifests_removed.len()
            );
            state.auth.db.finish_task_run(run, true, &summary, serde_json::to_value(r).ok().as_ref()).await?;
        }
        Err(e) => state.auth.db.finish_task_run(run, false, &format!("{e:#}"), None).await?,
    }
    lock.release().await;
    result
}

#[derive(Debug, Default, Serialize)]
pub struct ScanAllSummary {
    /// Images looked at (each platform of a multi-platform image counts).
    pub images: usize,
    pub queued: usize,
    /// Already had a recent enough report.
    pub current: usize,
    /// Not queued: the automatic-scan budget was spent or the queue was full.
    pub skipped: usize,
}

/// Queue scans for every tagged image whose report is missing, or older than `stale_after`
/// (with `None`, only missing ones). Scans run on the scan queue afterwards.
pub async fn scan_all(state: &AppState, trigger: &str, actor: &str, stale_after: Option<Duration>) -> Result<ScanAllSummary> {
    let Some(queue) = &state.scans else { bail!("no scanner is configured") };
    let _slot = Slot::take(&state.running.scan_all, "a scan of everything")?;
    let lock = cluster_slot(state, "scan_all", "a scan of everything").await?;
    let run = state.auth.db.start_task_run("scan_all", trigger, actor).await?;
    let result = async {
        let mut sum = ScanAllSummary::default();
        let mut seen: HashSet<Digest> = HashSet::new();
        // The schedule's rescans are automatic; a scan of everything someone started is not
        // held to the hourly budget (a full queue still stops it).
        let origin = if trigger == "schedule" { crate::scan::queue::Origin::Automatic } else { crate::scan::queue::Origin::Requested };
        let cutoff = stale_after.and_then(|d| chrono::Duration::from_std(d).ok()).map(|d| chrono::Utc::now() - d);
        for repo in state.storage.list_repositories().await? {
            for entry in state.storage.list_tags_resolved(&repo).await? {
                let Some(bytes) = state.storage.manifest_bytes(&repo, &entry.digest).await? else { continue };
                let Ok((manifest, _)) = Manifest::parse(&bytes, None) else { continue };
                // A multi-platform image is scanned platform by platform.
                let images: Vec<Digest> = match &manifest {
                    Manifest::Image(_) => vec![entry.digest.clone()],
                    Manifest::Index(ix) => ix.manifests.iter().map(|m| m.digest.clone()).collect(),
                };
                for d in images {
                    if !seen.insert(d.clone()) {
                        continue;
                    }
                    sum.images += 1;
                    if is_current(state, &d, cutoff).await {
                        sum.current += 1;
                    } else {
                        use crate::database::scan_jobs::Enqueued;
                        match queue.enqueue_as(&state.storage, &repo, &d, origin).await {
                            Some(Enqueued::Queued) => sum.queued += 1,
                            Some(Enqueued::OverBudget | Enqueued::QueueFull) => sum.skipped += 1,
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(sum)
    }
    .await;
    match &result {
        Ok(s) => {
            let mut summary = format!("Queued {} of {} images ({} up to date)", s.queued, s.images, s.current);
            if s.skipped > 0 {
                summary.push_str(&format!(", {} skipped (scan budget or full queue)", s.skipped));
            }
            state.auth.db.finish_task_run(run, true, &summary, serde_json::to_value(s).ok().as_ref()).await?;
        }
        Err(e) => state.auth.db.finish_task_run(run, false, &format!("{e:#}"), None).await?,
    }
    lock.release().await;
    result
}

/// Has `digest` a finished report newer than `cutoff` (any finished report without a cutoff)?
async fn is_current(state: &AppState, digest: &Digest, cutoff: Option<chrono::DateTime<chrono::Utc>>) -> bool {
    let Ok(Some(raw)) = state.storage.get_scan(digest).await else { return false };
    let Ok(report) = serde_json::from_slice::<crate::scan::ScanReport>(&raw) else { return false };
    // Queued or running scans count as current: they are about to finish.
    if matches!(report.status, crate::scan::ScanStatus::Pending | crate::scan::ScanStatus::Running) {
        return true;
    }
    match cutoff {
        None => report.status == crate::scan::ScanStatus::Done,
        Some(cutoff) => report.status == crate::scan::ScanStatus::Done
            && report.finished_at.as_deref().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok()).is_some_and(|t| t.to_utc() > cutoff),
    }
}

/// Start the schedules that are configured. Call once at startup.
pub async fn start(state: &AppState) {
    fail_interrupted(&state.auth.db, true).await;
    // Runs and jobs of instances that died while this one keeps running.
    let db = state.auth.db.clone();
    crate::background::every(Duration::from_secs(60), false, move || {
        let db = db.clone();
        async move { fail_interrupted(&db, false).await }
    });
    if let Some(every) = state.config.gc.interval {
        let state = state.clone();
        tokio::spawn(async move {
            schedule(&state, "gc", every, || async {
                let grace = state.config.storage.upload_ttl;
                gc(&state, "schedule", "schedule", state.config.gc.is_delete_untagged, false, grace).await.map(|_| ())
            })
            .await
        });
    }
    if let Some(every) = state.config.scanner.rescan_interval {
        if state.scans.is_some() {
            let state = state.clone();
            tokio::spawn(async move { schedule(&state, "scan_all", every, || async { scan_all(&state, "schedule", "schedule", Some(every)).await.map(|_| ()) }).await });
        }
    }
}

/// Mark maintenance runs and background jobs that can never finish as failed (see
/// [`fail_interrupted_task_runs`](crate::database::Db::fail_interrupted_task_runs)).
async fn fail_interrupted(db: &crate::database::Db, at_startup: bool) {
    match db.fail_interrupted_task_runs(crate::database::tasks::STALE_AFTER, at_startup).await {
        Ok(0) => {}
        Ok(n) => tracing::warn!(runs = n, "marked interrupted maintenance runs as failed"),
        Err(e) => tracing::warn!(error = %e, "checking for interrupted maintenance runs"),
    }
    // Background jobs work the same way: their owner updates them while they run.
    match db.fail_stale_jobs(crate::state::JOB_STALE_AFTER).await {
        Ok(0) => {}
        Ok(n) => tracing::warn!(jobs = n, "marked background jobs of a stopped instance as failed"),
        Err(e) => tracing::warn!(error = %e, "checking for interrupted background jobs"),
    }
}

/// Run `task` every `every`, counting from the last scheduled run so restarts don't reset it.
async fn schedule<F, Fut>(state: &AppState, kind: &str, every: Duration, task: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    loop {
        let last = state.auth.db.last_scheduled_run(kind).await.ok().flatten();
        let wait = match last {
            Some(t) => (t + chrono::Duration::from_std(every).unwrap_or_default() - chrono::Utc::now()).to_std().unwrap_or_default(),
            // Never ran: not at startup, but after a short while.
            None => Duration::from_secs(300),
        };
        tokio::time::sleep(wait.max(Duration::from_secs(60))).await;
        // With several instances, one runs it: the others find the schedule's lock taken, or (if
        // they get it after that run) the run no longer due.
        let ran = crate::database::locks::exclusive(&state.auth.db, &format!("schedule/{kind}"), async {
            if !is_due(state, kind, every).await {
                return Ok(());
            }
            task().await
        })
        .await;
        if let Some(Err(e)) = ran {
            if e.downcast_ref::<AlreadyRunning>().is_some() {
                tracing::info!(task = kind, "skipping a scheduled run: {e}");
            } else {
                tracing::warn!(task = kind, error = %format!("{e:#}"), "scheduled maintenance failed");
            }
        }
    }
}

/// Is a scheduled run of `kind` due (none yet, or the last started about `every` ago)?
async fn is_due(state: &AppState, kind: &str, every: Duration) -> bool {
    let Ok(last) = state.auth.db.last_scheduled_run(kind).await else { return false };
    let Some(last) = last else { return true };
    // Slack for timers: a run that wakes a little early is still the one that is due.
    let slack = chrono::Duration::from_std(every / 10).unwrap_or_default().min(chrono::Duration::seconds(30));
    chrono::Utc::now() + slack >= last + chrono::Duration::from_std(every).unwrap_or_default()
}
