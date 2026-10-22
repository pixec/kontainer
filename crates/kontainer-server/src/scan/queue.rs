//! The scan queue, kept in PostgreSQL (`scan_jobs`) so queued scans survive restarts and are
//! shared by every instance on the database: each runs `scanner.workers` scans at a time, taking
//! jobs with `FOR UPDATE SKIP LOCKED` so no image is scanned twice at once (see
//! [`crate::workqueue`]). A failed (or crashed) scan is retried with a growing delay, and after
//! the last attempt dropped: its report says why, and so does the job row until it is pruned or
//! the image is queued again.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use kontainer_core::digest::Digest;
use kontainer_store::Storage;

use crate::database::scan_jobs::{Enqueued, Limits, ScanJob};
use crate::database::Db;
use crate::scan::{ScanReport, ScanStatus, ScanTarget, Scanner};
use crate::workqueue::{self, Options};

/// Called with every finished (or finally failed) report, e.g. to send webhooks.
pub type OnReport = Arc<dyn Fn(&ScanTarget, &ScanReport) + Send + Sync>;

/// How an idle instance looks for scans queued elsewhere.
const POLL: Duration = Duration::from_secs(2);
/// A running scan refreshes its claim every quarter of this; one not refreshed for this long was
/// abandoned (its instance died) and is claimed again.
const LEASE: Duration = Duration::from_secs(120);
/// Dropped scans are kept this long, for a look at why.
const KEEP_FAILED: Duration = Duration::from_secs(7 * 24 * 3600);

/// Attempts per scan, and the wait after the first failure (doubling after each).
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    pub attempts: u32,
    pub backoff: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self { attempts: 3, backoff: Duration::from_secs(30) }
    }
}

/// Who asked for a scan: automatic scans count against `scanner.max_auto_per_hour`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Scan on push, scheduled rescans.
    Automatic,
    /// A user's scan of an image, or a scan of everything an administrator started.
    Requested,
}

/// `scanner.max_auto_per_hour` and `scanner.max_queue` (0: unlimited).
#[derive(Debug, Clone, Copy, Default)]
pub struct Budget {
    pub per_hour: u64,
    pub max_queue: u64,
}

impl Budget {
    pub fn from_config(cfg: &kontainer_core::config::ScannerConfig) -> Self {
        Self { per_hour: cfg.max_auto_per_hour, max_queue: cfg.max_queue }
    }
}

#[derive(Clone)]
pub struct ScanQueue {
    db: Db,
    wake: Arc<Notify>,
    stop: CancellationToken,
    pub scanner_name: &'static str,
    pub budget: Budget,
}

struct Worker {
    scanner: Arc<dyn Scanner>,
    storage: Storage,
    db: Db,
    on_report: OnReport,
    holder: String,
    lease: Duration,
    retry: Retry,
}

impl ScanQueue {
    pub fn start(scanner: Arc<dyn Scanner>, storage: Storage, db: Db, on_report: OnReport, workers: usize) -> Self {
        Self::with_options(scanner, storage, db, on_report, Options { workers, poll: POLL, lease: LEASE }, Retry::default())
    }

    pub fn with_options(scanner: Arc<dyn Scanner>, storage: Storage, db: Db, on_report: OnReport, opts: Options, retry: Retry) -> Self {
        let q = Self { db: db.clone(), wake: Arc::new(Notify::new()), stop: CancellationToken::new(), scanner_name: scanner.name(), budget: Budget::default() };
        let worker = Arc::new(Worker { scanner, storage, db: db.clone(), on_report, holder: workqueue::holder("scan"), lease: opts.lease, retry });
        let claim = { let w = worker.clone(); move || { let w = w.clone(); async move { w.db.claim_scan_job(&w.holder, w.lease).await } } };
        workqueue::spawn("scan", opts, q.wake.clone(), q.stop.clone(), claim, move |job| { let w = worker.clone(); async move { w.process(job).await } });
        let stop = q.stop.clone();
        tokio::spawn(async move {
            loop {
                match db.prune_failed_scan_jobs(KEEP_FAILED).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(n, "forgot old failed scans"),
                    Err(e) => tracing::warn!(error = %e, "pruning failed scans"),
                }
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(3600)) => {}
                }
            }
        });
        q
    }

    /// Apply `scanner.max_auto_per_hour` and `scanner.max_queue` to the scans queued from now.
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// Enqueue a scan someone asked for (it does not count against the hourly budget, but a
    /// full queue still refuses it). Returns false if one is already queued or running for
    /// this image (on any instance), or it could not be queued.
    pub async fn enqueue(&self, storage: &Storage, repository: &str, digest: &Digest) -> bool {
        self.enqueue_as(storage, repository, digest, Origin::Requested).await == Some(Enqueued::Queued)
    }

    /// Enqueue a scan, within the budget for `origin`. A skipped scan is counted (metrics,
    /// `scan_budget`) and logged. `None` when it could not be queued (database error).
    pub async fn enqueue_as(&self, storage: &Storage, repository: &str, digest: &Digest, origin: Origin) -> Option<Enqueued> {
        let limits = Limits { is_automatic: origin == Origin::Automatic, per_hour: self.budget.per_hour, max_queue: self.budget.max_queue };
        match self.db.enqueue_scan_job_within(repository, &digest.to_string(), limits).await {
            Ok(Enqueued::Queued) => {}
            Ok(skip @ (Enqueued::OverBudget | Enqueued::QueueFull)) => {
                let reason = if skip == Enqueued::OverBudget { "budget" } else { "queue_full" };
                crate::metrics::global().scan_skipped(reason);
                tracing::info!(repo = repository, %digest, reason, "scan skipped");
                return Some(skip);
            }
            Ok(other) => return Some(other),
            Err(e) => {
                tracing::warn!(repo = repository, %digest, error = %format!("{e:#}"), "queueing a scan");
                return None;
            }
        }
        let pending = ScanReport::pending(self.scanner_name, repository, digest);
        if let Ok(b) = serde_json::to_vec(&pending) {
            let _ = storage.put_scan(digest, b).await;
        }
        self.wake.notify_one();
        Some(Enqueued::Queued)
    }

    /// Stop taking scans on this instance; scans in progress are abandoned (like a crash: their
    /// claims lapse and another worker takes them over).
    pub fn stop(&self) {
        self.stop.cancel();
    }
}

/// Aborts the task when dropped, so an abandoned job does not keep scanning.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Worker {
    async fn process(&self, job: ScanJob) {
        let digest: Digest = match job.digest.parse() {
            Ok(d) => d,
            Err(_) => {
                let _ = self.db.fail_scan_job(job.id, &self.holder, "not a digest").await;
                return;
            }
        };
        let target = ScanTarget { repository: job.repository.clone(), digest };
        let mut task = AbortOnDrop({
            let (scanner, storage, target) = (self.scanner.clone(), self.storage.clone(), target.clone());
            tokio::spawn(async move { run_one(&*scanner, &storage, &target).await })
        });
        // Keep the claim fresh while the scan runs.
        let mut beat = tokio::time::interval((self.lease / 4).max(Duration::from_millis(10)));
        beat.tick().await;
        let outcome = loop {
            tokio::select! {
                r = &mut task.0 => break r,
                _ = beat.tick() => match self.db.heartbeat_scan_job(job.id, &self.holder).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(repo = %target.repository, digest = %target.digest, "lost the claim on a running scan; leaving it to its new worker");
                        return;
                    }
                    Err(e) => tracing::warn!(error = %e, "refreshing a scan's claim"),
                },
            }
        };
        let outcome = outcome.unwrap_or_else(|e| {
            tracing::error!(repo = %target.repository, digest = %target.digest, error = %e, "scan task panicked");
            Err("the scanner crashed".into())
        });
        let attempt = u32::try_from(job.attempts).unwrap_or(u32::MAX);
        let report = match outcome {
            Ok(report) => {
                store(&self.storage, &target, &report).await;
                if let Err(e) = self.db.finish_scan_job(job.id, &self.holder).await {
                    tracing::warn!(error = %e, "removing a finished scan from the queue");
                }
                report
            }
            Err(error) if attempt < self.retry.attempts => {
                let delay = workqueue::backoff(self.retry.backoff, attempt);
                tracing::warn!(repo = %target.repository, digest = %target.digest, attempt, error = %error, retry_in = ?delay, "scan failed; will retry");
                let mut r = ScanReport::pending(self.scanner.name(), &target.repository, &target.digest);
                r.error = Some(format!("attempt {attempt} of {} failed, retrying: {error}", self.retry.attempts));
                store(&self.storage, &target, &r).await;
                if let Err(e) = self.db.retry_scan_job(job.id, &self.holder, &error, delay).await {
                    tracing::warn!(error = %e, "rescheduling a failed scan");
                }
                return;
            }
            Err(error) => {
                tracing::warn!(repo = %target.repository, digest = %target.digest, attempts = attempt, error = %error, "scan failed; giving up");
                let r = failed(self.scanner.name(), &target, error.clone());
                store(&self.storage, &target, &r).await;
                if let Err(e) = self.db.fail_scan_job(job.id, &self.holder, &error).await {
                    tracing::warn!(error = %e, "dropping a failed scan");
                }
                r
            }
        };
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.on_report)(&target, &report))).is_err() {
            tracing::error!(repo = %target.repository, digest = %target.digest, "handling a scan report panicked");
        }
    }
}

fn failed(scanner: &str, target: &ScanTarget, error: String) -> ScanReport {
    let mut r = ScanReport::pending(scanner, &target.repository, &target.digest);
    r.status = ScanStatus::Failed;
    r.error = Some(error);
    r.finished_at = Some(chrono::Utc::now().to_rfc3339());
    r
}

async fn store(storage: &Storage, target: &ScanTarget, report: &ScanReport) {
    match serde_json::to_vec(report) {
        Ok(b) => {
            if let Err(e) = storage.put_scan(&target.digest, b).await {
                tracing::error!(error = %e, "storing scan report");
            }
        }
        Err(e) => tracing::error!(error = %e, "serializing scan report"),
    }
}

/// Scan `target`, marking its report running first. The finished report, or why it failed.
async fn run_one(scanner: &dyn Scanner, storage: &Storage, target: &ScanTarget) -> Result<ScanReport, String> {
    let mut running = ScanReport::pending(scanner.name(), &target.repository, &target.digest);
    running.status = ScanStatus::Running;
    if let Ok(b) = serde_json::to_vec(&running) {
        let _ = storage.put_scan(&target.digest, b).await;
    }
    tracing::info!(repo = %target.repository, digest = %target.digest, "scan started");
    match scanner.scan(target).await {
        Ok(mut r) => {
            r.status = ScanStatus::Done;
            r.started_at = running.started_at.clone();
            r.finalize();
            tracing::info!(repo = %target.repository, digest = %target.digest, total = r.total, "scan finished");
            Ok(r)
        }
        Err(e) => Err(format!("{e:#}")),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use anyhow::Result;
    use async_trait::async_trait;

    use super::*;
    use crate::database::test_support::fresh_database_url;

    /// Counts scans per image. `fail_first` scans fail (the first by panicking), then they succeed.
    struct Counting {
        calls: Mutex<HashMap<String, usize>>,
        total: AtomicUsize,
        fail_first: usize,
    }

    impl Counting {
        fn new(fail_first: usize) -> Arc<Self> {
            Arc::new(Self { calls: Mutex::default(), total: AtomicUsize::new(0), fail_first })
        }
    }

    #[async_trait]
    impl Scanner for Counting {
        fn name(&self) -> &'static str {
            "counting"
        }
        async fn scan(&self, target: &ScanTarget) -> Result<ScanReport> {
            *self.calls.lock().unwrap().entry(target.digest.to_string()).or_default() += 1;
            tokio::time::sleep(Duration::from_millis(300)).await;
            match self.total.fetch_add(1, Ordering::SeqCst) {
                0 if self.fail_first > 0 => panic!("scanner bug"),
                n if n < self.fail_first => anyhow::bail!("registry unreachable"),
                _ => Ok(ScanReport::pending("counting", &target.repository, &target.digest)),
            }
        }
    }

    async fn storage(dir: &std::path::Path) -> Storage {
        let mut cfg = kontainer_core::config::StorageConfig::default();
        cfg.filesystem.root = dir.join("data");
        cfg.upload_dir = dir.join("uploads");
        Storage::from_config(&cfg).await.unwrap()
    }

    fn fast(workers: usize) -> Options {
        Options { workers, poll: Duration::from_millis(50), lease: Duration::from_secs(30) }
    }

    fn reports() -> (OnReport, tokio::sync::mpsc::UnboundedReceiver<(String, ScanStatus)>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Arc::new(move |t: &ScanTarget, r: &ScanReport| { let _ = tx.send((t.digest.to_string(), r.status.clone())); }), rx)
    }

    async fn next(rx: &mut tokio::sync::mpsc::UnboundedReceiver<(String, ScanStatus)>) -> (String, ScanStatus) {
        tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.expect("a report in time").unwrap()
    }

    #[tokio::test]
    async fn each_scan_is_claimed_once_across_two_instances() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let url = fresh_database_url();
        let scanner = Counting::new(0);
        let (on_report, mut rx) = reports();
        // Two "instances" on one database, sharing a scanner that counts.
        let a = ScanQueue::with_options(scanner.clone(), storage.clone(), Db::open(&url, 4).await.unwrap(), on_report.clone(), fast(2), Retry::default());
        let b = ScanQueue::with_options(scanner.clone(), storage.clone(), Db::open(&url, 4).await.unwrap(), on_report, fast(2), Retry::default());
        let digests: Vec<Digest> = (0..8u8).map(|i| Digest::sha256_of(&[i])).collect();
        for (i, d) in digests.iter().enumerate() {
            let (first, second) = if i % 2 == 0 { (&a, &b) } else { (&b, &a) };
            assert!(first.enqueue(&storage, "acme/app", d).await);
            assert!(!second.enqueue(&storage, "acme/app", d).await, "already queued, on the other instance");
        }
        let mut done = vec![];
        for _ in 0..digests.len() {
            let (d, status) = next(&mut rx).await;
            assert_eq!(status, ScanStatus::Done);
            done.push(d);
        }
        done.sort();
        let mut want: Vec<String> = digests.iter().map(ToString::to_string).collect();
        want.sort();
        assert_eq!(done, want);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rx.try_recv().is_err(), "no scan ran twice");
        assert!(scanner.calls.lock().unwrap().values().all(|&n| n == 1), "{:?}", scanner.calls.lock().unwrap());
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM scan_jobs").fetch_one(a.db.pool()).await.unwrap();
        assert_eq!(left, 0, "finished scans leave the queue");
        a.stop();
        b.stop();
    }

    #[tokio::test]
    async fn a_failing_scan_is_retried_then_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let db = Db::open(&fresh_database_url(), 4).await.unwrap();
        // Fails (panic, error, error) more often than it is tried.
        let scanner = Counting::new(usize::MAX);
        let (on_report, mut rx) = reports();
        let retry = Retry { attempts: 3, backoff: Duration::from_millis(20) };
        let q = ScanQueue::with_options(scanner.clone(), storage.clone(), db.clone(), on_report, fast(1), retry);
        let d = Digest::sha256_of(b"image");
        assert!(q.enqueue(&storage, "acme/app", &d).await);
        // Only the final outcome is reported (webhooks fire once).
        assert_eq!(next(&mut rx).await, (d.to_string(), ScanStatus::Failed));
        assert_eq!(scanner.total.load(Ordering::SeqCst), 3, "tried three times");
        let stored: ScanReport = serde_json::from_slice(&storage.get_scan(&d).await.unwrap().unwrap()).unwrap();
        assert_eq!((stored.status, stored.error.as_deref()), (ScanStatus::Failed, Some("registry unreachable")));
        let (attempts, error) = db.failed_scan_job("acme/app", &d.to_string()).await.unwrap().expect("kept, with the error");
        assert_eq!((attempts, error.as_deref()), (3, Some("registry unreachable")));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(scanner.total.load(Ordering::SeqCst), 3, "dropped: not tried again");
        // It can be queued again by hand.
        assert!(q.enqueue(&storage, "acme/app", &d).await);
        assert_eq!(next(&mut rx).await.1, ScanStatus::Failed);
        q.stop();
    }

    #[tokio::test]
    async fn a_crashed_scan_is_retried_and_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let db = Db::open(&fresh_database_url(), 4).await.unwrap();
        let scanner = Counting::new(1);
        let (on_report, mut rx) = reports();
        let q = ScanQueue::with_options(scanner.clone(), storage.clone(), db, on_report, fast(1), Retry { attempts: 3, backoff: Duration::from_millis(20) });
        let d = Digest::sha256_of(b"image");
        assert!(q.enqueue(&storage, "acme/app", &d).await);
        assert_eq!(next(&mut rx).await.1, ScanStatus::Done, "the panic was retried");
        assert_eq!(scanner.total.load(Ordering::SeqCst), 2);
        q.stop();
    }

    #[tokio::test]
    async fn scans_queued_before_a_restart_still_run() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage(dir.path()).await;
        let url = fresh_database_url();
        let (on_report, mut rx) = reports();
        // The first instance dies holding the scan (it never finishes).
        let stuck = Arc::new(Notify::new());
        struct Hangs(Arc<Notify>);
        #[async_trait]
        impl Scanner for Hangs {
            fn name(&self) -> &'static str { "hangs" }
            async fn scan(&self, _: &ScanTarget) -> Result<ScanReport> { self.0.notified().await; anyhow::bail!("unreachable") }
        }
        let opts = Options { workers: 1, poll: Duration::from_millis(50), lease: Duration::from_millis(400) };
        let a = ScanQueue::with_options(Arc::new(Hangs(stuck)), storage.clone(), Db::open(&url, 2).await.unwrap(), on_report.clone(), opts, Retry::default());
        let d = Digest::sha256_of(b"image");
        assert!(a.enqueue(&storage, "acme/app", &d).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        a.stop();
        // The new instance takes it over once the dead one's claim lapses.
        let b = ScanQueue::with_options(Counting::new(0), storage.clone(), Db::open(&url, 2).await.unwrap(), on_report, opts, Retry::default());
        assert_eq!(next(&mut rx).await, (d.to_string(), ScanStatus::Done));
        b.stop();
    }
}
