//! The runner (`kontainer runner`): asks a registry for queued builds of the namespaces it
//! serves and runs them, in this process (`local`), in a pair of containers per build
//! (`docker`) or as a Kubernetes Job per build (`kubernetes`). Builds started elsewhere run
//! `kontainer runner --build-id <id>` there, which is [`Runner::run_one`].

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::{watch, Mutex};

use kontainer_core::config::{BuildBackend, BuildExecutor, RunnerConfig};
use kontainer_core::WireSecret;

use crate::runner::launch::docker::DockerLauncher;
use crate::runner::launch::kubernetes::KubernetesLauncher;
use crate::runner::launch::{Launched, Launcher};
use crate::runner::protocol::{self, BuildSpec, CheckIn, CheckInReply, ClaimRequest, Claimed, Commit, CommitReply, Finish, ImageReply, LOG_TAIL_BYTES};
use crate::runner::steps::{self, Backend, Log};

/// How often the log is sent (what it gained since); it doubles as the heartbeat.
const CHECKIN_EVERY: Duration = Duration::from_secs(2);
/// How long a launched build may take to show up on the platform before it counts as lost.
const LAUNCH_GRACE: Duration = Duration::from_secs(120);
/// The longest a launched build may live: the registry stops builds at its own (shorter)
/// timeout, so anything older is left over.
const MAX_BUILD: Duration = Duration::from_secs(6 * 3600);
/// A stopped build this runner doesn't know about (it was restarted, or another runner shares
/// the Docker host) is removed after this long, giving whoever launched it time to notice.
const ORPHAN_GRACE: Duration = Duration::from_secs(120);
/// An upload that makes no progress for this long is abandoned.
const UPLOAD_STALL: Duration = Duration::from_secs(120);
/// Once the archive is sent, how long the registry may take to import it.
const IMPORT_WAIT: Duration = Duration::from_secs(30 * 60);

/// Talks to one registry.
#[derive(Clone)]
pub struct Runner {
    server: String,
    name: String,
    backend: Backend,
    work_dir: PathBuf,
    http: reqwest::Client,
}

/// The backend `cfg` asks for.
pub fn backend(cfg: &RunnerConfig) -> Backend {
    match cfg.backend {
        BuildBackend::Docker => Backend::Docker,
        BuildBackend::Buildctl => Backend::Buildctl { addr: cfg.buildkit_addr.clone() },
    }
}

impl Runner {
    pub fn new(cfg: &RunnerConfig) -> Result<Self> {
        let http = reqwest::Client::builder().user_agent(kontainer_core::USER_AGENT).connect_timeout(Duration::from_secs(10)).build()?;
        let name = cfg.name.clone().or_else(hostname).unwrap_or_else(|| "runner".into());
        Ok(Self { server: cfg.server.trim_end_matches('/').to_string(), name, backend: backend(cfg), work_dir: cfg.work_dir.clone(), http })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}{path}", self.server, protocol::BASE)
    }

    async fn call<B: Serialize, R: DeserializeOwned>(&self, path: &str, token: &str, body: &B) -> Result<R> {
        let r = self.http.post(self.url(path)).bearer_auth(token).timeout(Duration::from_secs(30)).json(body).send().await.with_context(|| format!("reaching {}", self.server))?;
        decode(r).await
    }

    /// Ask for a build. `None`: nothing queued for us.
    async fn claim(&self, token: &str, report: &ClaimRequest) -> Result<Option<Claimed>> {
        let r = self.http.post(self.url("/claim")).bearer_auth(token).timeout(Duration::from_secs(30)).json(report).send().await.with_context(|| format!("reaching {}", self.server))?;
        if r.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if r.status() == StatusCode::UNAUTHORIZED {
            bail!("the registry doesn't recognise this runner's token: it was replaced, deleted or disabled");
        }
        decode(r).await.map(Some)
    }

    /// Claim and run builds until the process is stopped.
    pub async fn serve(&self, cfg: &RunnerConfig) -> Result<()> {
        let (_never, shutdown) = watch::channel(false);
        self.serve_until(cfg, shutdown).await
    }

    /// Claim and run builds until `shutdown` turns true. Then it stops claiming, cancels the
    /// builds running in this process (they report themselves as failed) and returns once they
    /// have; launched builds (Docker, Kubernetes) carry on and report on their own.
    pub async fn serve_until(&self, cfg: &RunnerConfig, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let token = cfg.token.clone().context("no runner token")?;
        let launcher: Option<Arc<dyn Launcher>> = match cfg.executor {
            BuildExecutor::Local => None,
            BuildExecutor::Docker => {
                let url = cfg.docker.server_url.clone().unwrap_or_else(|| self.server.clone());
                Some(Arc::new(DockerLauncher::new(&cfg.docker, &url).await.context("connecting to Docker")?))
            }
            BuildExecutor::Kubernetes => {
                let url = cfg.kubernetes.server_url.clone().unwrap_or_else(|| self.server.clone());
                // The registry stops builds at its own timeout; this is the Job's deadline.
                Some(Arc::new(KubernetesLauncher::new(&cfg.kubernetes, MAX_BUILD, &url).context("connecting to Kubernetes")?))
            }
        };
        let executor = format!("{:?}", cfg.executor).to_lowercase();
        let concurrency = cfg.concurrency.max(1);
        tracing::info!(server = %self.server, name = %self.name, %executor, concurrency, "runner ready");
        let active: Arc<Mutex<HashMap<i64, Active>>> = Arc::default();
        let watcher = launcher.as_ref().map(|l| tokio::spawn(watch_launched(self.clone(), l.clone(), active.clone())));
        let mut quiet = false;
        while !*shutdown.borrow() {
            let running = active.lock().await.len();
            // Busy: still report in, so the registry shows the runner as online and busy.
            let report_only = running >= concurrency;
            let report = ClaimRequest { hostname: hostname().unwrap_or_default(), version: env!("CARGO_PKG_VERSION").into(), executor: executor.clone(), concurrency, running, report_only };
            if report_only {
                let _ = self.claim(token.expose(), &report).await;
                pause(cfg.poll, &mut shutdown).await;
                continue;
            }
            match self.claim(token.expose(), &report).await {
                Ok(Some(c)) if *shutdown.borrow() => {
                    self.report_failure(c.id, c.token.expose(), "The runner shut down before the build started").await;
                }
                Ok(Some(c)) => {
                    quiet = false;
                    active.lock().await.insert(c.id, Active { token: c.token.clone(), since: Instant::now() });
                    match &launcher {
                        None => {
                            let (runner, active, shutdown) = (self.clone(), active.clone(), shutdown.clone());
                            tokio::spawn(async move {
                                if let Err(e) = runner.run_one_until(c.id, c.token.expose(), shutdown).await {
                                    tracing::warn!(build = c.id, error = %format!("{e:#}"), "build");
                                }
                                active.lock().await.remove(&c.id);
                            });
                        }
                        Some(l) => {
                            if let Err(e) = l.launch(c.id, c.token.expose()).await {
                                let _ = l.remove(c.id).await;
                                let msg = format!("Couldn't start the build: {e:#}");
                                tracing::warn!(build = c.id, error = %msg, "launching a build");
                                self.report_failure(c.id, c.token.expose(), &msg).await;
                                active.lock().await.remove(&c.id);
                            } else {
                                tracing::info!(build = c.id, runner = l.prefix(), "build launched");
                            }
                        }
                    }
                }
                Ok(None) => {
                    quiet = false;
                    pause(cfg.poll, &mut shutdown).await;
                }
                Err(e) => {
                    // Say so once per outage, not every few seconds.
                    if !quiet {
                        tracing::warn!(error = %format!("{e:#}"), server = %self.server, "asking the registry for work");
                        quiet = true;
                    }
                    pause(cfg.poll.max(Duration::from_secs(10)), &mut shutdown).await;
                }
            }
        }
        if let Some(w) = watcher {
            w.abort();
            tracing::info!("runner stopping; launched builds carry on and report on their own");
            return Ok(());
        }
        // Builds here saw `shutdown` too: they cancel, report and leave `active`.
        let running = active.lock().await.len();
        tracing::info!(running, "runner stopping; cancelling the builds running here");
        while !active.lock().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok(())
    }

    /// Fail build `id` with `message` (its log gets the message too).
    async fn report_failure(&self, id: i64, token: &str, message: &str) {
        let first = message.lines().next().unwrap_or_default().to_string();
        let finish = Finish { status: "failed".into(), message: first, line: Some(format!("==> {message}")), log: None };
        if let Err(e) = self.call::<_, serde_json::Value>(&format!("/builds/{id}/finish"), token, &finish).await {
            tracing::debug!(build = id, error = %format!("{e:#}"), "reporting a failure (the build may have ended already)");
        }
    }

    /// Run build `id`, already claimed (`token` is its build token), in this process. Reports
    /// the outcome to the registry; the error is only for our own log.
    pub async fn run_one(&self, id: i64, token: &str) -> Result<()> {
        let (_never, shutdown) = watch::channel(false);
        self.run_one_until(id, token, shutdown).await
    }

    /// [`Runner::run_one`], cancelled when `shutdown` turns true (and then reported as failed).
    pub async fn run_one_until(&self, id: i64, token: &str, shutdown: watch::Receiver<bool>) -> Result<()> {
        let spec: BuildSpec = decode(self.http.get(self.url(&format!("/builds/{id}"))).bearer_auth(token).timeout(Duration::from_secs(30)).send().await?).await?;
        tracing::info!(build = id, repository = %spec.repository, "build started");
        let log = Log::default();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let work = self.work_dir.join(format!("build-{id}"));
        let stopper = {
            let (cancel_tx, mut shutdown) = (cancel_tx.clone(), shutdown.clone());
            tokio::spawn(async move {
                if shutdown.wait_for(|s| *s).await.is_ok() {
                    let _ = cancel_tx.send(true);
                }
            })
        };

        // Check in until the build is over; the registry can tell us to stop.
        let server = Arc::new(HttpServer { runner: self.clone(), id, token: token.to_string() });
        let shipper = Arc::new(Mutex::new(LogShipper::default()));
        let checkin = {
            let (log, server, shipper, cancel_tx) = (log.clone(), server.clone(), shipper.clone(), cancel_tx.clone());
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(CHECKIN_EVERY).await;
                    match shipper.lock().await.check_in(&log, &*server, false).await {
                        Ok(r) if r.stop => {
                            let _ = cancel_tx.send(true);
                            break;
                        }
                        Ok(_) => {}
                        // Keep building through blips; the registry fails builds that go quiet.
                        Err(e) => tracing::warn!(build = id, error = %format!("{e:#}"), "checking in"),
                    }
                }
            })
        };
        let built = steps::run(&spec, &self.backend, &work, &log, &*server, cancel_rx.clone()).await;
        let outcome = match built {
            Ok(archive) => {
                log.line("==> Uploading the image to the registry");
                // All of the log before the image: the registry ends it with the outcome.
                match shipper.lock().await.check_in(&log, &*server, true).await {
                    Ok(r) if r.stop => {
                        let _ = cancel_tx.send(true);
                        Err(anyhow!("Cancelled"))
                    }
                    _ => {
                        let mut cancel = cancel_rx.clone();
                        tokio::select! {
                            r = self.upload(id, token, archive) => r,
                            _ = async { let _ = cancel.wait_for(|c| *c).await; } => Err(anyhow!("Cancelled")),
                        }
                    }
                }
            }
            Err(e) => Err(e),
        };
        checkin.abort();
        stopper.abort();
        let _ = tokio::fs::remove_dir_all(&work).await;
        match outcome {
            Ok(summary) => {
                tracing::info!(build = id, %summary, "build succeeded");
                Ok(())
            }
            Err(e) => {
                let cancelled = *cancel_rx.borrow();
                // Stopped by us rather than by the registry: a failure, so it can be retried.
                let shut_down = cancelled && *shutdown.borrow();
                let message = if shut_down {
                    "The runner shut down during the build".to_string()
                } else if cancelled {
                    "Cancelled".to_string()
                } else {
                    crate::runner::sentence(&format!("{e:#}"))
                };
                log.line(&format!("==> {message}"));
                // The rest of the log first, then how it ended.
                if let Err(e) = shipper.lock().await.check_in(&log, &*server, true).await {
                    tracing::warn!(build = id, error = %format!("{e:#}"), "sending the end of the log");
                }
                let finish = Finish { status: if cancelled && !shut_down { "cancelled" } else { "failed" }.into(), message: message.clone(), line: None, log: None };
                if let Err(report) = self.call::<_, serde_json::Value>(&format!("/builds/{id}/finish"), token, &finish).await {
                    tracing::warn!(build = id, error = %format!("{report:#}"), "reporting the failure");
                }
                Err(anyhow!(message))
            }
        }
    }

    /// Send the archive. Gives up when the transfer stalls for [`UPLOAD_STALL`], or the
    /// registry takes longer than [`IMPORT_WAIT`] to answer once it has all of it.
    async fn upload(&self, id: i64, token: &str, archive: PathBuf) -> Result<String> {
        let file = tokio::fs::File::open(&archive).await.with_context(|| format!("opening {}", archive.display()))?;
        let len = file.metadata().await?.len();
        let start = Instant::now();
        // Milliseconds since `start` at the last chunk, and bytes handed over so far.
        let (last, sent) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let stream = {
            let (last, sent) = (last.clone(), sent.clone());
            tokio_util::io::ReaderStream::new(file).inspect(move |chunk| {
                if let Ok(c) = chunk {
                    sent.fetch_add(c.len() as u64, Ordering::Relaxed);
                }
                last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
            })
        };
        let send = self.http.put(self.url(&format!("/builds/{id}/image"))).bearer_auth(token).header("content-type", "application/x-tar").header("content-length", len).body(reqwest::Body::wrap_stream(stream)).send();
        let watchdog = async {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let idle = start.elapsed().saturating_sub(Duration::from_millis(last.load(Ordering::Relaxed)));
                let done = sent.load(Ordering::Relaxed) >= len;
                if idle > if done { IMPORT_WAIT } else { UPLOAD_STALL } {
                    return done;
                }
            }
        };
        let r = tokio::select! {
            r = send => r?,
            done = watchdog => if done {
                bail!("The registry didn't finish importing the image within {} minutes", IMPORT_WAIT.as_secs() / 60)
            } else {
                bail!("Uploading the image stalled: nothing was sent for {} seconds", UPLOAD_STALL.as_secs())
            },
        };
        Ok(decode::<ImageReply>(r).await?.summary)
    }
}

/// A build this runner claimed and hasn't seen end.
struct Active {
    token: WireSecret,
    since: Instant,
}

/// Sleep for `d`, or until `shutdown` turns true.
async fn pause(d: Duration, shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    tokio::select! {
        _ = tokio::time::sleep(d) => {}
        r = shutdown.changed() => {
            // Nobody left to say stop: just wait.
            if r.is_err() {
                tokio::time::sleep(d).await;
            }
        }
    }
}

/// Look after launched builds: keep them alive while they start, fail the ones whose
/// container or pod died before reporting, cancel the ones the registry stopped, and clean up,
/// including after builds this runner lost track of (it restarted while they ran).
async fn watch_launched(runner: Runner, launcher: Arc<dyn Launcher>, active: Arc<Mutex<HashMap<i64, Active>>>) {
    // Launched builds that aren't ours (any more), and when we first saw them.
    let mut orphans: HashMap<i64, Instant> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let launched = match launcher.launched().await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "checking launched builds");
                continue;
            }
        };
        let builds: Vec<(i64, WireSecret, Instant)> = active.lock().await.iter().map(|(id, a)| (*id, a.token.clone(), a.since)).collect();
        let ours: HashSet<i64> = builds.iter().map(|b| b.0).collect();
        orphans.retain(|id, _| launched.contains_key(id) && !ours.contains(id));
        for (id, state) in &launched {
            if ours.contains(id) {
                continue;
            }
            let seen = orphans.entry(*id).or_insert_with(Instant::now).elapsed();
            if orphan_expired(state, seen, launcher.keeps_finished()) {
                tracing::info!(build = id, "removing a build this runner no longer tracks");
                match launcher.remove(*id).await {
                    Ok(()) => {
                        orphans.remove(id);
                    }
                    Err(e) => tracing::warn!(build = id, error = %format!("{e:#}"), "cleaning up a left-over build"),
                }
            }
        }
        for (id, token, since) in builds {
            let token = token.expose();
            let done = match launched.get(&id) {
                Some(Launched::Running) => match runner.call::<_, CheckInReply>(&format!("/builds/{id}/heartbeat"), token, &()).await {
                    Ok(r) if r.stop => true, // over on the registry's side: cancelled, or failed
                    _ => false,
                },
                Some(Launched::Stopped(why)) => {
                    // The agent reports on every normal path; this only counts if it didn't.
                    runner.report_failure(id, token, why).await;
                    true
                }
                None if since.elapsed() > LAUNCH_GRACE => {
                    runner.report_failure(id, token, &format!("Its {} disappeared", launcher.name(id))).await;
                    true
                }
                None => false,
            };
            if done {
                active.lock().await.remove(&id);
                if !launcher.keeps_finished() || !matches!(launched.get(&id), Some(Launched::Stopped(_))) {
                    if let Err(e) = launcher.remove(id).await {
                        tracing::warn!(build = id, error = %format!("{e:#}"), "cleaning up after a build");
                    }
                }
            }
        }
    }
}

/// Whether a launched build nobody tracks, first seen `seen` ago, should go. Stopped ones go
/// after [`ORPHAN_GRACE`] (unless the platform cleans up finished ones itself); running ones
/// once no build could still be running that long. Their agent reports to the registry either
/// way: only the containers are left over.
fn orphan_expired(state: &Launched, seen: Duration, keeps_finished: bool) -> bool {
    match state {
        Launched::Stopped(_) => !keeps_finished && seen > ORPHAN_GRACE,
        Launched::Running => seen > MAX_BUILD + LAUNCH_GRACE,
    }
}

struct HttpServer {
    runner: Runner,
    id: i64,
    token: String,
}

#[async_trait]
impl steps::Server for HttpServer {
    async fn commit(&self, sha: &str) -> Result<Vec<String>> {
        Ok(self.runner.call::<_, CommitReply>(&format!("/builds/{}/commit", self.id), &self.token, &Commit { sha: sha.to_string() }).await?.tags)
    }
}

/// Where check-ins go: the registry, or a stand-in in tests.
#[async_trait]
trait CheckInSink: Send + Sync {
    async fn check_in(&self, c: &CheckIn) -> Result<CheckInReply>;
}

#[async_trait]
impl CheckInSink for HttpServer {
    async fn check_in(&self, c: &CheckIn) -> Result<CheckInReply> {
        self.runner.call(&format!("/builds/{}/log", self.id), &self.token, c).await
    }
}

/// Sends a build's log a piece at a time: each check-in carries what the log gained since the
/// length the registry last acknowledged (see `protocol::CheckIn`).
#[derive(Debug, Default)]
struct LogShipper {
    /// Bytes of the log the registry has.
    acked: u64,
    /// The registry truncated the log: only the tail is left to send, at the end.
    truncated: bool,
}

/// Check-ins in a row that one [`LogShipper::check_in`] may make to catch up.
const CATCH_UP: usize = 3;

impl LogShipper {
    /// Check in. `last`: the build is over, so send everything, including the tail of a log the
    /// registry truncated. When the registry's copy ends somewhere else than expected (a reply
    /// was lost after it stored a chunk; this runner restarted) it resends from there at once.
    async fn check_in(&mut self, log: &Log, to: &dyn CheckInSink, last: bool) -> Result<CheckInReply> {
        let mut reply = CheckInReply::default();
        for _ in 0..CATCH_UP {
            let c = self.next(log, last);
            let (sent_tail, end) = (c.tail, c.offset + c.data.len() as u64);
            reply = to.check_in(&c).await?;
            self.acked = reply.length;
            self.truncated |= reply.truncated;
            // Truncated, only the tail can still be sent.
            log.forget_before(if self.truncated { log.len() } else { self.acked }, LOG_TAIL_BYTES);
            if reply.stop {
                break;
            }
            let resync = !self.truncated && reply.length != end && log.since(reply.length).is_some_and(|s| !s.is_empty());
            let tail_due = last && self.truncated && !sent_tail;
            if !resync && !tail_due {
                break;
            }
        }
        Ok(reply)
    }

    fn next(&self, log: &Log, last: bool) -> CheckIn {
        let since = || log.since(self.acked).unwrap_or_default();
        match (self.truncated, last) {
            (false, _) => CheckIn { offset: self.acked, data: since(), ..Default::default() },
            // Truncated: nothing but the heartbeat until the end.
            (true, false) => CheckIn { offset: self.acked, ..Default::default() },
            (true, true) => match log.tail(LOG_TAIL_BYTES) {
                (from, data) if from >= self.acked => CheckIn { offset: from, data, tail: true, log: None },
                _ => CheckIn { offset: self.acked, data: since(), tail: true, log: None },
            },
        }
    }
}

fn hostname() -> Option<String> {
    std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()).or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|h| h.trim().to_string()).filter(|h| !h.is_empty()))
}

/// The body as `R`, or the registry's error message.
async fn decode<R: DeserializeOwned>(r: reqwest::Response) -> Result<R> {
    let status = r.status();
    let body = r.bytes().await?;
    if !status.is_success() {
        // Registry errors look like {"errors":[{"message":...}]}.
        let msg = serde_json::from_slice::<serde_json::Value>(&body).ok().and_then(|v| v["errors"][0]["message"].as_str().map(str::to_string)).unwrap_or_else(|| String::from_utf8_lossy(&body).chars().take(300).collect());
        bail!("{status}: {msg}");
    }
    serde_json::from_slice(&body).with_context(|| format!("unexpected reply ({status})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn left_over_builds_expire() {
        let stopped = Launched::Stopped("exited".into());
        assert!(!orphan_expired(&stopped, Duration::from_secs(10), false));
        assert!(orphan_expired(&stopped, ORPHAN_GRACE + Duration::from_secs(1), false));
        // Kubernetes deletes finished Jobs itself (job_ttl).
        assert!(!orphan_expired(&stopped, ORPHAN_GRACE * 10, true));
        assert!(!orphan_expired(&Launched::Running, Duration::from_secs(3600), false));
        assert!(orphan_expired(&Launched::Running, MAX_BUILD + LAUNCH_GRACE + Duration::from_secs(1), true));
    }

    fn assert_send<T: Send>(_: &T) {}

    #[test]
    fn futures_can_be_spawned() {
        let runner = Runner::new(&RunnerConfig::default()).unwrap();
        let cfg = RunnerConfig::default();
        let (_tx, rx) = watch::channel(false);
        assert_send(&runner.serve_until(&cfg, rx.clone()));
        assert_send(&runner.run_one_until(1, "t", rx));
    }

    #[tokio::test]
    async fn pause_ends_on_shutdown() {
        let (tx, mut rx) = watch::channel(false);
        let t = Instant::now();
        let stop = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(true);
            tx
        });
        pause(Duration::from_secs(30), &mut rx).await;
        assert!(t.elapsed() < Duration::from_secs(5));
        let _tx = stop.await.unwrap();
        // Already stopping: no wait at all.
        pause(Duration::from_secs(30), &mut rx).await;
    }

    /// A stand-in registry keeping a log the way the real one does (append at the stored
    /// length, else say where it stands), that can lose replies and truncate.
    #[derive(Default)]
    struct FakeRegistry {
        state: std::sync::Mutex<FakeLog>,
    }

    #[derive(Default)]
    struct FakeLog {
        text: String,
        /// The runner's bytes accounted for.
        length: u64,
        /// Truncate past this many bytes (0: never).
        max: usize,
        truncated: bool,
        /// Store the next check-in but fail to answer it.
        lose_next_reply: bool,
        calls: Vec<(u64, usize, bool)>,
    }

    #[async_trait]
    impl CheckInSink for FakeRegistry {
        async fn check_in(&self, c: &CheckIn) -> Result<CheckInReply> {
            let mut s = self.state.lock().unwrap();
            s.calls.push((c.offset, c.data.len(), c.tail));
            if c.tail && s.truncated && c.offset >= s.length {
                let omitted = c.offset - s.length;
                s.text.push_str(&format!("==> log truncated: {omitted} bytes omitted\n{}", c.data));
                s.length = c.offset + c.data.len() as u64;
            } else if c.offset == s.length && !s.truncated {
                s.text.push_str(&c.data);
                s.length += c.data.len() as u64;
                if s.max > 0 && s.text.len() > s.max {
                    s.truncated = true;
                    let max = s.max;
                    s.text.truncate(max);
                    s.length = max as u64;
                }
            }
            if std::mem::take(&mut s.lose_next_reply) {
                bail!("connection reset");
            }
            Ok(CheckInReply { stop: false, length: s.length, truncated: s.truncated })
        }
    }

    #[tokio::test]
    async fn the_log_is_resent_from_where_the_registry_has_it() {
        let (log, registry, mut shipper) = (Log::default(), FakeRegistry::default(), LogShipper::default());
        log.line("one");
        shipper.check_in(&log, &registry, false).await.unwrap();
        assert_eq!(shipper.acked, 4);
        // Stored, but the reply never arrives: the runner still thinks 4.
        log.line("two");
        registry.state.lock().unwrap().lose_next_reply = true;
        assert!(shipper.check_in(&log, &registry, false).await.is_err());
        assert_eq!(shipper.acked, 4);
        // The next check-in starts at 4, hears 8, and sends the rest from 8 at once.
        log.line("three");
        let r = shipper.check_in(&log, &registry, false).await.unwrap();
        assert_eq!(r.length, 14);
        let s = registry.state.lock().unwrap();
        assert_eq!(s.text, "one\ntwo\nthree\n", "nothing twice, nothing lost");
        assert_eq!(s.calls[2..], [(4, 10, false), (8, 6, false)]);
        drop(s);
        // What the registry has is forgotten here.
        assert_eq!(log.text(), "one\ntwo\nthree\n", "short logs are kept whole (the tail)");
    }

    #[tokio::test]
    async fn a_truncated_log_sends_only_heartbeats_then_its_tail() {
        let (log, registry, mut shipper) = (Log::default(), FakeRegistry::default(), LogShipper::default());
        registry.state.lock().unwrap().max = 20;
        for i in 0..10 {
            log.line(&format!("line {i}")); // 7 bytes
        }
        let r = shipper.check_in(&log, &registry, false).await.unwrap();
        assert!(r.truncated && shipper.truncated);
        for i in 10..20_000 {
            log.line(&format!("line {i}"));
        }
        shipper.check_in(&log, &registry, false).await.unwrap();
        assert_eq!(registry.state.lock().unwrap().calls.last(), Some(&(20, 0, false)), "a heartbeat only");
        assert!(log.text().len() <= LOG_TAIL_BYTES + 16, "the runner keeps no more than the tail");
        log.line("==> done");
        shipper.check_in(&log, &registry, true).await.unwrap();
        let s = registry.state.lock().unwrap();
        let (offset, len, tail) = *s.calls.last().unwrap();
        assert!(tail && len <= LOG_TAIL_BYTES && offset + len as u64 == log.len());
        assert!(s.text.starts_with("line 0\nline 1\nline 2==> log truncated: "), "{}", &s.text[..60]);
        assert!(s.text.contains("==> log truncated: "));
        assert!(s.text.ends_with("line 19999\n==> done\n"));
    }
}
