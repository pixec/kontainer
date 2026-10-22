//! What the database-backed work queues (scans, webhook deliveries) share: each instance runs a
//! dispatcher that claims due rows (`FOR UPDATE SKIP LOCKED`, so instances never take the same
//! one) while it has a free worker slot. It looks for work every [`Options::poll`], and at once
//! when a local enqueue kicks its [`Notify`], so work queued on this instance starts right away
//! and work queued elsewhere within a poll interval.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Jobs in progress at once on this instance.
    pub workers: usize,
    /// How often an idle dispatcher looks for work queued by other instances (or come due).
    pub poll: Duration,
    /// A claim not refreshed for this long belongs to a worker that died; it is claimed again.
    pub lease: Duration,
}

/// Who holds claims made by this queue: host, process and a random part, so two queues in one
/// process (tests) or a restarted process never pass for each other.
pub fn holder(kind: &str) -> String {
    let host = std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| "kontainer".into());
    format!("{host}/{}/{kind}/{}", std::process::id(), kontainer_core::random_token(4))
}

/// Start a dispatcher: `claim` takes the next due job (or `None`), `process` runs it to the end
/// (recording the outcome itself). Each job runs in its own task, so one that panics loses only
/// itself; its claim then lapses after the lease and the job is retried. Stops at `stop`,
/// abandoning jobs in progress like a crash would.
pub fn spawn<J, C, CF, P, PF>(name: &'static str, opts: Options, wake: Arc<Notify>, stop: CancellationToken, claim: C, process: P)
where
    J: Send + 'static,
    C: Fn() -> CF + Send + 'static,
    CF: Future<Output = anyhow::Result<Option<J>>> + Send,
    P: Fn(J) -> PF + Send + Sync + 'static,
    PF: Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(opts.workers.max(1)));
    let process = Arc::new(process);
    tokio::spawn(async move {
        loop {
            let slot = tokio::select! {
                _ = stop.cancelled() => return,
                s = slots.clone().acquire_owned() => match s { Ok(s) => s, Err(_) => return },
            };
            let next = tokio::select! {
                _ = stop.cancelled() => return,
                n = claim() => n,
            };
            match next {
                Ok(Some(job)) => {
                    let (process, stop) = (process.clone(), stop.clone());
                    tokio::spawn(async move {
                        let run = tokio::spawn(async move {
                            tokio::select! {
                                _ = stop.cancelled() => {}
                                _ = process(job) => {}
                            }
                        });
                        if let Err(e) = run.await {
                            tracing::error!(queue = name, error = %e, "a queued job crashed; it will be retried");
                        }
                        drop(slot);
                    });
                }
                Ok(None) => {
                    drop(slot);
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = wake.notified() => {}
                        _ = tokio::time::sleep(opts.poll) => {}
                    }
                }
                Err(e) => {
                    drop(slot);
                    tracing::warn!(queue = name, error = %format!("{e:#}"), "claiming queued work");
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = tokio::time::sleep(opts.poll) => {}
                    }
                }
            }
        }
    });
}

/// `base * 2^(attempt - 1)`: the wait after failed attempt `attempt` (1-based).
pub fn backoff(base: Duration, attempt: u32) -> Duration {
    base.saturating_mul(1u32 << attempt.saturating_sub(1).min(16))
}
