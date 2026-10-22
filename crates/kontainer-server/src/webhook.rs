//! Outgoing webhooks.
//!
//! Two kinds: namespace webhooks, which namespace admins manage in the UI (stored in the
//! database, with a delivery history), and `[[webhooks]]` from the config file (fire and
//! forget). An [`Event`] goes to every enabled hook whose events and repositories match, in the
//! hook's format: our JSON, CloudEvents 1.0 or a Slack message.
//!
//! Deliveries are queued in `webhook_deliveries` (which is also the history the UI shows), so
//! they survive restarts and any instance on the database may make them; see
//! [`crate::workqueue`].

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::Sha256;

use kontainer_core::config::WebhookConfig;
use kontainer_core::digest::Digest;
use kontainer_core::glob;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::database::webhooks::{Attempt, Delivery, QueuedDelivery, Webhook};
use crate::database::Db;
use crate::workqueue::{self, Options};
use crate::scan::ScanReport;
use kontainer_core::upstream::netguard;

/// Every event a namespace webhook can subscribe to.
pub const EVENTS: &[&str] = &["push", "pull", "delete", "scan", "quota_exceeded", "quota_warning", "retention", "mirror_sync", "build", "replication"];
/// What config-file webhooks with no `events` get: what they always got.
const CONFIG_DEFAULT_EVENTS: &[&str] = &["push", "delete", "scan"];
pub const FORMATS: &[&str] = &["default", "cloudevents", "slack"];
/// Attempts per queued delivery; after a failure the next waits 2, then 4 seconds.
const ATTEMPTS: u32 = 3;
/// Deliveries in progress at once, per instance.
const WORKERS: usize = 8;

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub timestamp: String,
    /// The repository, or for namespace-wide events (retention, ping) the namespace.
    pub repository: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<ScanSummary>,
    /// Event-specific details (quota numbers, deleted tags, build outcome...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub status: crate::scan::ScanStatus,
    pub scanner: String,
    pub total: usize,
    pub summary: std::collections::BTreeMap<kontainer_core::config::Severity, usize>,
}

impl Event {
    fn base(kind: &'static str, repository: &str) -> Self {
        Self { kind, timestamp: chrono::Utc::now().to_rfc3339(), repository: repository.to_string(), tag: None, digest: None, media_type: None, actor: None, scan: None, details: None }
    }
    pub fn push(repository: &str, tag: Option<&str>, digest: &Digest, media_type: &str, actor: &str) -> Self {
        Self { tag: tag.map(str::to_string), digest: Some(digest.to_string()), media_type: Some(media_type.to_string()), actor: Some(actor.to_string()), ..Self::base("push", repository) }
    }
    pub fn pull(repository: &str, reference: &str, digest: &Digest, actor: &str) -> Self {
        let tag = (!reference.contains(':')).then(|| reference.to_string());
        Self { tag, digest: Some(digest.to_string()), actor: Some(actor.to_string()), ..Self::base("pull", repository) }
    }
    pub fn delete(repository: &str, tag: Option<&str>, digest: &Digest, actor: &str) -> Self {
        Self { tag: tag.map(str::to_string), digest: Some(digest.to_string()), actor: Some(actor.to_string()), ..Self::base("delete", repository) }
    }
    pub fn scan(repository: &str, digest: &Digest, report: &ScanReport) -> Self {
        Self {
            digest: Some(digest.to_string()),
            scan: Some(ScanSummary { status: report.status.clone(), scanner: report.scanner.clone(), total: report.total, summary: report.summary.clone() }),
            ..Self::base("scan", repository)
        }
    }
    /// A push refused (`exceeded`) or let through above 90% of the quota.
    pub fn quota(exceeded: bool, repository: &str, used: u64, quota: u64, adds: u64, actor: &str) -> Self {
        Self {
            actor: Some(actor.to_string()),
            details: Some(json!({ "used_bytes": used, "quota_bytes": quota, "push_bytes": adds })),
            ..Self::base(if exceeded { "quota_exceeded" } else { "quota_warning" }, repository)
        }
    }
    /// Retention policies deleted these `repository:tag`s in `namespace`.
    pub fn retention(namespace: &str, deleted: &[String]) -> Self {
        Self { actor: Some("retention".into()), details: Some(json!({ "deleted": deleted })), ..Self::base("retention", namespace) }
    }
    pub fn mirror_sync(repository: &str, ok: bool, message: &str) -> Self {
        Self { actor: Some("mirror".into()), details: Some(json!({ "ok": ok, "message": message })), ..Self::base("mirror_sync", repository) }
    }
    pub fn build(repository: &str, id: i64, status: &str, message: &str, tags: &[String], digest: Option<&str>) -> Self {
        Self {
            digest: digest.map(str::to_string),
            actor: Some(format!("build #{id}")),
            details: Some(json!({ "build": id, "status": status, "message": message, "tags": tags })),
            ..Self::base("build", repository)
        }
    }
    pub fn replication(repository: &str, target: &str, ok: bool, message: &str) -> Self {
        Self { actor: Some("replication".into()), details: Some(json!({ "target": target, "ok": ok, "message": message })), ..Self::base("replication", repository) }
    }
    /// A test delivery from the UI.
    pub fn ping(namespace: &str, actor: &str) -> Self {
        Self { actor: Some(actor.to_string()), details: Some(json!({ "message": "Test delivery from Kontainer" })), ..Self::base("ping", namespace) }
    }

    fn namespace(&self) -> &str {
        kontainer_core::names::namespace(&self.repository)
    }

    /// One line for chat.
    fn summary(&self) -> String {
        let what = match (&self.tag, &self.digest) {
            (Some(t), _) => format!("`{}:{t}`", self.repository),
            (None, Some(d)) => format!("`{}@{}`", self.repository, &d[..d.len().min(19)]),
            _ => format!("`{}`", self.repository),
        };
        let by = self.actor.as_deref().map(|a| format!(" by {a}")).unwrap_or_default();
        let d = self.details.as_ref();
        match self.kind {
            "push" => format!(":package: Pushed {what}{by}"),
            "pull" => format!(":inbox_tray: Pulled {what}{by}"),
            "delete" => format!(":wastebasket: Deleted {what}{by}"),
            "scan" => match &self.scan {
                Some(s) => format!(":mag: Scanned {what}: {} vulnerabilities ({:?})", s.total, s.status),
                None => format!(":mag: Scanned {what}"),
            },
            "quota_exceeded" => format!(":no_entry: Push to {what} refused: storage quota exceeded"),
            "quota_warning" => format!(":warning: {what} is above 90% of its storage quota"),
            "retention" => format!(":scissors: Retention deleted {} tags in {what}", d.and_then(|d| d["deleted"].as_array()).map_or(0, Vec::len)),
            "mirror_sync" => format!(":arrows_counterclockwise: Mirror sync of {what}: {}", d.and_then(|d| d["message"].as_str()).unwrap_or_default()),
            "build" => format!(":hammer: Build of {what} {}: {}", d.and_then(|d| d["status"].as_str()).unwrap_or_default(), d.and_then(|d| d["message"].as_str()).unwrap_or_default()),
            "replication" => format!(":satellite: Replication of {what}: {}", d.and_then(|d| d["message"].as_str()).unwrap_or_default()),
            "ping" => format!(":wave: Test delivery for {what}{by}"),
            other => format!("{other} {what}"),
        }
    }
}

#[derive(Clone)]
pub struct Webhooks {
    config: Arc<Vec<WebhookConfig>>,
    db: Db,
    hooks: Arc<RwLock<Vec<Webhook>>>,
    /// For config-file hooks: set by the operator, so internal targets are fine.
    config_client: reqwest::Client,
    /// For namespace hooks; unless private targets are allowed, its resolver refuses internal
    /// addresses, so the address it connects to is the one that was checked.
    client: reqwest::Client,
    /// For namespace hooks with TLS verification off.
    insecure: reqwest::Client,
    allow_private: bool,
    public_url: String,
    /// Who this instance's claims on the delivery queue are by.
    holder: Arc<str>,
    /// Kicked by local enqueues so the dispatcher looks at once.
    wake: Arc<Notify>,
    stop: CancellationToken,
    /// The wait after the first failed attempt, doubling after each.
    backoff: Duration,
}

/// What the guard's errors point at.
const PRIVATE_HINT: &str = "policy.webhooks_allow_private_targets";

/// The delivery queue's defaults.
pub const QUEUE_OPTIONS: Options = Options { workers: WORKERS, poll: Duration::from_secs(2), lease: Duration::from_secs(120) };

impl Webhooks {
    pub async fn new(config: Vec<WebhookConfig>, db: Db, allow_private: bool, public_url: &str) -> Result<Self> {
        Self::with_options(config, db, allow_private, public_url, QUEUE_OPTIONS, Duration::from_secs(2)).await
    }

    /// `opts.workers == 0` queues deliveries without delivering any (another instance does).
    pub async fn with_options(config: Vec<WebhookConfig>, db: Db, allow_private: bool, public_url: &str, opts: Options, backoff: Duration) -> Result<Self> {
        // No redirects: a redirect could send a delivery somewhere the target check never saw.
        let build = |verify: bool, guarded: bool| {
            let mut b = reqwest::Client::builder()
                .user_agent(kontainer_core::USER_AGENT)
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .tls_danger_accept_invalid_certs(!verify);
            if guarded {
                b = b.dns_resolver(netguard::PublicOnly { hint: PRIVATE_HINT });
            }
            b.build()
        };
        let guarded = !allow_private;
        let w = Self {
            config: Arc::new(config),
            db,
            hooks: Arc::default(),
            config_client: build(true, false)?,
            client: build(true, guarded)?,
            insecure: build(false, guarded)?,
            allow_private,
            public_url: public_url.trim_end_matches('/').to_string(),
            holder: workqueue::holder("webhook").into(),
            wake: Arc::new(Notify::new()),
            stop: CancellationToken::new(),
            backoff,
        };
        w.reload().await?;
        // A fixed number of deliveries at a time: a burst of events (a big push, every pull)
        // cannot turn into unbounded tasks and connections.
        if opts.workers > 0 {
            let claim = { let w = w.clone(); move || { let w = w.clone(); async move { w.db.claim_delivery(&w.holder, opts.lease).await } } };
            let run = { let w = w.clone(); move |job| { let w = w.clone(); async move { w.run(job).await } } };
            workqueue::spawn("webhook", opts, w.wake.clone(), w.stop.clone(), claim, run);
        }
        // Hooks changed through another instance show up here within this.
        let this = w.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = this.stop.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                }
                if let Err(e) = this.reload().await {
                    tracing::warn!(error = %format!("{e:#}"), "reloading webhooks");
                }
            }
        });
        Ok(w)
    }

    /// Stop delivering from this instance (queued deliveries stay queued for the next one).
    pub fn stop(&self) {
        self.stop.cancel();
    }

    /// Queue deliveries: in the database, so they survive a restart and any instance may make
    /// them. `fire` is synchronous, so this runs in the background.
    fn enqueue(&self, rows: Vec<(Result<i64, String>, &'static str, String, &'static str)>) {
        if rows.is_empty() {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            for (target, kind, body, content_type) in rows {
                if let Err(e) = this.db.insert_delivery(target.as_ref().map(|id| *id).map_err(String::as_str), kind, &body, content_type, ATTEMPTS, None).await {
                    crate::metrics::global().webhooks_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(event = kind, error = %format!("{e:#}"), "could not queue a webhook delivery; dropping it");
                }
            }
            this.wake.notify_one();
        });
    }

    /// Make the next attempt of a claimed delivery, and record it.
    async fn run(&self, job: QueuedDelivery) {
        if job.attempts >= i64::from(job.max_attempts) {
            // Its last attempt was cut short (the instance making it died).
            let _ = self.db.abandon_delivery(job.id, &self.holder, "the last attempt was interrupted").await;
            return;
        }
        let attempt = match (job.webhook_id, &job.config_hook) {
            (Some(id), _) => match self.db.webhook(id).await {
                Ok(Some(hook)) => {
                    let content_type = job.content_type.as_deref().unwrap_or_else(|| content_type(&hook));
                    self.attempt(&hook, job.id, &job.event, &job.payload, content_type).await
                }
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(hook = id, error = %e, "loading a webhook to deliver to");
                    return;
                }
            },
            (None, Some(name)) => match self.config.iter().find(|h| &h.name == name) {
                Some(hook) => self.attempt_config(hook, &job.payload).await,
                None => {
                    let _ = self.db.abandon_delivery(job.id, &self.holder, "no such hook in this instance's [[webhooks]]").await;
                    return;
                }
            },
            (None, None) => return,
        };
        let n = u32::try_from(job.attempts).unwrap_or(u32::MAX).saturating_add(1);
        match self.db.record_attempt(job.id, &self.holder, &attempt, workqueue::backoff(self.backoff, n)).await {
            Ok(Some(status)) if status != "succeeded" => tracing::warn!(delivery = job.id, attempt = n, status, error = attempt.error.as_deref().unwrap_or_default(), "webhook delivery failed"),
            Ok(_) => {}
            Err(e) => tracing::warn!(delivery = job.id, error = %format!("{e:#}"), "recording a webhook delivery"),
        }
    }

    /// Re-read namespace webhooks after a change.
    pub async fn reload(&self) -> Result<()> {
        let all = self.db.all_webhooks().await?;
        *self.hooks.write().unwrap_or_else(|e| e.into_inner()) = all;
        Ok(())
    }

    /// Whether anything listens for `kind` (pulls are frequent: skip building events for nobody).
    pub fn wants(&self, kind: &str) -> bool {
        self.config.iter().any(|h| if h.events.is_empty() { CONFIG_DEFAULT_EVENTS.contains(&kind) } else { h.events.iter().any(|e| e == kind) })
            || self.hooks.read().unwrap_or_else(|e| e.into_inner()).iter().any(|h| h.is_enabled && subscribes(h, kind))
    }

    pub fn fire(&self, event: Event) {
        let mut rows = vec![];
        for hook in self.config.iter() {
            let wanted = if hook.events.is_empty() { CONFIG_DEFAULT_EVENTS.contains(&event.kind) } else { hook.events.iter().any(|e| e == event.kind) };
            if !wanted || (!hook.repositories.is_empty() && !glob::any_matches(&hook.repositories, &event.repository)) {
                continue;
            }
            rows.push((Err(hook.name.clone()), event.kind, serde_json::to_string(&event).unwrap_or_default(), "application/json"));
        }
        let matching: Vec<Webhook> = self.hooks.read().unwrap_or_else(|e| e.into_inner()).iter().filter(|h| h.is_enabled && matches(h, &event)).cloned().collect();
        for hook in matching {
            let (content_type, body) = self.render(&hook, &event);
            rows.push((Ok(hook.id), event.kind, body, content_type));
        }
        self.enqueue(rows);
    }

    /// Send a test event to `hook` now, with one attempt, and return the delivery.
    pub async fn test(&self, hook: &Webhook, actor: &str) -> Result<Delivery> {
        let event = Event::ping(&hook.namespace, actor);
        let (content_type, body) = self.render(hook, &event);
        let id = self.deliver_now(hook, event.kind, &body, content_type).await?;
        self.db.delivery(id).await?.context("delivery vanished")
    }

    /// Send a past delivery's payload again, as a new delivery.
    pub async fn redeliver(&self, hook: &Webhook, past: &Delivery) -> Result<Delivery> {
        let id = self.deliver_now(hook, &past.event, &past.payload, content_type(hook)).await?;
        self.db.delivery(id).await?.context("delivery vanished")
    }

    /// The body to send `event` as, for `hook`'s format, and its content type.
    fn render(&self, hook: &Webhook, event: &Event) -> (&'static str, String) {
        match hook.format.as_str() {
            "cloudevents" => {
                let subject = event.tag.clone().or_else(|| event.digest.clone());
                let ce = json!({
                    "specversion": "1.0",
                    "id": uuid::Uuid::new_v4().to_string(),
                    "source": format!("{}/{}", self.public_url, event.repository),
                    "type": format!("dev.kontainer.{}", event.kind),
                    "subject": subject,
                    "time": event.timestamp,
                    "datacontenttype": "application/json",
                    "data": event,
                });
                ("application/cloudevents+json", ce.to_string())
            }
            "slack" => ("application/json", json!({ "text": event.summary() }).to_string()),
            _ => ("application/json", serde_json::to_string(event).unwrap_or_default()),
        }
    }

    /// Deliver `body` to `hook` once, right now (the UI waits for the outcome), recording it in
    /// the history like queued deliveries. Returns the delivery id.
    async fn deliver_now(&self, hook: &Webhook, kind: &str, body: &str, content_type: &str) -> Result<i64> {
        // Claimed by us from the start, so no worker picks it up meanwhile.
        let id = self.db.insert_delivery(Ok(hook.id), kind, body, content_type, 1, Some(&self.holder)).await?;
        let attempt = self.attempt(hook, id, kind, body, content_type).await;
        self.db.record_attempt(id, &self.holder, &attempt, Duration::ZERO).await?;
        Ok(id)
    }

    /// One attempt at delivering `body` to namespace hook `hook` as delivery `id`.
    async fn attempt(&self, hook: &Webhook, id: i64, kind: &str, body: &str, content_type: &str) -> Attempt {
        let started = Instant::now();
        let result = async {
            if !self.allow_private {
                check_target(&hook.url).await?;
            }
            let client = if hook.is_verify_tls { &self.client } else { &self.insecure };
            let mut req = client.post(&hook.url).header("content-type", content_type).header("x-kontainer-event", kind).header("x-kontainer-delivery", id.to_string()).body(body.to_string());
            if let Some(secret) = &hook.secret {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
                mac.update(body.as_bytes());
                req = req.header("x-kontainer-signature", format!("sha256={}", hex::encode(mac.finalize().into_bytes())));
            }
            if let Some(auth) = &hook.auth_header {
                req = req.header("authorization", auth);
            }
            let r = req.send().await?;
            let status = r.status();
            Ok::<_, anyhow::Error>((status, response_excerpt(r).await))
        }
        .await;
        outcome(started, result)
    }

    /// One attempt at delivering `body` to config-file hook `hook`.
    async fn attempt_config(&self, hook: &WebhookConfig, body: &str) -> Attempt {
        let started = Instant::now();
        let mut req = self.config_client.post(&hook.url).header("content-type", "application/json").body(body.to_string());
        for (k, v) in &hook.headers {
            req = req.header(k, v.expose());
        }
        let result = async {
            let r = req.send().await?;
            let status = r.status();
            Ok::<_, anyhow::Error>((status, response_excerpt(r).await))
        }
        .await;
        outcome(started, result)
    }
}

fn content_type(hook: &Webhook) -> &'static str {
    match hook.format.as_str() {
        "cloudevents" => "application/cloudevents+json",
        _ => "application/json",
    }
}

fn outcome(started: Instant, result: Result<(reqwest::StatusCode, String)>) -> Attempt {
    let duration_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok((status, text)) => {
            let ok = status.is_success();
            Attempt { ok, response_code: Some(status.as_u16()), response_body: Some(text), error: (!ok).then(|| "the endpoint did not answer 2xx".into()), duration_ms }
        }
        Err(e) => Attempt { ok: false, response_code: None, response_body: None, error: Some(format!("{e:#}")), duration_ms },
    }
}

/// The first 1024 characters of a response body, for the delivery history. Reading stops once
/// enough bytes have arrived, so an endpoint cannot make us buffer a huge (or endless) body.
async fn response_excerpt(r: reqwest::Response) -> String {
    use futures::StreamExt;
    // 4 bytes per character at most.
    const MAX_BYTES: usize = 4 * 1024;
    let mut buf = Vec::new();
    let mut stream = r.bytes_stream();
    while let Some(Ok(chunk)) = stream.next().await {
        buf.extend_from_slice(&chunk[..chunk.len().min(MAX_BYTES - buf.len())]);
        if buf.len() >= MAX_BYTES {
            break;
        }
    }
    String::from_utf8_lossy(&buf).chars().take(1024).collect()
}

fn subscribes(h: &Webhook, kind: &str) -> bool {
    let events = h.event_list();
    events.is_empty() || events.iter().any(|e| e == kind)
}

/// Does `hook` want `event`? Repository filters are relative to the namespace and only apply
/// to events about one repository.
fn matches(hook: &Webhook, event: &Event) -> bool {
    if hook.namespace != event.namespace() || !subscribes(hook, event.kind) {
        return false;
    }
    let repos = hook.repository_list();
    let relative = event.repository.strip_prefix(&format!("{}/", hook.namespace));
    repos.is_empty() || relative.is_none_or(|r| glob::any_matches(&repos, r))
}

/// Refuse to deliver to this machine, private networks or cloud metadata endpoints, so a
/// namespace admin cannot use webhooks to reach what only the registry can.
pub async fn check_target(raw: &str) -> Result<()> {
    netguard::check_target(raw, PRIVATE_HINT).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook(events: &[&str], repos: &[&str]) -> Webhook {
        Webhook {
            id: 1, namespace: "acme".into(), name: "h".into(), url: "https://x".into(), format: "default".into(),
            events: serde_json::to_string(events).unwrap(), repositories: serde_json::to_string(repos).unwrap(),
            secret: None, auth_header: None, is_verify_tls: true, is_enabled: true, created_by: "a".into(), created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn matching() {
        let d: Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap();
        let push = Event::push("acme/api", Some("v1"), &d, "x", "alice");
        assert!(matches(&hook(&[], &[]), &push));
        assert!(matches(&hook(&["push"], &["api", "web/*"]), &push));
        assert!(!matches(&hook(&["delete"], &[]), &push));
        assert!(!matches(&hook(&[], &["web/*"]), &push));
        assert!(!matches(&hook(&[], &[]), &Event::push("other/api", None, &d, "x", "a")));
        // Namespace-wide events ignore repository filters.
        assert!(matches(&hook(&[], &["web/*"]), &Event::retention("acme", &[])));
    }

    /// Queued deliveries outlive the instance that queued them: one never claimed, one whose
    /// worker died mid-attempt, and one whose first attempt fails, all arrive through a new
    /// instance on the same database.
    #[tokio::test]
    async fn deliveries_survive_a_restart() {
        use std::sync::Mutex;
        let got: Arc<Mutex<Vec<String>>> = Arc::default();
        let flaky_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let receiver = {
            let (rec, flaky) = (got.clone(), flaky_calls.clone());
            axum::Router::new().route("/{name}", axum::routing::post(move |axum::extract::Path(name): axum::extract::Path<String>| {
                let (rec, flaky) = (rec.clone(), flaky.clone());
                async move {
                    if name == "flaky" && flaky.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
                    }
                    rec.lock().unwrap().push(name);
                    axum::http::StatusCode::OK
                }
            }))
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, receiver).await.unwrap() });

        let url = crate::database::test_support::fresh_database_url();
        let db = Db::open(&url, 4).await.unwrap();
        for name in ["hook", "flaky"] {
            let input: crate::database::webhooks::WebhookInput = serde_json::from_value(json!({ "name": name, "url": format!("{base}/{name}") })).unwrap();
            db.create_webhook("acme", &input, "alice").await.unwrap();
        }
        let config = vec![WebhookConfig { name: "ops".into(), url: format!("{base}/ops"), events: vec![], repositories: vec![], headers: Default::default() }];

        // The first instance queues, but delivers nothing (no workers), then goes away.
        let idle = Options { workers: 0, ..QUEUE_OPTIONS };
        let a = Webhooks::with_options(config.clone(), db.clone(), true, "http://registry", idle, Duration::from_millis(20)).await.unwrap();
        let d: Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap();
        a.fire(Event::push("acme/app", Some("v1"), &d, "x", "alice"));
        let pending = || async { sqlx::query_scalar::<_, i64>("SELECT count(*) FROM webhook_deliveries WHERE status = 'pending'").fetch_one(db.pool()).await.unwrap() };
        for _ in 0..100 {
            if pending().await == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(pending().await, 3, "one delivery per hook, queued in the database");
        // A worker that dies holding one.
        let dead = db.claim_delivery("dead", QUEUE_OPTIONS.lease).await.unwrap().expect("claimable");
        a.stop();
        drop(a);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(got.lock().unwrap().is_empty());

        // "Restart": a new instance on the same database delivers all three.
        let opts = Options { workers: 8, poll: Duration::from_millis(50), lease: Duration::from_millis(300) };
        let b = Webhooks::with_options(config, Db::open(&url, 4).await.unwrap(), true, "http://registry", opts, Duration::from_millis(20)).await.unwrap();
        for _ in 0..200 {
            if got.lock().unwrap().len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut names = got.lock().unwrap().clone();
        names.sort();
        assert_eq!(names, ["flaky", "hook", "ops"]);
        // The receiver sees a delivery just before its outcome is recorded.
        for _ in 0..100 {
            if pending().await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let rows: Vec<(i64, String, i64)> = sqlx::query_as("SELECT id, status, attempts FROM webhook_deliveries ORDER BY id").fetch_all(db.pool()).await.unwrap();
        assert!(rows.iter().all(|r| r.1 == "succeeded"), "{rows:?}");
        assert_eq!(rows.iter().find(|r| r.0 == dead.id).unwrap().2, 2, "the interrupted attempt counts");
        assert_eq!(flaky_calls.load(std::sync::atomic::Ordering::SeqCst), 2, "a failed attempt is retried");
        b.stop();
    }
}
