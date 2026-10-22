//! Prometheus metrics, exposed at `/metrics` in the text exposition format.
//!
//! Hand-rolled to avoid a metrics framework: a handful of counters and one latency histogram.
//! Request labels use a coarse route class (`manifest`, `blob`, `blob_upload`, `api`, ...)
//! rather than paths, so cardinality stays bounded however many repositories exist.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

const BUCKETS: [f64; 12] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

#[derive(Default)]
struct Histogram {
    buckets: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
}

#[derive(Default)]
pub struct Metrics {
    /// (method, route, status class) -> count
    requests: Mutex<BTreeMap<(String, &'static str, &'static str), u64>>,
    /// (method, route) -> latency
    latency: Mutex<BTreeMap<(String, &'static str), Histogram>>,
    pub pushes: AtomicU64,
    pub pulls: AtomicU64,
    pub blob_bytes_in: AtomicU64,
    pub blob_bytes_out: AtomicU64,
    /// Webhook deliveries dropped because the delivery queue was full.
    pub webhooks_dropped: AtomicU64,
    /// Blob downloads redirected to presigned URLs, by location.
    redirects: Mutex<BTreeMap<String, u64>>,
    /// Scans not queued, by reason (`budget`, `queue_full`).
    scans_skipped: Mutex<BTreeMap<&'static str, u64>>,
    started: OnceLock<Instant>,
}

pub fn global() -> &'static Metrics {
    static M: OnceLock<Metrics> = OnceLock::new();
    let m = M.get_or_init(Metrics::default);
    m.started.get_or_init(Instant::now);
    m
}

impl Metrics {
    pub fn blob_redirect(&self, location: &str) {
        *self.redirects.lock().unwrap_or_else(|e| e.into_inner()).entry(location.to_string()).or_default() += 1;
    }

    pub fn scan_skipped(&self, reason: &'static str) {
        *self.scans_skipped.lock().unwrap_or_else(|e| e.into_inner()).entry(reason).or_default() += 1;
    }

    /// Scans this instance skipped since it started, by reason.
    pub fn scans_skipped(&self) -> BTreeMap<&'static str, u64> {
        self.scans_skipped.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started.get().map(|s| s.elapsed().as_secs()).unwrap_or(0)
    }
}

/// Coarse route class for labels.
pub fn route_class(path: &str) -> &'static str {
    if let Some(rest) = path.strip_prefix("/v2/") {
        return if rest.is_empty() {
            "v2_base"
        } else if rest == "_catalog" {
            "catalog"
        } else if rest.contains("/blobs/uploads") {
            "blob_upload"
        } else if rest.contains("/blobs/") {
            "blob"
        } else if rest.contains("/manifests/") {
            "manifest"
        } else if rest.ends_with("/tags/list") {
            "tags"
        } else if rest.contains("/referrers/") {
            "referrers"
        } else {
            "v2_other"
        };
    }
    match path {
        "/v2" => "v2_base",
        "/metrics" => "metrics",
        p if p.starts_with("/auth/") => "auth",
        p if p.starts_with("/api/") => "api",
        _ => "ui",
    }
}

fn status_class(s: StatusCode) -> &'static str {
    match s.as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

/// The method as a label: the standard ones, else `other`. Requests are counted before
/// authentication, so an arbitrary method token must not add a time series.
fn method_label(m: &axum::http::Method) -> &'static str {
    use axum::http::Method;
    match *m {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::CONNECT => "CONNECT",
        Method::TRACE => "TRACE",
        _ => "other",
    }
}

/// Middleware recording every request.
pub async fn track(req: Request, next: Next) -> Response {
    let method = method_label(req.method()).to_string();
    let route = route_class(req.uri().path());
    let content_length = |h: &HeaderMap| h.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let bytes_in = if route == "blob_upload" { content_length(req.headers()) } else { 0 };
    let start = Instant::now();
    let resp = next.run(req).await;
    let secs = start.elapsed().as_secs_f64();
    let m = global();
    let ok = resp.status().is_success();
    match (method.as_str(), route) {
        ("GET", "manifest") if ok => {
            m.pulls.fetch_add(1, Ordering::Relaxed);
        }
        ("PUT", "manifest") if ok => {
            m.pushes.fetch_add(1, Ordering::Relaxed);
        }
        ("GET", "blob") if ok => {
            m.blob_bytes_out.fetch_add(content_length(resp.headers()), Ordering::Relaxed);
        }
        (_, "blob_upload") if ok => {
            m.blob_bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        }
        _ => {}
    }
    *m.requests.lock().unwrap_or_else(|e| e.into_inner()).entry((method.clone(), route, status_class(resp.status()))).or_default() += 1;
    let mut lat = m.latency.lock().unwrap_or_else(|e| e.into_inner());
    let h = lat.entry((method, route)).or_default();
    for (i, b) in BUCKETS.iter().enumerate() {
        if secs <= *b {
            h.buckets[i] += 1;
        }
    }
    h.count += 1;
    h.sum += secs;
    drop(lat);
    resp
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render the exposition text. Storage gauges come from the cached usage report, if any.
/// `usage`: the cluster's storage report (one for all instances, see
/// [`AppState::shared_usage`]).
pub fn render(state: &AppState, usage: Option<&kontainer_store::usage::UsageReport>, counts: &[crate::database::placements::LocationCounts]) -> String {
    let m = global();
    let mut o = String::new();
    let counter = |o: &mut String, name: &str, help: &str, v: u64| {
        let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}");
    };
    let gauge = |o: &mut String, name: &str, help: &str, v: f64| {
        let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
    };
    let _ = writeln!(o, "# HELP kontainer_build_info Build information.\n# TYPE kontainer_build_info gauge\nkontainer_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"));
    gauge(&mut o, "kontainer_uptime_seconds", "Seconds since the process started.", m.started.get().map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0));

    let _ = writeln!(o, "# HELP kontainer_http_requests_total HTTP requests by method, route class and status class.\n# TYPE kontainer_http_requests_total counter");
    for ((method, route, status), v) in m.requests.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        let _ = writeln!(o, "kontainer_http_requests_total{{method=\"{method}\",route=\"{route}\",status=\"{status}\"}} {v}");
    }
    let _ = writeln!(o, "# HELP kontainer_http_request_duration_seconds Request latency by method and route class.\n# TYPE kontainer_http_request_duration_seconds histogram");
    for ((method, route), h) in m.latency.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        for (i, b) in BUCKETS.iter().enumerate() {
            let _ = writeln!(o, "kontainer_http_request_duration_seconds_bucket{{method=\"{method}\",route=\"{route}\",le=\"{b}\"}} {}", h.buckets[i]);
        }
        let _ = writeln!(o, "kontainer_http_request_duration_seconds_bucket{{method=\"{method}\",route=\"{route}\",le=\"+Inf\"}} {}", h.count);
        let _ = writeln!(o, "kontainer_http_request_duration_seconds_sum{{method=\"{method}\",route=\"{route}\"}} {}", h.sum);
        let _ = writeln!(o, "kontainer_http_request_duration_seconds_count{{method=\"{method}\",route=\"{route}\"}} {}", h.count);
    }
    counter(&mut o, "kontainer_pushes_total", "Manifests pushed.", m.pushes.load(Ordering::Relaxed));
    counter(&mut o, "kontainer_pulls_total", "Manifests pulled.", m.pulls.load(Ordering::Relaxed));
    counter(&mut o, "kontainer_blob_bytes_received_total", "Blob bytes received in uploads.", m.blob_bytes_in.load(Ordering::Relaxed));
    counter(&mut o, "kontainer_blob_bytes_served_total", "Blob bytes served to clients.", m.blob_bytes_out.load(Ordering::Relaxed));
    counter(&mut o, "kontainer_webhook_deliveries_dropped_total", "Webhook deliveries dropped because they could not be queued in the database.", m.webhooks_dropped.load(Ordering::Relaxed));
    let redirects = m.redirects.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if !redirects.is_empty() {
        let _ = writeln!(o, "# HELP kontainer_blob_redirects_total Blob downloads redirected to a presigned URL, by storage location.\n# TYPE kontainer_blob_redirects_total counter");
        for (loc, v) in &redirects {
            let _ = writeln!(o, "kontainer_blob_redirects_total{{location=\"{}\"}} {v}", esc(loc));
        }
    }
    if state.scans.is_some() {
        let skipped = m.scans_skipped();
        let _ = writeln!(o, "# HELP kontainer_scans_skipped_total Scans this instance did not queue, by reason (budget: scanner.max_auto_per_hour spent; queue_full: scanner.max_queue reached).\n# TYPE kontainer_scans_skipped_total counter");
        for reason in ["budget", "queue_full"] {
            let _ = writeln!(o, "kontainer_scans_skipped_total{{reason=\"{reason}\"}} {}", skipped.get(reason).copied().unwrap_or(0));
        }
    }
    let locations = state.storage.locations();
    if locations.len() > 1 {
        let stats: Vec<_> = locations.iter().map(|l| (esc(&l.name), state.storage.replication.stats(&l.name))).collect();
        let _ = writeln!(o, "# HELP kontainer_replication_copied_total Objects this instance copied to each storage location.\n# TYPE kontainer_replication_copied_total counter");
        for (n, s) in &stats {
            let _ = writeln!(o, "kontainer_replication_copied_total{{location=\"{n}\"}} {}", s.copied);
        }
        let _ = writeln!(o, "# HELP kontainer_replication_copied_bytes_total Bytes this instance copied to each storage location.\n# TYPE kontainer_replication_copied_bytes_total counter");
        for (n, s) in &stats {
            let _ = writeln!(o, "kontainer_replication_copied_bytes_total{{location=\"{n}\"}} {}", s.copied_bytes);
        }
        let _ = writeln!(o, "# HELP kontainer_replication_failures_total Failed copy attempts this instance made to each storage location.\n# TYPE kontainer_replication_failures_total counter");
        for (n, s) in &stats {
            let _ = writeln!(o, "kontainer_replication_failures_total{{location=\"{n}\"}} {}", s.failed);
        }
    }
    if !counts.is_empty() {
        let _ = writeln!(o, "# HELP kontainer_location_blobs Blobs recorded in each storage location.\n# TYPE kontainer_location_blobs gauge");
        for c in counts {
            let _ = writeln!(o, "kontainer_location_blobs{{location=\"{}\"}} {}", esc(&c.location), c.blobs);
        }
        let _ = writeln!(o, "# HELP kontainer_replication_pending Copies to each storage location waiting or in progress.\n# TYPE kontainer_replication_pending gauge");
        for c in counts {
            let _ = writeln!(o, "kontainer_replication_pending{{location=\"{}\"}} {}", esc(&c.location), c.pending);
        }
        let _ = writeln!(o, "# HELP kontainer_replication_failed Copies to each storage location given up on.\n# TYPE kontainer_replication_failed gauge");
        for c in counts {
            let _ = writeln!(o, "kontainer_replication_failed{{location=\"{}\"}} {}", esc(&c.location), c.failed);
        }
    }
    gauge(&mut o, "kontainer_search_documents", "Repositories in the search index.", state.search.len() as f64);
    if let Some(u) = usage {
        gauge(&mut o, "kontainer_storage_physical_bytes", "Bytes of every blob in storage.", u.physical_bytes as f64);
        gauge(&mut o, "kontainer_storage_logical_bytes", "Sum of every repository's referenced bytes (before deduplication).", u.logical_bytes as f64);
        gauge(&mut o, "kontainer_storage_reclaimable_bytes", "Bytes no manifest references (freed by the next garbage collection).", u.unreferenced_bytes as f64);
        gauge(&mut o, "kontainer_storage_blobs", "Blobs in storage.", u.blobs as f64);
        gauge(&mut o, "kontainer_repositories", "Repositories.", u.repositories.len() as f64);
        let _ = writeln!(o, "# HELP kontainer_namespace_bytes Distinct bytes referenced per namespace.\n# TYPE kontainer_namespace_bytes gauge");
        for n in &u.namespaces {
            let _ = writeln!(o, "kontainer_namespace_bytes{{namespace=\"{}\"}} {}", esc(&n.namespace), n.bytes);
        }
        let _ = writeln!(o, "# HELP kontainer_namespace_quota_bytes Quota per namespace.\n# TYPE kontainer_namespace_quota_bytes gauge");
        for n in u.namespaces.iter().filter(|n| n.quota.is_some()) {
            let _ = writeln!(o, "kontainer_namespace_quota_bytes{{namespace=\"{}\"}} {}", esc(&n.namespace), n.quota.unwrap_or(0));
        }
        let age = chrono::DateTime::parse_from_rfc3339(&u.computed_at).map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds()).unwrap_or(0);
        gauge(&mut o, "kontainer_storage_report_age_seconds", "Age of the storage figures above.", age as f64);
    }
    o
}

/// `GET /metrics`, behind `metrics.token`. Without a token configured nothing is served: the
/// output names every namespace and reveals the version.
pub async fn endpoint(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = state.config.metrics.token.as_ref().map(|t| t.expose()).filter(|t| !t.is_empty()) else {
        return (StatusCode::FORBIDDEN, "metrics are off until metrics.token is set\n").into_response();
    };
    let sent = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or_default();
    // Constant-time comparison, so response timing does not leak the token.
    let ok = sent.len() == token.len() && sent.bytes().zip(token.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !ok {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")], "metrics token required\n").into_response();
    }
    state.refresh_usage_in_background();
    // The report one instance computed for the whole cluster, as stored now.
    let usage = match state.shared_usage().await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "reading the storage report for /metrics");
            state.usage_cached()
        }
    };
    let counts = match state.auth.db.location_counts().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "reading storage location counts for /metrics");
            vec![]
        }
    };
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], render(&state, usage.as_deref(), &counts)).into_response()
}
