//! Health: liveness/readiness probes for orchestrators, and a detailed report for admins.

use std::time::Instant;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use kontainer_core::perm::Global;
use crate::auth::Principal;
use crate::error::Result;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/livez", get(livez)).route("/readyz", get(readyz)).route("/api/v1/health", get(report)).route("/api/v1/about", get(super::about::about))
}

/// The process is up.
async fn livez() -> &'static str {
    "ok\n"
}

/// Ready to serve: the database answers and storage can be listed.
async fn readyz(State(state): State<AppState>) -> Response {
    if let Err(e) = state.auth.db.ping().await {
        return (StatusCode::SERVICE_UNAVAILABLE, format!("database: {e:#}\n")).into_response();
    }
    if let Err(e) = state.storage.reachable().await {
        return (StatusCode::SERVICE_UNAVAILABLE, format!("storage: {e:#}\n")).into_response();
    }
    if state.config.server.is_ready_requires_all_locations {
        let here = &state.storage.preferred().name;
        for l in state.storage.locations().iter().filter(|l| &l.name != here) {
            if let Err(e) = state.storage.probe_location(&l.name).await {
                return (StatusCode::SERVICE_UNAVAILABLE, format!("storage location {}: {e:#}\n", l.name)).into_response();
            }
        }
    }
    (StatusCode::OK, "ok\n").into_response()
}

#[derive(Serialize)]
struct Check {
    name: String,
    group: &'static str,
    /// `ok`, `warn` or `error`.
    status: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<u64>,
}

fn check(name: impl Into<String>, group: &'static str, result: std::result::Result<String, String>, started: Option<Instant>) -> Check {
    let latency_ms = started.map(|s| s.elapsed().as_millis() as u64);
    match result {
        Ok(message) => Check { name: name.into(), group, status: "ok", message, latency_ms },
        Err(message) => Check { name: name.into(), group, status: "error", message, latency_ms },
    }
}

/// Detailed health for instance administrators.
async fn report(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    if !(p.has_global(Global::UsersRead) || p.has_global(Global::Gc)) {
        return Err(state.auth.denied(&p, None));
    }
    let mut checks = vec![];

    let t = Instant::now();
    checks.push(check("Database", "core", state.auth.db.ping().await.map(|_| "PostgreSQL answers queries".into()).map_err(|e| format!("{e:#}")), Some(t)));
    let t = Instant::now();
    let here = state.storage.preferred();
    let driver = format!("{:?}", here.driver).to_lowercase();
    checks.push(check("Storage", "core", state.storage.probe().await.map(|_| format!("{} ({driver}): write, read and delete succeeded", here.name)).map_err(|e| format!("{} ({driver}): {e:#}", here.name)), Some(t)));

    // The other locations, with what is still to be copied to each.
    let counts = state.auth.db.location_counts().await.unwrap_or_default();
    for l in state.storage.locations().iter().filter(|l| l.name != here.name) {
        let t = Instant::now();
        let mut c = check(format!("Location {}", l.name), "locations", state.storage.probe_location(&l.name).await.map(|_| "write, read and delete succeeded".into()).map_err(|e| format!("{e:#}")), Some(t));
        if c.status == "ok" {
            if let Some(n) = counts.iter().find(|n| n.location == l.name) {
                if n.failed > 0 {
                    c.status = "warn";
                    c.message = format!("{} copies failed: {}", n.failed, n.last_error.clone().unwrap_or_default());
                } else {
                    c.message = format!("{} blobs; {} copies pending", n.blobs, n.pending);
                }
            }
        }
        checks.push(c);
    }
    for n in counts.iter().filter(|n| state.storage.location(&n.location).is_none()) {
        checks.push(Check {
            name: format!("Location {}", n.location),
            group: "locations",
            status: "warn",
            message: format!("unknown location (not configured) still recorded as holding {} blobs; run `kontainer storage forget-location {}`", n.blobs, n.location),
            latency_ms: None,
        });
    }

    let indexed = state.search.len() as usize;
    let repos = state.storage.list_repositories().await.map(|r| r.len()).unwrap_or(indexed);
    checks.push(Check {
        name: "Search index".into(),
        group: "core",
        status: if indexed == repos { "ok" } else { "warn" },
        message: if indexed == repos { format!("{indexed} repositories indexed") } else { format!("{indexed} indexed, {repos} in storage; it catches up on the next change or restart") },
        latency_ms: None,
    });
    checks.push(Check {
        name: "Vulnerability scanner".into(),
        group: "core",
        status: "ok",
        message: match &state.scans {
            Some(q) => format!("{} configured", q.scanner_name),
            None => "not configured".into(),
        },
        latency_ms: None,
    });

    checks.push(secrets_at_rest(&state).await);

    for r in state.auth.db.registries().await? {
        let t = Instant::now();
        let result = match r.client() {
            Ok(up) => up.ping().await.map(|_| r.url.clone()).map_err(|e| format!("{e:#}")),
            Err(e) => Err(format!("{e:#}")),
        };
        checks.push(check(r.name.clone(), "upstreams", result, Some(t)));
    }

    for m in state.auth.db.mirrors().await?.into_iter().filter(|m| m.is_enabled) {
        let (status, message) = match m.last_status.as_deref() {
            Some("error") => ("error", m.last_message.clone().unwrap_or_default()),
            Some(_) => {
                let ago = m.last_sync_at.map(|t| (chrono::Utc::now() - t).num_minutes()).unwrap_or(0);
                let when = match ago { 0 => "just now".to_string(), m if m < 120 => format!("{m} min ago"), m if m < 48 * 60 => format!("{} h ago", m / 60), m => format!("{} days ago", m / 1440) };
                ("ok", format!("synced {when}: {}", m.last_message.clone().unwrap_or_default()))
            }
            None => ("warn", "not synced yet".into()),
        };
        checks.push(Check { name: format!("{} → {}", m.source, m.target), group: "mirrors", status, message, latency_ms: None });
    }

    // Jobs of every instance.
    let failed_jobs: Vec<_> = state.list_jobs(None).await?.into_iter().filter(|j| j.status == "failed").take(5).map(|j| format!("{}: {}", j.title, j.message.unwrap_or_default())).collect();
    if !failed_jobs.is_empty() {
        checks.push(Check { name: "Background jobs".into(), group: "jobs", status: "warn", message: failed_jobs.join("\n"), latency_ms: None });
    }

    let overall = if checks.iter().any(|c| c.status == "error") { "error" } else if checks.iter().any(|c| c.status == "warn") { "warn" } else { "ok" };
    Ok(Json(serde_json::json!({
        "status": overall,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": crate::metrics::global().uptime_seconds(),
        "checked_at": chrono::Utc::now().to_rfc3339(),
        "checks": checks,
    }))
    .into_response())
}

/// How the secrets stored in the database are protected (see `database::secrets`).
async fn secrets_at_rest(state: &AppState) -> Check {
    let db = &state.auth.db;
    let (status, message) = match (db.keyring().current_id(), db.encryption_status().await) {
        (_, Err(e)) => ("error", format!("{e:#}")),
        (None, Ok(_)) => ("warn", "not encrypted: set auth.encryption_key (KONTAINER_ENCRYPTION_KEY) or auth.secret".to_string()),
        (Some(id), Ok(cols)) => {
            let sum = |f: &dyn Fn(&crate::database::secrets::ColumnStatus) -> i64| cols.iter().map(f).sum::<i64>();
            let (plain, previous, unknown) = (sum(&|c| c.plaintext), sum(&|c| c.previous.values().sum()), sum(&|c| c.unknown.values().sum()));
            if unknown > 0 {
                ("error", format!("encrypted with key {id}; {unknown} stored secrets need a key that is not configured (`kontainer encryption-status`)"))
            } else if plain + previous > 0 {
                ("warn", format!("encrypted with key {id}; {plain} stored in plaintext and {previous} under previous keys: run `kontainer rotate-encryption-key`"))
            } else {
                ("ok", format!("encrypted with key {id}"))
            }
        }
    };
    Check { name: "Secrets at rest".into(), group: "core", status, message, latency_ms: None }
}
