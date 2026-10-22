//! Storage locations and geo-replication status for administrators.

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use kontainer_core::perm::Global;
use crate::auth::{require_global, Principal};
use kontainer_core::config::StorageDriver;
use crate::database::placements::LocationCounts;
use crate::error::{RegistryError, Result};
use crate::state::AppState;
use kontainer_store::replication::LocationStats;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/admin/storage", get(status)).route("/api/v1/admin/storage/sync", post(sync))
}

fn driver(d: StorageDriver) -> &'static str {
    match d {
        StorageDriver::Filesystem => "filesystem",
        StorageDriver::S3 => "s3",
        StorageDriver::Gcs => "gcs",
        StorageDriver::Azure => "azure",
        StorageDriver::Memory => "memory",
    }
}

#[derive(Serialize)]
struct Location {
    name: String,
    /// `unknown` for a location that is no longer configured but still has placements.
    driver: &'static str,
    /// Downloads served from here are redirected to presigned URLs.
    redirect: bool,
    regions: Vec<String>,
    /// This instance's preferred location (where it writes).
    preferred: bool,
    /// In this instance's configuration. A location removed from it keeps its placements until
    /// `kontainer storage forget-location`.
    configured: bool,
    /// Blobs recorded here, and their bytes.
    blobs: i64,
    bytes: i64,
    /// Copies to here waiting or in progress, and given up on.
    pending: i64,
    failed: i64,
    last_error: Option<String>,
    last_error_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Copies this instance made to here since it started.
    stats: LocationStats,
}

async fn status(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    require_global(&state, &p, Global::Gc)?;
    let st = &state.storage;
    let cfg = &state.config.storage;
    let mut counts: Vec<LocationCounts> = state.auth.db.location_counts().await?;
    let mut take = |name: &str| counts.iter().position(|c| c.location == name).map(|i| counts.remove(i)).unwrap_or_default();
    let mut locations: Vec<Location> = st
        .locations()
        .iter()
        .map(|l| {
            let c = take(&l.name);
            Location {
                name: l.name.clone(),
                driver: driver(l.driver),
                redirect: l.redirects(),
                regions: l.regions.clone(),
                preferred: l.name == st.preferred().name,
                configured: true,
                blobs: c.blobs,
                bytes: c.bytes,
                pending: c.pending,
                failed: c.failed,
                last_error: c.last_error,
                last_error_at: c.last_error_at,
                stats: st.replication.stats(&l.name),
            }
        })
        .collect();
    let unknown: Vec<Location> = counts
        .into_iter()
        .map(|c| Location {
            stats: st.replication.stats(&c.location),
            name: c.location,
            driver: "unknown",
            redirect: false,
            regions: vec![],
            preferred: false,
            configured: false,
            blobs: c.blobs,
            bytes: c.bytes,
            pending: c.pending,
            failed: c.failed,
            last_error: c.last_error,
            last_error_at: c.last_error_at,
        })
        .collect();
    let (pending, failed) = locations.iter().chain(&unknown).fold((0, 0), |(p, f), l| (p + l.pending, f + l.failed));
    let syncing = match state.auth.db.try_advisory_lock(crate::locations::BACKFILL_LOCK).await? {
        Some(lock) => {
            lock.release().await;
            false
        }
        None => true,
    };
    let preferred = locations.iter().position(|l| l.preferred).map(|i| locations.remove(i));
    let replicas: Vec<&Location> = locations.iter().collect();
    let all: Vec<&Location> = preferred.iter().chain(&locations).chain(&unknown).collect();
    Ok(Json(serde_json::json!({
        // This instance's preferred location, then the other configured ones (the names from
        // before every location became a peer).
        "primary": preferred,
        "replicas": replicas,
        // Every location: the preferred one, the others configured, then those only the
        // database still knows ("unknown locations").
        "locations": all,
        "unknown_locations": unknown.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
        "region_header": cfg.region_header,
        "redirect_ttl_secs": cfg.redirect_ttl.as_secs(),
        "replication_interval_secs": cfg.replication_interval.as_secs(),
        "pending": pending,
        "failed": failed,
        "syncing": syncing,
    }))
    .into_response())
}

#[derive(Deserialize)]
struct SyncQuery {
    /// Only this location; every location by default.
    location: Option<String>,
}

/// Queue a copy of every blob each location (or `?location=`) is missing, as a background job.
async fn sync(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(q): Query<SyncQuery>) -> Result<Response> {
    require_global(&state, &p, Global::Gc)?;
    if state.storage.locations().len() < 2 {
        return Err(RegistryError::bad_request("only one storage location is configured"));
    }
    if let Some(l) = &q.location {
        if state.storage.location(l).is_none() {
            return Err(RegistryError::bad_request(format!("no storage location `{l}`")));
        }
    }
    let lock = match crate::maintenance::cluster_slot(&state, crate::locations::BACKFILL_LOCK, "a storage sync").await {
        Ok(l) => l,
        Err(e) if e.downcast_ref::<crate::maintenance::AlreadyRunning>().is_some() => return Err(RegistryError::conflict("a storage sync is already running")),
        Err(e) => return Err(RegistryError::internal(e)),
    };
    state.audit.record(&p, "replicate_storage", None, None, q.location.as_deref(), None);
    let storage = state.storage.clone();
    let job = state
        .spawn_job("replication", "Sync storage locations".into(), p.name().to_string(), async move {
            let result = async {
                let mut parts = vec![];
                for l in storage.locations().iter().filter(|l| q.location.as_ref().is_none_or(|w| *w == l.name)) {
                    let n = storage.backfill(&l.name).await?;
                    parts.push(format!("{}: {n} queued", l.name));
                }
                Ok(parts.join("; "))
            }
            .await;
            lock.release().await;
            result
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "job": job }))).into_response())
}
