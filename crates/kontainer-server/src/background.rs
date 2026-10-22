//! Everything the server does on its own: periodic cleanup, retention, mirrors, tag expiry,
//! storage replication, builds, maintenance schedules and push replication.

use std::time::Duration;

use crate::state::AppState;

/// Start all background work. Call once, after building the state; tests that drive the
/// router alone don't need it.
pub async fn start(state: &AppState) {
    crate::locations::start(&state.storage, &state.auth.db, state.config.storage.replication_concurrency, state.config.storage.replication_interval);
    if state.config.builds.is_enabled {
        crate::build::start(state).await;
    }
    crate::maintenance::start(state).await;
    crate::replicate::start(state);

    // Abandoned uploads (sessions in the database, chunks in the store) and local temp files.
    // Every instance runs this; removing an upload twice is harmless.
    let ttl = state.config.storage.upload_ttl;
    let storage = state.storage.clone();
    every(ttl.clamp(Duration::from_secs(60), Duration::from_secs(3600)), true, move || {
        let storage = storage.clone();
        async move {
            match storage.purge_stale_uploads(ttl).await {
                Ok(p) if p.total() == 0 => {}
                Ok(p) => tracing::info!(sessions = p.sessions, orphan_chunks = p.orphan_chunks, local = p.local, "purged stale uploads"),
                Err(e) => tracing::warn!(error = %e, "purging stale uploads"),
            }
        }
    });

    // Expired sessions and pending SSO logins.
    let db = state.auth.db.clone();
    every(Duration::from_secs(600), true, move || {
        let db = db.clone();
        async move {
            if let Err(e) = db.purge_expired().await {
                tracing::warn!(error = %e, "purging expired sessions");
            }
        }
    });

    // Retention policies, the storage report (kept warm for /metrics) and tag history pruning.
    // On one instance at a time (as are mirrors and expiry below).
    let bg = state.clone();
    every(state.config.retention.interval.max(Duration::from_secs(60)), false, move || {
        let bg = bg.clone();
        async move {
            let (db, bg2) = (bg.auth.db.clone(), bg.clone());
            crate::database::locks::exclusive(&db, "retention", async move {
                match crate::retention::run_all(&bg).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(tags = n, "retention policies deleted tags"),
                    Err(e) => tracing::warn!(error = %format!("{e:#}"), "running retention policies"),
                }
                // Tag history: keep 90 days, or the longest Time Machine window if that is longer.
                if let Ok(window) = crate::tags::longest_time_machine(&bg.auth.db, bg.config.policy.time_machine).await {
                    let keep = window.max(chrono::Duration::days(90));
                    if let Err(e) = bg.auth.db.prune_tag_events(chrono::Utc::now() - keep).await {
                        tracing::warn!(error = %e, "pruning tag history");
                    }
                }
            })
            .await;
            // Every instance keeps its own report warm (its /metrics shows it).
            bg2.refresh_usage_in_background();
        }
    });

    // Mirrors that are due, and expired tags.
    let bg = state.clone();
    every(Duration::from_secs(60), true, move || {
        let bg = bg.clone();
        async move {
            let db = bg.auth.db.clone();
            crate::database::locks::exclusive(&db, "mirrors", async move {
                if let Err(e) = crate::sync::sync_due_mirrors(&bg).await {
                    tracing::warn!(error = %e, "running mirrors");
                }
                match crate::tags::expire_due(&bg).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(tags = n, "expired tags deleted"),
                    Err(e) => tracing::warn!(error = %e, "expiring tags"),
                }
            })
            .await;
        }
    });
}

/// Run `task` every `period` (right away too when `at_start`). A slow run is not followed by a
/// burst of catch-up runs. Each run is its own task: one that panics is logged and the
/// schedule carries on, instead of the job silently stopping for good.
pub(crate) fn every<F, Fut>(period: Duration, at_start: bool, task: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        if !at_start {
            tick.tick().await;
        }
        loop {
            tick.tick().await;
            if let Err(e) = tokio::spawn(task()).await {
                tracing::error!(error = %e, "a background job crashed; it will run again on schedule");
            }
        }
    });
}
