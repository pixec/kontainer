//! `GET /api/v1/about`: version, build, license and runtime details for the admin About page.
//! Administrators only: a version number tells an attacker which advisories apply.

use axum::extract::{Extension, State};
use axum::Json;
use serde::Serialize;

use kontainer_core::perm::Global;
use crate::auth::Principal;
use crate::error::Result;
use crate::state::AppState;

pub const LICENSE_TEXT: &str = include_str!("../../../../LICENSE");

#[derive(Serialize)]
pub struct About {
    name: &'static str,
    version: &'static str,
    description: &'static str,
    commit: Option<&'static str>,
    /// RFC 3339.
    built_at: Option<String>,
    rustc: Option<&'static str>,
    license: &'static str,
    license_text: &'static str,
    homepage: Option<&'static str>,
    repository: Option<&'static str>,
    runtime: Runtime,
}

#[derive(Serialize)]
struct Runtime {
    os: &'static str,
    arch: &'static str,
    uptime_seconds: u64,
    storage: String,
    auth: String,
    scanner: Option<&'static str>,
    /// `on`, `off`, or `no token` (enabled but refusing every scrape).
    metrics: &'static str,
}

fn non_empty(s: &'static str) -> Option<&'static str> {
    (!s.is_empty()).then_some(s)
}

pub async fn about(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Json<About>> {
    if ![Global::UsersRead, Global::RolesWrite, Global::Gc].into_iter().any(|g| p.has_global(g)) {
        return Err(state.auth.denied(&p, None));
    }
    let built_at = env!("KONTAINER_BUILD_EPOCH").parse::<i64>().ok().filter(|&t| t > 0).and_then(|t| chrono::DateTime::from_timestamp(t, 0)).map(|t| t.to_rfc3339());
    let runtime = Runtime {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        uptime_seconds: crate::metrics::global().uptime_seconds(),
        storage: format!("{:?}", state.storage.preferred().driver).to_lowercase(),
        auth: format!("{:?}", state.config.auth.mode).to_lowercase(),
        scanner: state.scans.as_ref().map(|q| q.scanner_name),
        metrics: match (state.config.metrics.is_enabled, state.config.metrics.token.as_ref().is_some_and(|t| !t.is_empty())) {
            (false, _) => "off",
            (true, true) => "on",
            (true, false) => "no token",
        },
    };
    Ok(Json(About {
        name: "kontainer",
        version: env!("CARGO_PKG_VERSION"),
        description: env!("CARGO_PKG_DESCRIPTION"),
        commit: non_empty(env!("KONTAINER_GIT_COMMIT")),
        built_at,
        rustc: non_empty(env!("KONTAINER_RUSTC")),
        license: env!("CARGO_PKG_LICENSE"),
        license_text: LICENSE_TEXT,
        homepage: non_empty(env!("CARGO_PKG_HOMEPAGE")),
        repository: non_empty(env!("CARGO_PKG_REPOSITORY")),
        runtime,
    }))
}
