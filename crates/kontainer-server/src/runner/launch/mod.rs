//! Launchers start an agent for one build somewhere else: a pair of containers on a Docker host
//! ([`docker`]) or a Kubernetes Job ([`kubernetes`]). The agent then runs the build over the
//! [`protocol`](crate::runner::protocol) like any other.
//!
//! A launcher knows nothing about the queue: the runner claims a build, gets its token, and
//! asks the launcher to start it. It also asks, now and then, what is still running, so it can
//! fail builds whose agent died before reporting, and clean up after the others.

pub mod docker;
pub mod kubernetes;

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;

/// What a launcher reports about a build it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launched {
    /// Starting or running.
    Running,
    /// Gone down: out of memory, evicted, timed out, exited. The agent reports on every normal
    /// path, so this only matters while the build still counts as running.
    Stopped(String),
}

#[async_trait]
pub trait Launcher: Send + Sync {
    /// Agent name prefix for builds this launcher runs, e.g. `docker/`.
    fn prefix(&self) -> &'static str;

    /// What runs build `id`, e.g. `kontainer-build-7`; shown on the build after the prefix.
    fn name(&self, id: i64) -> String {
        format!("kontainer-build-{id}")
    }

    /// Start an agent for build `id`, which proves itself with `token`.
    async fn launch(&self, id: i64, token: &str) -> Result<()>;

    /// Stop and remove whatever runs build `id`. Already gone is fine.
    async fn remove(&self, id: i64) -> Result<()>;

    /// Builds this launcher started that still exist, by id.
    async fn launched(&self) -> Result<HashMap<i64, Launched>>;

    /// Leave finished builds for the platform to clean up (e.g. a Job's TTL keeps pod logs
    /// around for a while) instead of removing them as soon as they end.
    fn keeps_finished(&self) -> bool {
        false
    }
}
