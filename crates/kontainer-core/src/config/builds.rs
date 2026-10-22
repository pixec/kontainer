//! Building images from Git: the registry's side (the queue and its runners). How a runner
//! builds is in [`crate::config::runner`].

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{humantime_serde, Secret};

/// Building images from Git (build triggers). The registry keeps the queue; **runners**
/// (`kontainer runner`, anywhere that reaches the registry) claim builds and run them in
/// BuildKit. A namespace gets the Builds tab once a runner serves it: a shared one an
/// administrator registered for it, or its own self-hosted one.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BuildsConfig {
    /// Off: no build triggers or runners at all.
    #[serde(rename = "enabled")]
    pub is_enabled: bool,
    /// Let users and organization admins register runners for their own namespace.
    #[serde(rename = "self_hosted_runners")]
    pub is_self_hosted_runners: bool,
    /// A build running longer is cancelled.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Allow `file://` Git URLs (tests and single-machine setups only).
    #[serde(rename = "allow_file_urls")]
    pub is_allow_file_urls: bool,
    /// A running build whose runner has not checked in for this long is failed.
    #[serde(with = "humantime_serde")]
    pub heartbeat_timeout: Duration,
    /// Builds one namespace (user or organization) may run at once, across every runner; its
    /// other builds wait while other namespaces' builds go ahead. 0: no limit. Either way,
    /// namespaces with fewer builds running are served first.
    pub max_per_namespace: usize,
    /// A build's log is kept up to this many bytes; past it, the registry stops storing what the
    /// runner sends and keeps only the last 64 KiB, behind a `==> log truncated` line.
    pub max_log_bytes: u64,
    /// Shared runners defined here (read-only in the UI), e.g. the one deployed next to the
    /// registry. `KONTAINER_RUNNER_TOKEN` adds one named `default` that serves every namespace.
    pub runners: Vec<ConfigRunner>,
}

impl Default for BuildsConfig {
    fn default() -> Self {
        Self {
            is_enabled: true,
            is_self_hosted_runners: true,
            timeout: Duration::from_secs(30 * 60),
            is_allow_file_urls: false,
            heartbeat_timeout: Duration::from_secs(120),
            max_per_namespace: 0,
            max_log_bytes: 8 << 20,
            runners: vec![],
        }
    }
}

/// A shared runner from the configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigRunner {
    pub name: String,
    /// What the runner authenticates with (`--token` / `KONTAINER_RUNNER_TOKEN` on the runner).
    pub token: Secret,
    /// Namespaces it serves; empty: all of them.
    #[serde(default)]
    pub namespaces: Vec<String>,
}
