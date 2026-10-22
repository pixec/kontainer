//! Audit log, metrics and webhooks.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::Secret;

/// Usage log of registry activity, persisted in storage under `logs/`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(rename = "enabled")]
    pub is_enabled: bool,
    /// Also record manifest pulls (noisy on busy registries).
    #[serde(rename = "log_pulls")]
    pub is_log_pulls: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { is_enabled: true, is_log_pulls: false }
    }
}

/// Prometheus metrics at `/metrics`. Served only once a token is set: the output names every
/// namespace with its usage and quota.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(rename = "enabled")]
    pub is_enabled: bool,
    /// Required. Scrapers send `Authorization: Bearer <token>`; without one the endpoint refuses.
    pub token: Option<Secret>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self { is_enabled: true, token: None }
    }
}

/// Outgoing HTTP notifications. Each event is POSTed as JSON.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    /// Subset of `push`, `delete`, `scan`. Empty means all.
    #[serde(default)]
    pub events: Vec<String>,
    /// Only fire for repositories matching these globs. Empty means all.
    #[serde(default)]
    pub repositories: Vec<String>,
    /// Extra headers, e.g. an `Authorization` token.
    #[serde(default)]
    pub headers: HashMap<String, Secret>,
}
