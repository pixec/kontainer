//! Vulnerability scanning.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{humantime_serde, Secret};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScannerConfig {
    /// `none`, `trivy` or `grype`.
    pub kind: ScannerKind,
    /// Path to the scanner binary.
    pub binary: Option<String>,
    /// Extra CLI arguments appended to the scanner invocation.
    pub extra_args: Vec<String>,
    /// Automatically scan every pushed image manifest.
    #[serde(rename = "scan_on_push")]
    pub is_scan_on_push: bool,
    /// Host:port the scanner uses to reach this registry. Defaults to `127.0.0.1:<port>`.
    pub registry_host: Option<String>,
    /// Registry is reachable over plain HTTP from the scanner.
    #[serde(rename = "insecure")]
    pub is_insecure: bool,
    /// Credentials the scanner uses to pull from this registry. Unset, the registry mints a
    /// short-lived pull-only token per scan instead, which is all a scanner needs.
    pub username: Option<String>,
    pub password: Option<Secret>,
    /// Store the scanner's raw JSON output alongside the normalized report.
    #[serde(rename = "store_raw")]
    pub is_store_raw: bool,
    /// Number of concurrent scans.
    pub workers: usize,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Refuse to serve manifests whose scan report contains a vulnerability at or above this
    /// severity (`critical`, `high`, `medium`, `low`). Unscanned images are still served.
    pub block_pull_at: Option<Severity>,
    /// Extra environment variables passed to the scanner process.
    pub env: HashMap<String, String>,
    /// Rescan tagged images whose report is older than this (e.g. `7d`), to catch newly
    /// published vulnerabilities. Unset: no rescans.
    #[serde(with = "humantime_serde::option", skip_serializing_if = "Option::is_none")]
    pub rescan_interval: Option<Duration>,
    /// Automatic scans (scan on push, scheduled rescans) queued per hour across the cluster;
    /// beyond it they are skipped. 0: unlimited. Scans asked for by a user are not counted
    /// against it.
    pub max_auto_per_hour: u64,
    /// Scans waiting or running, across the cluster, beyond which new ones are skipped
    /// (including ones asked for by a user). 0: unlimited.
    pub max_queue: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            kind: ScannerKind::None,
            binary: None,
            extra_args: vec![],
            is_scan_on_push: true,
            registry_host: None,
            is_insecure: true,
            username: None,
            password: None,
            is_store_raw: false,
            workers: 1,
            timeout: Duration::from_secs(600),
            block_pull_at: None,
            env: HashMap::new(),
            rescan_interval: None,
            max_auto_per_hour: 0,
            max_queue: 10_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScannerKind {
    None,
    Trivy,
    Grype,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Unknown,
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}
