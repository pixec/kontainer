//! Tag immutability, the tag time machine and retention.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::humantime_serde;

/// Scheduled garbage collection (it can always be run by hand).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct GcConfig {
    /// How often to collect, e.g. `24h`. Unset: only by hand.
    #[serde(with = "humantime_serde::option", skip_serializing_if = "Option::is_none")]
    pub interval: Option<Duration>,
    /// Also remove manifests no tag points at (beyond the Time Machine window).
    #[serde(rename = "delete_untagged")]
    pub is_delete_untagged: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Tags matching these rules cannot be overwritten or deleted once pushed.
    pub immutable_tags: Vec<ImmutableTagRule>,
    /// How long a deleted or moved tag can be restored (organizations may override it). The
    /// images it pointed at are kept by garbage collection for this long. `0s` turns it off.
    #[serde(with = "humantime_serde")]
    pub time_machine: Duration,
    /// Storage quota for users and organizations that have none of their own, e.g. `10g`.
    /// Administrators can still set one per namespace, including no limit.
    pub default_user_quota: Option<String>,
    pub default_org_quota: Option<String>,
    /// Let namespace webhooks reach private networks, this machine and cloud metadata
    /// endpoints. Off by default: namespace admins could otherwise probe your internal network.
    #[serde(rename = "webhooks_allow_private_targets")]
    pub is_webhooks_allow_private_targets: bool,
    /// Robot credentials expire after this many days unless whoever creates the robot picks
    /// otherwise. Unset: they never expire by default.
    pub robot_expiry_days: Option<u32>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self { immutable_tags: vec![], time_machine: Duration::from_secs(7 * 86400), default_user_quota: None, default_org_quota: None, is_webhooks_allow_private_targets: false, robot_expiry_days: None }
    }
}

/// `repositories` and `tags` are globs (`*`, `**` for repositories; `*` for tags).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableTagRule {
    pub repositories: Vec<String>,
    pub tags: Vec<String>,
}

/// Background work for retention policies and the storage report.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// How often enabled retention policies run.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// How long a storage report is reused before it is recomputed.
    #[serde(with = "humantime_serde")]
    pub report_ttl: Duration,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self { interval: Duration::from_secs(3600), report_ttl: Duration::from_secs(600) }
    }
}
