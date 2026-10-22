//! HTTP server, API feature switches and the web UI.

use serde::{Deserialize, Serialize};

pub use ipnet::IpNet;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind, e.g. `0.0.0.0:5000`.
    pub bind: String,
    /// Public URL clients use to reach this registry (used for `Location` headers and scanner
    /// image references). Defaults to `http://<bind>`.
    pub public_url: Option<String>,
    /// Maximum manifest size accepted on PUT, in bytes.
    pub max_manifest_size: u64,
    /// Largest blob (layer) accepted on upload, e.g. `10g` or `512Mi`. Larger uploads are refused
    /// with 413. Unset: no limit beyond namespace quotas.
    pub max_blob_size: Option<String>,
    /// Reverse proxies whose `X-Forwarded-For` is believed: IP addresses or CIDR ranges, e.g.
    /// `["10.0.0.0/8", "192.168.1.5"]`. The client address (sign-in rate limits, session list) is
    /// the TCP peer unless the peer is one of these. Empty: the header is ignored.
    pub trusted_proxies: Vec<String>,
    /// Log filter (RUST_LOG syntax).
    pub log: String,
    /// `/readyz` also probes every other storage location, not only this instance's own, so a
    /// load balancer takes the node out while any region's bucket is unreachable.
    #[serde(rename = "ready_requires_all_locations")]
    pub is_ready_requires_all_locations: bool,
}

impl ServerConfig {
    /// `max_blob_size` in bytes (checked when the configuration is loaded).
    pub fn max_blob_bytes(&self) -> Option<u64> {
        self.max_blob_size.as_deref().and_then(crate::config::parse_bytes).map(|n| n as u64)
    }

    /// `trusted_proxies`, parsed. Entries that don't parse (refused when loading) are skipped.
    pub fn trusted_proxy_nets(&self) -> Vec<IpNet> {
        self.trusted_proxies.iter().filter_map(|s| parse_net(s)).collect()
    }
}

/// `10.0.0.0/8`, or a single address (`192.168.1.5`, `::1`).
pub(crate) fn parse_net(raw: &str) -> Option<IpNet> {
    let raw = raw.trim();
    raw.parse::<IpNet>().ok().or_else(|| raw.parse::<std::net::IpAddr>().ok().map(IpNet::from))
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:5000".into(),
            public_url: None,
            max_manifest_size: 4 * 1024 * 1024,
            max_blob_size: None,
            trusted_proxies: vec![],
            log: "info,kontainer=debug".into(),
            is_ready_requires_all_locations: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeatureConfig {
    /// Allow `DELETE` of manifests, tags and blobs.
    #[serde(rename = "delete")]
    pub is_delete: bool,
    /// Expose `/v2/_catalog`.
    #[serde(rename = "catalog")]
    pub is_catalog: bool,
    /// Allow cross-repository blob mounts.
    #[serde(rename = "cross_repo_mount")]
    pub is_cross_repo_mount: bool,
    /// Serve the OCI 1.1 referrers API.
    #[serde(rename = "referrers")]
    pub is_referrers: bool,
    /// Honour containerd's `?ns=<upstream host>` on pulls: a repository that does not exist
    /// here is served from the pull-through cache namespace whose upstream is that host.
    #[serde(rename = "containerd_ns")]
    pub is_containerd_ns: bool,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self { is_delete: true, is_catalog: true, is_cross_repo_mount: true, is_referrers: true, is_containerd_ns: true }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// Serve the web UI and the `/api/v1` inspection API.
    #[serde(rename = "enabled")]
    pub is_enabled: bool,
    /// Maximum number of entries returned when listing a layer's files.
    pub max_layer_entries: usize,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self { is_enabled: true, max_layer_entries: 5000 }
    }
}
