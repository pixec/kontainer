//! Storage locations.
//!
//! A deployment has one or more named locations (`[[storage.locations]]`), all peers: each
//! instance writes to its own preferred one (`storage.location`), and blobs are copied to the
//! others in the background. The older flat form (`storage.driver` and its sections, plus
//! `[[storage.replicas]]`) is converted into the same list by [`StorageConfig::resolved_locations`].

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{humantime_serde, Secret};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// `filesystem`, `s3`, `gcs`, `azure` or `memory`.
    pub driver: StorageDriver,
    /// Local directory for temporary files that live within one request: a chunk on its way
    /// into the backend, a completed upload being verified, pull-through downloads, archive
    /// imports. Upload sessions themselves are not kept here (their state is in the database,
    /// their chunks in the backend under `_upload_chunks/`), so it need not be shared between
    /// instances; it should have room for the largest blob being pushed at once.
    pub upload_dir: PathBuf,
    /// Uploads untouched for longer than this are purged (session, chunks and temporary files).
    #[serde(with = "humantime_serde")]
    pub upload_ttl: Duration,
    /// Key/path prefix inside the backend (e.g. a subfolder in the bucket).
    pub prefix: Option<String>,
    pub filesystem: FilesystemConfig,
    pub s3: S3Config,
    pub gcs: GcsConfig,
    pub azure: AzureConfig,
    /// This instance's preferred location: where it writes blobs, upload chunks, scan reports
    /// and logs, and where it reads from first. Must name one of [`Self::locations`] (with the
    /// flat form: the name given to the flat driver, `primary` by default).
    pub location: String,
    /// Answer blob downloads with a short-lived presigned URL into the bucket instead of
    /// streaming them through the server (`s3`, `gcs` and `azure`).
    #[serde(rename = "redirect")]
    pub is_redirect: bool,
    /// How long a presigned download URL stays valid.
    #[serde(with = "humantime_serde")]
    pub redirect_ttl: Duration,
    /// Request header naming the client's region, set by the CDN or load balancer in front of
    /// the registry (`CloudFront-Viewer-Country`, `CF-IPCountry`, or your own). Downloads go to
    /// the first location whose `regions` match it and that has the blob. Only trust a header
    /// your proxy overwrites.
    pub region_header: Option<String>,
    /// How often every location is checked for blobs it is missing (which are then queued for
    /// copying). New blobs are queued as they are written, so this only catches up after an
    /// outage or a newly added location.
    #[serde(with = "humantime_serde")]
    pub replication_interval: Duration,
    /// Copies to other locations this instance makes at once.
    pub replication_concurrency: usize,
    /// Flat form only: further locations, converted into [`Self::locations`] after the flat
    /// driver. Kept for configurations written before `[[storage.locations]]`.
    pub replicas: Vec<LocationConfig>,
    /// The storage locations, all peers. Mutually exclusive with the flat driver settings
    /// (`driver`, `prefix`, `redirect`, `filesystem`, `s3`, `gcs`, `azure`) and `replicas`.
    pub locations: Vec<LocationConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            driver: StorageDriver::Filesystem,
            upload_dir: PathBuf::from("./data/_uploads"),
            upload_ttl: Duration::from_secs(24 * 3600),
            prefix: None,
            filesystem: Default::default(),
            s3: Default::default(),
            gcs: Default::default(),
            azure: Default::default(),
            location: "primary".into(),
            is_redirect: false,
            redirect_ttl: Duration::from_secs(15 * 60),
            region_header: None,
            replication_interval: Duration::from_secs(3600),
            replication_concurrency: 4,
            replicas: vec![],
            locations: vec![],
        }
    }
}

impl StorageConfig {
    /// The locations, with the flat form converted: the flat driver becomes a location named
    /// [`Self::location`] (serving no particular region), followed by each of `replicas`.
    pub fn resolved_locations(&self) -> anyhow::Result<Vec<LocationConfig>> {
        if !self.locations.is_empty() {
            anyhow::ensure!(self.replicas.is_empty(), "storage.locations and storage.replicas cannot be used together: list every location under [[storage.locations]]");
            return Ok(self.locations.clone());
        }
        let flat = LocationConfig {
            name: self.location.clone(),
            regions: vec![],
            driver: self.driver,
            prefix: self.prefix.clone(),
            is_redirect: self.is_redirect,
            filesystem: self.filesystem.clone(),
            s3: self.s3.clone(),
            gcs: self.gcs.clone(),
            azure: self.azure.clone(),
        };
        Ok(std::iter::once(flat).chain(self.replicas.iter().cloned()).collect())
    }

    /// The preferred location's settings.
    pub fn preferred_location(&self) -> anyhow::Result<LocationConfig> {
        self.resolved_locations()?
            .into_iter()
            .find(|l| l.name == self.location)
            .ok_or_else(|| anyhow::anyhow!("storage.location `{}` names none of the storage locations", self.location))
    }
}

/// The settings of the flat form that `[[storage.locations]]` replaces.
pub const FLAT_STORAGE_KEYS: [&str; 8] = ["driver", "prefix", "redirect", "filesystem", "s3", "gcs", "azure", "replicas"];

/// One storage location (`[[storage.locations]]`, or `[[storage.replicas]]` in the flat form).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocationConfig {
    pub name: String,
    /// Client regions served from here: values of `storage.region_header`, matched
    /// case-insensitively, `*` wildcards allowed (`["DE", "FR", "eu-*"]`).
    pub regions: Vec<String>,
    pub driver: StorageDriver,
    pub prefix: Option<String>,
    /// Answer downloads served from here with presigned URLs (`s3`, `gcs`, `azure`). Without
    /// it (or on `filesystem`) blobs are streamed through the server; a location no region
    /// maps to is then a standby copy, read when the others fail.
    #[serde(rename = "redirect")]
    pub is_redirect: bool,
    pub filesystem: FilesystemConfig,
    pub s3: S3Config,
    pub gcs: GcsConfig,
    pub azure: AzureConfig,
}

/// The name `[[storage.replicas]]` entries had before every location became a peer.
pub type ReplicaConfig = LocationConfig;

impl Default for LocationConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            regions: vec![],
            driver: StorageDriver::S3,
            prefix: None,
            is_redirect: true,
            filesystem: Default::default(),
            s3: Default::default(),
            gcs: Default::default(),
            azure: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageDriver {
    Filesystem,
    S3,
    Gcs,
    Azure,
    Memory,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesystemConfig {
    pub root: PathBuf,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self { root: PathBuf::from("./data") }
    }
}

/// S3 (and S3-compatible: MinIO, R2, Ceph RGW...). Credentials fall back to the standard
/// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` environment variables and the
/// instance metadata service.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct S3Config {
    pub bucket: String,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<Secret>,
    pub session_token: Option<Secret>,
    /// Use `bucket.endpoint` virtual-hosted addressing instead of path style.
    #[serde(rename = "virtual_hosted_style")]
    pub is_virtual_hosted_style: bool,
    /// Allow plain-HTTP endpoints (MinIO in dev).
    #[serde(rename = "allow_http")]
    pub is_allow_http: bool,
    /// Skip signature (public buckets).
    #[serde(rename = "skip_signature")]
    pub is_skip_signature: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct GcsConfig {
    pub bucket: String,
    pub service_account_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AzureConfig {
    pub container: String,
    pub account: Option<String>,
    pub access_key: Option<Secret>,
}
