//! OCI image manifest / index / Docker v2 schema 2 parsing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::digest::Digest;

pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

/// Is `content_type` (parameters and case ignored) one of the manifest media types this
/// registry understands?
pub fn is_manifest_media_type(content_type: &str) -> bool {
    let t = essence(content_type);
    [OCI_MANIFEST, OCI_INDEX, DOCKER_MANIFEST, DOCKER_LIST].iter().any(|m| t.eq_ignore_ascii_case(m))
}

/// The `type/subtype` of a media type, without parameters or surrounding whitespace.
pub fn essence(media_type: &str) -> &str {
    media_type.split(';').next().unwrap_or(media_type).trim()
}

/// The `mediaType` field of a manifest body, if it has one.
pub fn body_media_type(bytes: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(bytes).ok()?.get("mediaType")?.as_str().map(str::to_string)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "os.version")]
    pub os_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub config: Descriptor,
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageIndex {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Descriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone)]
pub enum Manifest {
    Image(Box<ImageManifest>),
    Index(Box<ImageIndex>),
}

/// Why manifest bytes were rejected.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("invalid json: {0}")]
    Json(serde_json::Error),
    #[error("cannot determine manifest media type")]
    UnknownMediaType,
    #[error("unsupported schemaVersion {0} (expected 2)")]
    SchemaVersion(String),
    #[error("invalid image index: {0}")]
    Index(serde_json::Error),
    #[error("invalid image manifest: {0}")]
    Image(serde_json::Error),
}

impl Manifest {
    /// Parse manifest bytes. `content_type` is the request's `Content-Type`, used when the
    /// body has no `mediaType` field (Docker schema 2 always has it, OCI may omit it). Only
    /// `schemaVersion: 2` documents (OCI and Docker schema 2) are accepted.
    pub fn parse(bytes: &[u8], content_type: Option<&str>) -> Result<(Manifest, String), ManifestError> {
        let v: Value = serde_json::from_slice(bytes).map_err(ManifestError::Json)?;
        match v.get("schemaVersion") {
            Some(n) if n.as_u64() == Some(2) => {}
            Some(n) => return Err(ManifestError::SchemaVersion(n.to_string())),
            None => return Err(ManifestError::SchemaVersion("missing".into())),
        }
        let media_type = v
            .get("mediaType")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| content_type.map(|c| c.split(';').next().unwrap_or(c).trim().to_string()))
            .ok_or(ManifestError::UnknownMediaType)?;
        let is_index = match media_type.as_str() {
            OCI_INDEX | DOCKER_LIST => true,
            OCI_MANIFEST | DOCKER_MANIFEST => false,
            // Fall back to structure for unknown types.
            _ => v.get("manifests").is_some(),
        };
        let m = if is_index {
            Manifest::Index(Box::new(serde_json::from_value(v).map_err(ManifestError::Index)?))
        } else {
            Manifest::Image(Box::new(serde_json::from_value(v).map_err(ManifestError::Image)?))
        };
        Ok((m, media_type))
    }

    pub fn subject(&self) -> Option<&Descriptor> {
        match self {
            Manifest::Image(m) => m.subject.as_ref(),
            Manifest::Index(i) => i.subject.as_ref(),
        }
    }

    pub fn annotations(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            Manifest::Image(m) => m.annotations.as_ref(),
            Manifest::Index(i) => i.annotations.as_ref(),
        }
    }

    /// `artifactType` per the OCI 1.1 referrers rules: explicit field (an empty one counts as
    /// absent), else config media type for image manifests; an index without one has none.
    pub fn artifact_type(&self) -> Option<String> {
        let explicit = |t: &Option<String>| t.clone().filter(|t| !t.is_empty());
        match self {
            Manifest::Image(m) => explicit(&m.artifact_type).or_else(|| Some(m.config.media_type.clone()).filter(|t| !t.is_empty())),
            Manifest::Index(i) => explicit(&i.artifact_type),
        }
    }

    /// Blobs that must exist in the repository before this manifest is accepted.
    pub fn required_blobs(&self) -> Vec<&Descriptor> {
        match self {
            Manifest::Image(m) => {
                let mut v = vec![&m.config];
                // Layers with `urls` are foreign and may be absent.
                v.extend(m.layers.iter().filter(|l| l.urls.as_ref().is_none_or(|u| u.is_empty())));
                v
            }
            Manifest::Index(_) => vec![],
        }
    }

    pub fn child_manifests(&self) -> Vec<&Descriptor> {
        match self {
            Manifest::Image(_) => vec![],
            Manifest::Index(i) => i.manifests.iter().collect(),
        }
    }
}

/// Image config (`application/vnd.oci.image.config.v1+json`), only the parts we display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub config: Option<ContainerConfig>,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    #[serde(default)]
    pub rootfs: Option<RootFs>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    #[serde(default, rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(default, rename = "Cmd")]
    pub cmd: Option<Vec<String>>,
    #[serde(default, rename = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "WorkingDir")]
    pub working_dir: Option<String>,
    #[serde(default, rename = "User")]
    pub user: Option<String>,
    #[serde(default, rename = "Labels")]
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "ExposedPorts")]
    pub exposed_ports: Option<BTreeMap<String, Value>>,
    #[serde(default, rename = "Volumes")]
    pub volumes: Option<BTreeMap<String, Value>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryEntry {
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default, rename = "empty_layer")]
    pub is_empty_layer: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootFs {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub diff_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_schema_2() {
        let m = format!(r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{DIGEST}","size":0}},"layers":[]}}"#);
        assert!(matches!(Manifest::parse(m.as_bytes(), None), Ok((Manifest::Image(_), _))));
        let ix = br#"{"schemaVersion":2,"manifests":[]}"#;
        assert!(matches!(Manifest::parse(ix, Some(OCI_INDEX)), Ok((Manifest::Index(_), _))));
    }

    #[test]
    fn rejects_other_schema_versions() {
        for v in ["1", "3", "\"2\""] {
            let m = format!(r#"{{"schemaVersion":{v},"mediaType":"{OCI_INDEX}","manifests":[]}}"#);
            assert!(matches!(Manifest::parse(m.as_bytes(), None), Err(ManifestError::SchemaVersion(_))), "{v}");
        }
        let m = format!(r#"{{"mediaType":"{OCI_INDEX}","manifests":[]}}"#);
        assert!(matches!(Manifest::parse(m.as_bytes(), None), Err(ManifestError::SchemaVersion(_))));
        assert!(matches!(Manifest::parse(b"nope", None), Err(ManifestError::Json(_))));
        assert!(matches!(Manifest::parse(br#"{"schemaVersion":2}"#, None), Err(ManifestError::UnknownMediaType)));
    }

    #[test]
    fn empty_artifact_type_counts_as_absent() {
        let cfg = "application/vnd.example.config.v1+json";
        let m = format!(r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","artifactType":"","config":{{"mediaType":"{cfg}","digest":"{DIGEST}","size":0}},"layers":[]}}"#);
        assert_eq!(Manifest::parse(m.as_bytes(), None).unwrap().0.artifact_type().as_deref(), Some(cfg));
        let m = format!(r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","artifactType":"application/x-a","config":{{"mediaType":"{cfg}","digest":"{DIGEST}","size":0}},"layers":[]}}"#);
        assert_eq!(Manifest::parse(m.as_bytes(), None).unwrap().0.artifact_type().as_deref(), Some("application/x-a"));
        let ix = format!(r#"{{"schemaVersion":2,"mediaType":"{OCI_INDEX}","artifactType":"","manifests":[]}}"#);
        assert_eq!(Manifest::parse(ix.as_bytes(), None).unwrap().0.artifact_type(), None);
    }
}
