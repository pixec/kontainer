//! What an OCI manifest *is* (image, Helm chart, WASM module, SBOM, signature, ...), plus the
//! readers behind the artifact views: SBOM documents and cosign signatures.
//!
//! Classification only looks at media types (artifactType, config and layer media types), so it
//! is cheap enough for listings.

use base64::Engine;
use serde::Serialize;

use crate::manifest::{ImageManifest, Manifest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Image,
    Index,
    HelmChart,
    Wasm,
    Sbom,
    Signature,
    Attestation,
    Artifact,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactInfo {
    pub kind: ArtifactKind,
    /// Human label, e.g. "Helm chart" or "SBOM (CycloneDX)".
    pub label: String,
    /// The media type that decided the classification.
    pub media_type: Option<String>,
}

pub const HELM_CONFIG: &str = "application/vnd.cncf.helm.config.v1+json";
pub const COSIGN_SIMPLE_SIGNING: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
pub const COSIGN_SIG_ARTIFACT: &str = "application/vnd.dev.cosign.artifact.sig.v1+json";
pub const SIGSTORE_BUNDLE_PREFIX: &str = "application/vnd.dev.sigstore.bundle";
pub const DSSE_ENVELOPE: &str = "application/vnd.dsse.envelope.v1+json";
pub const IN_TOTO: &str = "application/vnd.in-toto+json";
/// cosign stores the base64 signature of the layer payload in this layer annotation.
pub const COSIGN_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
pub const COSIGN_CERT_ANNOTATION: &str = "dev.sigstore.cosign/certificate";

fn sbom_format(media_type: &str) -> Option<&'static str> {
    let m = media_type.to_ascii_lowercase();
    if m.contains("cyclonedx") {
        Some("CycloneDX")
    } else if m.contains("spdx") {
        Some("SPDX")
    } else if m.contains("syft") {
        Some("Syft")
    } else {
        None
    }
}

fn is_wasm(media_type: &str) -> bool {
    media_type == "application/wasm" || media_type.starts_with("application/vnd.wasm")
}

fn info(kind: ArtifactKind, label: impl Into<String>, media_type: Option<&str>) -> ArtifactInfo {
    ArtifactInfo { kind, label: label.into(), media_type: media_type.map(str::to_string) }
}

/// Classify from what a descriptor alone tells us (artifactType or media type). Used for
/// referrers and index children where the manifest body is not loaded.
pub fn classify_media_type(media_type: &str, artifact_type: Option<&str>) -> ArtifactInfo {
    let t = artifact_type.unwrap_or(media_type);
    if let Some(f) = sbom_format(t) {
        return info(ArtifactKind::Sbom, format!("SBOM ({f})"), Some(t));
    }
    if t == COSIGN_SIG_ARTIFACT || t == COSIGN_SIMPLE_SIGNING || t.starts_with(SIGSTORE_BUNDLE_PREFIX) {
        return info(ArtifactKind::Signature, "Signature", Some(t));
    }
    if t == DSSE_ENVELOPE || t.contains("in-toto") || t.contains("provenance") {
        return info(ArtifactKind::Attestation, "Attestation", Some(t));
    }
    if t == HELM_CONFIG {
        return info(ArtifactKind::HelmChart, "Helm chart", Some(t));
    }
    if is_wasm(t) {
        return info(ArtifactKind::Wasm, "WASM module", Some(t));
    }
    match media_type {
        crate::manifest::OCI_INDEX | crate::manifest::DOCKER_LIST => info(ArtifactKind::Index, "Multi-platform image", None),
        _ if artifact_type.is_some() => info(ArtifactKind::Artifact, "Artifact", Some(t)),
        _ => info(ArtifactKind::Image, "Container image", None),
    }
}

/// Classify a parsed manifest.
pub fn classify(manifest: &Manifest, media_type: &str) -> ArtifactInfo {
    match manifest {
        Manifest::Index(ix) => match ix.artifact_type.as_deref() {
            Some(t) => classify_media_type(media_type, Some(t)),
            None => info(ArtifactKind::Index, "Multi-platform image", None),
        },
        Manifest::Image(im) => classify_image(im),
    }
}

fn classify_image(im: &ImageManifest) -> ArtifactInfo {
    let config = im.config.media_type.as_str();
    if let Some(t) = im.artifact_type.as_deref() {
        let c = classify_media_type("", Some(t));
        if c.kind != ArtifactKind::Artifact {
            return c;
        }
    }
    if config == HELM_CONFIG {
        return info(ArtifactKind::HelmChart, "Helm chart", Some(config));
    }
    if is_wasm(config) || im.layers.iter().any(|l| is_wasm(&l.media_type)) {
        return info(ArtifactKind::Wasm, "WASM module", Some(config));
    }
    for l in &im.layers {
        if l.media_type == COSIGN_SIMPLE_SIGNING || l.media_type.starts_with(SIGSTORE_BUNDLE_PREFIX) {
            return info(ArtifactKind::Signature, "Signature", Some(&l.media_type));
        }
        if l.media_type == DSSE_ENVELOPE || l.media_type == IN_TOTO {
            return info(ArtifactKind::Attestation, "Attestation", Some(&l.media_type));
        }
        if let Some(f) = sbom_format(&l.media_type) {
            return info(ArtifactKind::Sbom, format!("SBOM ({f})"), Some(&l.media_type));
        }
    }
    let is_container = config.contains("container.image") || config == "application/vnd.oci.image.config.v1+json";
    match (im.artifact_type.as_deref(), is_container) {
        (Some(t), _) => info(ArtifactKind::Artifact, "Artifact", Some(t)),
        (None, true) => info(ArtifactKind::Image, "Container image", None),
        (None, false) => info(ArtifactKind::Artifact, "Artifact", Some(config)),
    }
}

/// cosign's tag convention for artifacts attached to `sha256:<hex>`: `sha256-<hex>.sig|.att|.sbom`.
pub fn cosign_tag_target(tag: &str) -> Option<(String, ArtifactKind)> {
    let (base, ext) = tag.rsplit_once('.')?;
    let kind = match ext {
        "sig" => ArtifactKind::Signature,
        "att" => ArtifactKind::Attestation,
        "sbom" => ArtifactKind::Sbom,
        _ => return None,
    };
    let hex = base.strip_prefix("sha256-")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| (format!("sha256:{hex}"), kind))
}


#[derive(Debug, Clone, Serialize)]
pub struct SbomPackage {
    pub name: String,
    pub version: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub purl: Option<String>,
    pub licenses: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Sbom {
    pub format: String,
    pub spec_version: Option<String>,
    pub created: Option<String>,
    pub tools: Vec<String>,
    pub packages: Vec<SbomPackage>,
}

fn s(v: &serde_json::Value) -> Option<String> {
    v.as_str().filter(|x| !x.is_empty() && *x != "NOASSERTION" && *x != "NONE").map(str::to_string)
}

/// Why a document could not be read as an SBOM.
#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    #[error("not JSON: {0}")]
    Json(serde_json::Error),
    #[error("bad DSSE payload: {0}")]
    DssePayload(base64::DecodeError),
    #[error("bad in-toto statement: {0}")]
    InToto(serde_json::Error),
    #[error("unrecognised SBOM format (expected CycloneDX or SPDX JSON)")]
    UnknownFormat,
}

/// Read a CycloneDX or SPDX JSON document into one package list. Also unwraps in-toto/DSSE
/// envelopes whose predicate is an SBOM (as produced by `cosign attest --type cyclonedx`).
pub fn parse_sbom(bytes: &[u8]) -> Result<Sbom, SbomError> {
    let mut doc: serde_json::Value = serde_json::from_slice(bytes).map_err(SbomError::Json)?;
    // DSSE envelope -> in-toto statement -> predicate.
    if let Some(payload) = doc.get("payload").and_then(|p| p.as_str()) {
        let raw = base64::engine::general_purpose::STANDARD.decode(payload).map_err(SbomError::DssePayload)?;
        doc = serde_json::from_slice(&raw).map_err(SbomError::InToto)?;
    }
    if doc.get("predicate").is_some() && doc.get("_type").is_some() {
        doc = doc["predicate"].clone();
    }
    if doc.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX") || doc.get("components").is_some() {
        let tools = doc["metadata"]["tools"]
            .as_array()
            .cloned()
            .or_else(|| doc["metadata"]["tools"]["components"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|t| s(&t["name"]).map(|n| match s(&t["version"]) { Some(v) => format!("{n} {v}"), None => n }))
            .collect();
        let packages = doc["components"]
            .as_array()
            .map(|cs| {
                cs.iter()
                    .filter_map(|c| {
                        Some(SbomPackage {
                            name: s(&c["name"])?,
                            version: s(&c["version"]),
                            kind: s(&c["type"]),
                            purl: s(&c["purl"]),
                            licenses: c["licenses"]
                                .as_array()
                                .map(|ls| ls.iter().filter_map(|l| s(&l["license"]["id"]).or_else(|| s(&l["license"]["name"])).or_else(|| s(&l["expression"]))).collect())
                                .unwrap_or_default(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        return Ok(Sbom { format: "CycloneDX".into(), spec_version: s(&doc["specVersion"]), created: s(&doc["metadata"]["timestamp"]), tools, packages });
    }
    if doc.get("spdxVersion").is_some() || doc.get("SPDXID").is_some() {
        let packages = doc["packages"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .filter_map(|p| {
                        let purl = p["externalRefs"].as_array().and_then(|refs| refs.iter().find(|r| r["referenceType"] == "purl").and_then(|r| s(&r["referenceLocator"])));
                        let license = s(&p["licenseConcluded"]).or_else(|| s(&p["licenseDeclared"]));
                        Some(SbomPackage { name: s(&p["name"])?, version: s(&p["versionInfo"]), kind: s(&p["primaryPackagePurpose"]), purl, licenses: license.into_iter().collect() })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let tools = doc["creationInfo"]["creators"].as_array().map(|cs| cs.iter().filter_map(s).collect()).unwrap_or_default();
        return Ok(Sbom { format: "SPDX".into(), spec_version: s(&doc["spdxVersion"]), created: s(&doc["creationInfo"]["created"]), tools, packages });
    }
    Err(SbomError::UnknownFormat)
}


/// The outcome of checking one signature. Serialized as the lowercase variant name
/// (`verified`, `invalid`, ...), which the UI relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureStatus {
    /// Signed by the key, for the expected digest.
    Verified,
    /// The signature does not match the key.
    Invalid,
    /// A valid signature by the key, but for another image.
    Mismatch,
    /// Certificate-based (Fulcio/Sigstore): not verified here.
    Keyless,
    /// The payload or signature cannot be decoded.
    Malformed,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureCheck {
    /// Digest of the signature manifest.
    pub signature: String,
    pub status: SignatureStatus,
    pub detail: String,
}

/// Verify one cosign simple-signing layer: `payload` is the layer blob, `sig_b64` the
/// `dev.cosignproject.cosign/signature` annotation. The payload must name `expected_digest`.
pub fn verify_cosign(payload: &[u8], sig_b64: &str, key: &p256::ecdsa::VerifyingKey, expected_digest: &str) -> (SignatureStatus, String) {
    use p256::ecdsa::signature::Verifier;
    let json: serde_json::Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(e) => return (SignatureStatus::Malformed, format!("payload is not JSON: {e}")),
    };
    let signed = json["critical"]["image"]["docker-manifest-digest"].as_str().unwrap_or_default();
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(sig_b64.trim()) else { return (SignatureStatus::Malformed, "signature is not base64".into()) };
    let sig = match p256::ecdsa::Signature::from_der(&raw).or_else(|_| p256::ecdsa::Signature::from_slice(&raw)) {
        Ok(s) => s,
        Err(_) => return (SignatureStatus::Malformed, "signature is not an ECDSA P-256 signature".into()),
    };
    if key.verify(payload, &sig).is_err() {
        return (SignatureStatus::Invalid, "signature does not match this public key".into());
    }
    if signed != expected_digest {
        return (SignatureStatus::Mismatch, format!("valid signature, but for {signed}"));
    }
    let identity = json["critical"]["identity"]["docker-reference"].as_str().unwrap_or_default();
    (SignatureStatus::Verified, if identity.is_empty() { "signed by this key".into() } else { format!("signed by this key for {identity}") })
}

/// A cosign public key (ECDSA P-256).
pub type PublicKey = p256::ecdsa::VerifyingKey;

/// The text is not a cosign public key.
#[derive(Debug, thiserror::Error)]
#[error("expected an ECDSA P-256 public key in PEM format (cosign.pub)")]
pub struct PublicKeyError(#[source] p256::pkcs8::spki::Error);

pub fn parse_public_key(pem: &str) -> Result<p256::ecdsa::VerifyingKey, PublicKeyError> {
    use p256::pkcs8::DecodePublicKey;
    p256::ecdsa::VerifyingKey::from_public_key_pem(pem.trim()).map_err(PublicKeyError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosign_tags() {
        let hex = "a".repeat(64);
        assert_eq!(cosign_tag_target(&format!("sha256-{hex}.sig")), Some((format!("sha256:{hex}"), ArtifactKind::Signature)));
        assert_eq!(cosign_tag_target(&format!("sha256-{hex}.att")).unwrap().1, ArtifactKind::Attestation);
        assert_eq!(cosign_tag_target("v1.2.sig"), None);
        assert_eq!(cosign_tag_target("latest"), None);
    }

    #[test]
    fn media_types() {
        assert_eq!(classify_media_type("x", Some("application/vnd.cyclonedx+json")).kind, ArtifactKind::Sbom);
        assert_eq!(classify_media_type("x", Some("application/spdx+json")).label, "SBOM (SPDX)");
        assert_eq!(classify_media_type("x", Some(COSIGN_SIG_ARTIFACT)).kind, ArtifactKind::Signature);
        assert_eq!(classify_media_type("x", Some(HELM_CONFIG)).kind, ArtifactKind::HelmChart);
        assert_eq!(classify_media_type(crate::manifest::OCI_INDEX, None).kind, ArtifactKind::Index);
        assert_eq!(classify_media_type(crate::manifest::OCI_MANIFEST, None).kind, ArtifactKind::Image);
    }

    #[test]
    fn sboms() {
        let cdx = br#"{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"tools":[{"name":"syft","version":"1.0"}]},"components":[{"type":"library","name":"openssl","version":"3.1","purl":"pkg:apk/alpine/openssl@3.1","licenses":[{"license":{"id":"Apache-2.0"}}]}]}"#;
        let s = parse_sbom(cdx).unwrap();
        assert_eq!((s.format.as_str(), s.packages.len(), s.tools[0].as_str()), ("CycloneDX", 1, "syft 1.0"));
        assert_eq!(s.packages[0].licenses, vec!["Apache-2.0"]);
        let spdx = br#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"creators":["Tool: syft"]},"packages":[{"name":"busybox","versionInfo":"1.36","licenseConcluded":"GPL-2.0-only","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/alpine/busybox@1.36"}]}]}"#;
        let s = parse_sbom(spdx).unwrap();
        assert_eq!((s.format.as_str(), s.packages[0].purl.as_deref()), ("SPDX", Some("pkg:apk/alpine/busybox@1.36")));
        assert!(parse_sbom(b"{}").is_err());
    }

    #[test]
    fn cosign_verify() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = *sk.verifying_key();
        let payload = br#"{"critical":{"identity":{"docker-reference":"reg/app"},"image":{"docker-manifest-digest":"sha256:abc"},"type":"cosign container image signature"}}"#;
        let sig: Signature = sk.sign(payload);
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes());
        assert_eq!(verify_cosign(payload, &b64, &vk, "sha256:abc").0, SignatureStatus::Verified);
        assert_eq!(verify_cosign(payload, &b64, &vk, "sha256:other").0, SignatureStatus::Mismatch);
        let other = *SigningKey::from_slice(&[9u8; 32]).unwrap().verifying_key();
        assert_eq!(verify_cosign(payload, &b64, &other, "sha256:abc").0, SignatureStatus::Invalid);
        assert_eq!(verify_cosign(payload, "!!", &vk, "sha256:abc").0, SignatureStatus::Malformed);
        // The wire format the UI matches on.
        assert_eq!(serde_json::to_value(SignatureStatus::Verified).unwrap(), "verified");
        assert_eq!(serde_json::to_value(SignatureStatus::Keyless).unwrap(), "keyless");
    }
}
