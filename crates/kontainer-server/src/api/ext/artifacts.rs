//! Artifact views: what is attached to a manifest (signatures, SBOMs, attestations), the SBOM
//! reader, cosign verification and image comparison.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::resolve;
use kontainer_core::artifact::{self, ArtifactInfo, ArtifactKind, SignatureStatus};
use kontainer_core::perm::Action;
use crate::auth::{require, Principal};
use kontainer_core::digest::Digest;
use crate::error::{Code, RegistryError, Result};
use kontainer_core::manifest::{ImageConfig, ImageManifest, Manifest};
use crate::state::AppState;

/// Largest SBOM document we parse in the request path.
const MAX_SBOM_BYTES: u64 = 32 * 1024 * 1024;


/// Something attached to a manifest: an OCI referrer or a cosign `sha256-<hex>.<sig|att|sbom>` tag.
#[derive(Debug, Clone, Serialize)]
pub struct Attached {
    pub digest: String,
    #[serde(flatten)]
    pub artifact: ArtifactInfo,
    /// Set for cosign tag-style attachments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

pub async fn attached(state: &AppState, name: &str, digest: &Digest) -> Result<Vec<Attached>> {
    let mut out = vec![];
    for r in state.storage.list_referrers(name, digest, None).await? {
        if let Some(d) = super::super::v2::describe(&r) {
            let mut a = artifact::classify_media_type(&d.media_type, d.artifact_type.as_deref());
            // Referrers without an artifactType: look inside to classify.
            if a.kind == ArtifactKind::Image {
                if let Ok((m, mt)) = Manifest::parse(&r.body, None) {
                    a = artifact::classify(&m, &mt);
                }
            }
            out.push(Attached { digest: d.digest.to_string(), artifact: a, tag: None, size: d.size, annotations: d.annotations });
        }
    }
    let target = digest.to_string();
    for t in state.storage.list_tags_resolved(name).await? {
        if let Some((for_digest, kind)) = artifact::cosign_tag_target(&t.tag) {
            if for_digest == target && !out.iter().any(|a| a.digest == t.digest.to_string()) {
                let size = state.storage.manifest(name, &t.digest).await?.map_or(0, |m| m.size());
                let label = match kind {
                    ArtifactKind::Signature => "Signature (cosign)",
                    ArtifactKind::Attestation => "Attestation (cosign)",
                    _ => "SBOM (cosign)",
                };
                out.push(Attached { digest: t.digest.to_string(), artifact: ArtifactInfo { kind, label: label.into(), media_type: None }, tag: Some(t.tag), size, annotations: None });
            }
        }
    }
    Ok(out)
}

/// A manifest of repository `name`: refused unless the repository has it (a digest named in
/// another document, such as an index child, must not read content from elsewhere).
async fn load_manifest(state: &AppState, name: &str, digest: &Digest) -> Result<(Manifest, String)> {
    let b = state.storage.manifest_bytes(name, digest).await?.ok_or_else(|| RegistryError::new(Code::ManifestUnknown))?;
    Manifest::parse(&b, None).map_err(|e| RegistryError::with_message(Code::ManifestInvalid, e.to_string()))
}

/// GET .../manifests/{ref}/sbom: the SBOM document inside an SBOM artifact (or attestation).
pub async fn sbom(state: AppState, p: Principal, name: String, reference: String) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let (_, bytes) = resolve(&state, &name, &reference).await?;
    let Ok((Manifest::Image(im), _)) = Manifest::parse(&bytes, None) else { return Err(RegistryError::bad_request("an SBOM is a single manifest, not an index")) };
    // Prefer a layer with an SBOM media type, then DSSE/in-toto, then any JSON layer.
    let pick = im
        .layers
        .iter()
        .find(|l| artifact::classify_media_type(&l.media_type, None).kind == ArtifactKind::Sbom)
        .or_else(|| im.layers.iter().find(|l| l.media_type == artifact::DSSE_ENVELOPE || l.media_type.contains("in-toto")))
        .or_else(|| im.layers.iter().find(|l| l.media_type.contains("json")))
        .ok_or_else(|| RegistryError::bad_request("this artifact has no SBOM document"))?;
    // The descriptor's size is the client's claim: the limit applies to what is stored, and
    // only a blob this repository links may be read.
    let Some(size) = state.storage.repo_blob_size(&name, &pick.digest).await? else {
        return Err(RegistryError::new(Code::BlobUnknown).detail(serde_json::json!({ "digest": pick.digest })));
    };
    if size > MAX_SBOM_BYTES {
        return Err(RegistryError::bad_request(format!("SBOM is too large to display ({} MB)", size / 1024 / 1024)));
    }
    let doc = state.storage.blob_bytes(&pick.digest).await?.ok_or_else(|| RegistryError::new(Code::BlobUnknown))?;
    let parsed = artifact::parse_sbom(&doc).map_err(|e| RegistryError::bad_request(e.to_string()))?;
    Ok(Json(serde_json::json!({ "document": pick.digest.to_string(), "media_type": pick.media_type, "sbom": parsed })).into_response())
}

#[derive(Deserialize)]
pub struct VerifyBody {
    public_key: String,
}

/// POST .../manifests/{ref}/verify: check every cosign signature attached to the manifest
/// against a public key.
pub async fn verify(state: AppState, p: Principal, name: String, reference: String, body: &[u8]) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let body: VerifyBody = serde_json::from_slice(body).map_err(|e| RegistryError::bad_request(format!("invalid body: {e}")))?;
    let key = artifact::parse_public_key(&body.public_key).map_err(|e| RegistryError::bad_request(e.to_string()))?;
    let (digest, _) = resolve(&state, &name, &reference).await?;
    let expected = digest.to_string();
    let checks = signature_checks(&state, &name, &digest, &key).await?;
    let verified = checks.iter().any(|c| c.status == SignatureStatus::Verified);
    Ok(Json(serde_json::json!({ "digest": expected, "verified": verified, "signatures": checks })).into_response())
}

/// Check every cosign signature attached to `digest` in `name` against `key`.
pub async fn signature_checks(state: &AppState, name: &str, digest: &Digest, key: &artifact::PublicKey) -> Result<Vec<artifact::SignatureCheck>> {
    let expected = digest.to_string();
    let mut checks = vec![];
    for a in attached(state, name, digest).await?.into_iter().filter(|a| a.artifact.kind == ArtifactKind::Signature) {
        let sig_digest: Digest = a.digest.parse().map_err(|_| RegistryError::new(Code::DigestInvalid))?;
        let Ok((Manifest::Image(sm), _)) = load_manifest(state, name, &sig_digest).await else { continue };
        for l in &sm.layers {
            let ann = l.annotations.clone().unwrap_or_default();
            let (status, detail) = if l.media_type.starts_with(artifact::SIGSTORE_BUNDLE_PREFIX) {
                (SignatureStatus::Keyless, "Sigstore bundle; keyless verification is not supported here".to_string())
            } else if let Some(sig) = ann.get(artifact::COSIGN_SIGNATURE_ANNOTATION) {
                // Only a payload this repository links: the digest comes from the signature manifest.
                let payload = match state.storage.repo_blob_size(name, &l.digest).await? {
                    Some(_) => state.small_blob(&l.digest).await?,
                    None => None,
                };
                match payload {
                    Some(payload) => {
                        let (st, d) = artifact::verify_cosign(&payload, sig, key, &expected);
                        // A certificate means keyless signing; a key mismatch then is expected.
                        if st == SignatureStatus::Invalid && ann.contains_key(artifact::COSIGN_CERT_ANNOTATION) {
                            (SignatureStatus::Keyless, "Signed with a Fulcio certificate (keyless); verify with cosign".to_string())
                        } else {
                            (st, d)
                        }
                    }
                    None => (SignatureStatus::Malformed, "signature payload blob is missing or too large".to_string()),
                }
            } else {
                continue;
            };
            checks.push(artifact::SignatureCheck { signature: a.digest.clone(), status, detail });
        }
    }
    Ok(checks)
}

// Comparison
#[derive(Serialize)]
struct Side {
    reference: String,
    digest: String,
    platform: Option<String>,
    created: Option<String>,
    size: u64,
    layers: usize,
}

#[derive(Serialize)]
struct LayerRow {
    /// `shared` (same position in both), `changed` (same position and command, different
    /// content: a rebuild), `removed` (only in A), `added` (only in B), or `moved` (present in
    /// both but at a different position).
    status: &'static str,
    digest: String,
    size: u64,
    created_by: Option<String>,
    /// For `changed`: what A had there.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_digest: Option<String>,
}

#[derive(Serialize)]
struct Change {
    field: String,
    before: Option<String>,
    after: Option<String>,
}

struct Loaded {
    digest: Digest,
    platform: Option<String>,
    manifest: ImageManifest,
    config: Option<ImageConfig>,
}

/// Resolve a reference to one image, picking `platform` (or the first real platform) from an index.
async fn load_image(state: &AppState, name: &str, reference: &str, platform: Option<&str>) -> Result<Loaded> {
    let (mut digest, bytes) = resolve(state, name, reference).await?;
    let (mut m, _) = Manifest::parse(&bytes, None).map_err(|e| RegistryError::with_message(Code::ManifestInvalid, e.to_string()))?;
    let mut plat = None;
    if let Manifest::Index(ix) = &m {
        let label = |c: &kontainer_core::manifest::Descriptor| c.platform.as_ref().map(|p| match &p.variant { Some(v) => format!("{}/{}/{v}", p.os, p.architecture), None => format!("{}/{}", p.os, p.architecture) });
        let real: Vec<_> = ix.manifests.iter().filter(|c| c.platform.as_ref().is_some_and(|p| p.os != "unknown")).collect();
        let child = platform
            .and_then(|want| real.iter().find(|c| label(c).as_deref() == Some(want)))
            .or_else(|| real.iter().find(|c| label(c).as_deref() == Some("linux/amd64")))
            .or_else(|| real.first())
            .ok_or_else(|| RegistryError::bad_request(format!("{reference} has no platform images")))?;
        plat = label(child);
        digest = child.digest.clone();
        m = load_manifest(state, name, &digest).await?.0;
    }
    let Manifest::Image(im) = m else { return Err(RegistryError::bad_request("nested indexes are not supported")) };
    let config = match state.storage.repo_blob_size(name, &im.config.digest).await? {
        Some(_) => state.small_blob(&im.config.digest).await?.and_then(|b| serde_json::from_slice::<ImageConfig>(&b).ok()),
        None => None,
    };
    if plat.is_none() {
        plat = config.as_ref().and_then(|c| Some(format!("{}/{}", c.os.as_deref()?, c.architecture.as_deref()?)));
    }
    Ok(Loaded { digest, platform: plat, manifest: *im, config })
}

fn side(reference: &str, l: &Loaded) -> Side {
    Side {
        reference: reference.to_string(),
        digest: l.digest.to_string(),
        platform: l.platform.clone(),
        created: l.config.as_ref().and_then(|c| c.created.clone()),
        size: l.manifest.config.size + l.manifest.layers.iter().map(|x| x.size).sum::<u64>(),
        layers: l.manifest.layers.len(),
    }
}

fn layer_commands(l: &Loaded) -> Vec<Option<String>> {
    let mut hist = l.config.as_ref().map(|c| c.history.iter().filter(|h| !h.is_empty_layer).map(|h| h.created_by.clone()).collect::<Vec<_>>()).unwrap_or_default().into_iter();
    l.manifest.layers.iter().map(|_| hist.next().flatten()).collect()
}

fn map_diff(field: &str, a: &BTreeMap<String, String>, b: &BTreeMap<String, String>, out: &mut Vec<Change>) {
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    for k in keys {
        let (x, y) = (a.get(k), b.get(k));
        if x != y {
            out.push(Change { field: format!("{field} {k}"), before: x.cloned(), after: y.cloned() });
        }
    }
}

fn env_map(c: Option<&ImageConfig>) -> BTreeMap<String, String> {
    c.and_then(|c| c.config.as_ref())
        .and_then(|c| c.env.as_ref())
        .map(|e| e.iter().map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())).unwrap_or((kv.clone(), String::new()))).collect())
        .unwrap_or_default()
}

/// GET .../compare?a=<ref>&b=<ref>[&platform=linux/arm64]
pub async fn compare(state: AppState, p: Principal, name: String, query: HashMap<String, String>) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let (Some(ra), Some(rb)) = (query.get("a"), query.get("b")) else { return Err(RegistryError::bad_request("pass two references as ?a=...&b=...")) };
    let platform = query.get("platform").map(String::as_str).filter(|s| !s.is_empty());
    let a = load_image(&state, &name, ra, platform).await?;
    // Compare like with like: B uses A's platform when it is an index.
    let b = load_image(&state, &name, rb, platform.or(a.platform.as_deref())).await?;

    let (la, lb) = (&a.manifest.layers, &b.manifest.layers);
    let (ca, cb) = (layer_commands(&a), layer_commands(&b));
    let prefix = la.iter().zip(lb).take_while(|(x, y)| x.digest == y.digest).count();
    let in_a: HashMap<String, usize> = la.iter().enumerate().map(|(i, l)| (l.digest.to_string(), i)).collect();
    let in_b: BTreeSet<String> = lb.iter().map(|l| l.digest.to_string()).collect();
    let row = |status, l: &kontainer_core::manifest::Descriptor, created_by: &Option<String>| LayerRow { status, digest: l.digest.to_string(), size: l.size, created_by: created_by.clone(), previous_size: None, previous_digest: None };
    let mut layers = vec![];
    for i in 0..prefix {
        layers.push(row("shared", &la[i], &ca[i]));
    }
    // After the common prefix, position by position. A rebuilt step (same command, new bytes:
    // timestamps, `uname`) is one changed layer, not a removal and an addition.
    for i in prefix..la.len().max(lb.len()) {
        let (a, b) = (la.get(i), lb.get(i));
        if let (Some(a), Some(b)) = (a, b) {
            let same_step = ca[i].is_some() && ca[i] == cb[i];
            if same_step && !in_b.contains(&a.digest.to_string()) && !in_a.contains_key(&b.digest.to_string()) {
                layers.push(LayerRow { previous_size: Some(a.size), previous_digest: Some(a.digest.to_string()), ..row("changed", b, &cb[i]) });
                continue;
            }
        }
        if let Some(a) = a {
            layers.push(row(if in_b.contains(&a.digest.to_string()) { "moved" } else { "removed" }, a, &ca[i]));
        }
        if let Some(b) = b {
            if !in_a.contains_key(&b.digest.to_string()) {
                layers.push(row("added", b, &cb[i]));
            }
        }
    }

    let mut changes = vec![];
    let (xa, xb) = (a.config.as_ref().and_then(|c| c.config.as_ref()), b.config.as_ref().and_then(|c| c.config.as_ref()));
    let join = |v: Option<&Vec<String>>| v.map(|v| v.join(" "));
    // An empty value and a missing one mean the same ("not set").
    let scalar = |field: &str, x: Option<String>, y: Option<String>, out: &mut Vec<Change>| {
        let (x, y) = (x.filter(|v| !v.is_empty()), y.filter(|v| !v.is_empty()));
        if x != y {
            out.push(Change { field: field.into(), before: x, after: y });
        }
    };
    scalar("Platform", a.platform.clone(), b.platform.clone(), &mut changes);
    scalar("Entrypoint", join(xa.and_then(|c| c.entrypoint.as_ref())), join(xb.and_then(|c| c.entrypoint.as_ref())), &mut changes);
    scalar("Cmd", join(xa.and_then(|c| c.cmd.as_ref())), join(xb.and_then(|c| c.cmd.as_ref())), &mut changes);
    scalar("WorkingDir", xa.and_then(|c| c.working_dir.clone()), xb.and_then(|c| c.working_dir.clone()), &mut changes);
    scalar("User", xa.and_then(|c| c.user.clone()), xb.and_then(|c| c.user.clone()), &mut changes);
    let ports = |c: Option<&kontainer_core::manifest::ContainerConfig>| c.and_then(|c| c.exposed_ports.as_ref()).map(|p| p.keys().cloned().collect::<Vec<_>>().join(", ")).filter(|s| !s.is_empty());
    scalar("ExposedPorts", ports(xa), ports(xb), &mut changes);
    map_diff("Env", &env_map(a.config.as_ref()), &env_map(b.config.as_ref()), &mut changes);
    let labels = |c: Option<&kontainer_core::manifest::ContainerConfig>| c.and_then(|c| c.labels.clone()).unwrap_or_default().into_iter().collect::<BTreeMap<_, _>>();
    map_diff("Label", &labels(xa), &labels(xb), &mut changes);

    let (sa, sb) = (side(ra, &a), side(rb, &b));
    let shared_bytes: u64 = lb.iter().filter(|l| in_a.contains_key(&l.digest.to_string())).map(|l| l.size).sum();
    Ok(Json(serde_json::json!({
        "a": sa, "b": sb,
        "size_delta": sb.size as i64 - sa.size as i64,
        "shared_bytes": shared_bytes,
        "layers": layers,
        "changes": changes,
    }))
    .into_response())
}
