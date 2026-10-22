//! Pull policies: what a namespace refuses to serve. Vulnerabilities at or above a severity
//! (minus allowlisted CVEs), images not scanned yet, and images without a trusted signature.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use kontainer_core::config::Severity;
use kontainer_core::artifact::{self, ArtifactKind, PublicKey};
use kontainer_core::digest::Digest;
use kontainer_core::manifest::Manifest;
use crate::scan::{ScanReport, ScanStatus};

use crate::auth::Principal;
use crate::error::{Code, RegistryError, Result};
use crate::state::AppState;

/// Digests known to carry a trusted signature, per set of keys. Only positive answers are kept:
/// a signature, once there, stays, while an unsigned image may be signed at any moment.
#[derive(Clone, Default)]
pub struct SignedCache(Arc<Mutex<HashSet<(String, String)>>>);

impl SignedCache {
    fn has(&self, digest: &Digest, keys: &str) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).contains(&(digest.to_string(), keys.to_string()))
    }
    fn add(&self, digest: &Digest, keys: &str) {
        let mut set = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if set.len() > 50_000 {
            set.clear();
        }
        set.insert((digest.to_string(), keys.to_string()));
    }
}

fn denied(msg: String, detail: serde_json::Value) -> RegistryError {
    RegistryError::with_message(Code::Denied, msg).detail(detail)
}

/// The severity at or above which `namespace` refuses images, if any.
pub fn block_threshold(state: &AppState, policy: Option<&crate::database::security::SecurityPolicy>) -> Option<Severity> {
    match policy.and_then(|p| p.block_severity.as_deref()) {
        Some("none") => None,
        Some(s) => serde_json::from_value(serde_json::Value::String(s.to_string())).ok(),
        None => state.config.scanner.block_pull_at,
    }
}

/// May `who` pull manifest `digest` (`bytes`) from `repo`? `by_tag`: it was asked for by tag.
pub async fn check_pull(state: &AppState, who: &Principal, repo: &str, by_tag: bool, digest: &Digest, bytes: &[u8]) -> Result<()> {
    // The scanner pulls images to scan them: blocking it would keep them unscanned forever.
    // It is either the configured account or the registry's own scanner token (no account).
    let is_scanner_token = who.user_id.is_none() && who.username.as_deref() == Some(crate::auth::token::SVC_SCANNER);
    if is_scanner_token || state.config.scanner.username.as_deref().is_some_and(|u| who.username.as_deref() == Some(u)) {
        return Ok(());
    }
    let ns = kontainer_core::names::namespace(repo);
    let policy = state.auth.db.security_policy(ns).await?;
    let manifest = Manifest::parse(bytes, None).ok().map(|(m, _)| m);
    let is_image = matches!(manifest, Some(Manifest::Image(_)));

    // Vulnerabilities, per image (an index has no report of its own; its images are checked
    // when they are pulled).
    let threshold = block_threshold(state, policy.as_ref());
    let block_unscanned = policy.as_ref().is_some_and(|p| p.is_block_unscanned);
    if is_image && (threshold.is_some() || block_unscanned) {
        let report = match state.storage.get_scan(digest).await? {
            Some(raw) => serde_json::from_slice::<ScanReport>(&raw).ok(),
            None => None,
        };
        match &report {
            Some(r) if r.status == ScanStatus::Done => {
                if let Some(threshold) = threshold {
                    let allowed: HashSet<String> = state.auth.db.allowed_cves(ns).await?.into_iter().collect();
                    let mut blocking: Vec<&crate::scan::Vulnerability> = r.vulnerabilities.iter().filter(|v| v.severity >= threshold && !allowed.contains(&v.id)).collect();
                    if !blocking.is_empty() {
                        blocking.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
                        let ids: Vec<&str> = blocking.iter().map(|v| v.id.as_str()).collect();
                        let shown = ids.iter().take(5).copied().collect::<Vec<_>>().join(", ");
                        let more = if ids.len() > 5 { format!(" and {} more", ids.len() - 5) } else { String::new() };
                        return Err(denied(
                            format!("image blocked by the security policy of {ns}: {:?} vulnerabilities ({shown}{more})", blocking[0].severity),
                            serde_json::json!({ "digest": digest, "summary": r.summary, "blocking": ids }),
                        ));
                    }
                }
            }
            _ if block_unscanned => {
                let why = match &report {
                    Some(r) if r.status == ScanStatus::Failed => "its scan failed",
                    Some(_) => "it is still being scanned",
                    None => "it has not been scanned",
                };
                return Err(denied(format!("image blocked by the security policy of {ns}: {why}"), serde_json::json!({ "digest": digest })));
            }
            _ => {}
        }
    }

    // Signatures.
    if let Some(p) = policy.as_ref().filter(|p| p.is_require_signature) {
        // Keys are checked when the policy is saved; ones that no longer parse must not
        // quietly turn "signed by a trusted key" into "signed by anyone" (empty `keys`).
        let pems = match p.keys() {
            Ok(pems) => pems,
            Err(e) => {
                tracing::error!(namespace = ns, error = %e, "the security policy's trusted signing keys are corrupt; refusing pulls");
                return Err(denied(
                    format!("image blocked by the security policy of {ns}: its trusted signing keys are unreadable; a namespace administrator must save them again"),
                    serde_json::json!({ "digest": digest }),
                ));
            }
        };
        let mut keys: Vec<PublicKey> = Vec::with_capacity(pems.len());
        for (i, pem) in pems.iter().enumerate() {
            match artifact::parse_public_key(pem) {
                Ok(k) => keys.push(k),
                Err(e) => {
                    tracing::error!(namespace = ns, key = i + 1, error = %e, "a trusted signing key in the security policy does not parse; refusing pulls");
                    return Err(denied(
                        format!("image blocked by the security policy of {ns}: trusted signing key {} is invalid; a namespace administrator must fix it", i + 1),
                        serde_json::json!({ "digest": digest }),
                    ));
                }
            }
        }
        let cache_key = pems.join("\n");
        if !state.signed.has(digest, &cache_key) {
            if signed(state, repo, digest, &keys).await? {
                state.signed.add(digest, &cache_key);
            } else if by_tag || !signed_parent(state, repo, digest, &keys, &cache_key).await? {
                let what = if keys.is_empty() { "a cosign signature" } else { "a signature from one of its trusted keys" };
                return Err(denied(format!("image blocked by the security policy of {ns}: it has no {what}"), serde_json::json!({ "digest": digest })));
            }
        }
        // The images inside a signed index are fetched next, by digest: let them through.
        if let Some(Manifest::Index(ix)) = &manifest {
            for m in &ix.manifests {
                state.signed.add(&m.digest, &cache_key);
            }
        }
    }
    Ok(())
}

/// Is `digest` signed, by one of `keys` if any are given? An empty `keys` means none are
/// configured (any signature will do); `check_pull` refuses before getting here when keys are
/// configured but do not parse.
async fn signed(state: &AppState, repo: &str, digest: &Digest, keys: &[PublicKey]) -> Result<bool> {
    let sigs = crate::api::ext::artifacts::attached(state, repo, digest).await?;
    if !sigs.iter().any(|a| a.artifact.kind == ArtifactKind::Signature) {
        return Ok(false);
    }
    if keys.is_empty() {
        return Ok(true);
    }
    for key in keys {
        if crate::api::ext::artifacts::signature_checks(state, repo, digest, key).await?.iter().any(|c| c.status == artifact::SignatureStatus::Verified) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Is `digest` an image inside a signed index in `repo`? (Pulled by digest without its index
/// first, e.g. after a restart.)
async fn signed_parent(state: &AppState, repo: &str, digest: &Digest, keys: &[PublicKey], cache_key: &str) -> Result<bool> {
    for m in state.storage.metadata().manifests(repo).await? {
        let d = m.digest;
        let Ok((Manifest::Index(ix), _)) = Manifest::parse(&m.body, None) else { continue };
        if ix.manifests.iter().any(|m| &m.digest == digest) && (state.signed.has(&d, cache_key) || signed(state, repo, &d, keys).await?) {
            state.signed.add(&d, cache_key);
            state.signed.add(digest, cache_key);
            return Ok(true);
        }
    }
    Ok(false)
}
