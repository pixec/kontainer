use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;

use super::Ctx;
use crate::sync::ProxyError;
use crate::auth::require;
use kontainer_core::perm::Action;
use kontainer_core::digest::Digest;
use crate::error::{Code, RegistryError, Result};
use kontainer_core::manifest::{self, Manifest};
use kontainer_core::names::Reference;
use kontainer_store::metadata::{PutManifest, StoredManifest};
use crate::webhook::Event;

/// A tag or digest from the path. One that is neither is `DIGEST_INVALID` when it looks like a
/// digest (has a `:`), else `TAG_INVALID`.
fn parse_reference(r: &str) -> Result<Reference> {
    Reference::parse(r).ok_or_else(|| {
        let code = if r.contains(':') { Code::DigestInvalid } else { Code::TagInvalid };
        RegistryError::with_message(code, "invalid reference").detail(serde_json::json!({ "reference": r }))
    })
}

/// Resolve a tag or digest to a digest that exists in the repository.
pub async fn resolve(ctx: &Ctx, reference: &Reference) -> Result<Digest> {
    let storage = &ctx.state.storage;
    let digest = match reference {
        Reference::Digest(d) => d.clone(),
        Reference::Tag(t) => storage
            .resolve_tag(&ctx.name, t)
            .await?
            .ok_or_else(|| RegistryError::new(Code::ManifestUnknown).detail(serde_json::json!({ "tag": t })))?,
    };
    if !storage.has_manifest(&ctx.name, &digest).await? {
        return Err(RegistryError::new(Code::ManifestUnknown).detail(serde_json::json!({ "digest": digest })));
    }
    Ok(digest)
}

/// Is `s` a well-formed media type (RFC 6838 `type/subtype`, optionally with `; name=value`
/// parameters)? Stored media types end up in `Content-Type` response headers, so anything
/// else (control characters, newlines) is refused at push time.
pub fn is_valid_media_type(s: &str) -> bool {
    fn restricted_name(n: &str) -> bool {
        let b = n.as_bytes();
        !b.is_empty() && b.len() <= 127 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(c))
    }
    // RFC 7230 token characters, for parameter names and unquoted values.
    fn token(t: &str) -> bool {
        !t.is_empty() && t.bytes().all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
    }
    let mut parts = s.split(';');
    let Some((ty, sub)) = parts.next().unwrap_or_default().split_once('/') else { return false };
    if !restricted_name(ty) || !restricted_name(sub) {
        return false;
    }
    parts.all(|p| p.trim().split_once('=').is_some_and(|(k, v)| token(k) && token(v)))
}

/// A header value from a string we built from validated parts (digests, repository names).
fn header_value(s: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(s).map_err(RegistryError::internal)
}

/// Media type of stored manifest bytes.
pub fn media_type_of(bytes: &[u8]) -> String {
    match Manifest::parse(bytes, None) {
        Ok((_, mt)) => mt,
        Err(_) => {
            let v: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
            if v.get("manifests").is_some() { manifest::OCI_INDEX.into() } else { manifest::OCI_MANIFEST.into() }
        }
    }
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-manifests (end-3)
pub async fn get(ctx: Ctx, reference: String, head: bool) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Pull, &ctx.name)?;
    let reference = parse_reference(&reference)?;
    // Pull-through cache namespaces fetch from their upstream on demand. A cached copy is
    // served when the upstream is down, so an error here means there is nothing to serve.
    match crate::sync::proxy_manifest(&ctx.state, &ctx.name, &reference).await {
        Ok(()) => {}
        Err(e @ ProxyError::NotFound(_)) => tracing::debug!(repo = %ctx.name, reference = %reference_str(&reference), error = %e, "pull-through cache miss"),
        Err(e @ ProxyError::Failed(_)) => return Err(RegistryError::upstream_unavailable(e)),
    }
    let digest = resolve(&ctx, &reference).await?;
    let Some(row) = ctx.state.storage.manifest(&ctx.name, &digest).await? else {
        return Err(RegistryError::new(Code::ManifestUnknown));
    };
    let bytes = row.body.clone();

    // Security policy: vulnerabilities, unscanned images, signatures.
    crate::policy::check_pull(&ctx.state, &ctx.principal, &ctx.name, matches!(reference, Reference::Tag(_)), &digest, &bytes).await?;

    if !head && ctx.state.audit.log_pulls {
        ctx.state.audit.record(&ctx.principal, "pull", Some(&ctx.name), Some(&reference_str(&reference)), Some(&digest.to_string()), None);
    }
    if !head && ctx.state.webhooks.wants("pull") {
        ctx.state.webhooks.fire(Event::pull(&ctx.name, &reference_str(&reference), &digest, ctx.principal.name()));
    }
    // A body without `mediaType` is served with the Content-Type it was pushed with.
    let media_type = match manifest::body_media_type(&bytes) {
        Some(_) => media_type_of(&bytes),
        None => row.media_type,
    };
    let mut headers = HeaderMap::new();
    // Pushes validate the media type, but manifests stored before that (or by the pull-through
    // cache) may carry anything: fall back to the OCI default rather than fail every pull.
    let content_type = HeaderValue::from_str(&media_type).ok().filter(|_| is_valid_media_type(&media_type)).unwrap_or_else(|| {
        tracing::warn!(repo = %ctx.name, %digest, "stored manifest has an invalid media type; serving it as an OCI manifest");
        HeaderValue::from_static(if media_type.contains("index") || media_type.contains("list") { manifest::OCI_INDEX } else { manifest::OCI_MANIFEST })
    });
    headers.insert(header::CONTENT_TYPE, content_type);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    headers.insert("Docker-Content-Digest", header_value(&digest.to_string())?);
    headers.insert(header::ETAG, header_value(&format!("\"{digest}\""))?);
    if head {
        return Ok((StatusCode::OK, headers).into_response());
    }
    Ok((StatusCode::OK, headers, bytes).into_response())
}

/// Tags accepted on one push by digest (`?tag=a&tag=b`); the spec asks for at least 10.
const MAX_TAG_PARAMS: usize = 64;

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-manifests (end-7a, end-7b)
pub async fn put(ctx: Ctx, reference: String, body: Body) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Push, &ctx.name)?;
    ctx.state.require_writable(&ctx.name).await?;
    let reference = parse_reference(&reference)?;
    let storage = &ctx.state.storage;
    let max = ctx.state.config.server.max_manifest_size;

    let bytes = http_body_util::Limited::new(body, max as usize)
        .collect()
        .await
        .map_err(|_| RegistryError::with_message(Code::ManifestInvalid, "manifest too large").status(StatusCode::PAYLOAD_TOO_LARGE))?
        .to_bytes();

    let content_type = ctx.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
    let (parsed, media_type) = Manifest::parse(&bytes, content_type)
        .map_err(|e| RegistryError::with_message(Code::ManifestInvalid, e.to_string()))?;
    if !is_valid_media_type(&media_type) {
        return Err(RegistryError::with_message(Code::ManifestInvalid, "mediaType is not a valid media type").detail(serde_json::json!({ "mediaType": media_type })));
    }
    // The body's `mediaType` and a manifest `Content-Type` must agree (spec: the registry
    // should reject a mismatch rather than guess which one the client meant).
    let body_media_type = manifest::body_media_type(&bytes);
    if let (Some(body), Some(ct)) = (&body_media_type, content_type.filter(|c| manifest::is_manifest_media_type(c))) {
        if !manifest::essence(body).eq_ignore_ascii_case(manifest::essence(ct)) {
            return Err(RegistryError::with_message(Code::ManifestInvalid, "mediaType does not match the Content-Type header").detail(serde_json::json!({ "mediaType": body, "contentType": ct })));
        }
    }

    // Pushed by digest: verify with that digest's algorithm (sha512 too). The canonical
    // digest the manifest is stored under is then that one.
    let digest = match &reference {
        Reference::Digest(d) => {
            let mut h = Digest::hasher(d.algorithm());
            h.update(&bytes);
            let actual = h.finalize();
            if *d != actual {
                return Err(RegistryError::new(Code::DigestInvalid).detail(serde_json::json!({ "expected": d, "actual": actual })));
            }
            actual
        }
        Reference::Tag(_) => Digest::sha256_of(&bytes),
    };

    // Every referenced blob must already be in this repository.
    let mut missing = vec![];
    for d in parsed.required_blobs() {
        if storage.repo_blob_size(&ctx.name, &d.digest).await?.is_none() {
            missing.push(serde_json::json!({ "digest": d.digest, "mediaType": d.media_type }));
        }
    }
    for d in parsed.child_manifests() {
        if !storage.has_manifest(&ctx.name, &d.digest).await? {
            missing.push(serde_json::json!({ "digest": d.digest, "mediaType": d.media_type }));
        }
    }
    if !missing.is_empty() {
        return Err(RegistryError::new(Code::ManifestBlobUnknown).detail(missing));
    }

    // Namespace storage quota: what this manifest adds that the namespace does not already hold.
    let namespace = kontainer_core::names::namespace(&ctx.name);
    if let Some(quota) = ctx.state.quota_for(namespace).await?.max_bytes {
        // Cached per namespace for a short while (see `namespace_missing`): a soft quota.
        let claimed: std::collections::HashMap<Digest, u64> = parsed.required_blobs().into_iter().map(|d| (d.digest.clone(), d.size)).collect();
        let mut wanted: Vec<Digest> = claimed.keys().cloned().collect();
        wanted.push(digest.clone());
        let (used, missing) = kontainer_store::usage::namespace_missing(storage, namespace, wanted).await?;
        let mut adding = Vec::with_capacity(missing.len());
        for d in missing {
            let n = if d == digest { bytes.len() as u64 } else { storage.repo_blob_size(&ctx.name, &d).await?.unwrap_or_else(|| claimed.get(&d).copied().unwrap_or(0)) };
            adding.push((d, n));
        }
        let added: u64 = adding.iter().map(|(_, n)| n).sum();
        if added > 0 && used + added > quota {
            ctx.state.webhooks.fire(Event::quota(true, &ctx.name, used, quota, added, ctx.principal.name()));
            return Err(RegistryError::with_message(
                Code::Denied,
                format!("storage quota exceeded for {namespace}: {} used of {}, this push adds {}", kontainer_store::usage::human(used), kontainer_store::usage::human(quota), kontainer_store::usage::human(added)),
            ));
        }
        // Crossing 90% with this push.
        if added > 0 && (used + added) * 10 > quota * 9 && used * 10 <= quota * 9 {
            ctx.state.webhooks.fire(Event::quota(false, &ctx.name, used, quota, added, ctx.principal.name()));
        }
        kontainer_store::usage::record_namespace_blobs(storage, namespace, adding);
    }

    // Immutable tags cannot be re-pointed. A push by digest may name tags as `?tag=` parameters
    // (distribution-spec end-7b); they are validated and checked here and set after the store.
    let extra_tags: Vec<String> = match &reference {
        Reference::Digest(_) => ctx.query_all("tag"),
        Reference::Tag(_) => vec![],
    };
    if extra_tags.len() > MAX_TAG_PARAMS {
        return Err(RegistryError::with_message(Code::TagInvalid, format!("at most {MAX_TAG_PARAMS} tags per push")).status(StatusCode::URI_TOO_LONG));
    }
    if let Some(bad) = extra_tags.iter().find(|t| !kontainer_core::names::is_valid_tag(t)) {
        return Err(RegistryError::new(Code::TagInvalid).detail(serde_json::json!({ "tag": bad })));
    }
    if let Reference::Tag(t) = &reference {
        ctx.state.check_tag_change(&ctx.name, t, &digest).await?;
    }
    for t in &extra_tags {
        ctx.state.check_tag_change(&ctx.name, t, &digest).await?;
    }

    // The manifest, its tag and the refreshed links of the blobs it references, in one
    // transaction: every instance sees all of it or nothing. The blobs and children are checked
    // again there (a garbage collection may have removed a link since the check above).
    let row = StoredManifest { subject: parsed.subject().map(|s| s.digest.clone()), artifact_type: parsed.artifact_type(), ..StoredManifest::new(digest.clone(), media_type.clone(), bytes.clone()) };
    let blobs: Vec<Digest> = parsed.required_blobs().iter().map(|d| d.digest.clone()).collect();
    let children: Vec<Digest> = parsed.child_manifests().iter().map(|d| d.digest.clone()).collect();
    let tag_name = match &reference {
        Reference::Tag(t) => Some(t.as_str()),
        Reference::Digest(_) => None,
    };
    let previous = match storage.put_manifest(&ctx.name, &row, &blobs, &children, tag_name).await? {
        PutManifest::Stored { previous_tag } => previous_tag,
        PutManifest::Missing(gone) => {
            let detail: Vec<serde_json::Value> = parsed
                .required_blobs()
                .into_iter()
                .chain(parsed.child_manifests())
                .filter(|d| gone.contains(&d.digest))
                .map(|d| serde_json::json!({ "digest": d.digest, "mediaType": d.media_type }))
                .collect();
            return Err(RegistryError::new(Code::ManifestBlobUnknown).detail(detail));
        }
    };
    let tag = match &reference {
        Reference::Tag(t) => {
            crate::tags::record_set(&ctx.state, &ctx.name, t, &digest, previous, "push", ctx.principal.name()).await?;
            // `quay.expires-after` on the image config: the tag deletes itself after that long.
            if let Manifest::Image(im) = &parsed {
                if let Some(cfg) = ctx.state.small_blob(&im.config.digest).await? {
                    let v: serde_json::Value = serde_json::from_slice(&cfg).unwrap_or_default();
                    if let Some(after) = v["config"]["Labels"]["quay.expires-after"].as_str().and_then(crate::tags::parse_expires_after) {
                        ctx.state.auth.db.set_tag_expiration(&ctx.name, t, Some(chrono::Utc::now() + after), "label").await?;
                    }
                }
            }
            Some(t.clone())
        }
        Reference::Digest(_) => None,
    };

    for t in &extra_tags {
        let previous = storage.put_tag(&ctx.name, t, &digest).await?;
        crate::tags::record_set(&ctx.state, &ctx.name, t, &digest, previous, "push", ctx.principal.name()).await?;
    }

    let mut headers = HeaderMap::new();
    for t in &extra_tags {
        headers.append("OCI-Tag", header_value(t)?);
    }
    headers.insert(header::LOCATION, header_value(&format!("/v2/{}/manifests/{digest}", ctx.name))?);
    headers.insert("Docker-Content-Digest", header_value(&digest.to_string())?);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(0));
    // `OCI-Subject` tells the client the referrers API indexed this manifest, so it need not
    // maintain the `sha256-<hex>` fallback tag: only true when that API is on.
    if let (Some(subject), true) = (parsed.subject(), ctx.state.config.features.is_referrers) {
        headers.insert("OCI-Subject", header_value(&subject.digest.to_string())?);
    }

    if let (Some(q), Manifest::Image(_), true) = (&ctx.state.scans, &parsed, ctx.state.config.scanner.is_scan_on_push) {
        q.enqueue_as(storage, &ctx.name, &digest, crate::scan::queue::Origin::Automatic).await;
    }
    // First manifest in a repository: remember it exists, and a Creator team member
    // who pushed it into existence becomes its admin.
    if ctx.principal.creates(&ctx.name) {
        if let Some(uid) = ctx.principal.user_id {
            ctx.state.auth.db.set_user_grant(&ctx.name, uid, Some(kontainer_core::perm::Level::ADMIN)).await?;
        }
    }
    ctx.state.auth.note_repo(&ctx.name, true).await;
    ctx.state.reindex(&ctx.name).await;
    ctx.state.webhooks.fire(Event::push(&ctx.name, tag.as_deref(), &digest, &media_type, ctx.principal.name()));
    ctx.state.audit.record(&ctx.principal, "push", Some(&ctx.name), Some(&reference_str(&reference)), Some(&digest.to_string()), Some(media_type.clone()));
    tracing::info!(repo = %ctx.name, ?tag, %digest, user = ctx.principal.name(), "manifest pushed");

    Ok((StatusCode::CREATED, headers).into_response())
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#deleting-manifests (end-9)
pub async fn delete(ctx: Ctx, reference: String) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Delete, &ctx.name)?;
    ctx.state.require_writable(&ctx.name).await?;
    if !ctx.state.config.features.is_delete {
        return Err(RegistryError::new(Code::Unsupported));
    }
    let reference = parse_reference(&reference)?;
    let storage = &ctx.state.storage;
    match &reference {
        Reference::Tag(t) => {
            if ctx.state.tag_is_immutable(&ctx.name, t) {
                return Err(RegistryError::with_message(Code::Denied, format!("tag {t} is immutable")).status(StatusCode::CONFLICT));
            }
            let digest = storage
                .resolve_tag(&ctx.name, t)
                .await?
                .ok_or_else(|| RegistryError::new(Code::ManifestUnknown))?;
            crate::tags::remove(&ctx.state, &ctx.name, t, "delete", ctx.principal.name()).await?;
            ctx.state.webhooks.fire(Event::delete(&ctx.name, Some(t), &digest, ctx.principal.name()));
            ctx.state.audit.record(&ctx.principal, "delete_tag", Some(&ctx.name), Some(t), Some(&digest.to_string()), None);
        }
        Reference::Digest(d) => {
            if !storage.has_manifest(&ctx.name, d).await? {
                return Err(RegistryError::new(Code::ManifestUnknown));
            }
            // Tags pointing at it go with it (immutable ones block the whole delete).
            for t in storage.list_tags_resolved(&ctx.name).await? {
                if &t.digest == d && ctx.state.tag_is_immutable(&ctx.name, &t.tag) {
                    return Err(RegistryError::with_message(Code::Denied, format!("tag {} is immutable", t.tag)).status(StatusCode::CONFLICT));
                }
            }
            // The manifest and its tags in one transaction; referrers are derived from the rows.
            let removed = storage.delete_manifest(&ctx.name, d).await?.ok_or_else(|| RegistryError::new(Code::ManifestUnknown))?;
            for t in &removed {
                crate::tags::record_removal(&ctx.state, &ctx.name, t, d, "delete", ctx.principal.name()).await?;
            }
            ctx.state.webhooks.fire(Event::delete(&ctx.name, None, d, ctx.principal.name()));
            ctx.state.audit.record(&ctx.principal, "delete_manifest", Some(&ctx.name), None, Some(&d.to_string()), None);
        }
    }
    ctx.state.reindex(&ctx.name).await;
    Ok(StatusCode::ACCEPTED.into_response())
}

fn reference_str(r: &Reference) -> String {
    match r {
        Reference::Tag(t) => t.clone(),
        Reference::Digest(d) => d.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::is_valid_media_type;

    #[test]
    fn media_types() {
        for ok in ["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/json; charset=utf-8", "text/plain;a=b;c=d"] {
            assert!(is_valid_media_type(ok), "{ok}");
        }
        for bad in ["", "application", "application/", "/json", "application/json\nX-Evil: 1", "application/json\r", "appli cation/json", "application/json; charset", "application/jsön", "a/b/c"] {
            assert!(!is_valid_media_type(bad), "{bad:?}");
        }
    }
}
