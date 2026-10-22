use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use super::Ctx;
use kontainer_store::uploads::{AppendError, Assembled, UploadSession};
use crate::sync::ProxyError;
use crate::auth::{require, AuthMethod};
use kontainer_core::perm::Action;
use kontainer_core::digest::Digest;
use crate::error::{Code, RegistryError, Result};
use kontainer_core::names;

/// A header value from a string we built from validated parts (digests, repository names,
/// upload ids).
fn header_value(s: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(s).map_err(RegistryError::internal)
}

fn parse_digest(s: &str) -> Result<Digest> {
    s.parse::<Digest>().map_err(|_| RegistryError::new(Code::DigestInvalid).detail(serde_json::json!({ "digest": s })))
}

/// The part of a blob of `total` bytes a GET asks for, per RFC 9110 section 14: `None` serves
/// the whole blob. A `Range` the server does not handle is ignored rather than refused: another
/// unit than `bytes`, several ranges, a malformed one, or an `If-Range` that is not this blob's
/// `etag`. Only a single range that is unsatisfiable (starts at or past the end, ends before it
/// starts, or asks for the last 0 bytes) is an error, `416` with `Content-Range: bytes */<total>`.
fn parse_range(h: &HeaderMap, total: u64, etag: &str) -> Result<Option<std::ops::Range<u64>>> {
    let Some(v) = h.get(header::RANGE).and_then(|v| v.to_str().ok()) else { return Ok(None) };
    if let Some(if_range) = h.get(header::IF_RANGE) {
        // Strong comparison: a weak validator or a date never matches.
        if if_range.to_str().ok().map(str::trim) != Some(etag) {
            return Ok(None);
        }
    }
    let Some((unit, spec)) = v.split_once('=') else { return Ok(None) };
    if !unit.trim().eq_ignore_ascii_case("bytes") || spec.contains(',') {
        return Ok(None);
    }
    let Some((a, b)) = spec.trim().split_once('-') else { return Ok(None) };
    let (a, b) = (a.trim(), b.trim());
    let unsatisfiable = || {
        RegistryError::with_message(Code::Unsupported, "requested range not satisfiable").status(StatusCode::RANGE_NOT_SATISFIABLE).header("Content-Range", format!("bytes */{total}"))
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    if a.is_empty() {
        // Suffix range: the last N bytes.
        if !digits(b) {
            return Ok(None);
        }
        let n: u64 = b.parse().unwrap_or(u64::MAX);
        if n == 0 {
            return Err(unsatisfiable());
        }
        if total == 0 {
            return Ok(None);
        }
        return Ok(Some(total.saturating_sub(n)..total));
    }
    if !digits(a) || !(b.is_empty() || digits(b)) {
        return Ok(None);
    }
    let start: u64 = a.parse().unwrap_or(u64::MAX);
    let end: Option<u64> = if b.is_empty() { None } else { Some(b.parse().unwrap_or(u64::MAX)) };
    // `last-pos` before `first-pos` (RFC 9110 calls it invalid, which a server may ignore) is
    // refused like an unsatisfiable range, as the conformance suite expects.
    if start >= total || end.is_some_and(|e| e < start) {
        return Err(unsatisfiable());
    }
    let end = end.map_or(total, |e| e.saturating_add(1).min(total));
    Ok(Some(start..end))
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-blobs (end-2)
/// Pull policies (`policy::check_pull`) are not applied here: a blob is not tied to one
/// manifest (layers are shared between images, and a blob may be linked before any manifest
/// references it), so there is no image to judge without scanning every manifest in the
/// repository on every layer download. The policy gates the manifest instead: clients learn
/// layer digests from a manifest GET (or the UI's manifest detail and export), and those
/// refuse blocked images.
pub async fn get(ctx: Ctx, digest: String, head: bool) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Pull, &ctx.name)?;
    let digest = parse_digest(&digest)?;
    match crate::sync::proxy_blob(&ctx.state, &ctx.name, &digest).await {
        Ok(()) => {}
        Err(e @ ProxyError::NotFound(_)) => tracing::debug!(repo = %ctx.name, %digest, error = %e, "pull-through cache miss"),
        Err(e @ ProxyError::Failed(_)) => {
            if ctx.state.storage.repo_blob_size(&ctx.name, &digest).await?.is_none() {
                return Err(RegistryError::upstream_unavailable(e));
            }
        }
    }
    let Some(size) = ctx.state.storage.repo_blob_size(&ctx.name, &digest).await? else {
        return Err(RegistryError::new(Code::BlobUnknown).detail(serde_json::json!({ "digest": digest })));
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert("Docker-Content-Digest", header_value(&digest.to_string())?);
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    let etag = format!("\"{digest}\"");
    headers.insert(header::ETAG, header_value(&etag)?);
    if head {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
        return Ok((StatusCode::OK, headers).into_response());
    }
    // Geo-replication: read from the location serving the client's region when it has the
    // blob, else the preferred one, else any (see `Storage::blob_sources`); when that location
    // redirects, send the client to a presigned URL there, so the bytes skip this server.
    let region = ctx.state.config.storage.region_header.as_deref().and_then(|h| ctx.headers.get(h)).and_then(|v| v.to_str().ok());
    if let Some((location, url)) = ctx.state.storage.blob_redirect(&digest, region).await {
        tracing::debug!(repo = %ctx.name, %digest, location, "redirecting a blob download");
        crate::metrics::global().blob_redirect(&location);
        headers.insert(header::LOCATION, HeaderValue::from_str(url.as_str()).map_err(RegistryError::internal)?);
        return Ok((StatusCode::TEMPORARY_REDIRECT, headers).into_response());
    }
    let range = parse_range(&ctx.headers, size, &etag)?;
    let Some(blob) = ctx.state.storage.blob_stream_near(&digest, range.clone(), region).await? else {
        return Err(RegistryError::new(Code::BlobUnknown));
    };
    let status = if range.is_some() {
        headers.insert(
            header::CONTENT_RANGE,
            header_value(&format!("bytes {}-{}/{}", blob.range.start, blob.range.end - 1, blob.total_size))?,
        );
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(blob.range.end - blob.range.start));
    Ok((status, headers, Body::from_stream(blob.stream)).into_response())
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#deleting-blobs (end-10)
pub async fn delete(ctx: Ctx, digest: String) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Delete, &ctx.name)?;
    ctx.state.require_writable(&ctx.name).await?;
    if !ctx.state.config.features.is_delete {
        return Err(RegistryError::new(Code::Unsupported));
    }
    let digest = parse_digest(&digest)?;
    if ctx.state.storage.repo_blob_size(&ctx.name, &digest).await?.is_none() {
        return Err(RegistryError::new(Code::BlobUnknown));
    }
    ctx.state.storage.unlink_blob(&ctx.name, &digest).await?;
    ctx.state.audit.record(&ctx.principal, "delete_blob", Some(&ctx.name), None, Some(&digest.to_string()), None);
    Ok((StatusCode::ACCEPTED, [("Docker-Content-Digest", digest.to_string())]).into_response())
}

fn upload_headers(ctx: &Ctx, id: &str, offset: u64) -> Result<HeaderMap> {
    let mut h = HeaderMap::new();
    h.insert(header::LOCATION, header_value(&format!("/v2/{}/blobs/uploads/{id}", ctx.name))?);
    h.insert(header::RANGE, header_value(&format!("0-{}", offset.saturating_sub(1)))?);
    h.insert("Docker-Upload-UUID", header_value(id)?);
    Ok(h)
}

/// `204 No Content` without a `Content-Length` (RFC 9110 section 8.6). axum's router adds one to
/// any body whose size it knows, after every middleware, so the body here has no exact size
/// hint; hyper sends no body, `Content-Length` or `Transfer-Encoding` with a 204.
fn no_content(headers: HeaderMap) -> Response {
    let empty = futures::stream::empty::<std::result::Result<bytes::Bytes, std::convert::Infallible>>();
    (StatusCode::NO_CONTENT, headers, Body::from_stream(empty)).into_response()
}

/// `202 Accepted` for an upload session at `offset`. (`204`s carry no `Content-Length`.)
fn accepted(ctx: &Ctx, id: &str, offset: u64) -> Result<Response> {
    let mut h = upload_headers(ctx, id, offset)?;
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(0));
    Ok((StatusCode::ACCEPTED, h).into_response())
}

fn created(ctx: &Ctx, digest: &Digest) -> Result<Response> {
    let mut h = HeaderMap::new();
    h.insert(header::LOCATION, header_value(&format!("/v2/{}/blobs/{digest}", ctx.name))?);
    h.insert("Docker-Content-Digest", header_value(&digest.to_string())?);
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(0));
    Ok((StatusCode::CREATED, h).into_response())
}

fn digest_invalid(digest: &Digest) -> RegistryError {
    RegistryError::new(Code::DigestInvalid).detail(serde_json::json!({ "digest": digest }))
}

/// Seal the upload, verify its chunks against `digest`, move them into the blob store and link
/// the blob. Works on whichever instance gets the `PUT`: the chunks are in the shared store.
async fn commit(ctx: &Ctx, id: &str, digest: &Digest) -> Result<()> {
    let storage = &ctx.state.storage;
    let file = match storage.upload_assemble(id, digest).await? {
        Assembled::Verified(file) => file,
        Assembled::Mismatch => {
            storage.upload_remove(id).await?;
            return Err(digest_invalid(digest));
        }
        Assembled::Unknown => return Err(RegistryError::new(Code::BlobUploadUnknown)),
    };
    store_verified(ctx, digest, &file).await?;
    storage.upload_remove(id).await?;
    Ok(())
}

/// Store `file`, already verified to hash to `digest`, as that blob and link it here.
async fn store_verified(ctx: &Ctx, digest: &Digest, file: &std::path::Path) -> Result<()> {
    // An existing blob is not rewritten; one a garbage collection removes meanwhile is stored
    // again (see `kontainer_store::gc`).
    ctx.state.storage.store_and_link_file(&ctx.name, digest, file).await?;
    Ok(())
}

/// Best-effort namespace quota pre-check for blob bytes about to be stored in this repository:
/// refuse when the namespace's (cached) usage plus `incoming` bytes would exceed its quota.
/// With `digest`, a blob the namespace already holds costs nothing. Nothing is recorded: the
/// authoritative check (and accounting) is still the manifest `PUT`; this only stops a push
/// from uploading gigabytes that manifest would then be refused for.
async fn check_quota(ctx: &Ctx, incoming: u64, digest: Option<&Digest>) -> Result<()> {
    if incoming == 0 {
        return Ok(());
    }
    let Some(q) = ctx.state.quota_check(&ctx.name).await? else { return Ok(()) };
    let wanted: Vec<Digest> = digest.into_iter().cloned().collect();
    let (used, missing) = kontainer_store::usage::namespace_missing(&ctx.state.storage, &q.namespace, wanted).await?;
    if digest.is_some() && missing.is_empty() {
        return Ok(());
    }
    if used.saturating_add(incoming) > q.quota {
        use kontainer_store::usage::human;
        return Err(RegistryError::with_message(
            Code::Denied,
            format!("storage quota exceeded for {}: {} used of {}, this upload adds {}", q.namespace, human(used), human(q.quota), human(incoming)),
        ));
    }
    Ok(())
}

fn declared_length(ctx: &Ctx) -> Option<u64> {
    ctx.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok())
}

/// `Content-Range: <start>-<end>` of a chunk (inclusive; a `bytes ` prefix and a `/<total>`
/// suffix are tolerated). `Err` when present but malformed.
fn content_range(h: &HeaderMap) -> std::result::Result<Option<(u64, u64)>, ()> {
    let Some(v) = h.get(header::CONTENT_RANGE) else { return Ok(None) };
    let v = v.to_str().map_err(|_| ())?.trim();
    let v = v.strip_prefix("bytes").map(str::trim_start).unwrap_or(v);
    let v = v.split('/').next().unwrap_or_default();
    let (a, b) = v.split_once('-').ok_or(())?;
    let (a, b) = (a.trim().parse::<u64>().map_err(|_| ())?, b.trim().parse::<u64>().map_err(|_| ())?);
    if b < a {
        return Err(());
    }
    Ok(Some((a, b)))
}

/// `416 BLOB_UPLOAD_INVALID` for an out-of-order chunk, telling the client what the session holds.
fn range_invalid(ctx: &Ctx, id: &str, offset: u64) -> RegistryError {
    // The spec has the 416 carry `Location` and `Range` like a 202, so the client can resume.
    RegistryError::with_message(Code::BlobUploadInvalid, "chunk does not continue the upload")
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header("Location", format!("/v2/{}/blobs/uploads/{id}", ctx.name))
        .header("Range", format!("0-{}", offset.saturating_sub(1)))
        .header("Docker-Upload-UUID", id)
}

/// Append a request body to upload `id`, keeping the upload within `server.max_blob_size`.
async fn append(ctx: &Ctx, id: &str, body: Body, range: Option<(u64, u64)>) -> Result<u64> {
    let limit = ctx.state.config.server.max_blob_bytes();
    let declared = declared_length(ctx);
    // Too large on its own: refused before reading it.
    if let Some(limit) = limit.filter(|l| declared.is_some_and(|n| n > *l)) {
        return Err(too_large(ctx, id, limit).await);
    }
    match ctx.state.storage.upload_append_range(id, body.into_data_stream(), limit, range).await {
        Ok(offset) => Ok(offset),
        Err(AppendError::TooLarge { limit }) => Err(too_large(ctx, id, limit).await),
        Err(AppendError::RangeMismatch { offset }) => Err(range_invalid(ctx, id, offset)),
        Err(AppendError::Other(e)) => Err(e.into()),
    }
}

/// `413 SIZE_INVALID` for an upload past `limit` bytes. It can never complete, so it is dropped.
async fn too_large(ctx: &Ctx, id: &str, limit: u64) -> RegistryError {
    if let Err(e) = ctx.state.storage.upload_remove(id).await {
        tracing::warn!(upload = id, error = %e, "removing an oversized upload");
    }
    size_invalid(limit)
}

fn size_invalid(limit: u64) -> RegistryError {
    RegistryError::with_message(Code::SizeInvalid, format!("blob is larger than the registry's maximum of {limit} bytes (server.max_blob_size)"))
        .detail(serde_json::json!({ "max_blob_size": limit }))
        .status(StatusCode::PAYLOAD_TOO_LARGE)
}

/// Ensure the upload session exists and belongs to this repository.
async fn session(ctx: &Ctx, id: &str) -> Result<UploadSession> {
    match ctx.state.storage.upload_session(id).await? {
        Some(s) if s.repository == ctx.name => Ok(s),
        _ => Err(RegistryError::new(Code::BlobUploadUnknown)),
    }
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-blobs (end-4a, end-4b, end-11)
pub async fn start_upload(ctx: Ctx, body: Body) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Push, &ctx.name)?;
    ctx.state.require_writable(&ctx.name).await?;
    let storage = &ctx.state.storage;
    // The digest algorithm the client means to finish with: refused now if it is not one this
    // registry verifies, rather than after the whole upload.
    if let Some(alg) = ctx.query.get("digest-algorithm") {
        if !matches!(alg.as_str(), "sha256" | "sha512") {
            return Err(RegistryError::with_message(Code::DigestInvalid, format!("unsupported digest algorithm {alg:?}; use sha256 or sha512")).detail(serde_json::json!({ "digest-algorithm": alg })));
        }
    }

    // Cross-repository mount.
    if let (Some(mount), Some(from)) = (ctx.query.get("mount"), ctx.query.get("from")) {
        if ctx.state.config.features.is_cross_repo_mount && names::is_valid_repository(from) {
            if let Ok(d) = mount.parse::<Digest>() {
                // A scoped token that lacks pull on `from` gets a challenge naming both
                // repositories, so the client re-authenticates and the mount
                // succeeds instead of silently falling back to an upload.
                if !ctx.principal.allowed(Action::Pull, from) && ctx.principal.method == AuthMethod::Bearer && ctx.principal.restrict.is_some() {
                    return Err(ctx.state.auth.unauthorized(Some(format!("repository:{}:pull,push repository:{from}:pull", ctx.name))));
                }
                let size = if ctx.principal.allowed(Action::Pull, from) { storage.repo_blob_size(from, &d).await? } else { None };
                if let Some(size) = size {
                    check_quota(&ctx, size, Some(&d)).await?;
                    // `false`: garbage collection removed the blob meanwhile; upload it instead.
                    if storage.link_blob(&ctx.name, &d, size).await? {
                        ctx.state.audit.record(&ctx.principal, "mount_blob", Some(&ctx.name), None, Some(&d.to_string()), Some(format!("from {from}")));
                        return created(&ctx, &d);
                    }
                }
            }
        }
        // Fall through: spec says to start a regular upload when the mount fails.
    }

    // Monolithic single-request upload: one request, one instance, so no session is needed.
    if let Some(d) = ctx.query.get("digest") {
        let digest = parse_digest(d)?;
        let declared = declared_length(&ctx);
        check_quota(&ctx, declared.unwrap_or(0), Some(&digest)).await?;
        let limit = ctx.state.config.server.max_blob_bytes();
        if let Some(limit) = limit.filter(|l| declared.is_some_and(|n| n > *l)) {
            return Err(size_invalid(limit));
        }
        let staged = match storage.stage_body(body.into_data_stream(), 0, limit, None, Some(digest.algorithm())).await {
            Ok(staged) => staged,
            Err(AppendError::TooLarge { limit }) => return Err(size_invalid(limit)),
            Err(e @ AppendError::RangeMismatch { .. }) => return Err(RegistryError::internal(e)),
            Err(AppendError::Other(e)) => return Err(e.into()),
        };
        if staged.digest.as_ref() != Some(&digest) {
            return Err(digest_invalid(&digest));
        }
        check_quota(&ctx, staged.len, Some(&digest)).await?;
        store_verified(&ctx, &digest, &staged.file).await?;
        return created(&ctx, &digest);
    }

    let id = storage.upload_start(&ctx.name).await?;
    accepted(&ctx, &id, 0)
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-a-blob-in-chunks (end-13)
pub async fn upload_status(ctx: Ctx, id: String) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Push, &ctx.name)?;
    let s = session(&ctx, &id).await?;
    Ok(no_content(upload_headers(&ctx, &id, s.offset)?))
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-a-blob-in-chunks (end-5)
pub async fn upload_chunk(ctx: Ctx, id: String, body: Body) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Push, &ctx.name)?;
    ctx.state.require_writable(&ctx.name).await?;
    let s = session(&ctx, &id).await?;
    // Validated here for a quick answer; the chunk is then recorded with a compare-and-set on
    // this offset (`upload_append_range`), so of concurrent PATCHes for the same offset, on any
    // instances, one lands and the others get 416.
    let range = content_range(&ctx.headers).map_err(|()| range_invalid(&ctx, &id, s.offset))?;
    if let Some((start, end)) = range {
        if start != s.offset || declared_length(&ctx).is_some_and(|n| n != end - start + 1) {
            return Err(range_invalid(&ctx, &id, s.offset));
        }
    }
    let incoming = range.map(|(a, b)| b - a + 1).or(declared_length(&ctx)).unwrap_or(0);
    check_quota(&ctx, s.offset.saturating_add(incoming), None).await?;
    let offset = append(&ctx, &id, body, range).await?;
    accepted(&ctx, &id, offset)
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-a-blob-in-chunks (end-6)
pub async fn upload_complete(ctx: Ctx, id: String, body: Body) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Push, &ctx.name)?;
    ctx.state.require_writable(&ctx.name).await?;
    let s = session(&ctx, &id).await?;
    let Some(d) = ctx.query.get("digest") else {
        return Err(RegistryError::with_message(Code::DigestInvalid, "digest query parameter required"));
    };
    let digest = parse_digest(d)?;
    // A last chunk may carry Content-Range; it must continue where the session is.
    let range = content_range(&ctx.headers).map_err(|()| range_invalid(&ctx, &id, s.offset))?;
    if let Some((start, end)) = range {
        if start != s.offset || declared_length(&ctx).is_some_and(|n| n != end - start + 1) {
            return Err(range_invalid(&ctx, &id, s.offset));
        }
    }
    check_quota(&ctx, s.offset.saturating_add(declared_length(&ctx).unwrap_or(0)), Some(&digest)).await?;
    append(&ctx, &id, body, range).await?;
    complete(&ctx, &id, &digest).await?;
    created(&ctx, &digest)
}

/// Final quota check on the bytes actually received, then [`commit`]. A refused upload is
/// dropped: it cannot complete.
async fn complete(ctx: &Ctx, id: &str, digest: &Digest) -> Result<()> {
    let received = ctx.state.storage.upload_session(id).await?.map_or(0, |s| s.offset);
    if let Err(e) = check_quota(ctx, received, Some(digest)).await {
        ctx.state.storage.upload_remove(id).await?;
        return Err(e);
    }
    commit(ctx, id, digest).await
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-blobs
pub async fn upload_cancel(ctx: Ctx, id: String) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Push, &ctx.name)?;
    session(&ctx, &id).await?;
    ctx.state.storage.upload_remove(&id).await?;
    Ok(no_content(HeaderMap::new()))
}
