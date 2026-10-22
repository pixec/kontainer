use std::collections::HashMap;

use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::{link_next, page_size, paginate, Ctx};
use crate::auth::{require, Principal};
use kontainer_core::perm::Action;
use kontainer_core::digest::Digest;
use crate::error::{Code, RegistryError, Result};
use kontainer_core::manifest::{self, Descriptor};
use crate::state::AppState;
use kontainer_store::metadata::StoredManifest;

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-tags (end-8a, end-8b)
pub async fn list(ctx: Ctx) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Pull, &ctx.name)?;
    // One page straight from the database: `n` (plus one, to know whether there is more) after `last`.
    let last = ctx.query.get("last").map(String::as_str).filter(|l| !l.is_empty());
    let n = page_size(&ctx.query)?;
    let mut page = ctx.state.storage.list_tags_page(&ctx.name, last, n.map(|n| n.saturating_add(1))).await?;
    if page.is_empty() && !ctx.state.storage.repository_exists(&ctx.name).await? {
        return Err(RegistryError::new(Code::NameUnknown).detail(serde_json::json!({ "name": ctx.requested_name })));
    }
    let more = n.filter(|n| page.len() > *n);
    if let Some(n) = more {
        page.truncate(n);
    }
    // Under a containerd `?ns=` rewrite the client sees the repository it asked for, and the
    // next page keeps the `ns`.
    let mut headers = HeaderMap::new();
    if let (Some(n), Some(last)) = (more, page.last()) {
        let base = match &ctx.ns {
            Some(ns) => format!("/v2/{}/tags/list?ns={}&", ctx.requested_name, url::form_urlencoded::byte_serialize(ns.as_bytes()).collect::<String>()),
            None => format!("/v2/{}/tags/list?", ctx.requested_name),
        };
        let link = link_next(&base, n, last);
        headers.insert(header::LINK, HeaderValue::from_str(&link).map_err(RegistryError::internal)?);
    }
    Ok((headers, Json(serde_json::json!({ "name": ctx.requested_name, "tags": page }))).into_response())
}

// `/v2/_catalog` is not part of the OCI distribution spec; it is the de-facto extension every
// client expects.
pub async fn catalog(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response> {
    if !state.config.features.is_catalog {
        return Err(RegistryError::new(Code::Unsupported));
    }
    let repos: Vec<String> = state.storage.list_repositories().await?.into_iter().filter(|r| principal.can_see(r)).collect();
    let (page, more) = paginate(&repos, &query)?;
    let mut headers = HeaderMap::new();
    if let (Some(n), Some(last)) = (more, page.last()) {
        headers.insert(header::LINK, HeaderValue::from_str(&link_next("/v2/_catalog?", n, last)).map_err(RegistryError::internal)?);
    }
    Ok((headers, Json(serde_json::json!({ "repositories": page }))).into_response())
}

/// The referrers descriptor of a stored manifest; `None` when its body is not a manifest.
pub fn describe(m: &StoredManifest) -> Option<Descriptor> {
    let parsed = kontainer_store::parse_stored_manifest(&m.body).ok()?;
    let media_type = match manifest::body_media_type(&m.body) {
        Some(mt) => mt,
        None => m.media_type.clone(),
    };
    Some(Descriptor {
        media_type,
        digest: m.digest.clone(),
        size: m.size(),
        urls: None,
        annotations: parsed.annotations().cloned(),
        platform: None,
        // The effective type (an empty `artifactType` falls back to the config media type),
        // the same value stored in `manifests.artifact_type` and matched by `?artifactType=`.
        artifact_type: parsed.artifact_type(),
    })
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers (end-12a, end-12b)
pub async fn referrers(ctx: Ctx, digest: String) -> Result<Response> {
    require(&ctx.state, &ctx.principal, Action::Pull, &ctx.name)?;
    if !ctx.state.config.features.is_referrers {
        return Err(RegistryError::new(Code::Unsupported).status(StatusCode::NOT_FOUND));
    }
    let subject: Digest = digest.parse().map_err(|_| RegistryError::new(Code::DigestInvalid).status(StatusCode::BAD_REQUEST))?;
    // An empty `?artifactType=` is no filter at all.
    let filter = ctx.query.get("artifactType").filter(|t| !t.is_empty()).cloned();
    let manifests: Vec<Descriptor> = ctx.state.storage.list_referrers(&ctx.name, &subject, filter.as_deref()).await?.iter().filter_map(describe).collect();
    let body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": manifest::OCI_INDEX,
        "manifests": manifests,
    });
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(manifest::OCI_INDEX));
    if filter.is_some() {
        headers.insert("OCI-Filters-Applied", HeaderValue::from_static("artifactType"));
    }
    Ok((StatusCode::OK, headers, serde_json::to_vec(&body).map_err(RegistryError::internal)?).into_response())
}
