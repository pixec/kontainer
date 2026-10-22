//! OCI Distribution Spec v2 endpoints.
//!
//! Repository names may contain `/`, so a single wildcard route catches everything under
//! `/v2/` and [`dispatch`] parses the tail of the path to pick the handler.

mod blobs;
mod manifests;
mod tags;

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;

use crate::auth::Principal;
use crate::error::{Code, RegistryError, Result};
use kontainer_core::names;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v2/", get(root))
        .route("/v2", get(root))
        .route("/v2/_catalog", get(tags::catalog))
        .route("/v2/{*path}", any(dispatch))
}

// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#determining-support (end-1)
/// API version check. Also where clients discover that auth is required.
async fn root(Extension(principal): Extension<Principal>, State(state): State<AppState>) -> Result<Response> {
    if !principal.is_authenticated() && state.config.auth.mode != kontainer_core::config::AuthMode::None && principal.roles.is_empty() {
        return Err(state.auth.unauthorized(None));
    }
    Ok((StatusCode::OK, [("Docker-Distribution-API-Version", "registry/2.0")], "{}").into_response())
}

pub struct Ctx {
    pub state: AppState,
    pub principal: Principal,
    pub headers: HeaderMap,
    pub query: HashMap<String, String>,
    /// The query string as sent, for parameters that repeat (`?tag=a&tag=b`).
    pub raw_query: String,
    /// The repository storage is read from and written to. Under a containerd `?ns=` rewrite
    /// this is the pull-through cache's repository, not the one the client asked for.
    pub name: String,
    /// The repository as the client named it in the path, for response bodies and links.
    pub requested_name: String,
    /// The `?ns=` value when the request was rewritten to the pull-through cache.
    pub ns: Option<String>,
}

impl Ctx {
    /// Every value of the repeated query parameter `key`, in order.
    pub fn query_all(&self, key: &str) -> Vec<String> {
        url::form_urlencoded::parse(self.raw_query.as_bytes()).filter(|(k, _)| k == key).map(|(_, v)| v.into_owned()).collect()
    }
}

enum Route {
    Tags,
    Manifest(String),
    Referrers(String),
    UploadStart,
    Upload(String),
    Blob(String),
}

fn parse(path: &str) -> Option<(String, Route)> {
    let segs: Vec<&str> = path.split('/').collect();
    let n = segs.len();
    let name = |k: usize| segs[..n - k].join("/");
    if n >= 3 && segs[n - 2] == "tags" && segs[n - 1] == "list" {
        return Some((name(2), Route::Tags));
    }
    if n >= 3 && segs[n - 2] == "manifests" {
        return Some((name(2), Route::Manifest(segs[n - 1].to_string())));
    }
    if n >= 3 && segs[n - 2] == "referrers" {
        return Some((name(2), Route::Referrers(segs[n - 1].to_string())));
    }
    if n >= 4 && segs[n - 3] == "blobs" && segs[n - 2] == "uploads" {
        if segs[n - 1].is_empty() {
            return Some((name(3), Route::UploadStart));
        }
        return Some((name(3), Route::Upload(segs[n - 1].to_string())));
    }
    if n >= 3 && segs[n - 2] == "blobs" && segs[n - 1] == "uploads" {
        return Some((name(2), Route::UploadStart));
    }
    if n >= 3 && segs[n - 2] == "blobs" {
        return Some((name(2), Route::Blob(segs[n - 1].to_string())));
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    uri: axum::http::Uri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let Some((name, route)) = parse(&path) else {
        return Err(RegistryError::with_message(Code::Unsupported, "unknown endpoint").status(StatusCode::NOT_FOUND));
    };
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid).detail(serde_json::json!({ "name": name })));
    }
    // containerd using this registry as a mirror names the upstream in `?ns=`: pulls of a
    // repository that is not here go to the pull-through cache namespace for that upstream.
    let requested_name = name.clone();
    let mut name = name;
    let mut rewritten_ns = None;
    let is_pull = matches!(route, Route::Tags | Route::Manifest(_) | Route::Referrers(_) | Route::Blob(_)) && (method == Method::GET || method == Method::HEAD);
    if let (true, true, Some(ns)) = (is_pull, state.config.features.is_containerd_ns, query.get("ns")) {
        if let Some(target) = crate::sync::containerd_ns_target(&state, &principal, ns, &name).await? {
            tracing::debug!(%name, %ns, %target, "containerd mirror request served from the pull-through cache");
            name = target;
            rewritten_ns = Some(ns.clone());
        }
    }
    let mut principal = principal;
    // Whether a Creator team's push would create the repository is decided on what storage
    // holds, not on a set another instance may not have caught up with.
    if method != Method::GET && method != Method::HEAD {
        state.auth.confirm_new_repo(&mut principal, &name).await?;
    }
    let raw_query = uri.query().unwrap_or("").to_string();
    let ctx = Ctx { state, principal, headers, query, raw_query, name, requested_name, ns: rewritten_ns.clone() };
    let resp = match (route, method) {
        (Route::Tags, Method::GET) => tags::list(ctx).await,
        (Route::Manifest(r), Method::GET) => manifests::get(ctx, r, false).await,
        (Route::Manifest(r), Method::HEAD) => manifests::get(ctx, r, true).await,
        (Route::Manifest(r), Method::PUT) => manifests::put(ctx, r, body).await,
        (Route::Manifest(r), Method::DELETE) => manifests::delete(ctx, r).await,
        (Route::Referrers(d), Method::GET) => tags::referrers(ctx, d).await,
        (Route::UploadStart, Method::POST) => blobs::start_upload(ctx, body).await,
        (Route::Upload(id), Method::GET) => blobs::upload_status(ctx, id).await,
        (Route::Upload(id), Method::PATCH) => blobs::upload_chunk(ctx, id, body).await,
        (Route::Upload(id), Method::PUT) => blobs::upload_complete(ctx, id, body).await,
        (Route::Upload(id), Method::DELETE) => blobs::upload_cancel(ctx, id).await,
        (Route::Blob(d), Method::GET) => blobs::get(ctx, d, false).await,
        (Route::Blob(d), Method::HEAD) => blobs::get(ctx, d, true).await,
        (Route::Blob(d), Method::DELETE) => blobs::delete(ctx, d).await,
        _ => Err(RegistryError::new(Code::Unsupported)),
    };
    // A rewritten request says which upstream namespace answered it.
    let Some(ns) = rewritten_ns.and_then(|ns| axum::http::HeaderValue::from_str(&ns).ok()) else { return resp };
    let mut resp = resp.unwrap_or_else(IntoResponse::into_response);
    resp.headers_mut().insert("OCI-Namespace", ns);
    Ok(resp)
}

/// Build the `Link: <url>; rel="next"` header for paginated lists. `base` ends in `?`, or in
/// `&` after query parameters the next page must keep.
pub fn link_next(base: &str, n: usize, last: &str) -> String {
    format!("<{base}n={n}&last={last}>; rel=\"next\"")
}

/// Apply `n`/`last` pagination to a sorted list. Returns the page and whether more follow.
pub fn paginate<'a>(items: &'a [String], query: &HashMap<String, String>) -> Result<(&'a [String], Option<usize>)> {
    let start = match query.get("last") {
        Some(last) if !last.is_empty() => items.iter().position(|i| i > last).unwrap_or(items.len()),
        _ => 0,
    };
    let rest = &items[start..];
    match page_size(query)? {
        Some(n) => {
            let end = n.min(rest.len());
            Ok((&rest[..end], (rest.len() > n).then_some(n)))
        }
        None => Ok((rest, None)),
    }
}

/// The `n` of a paginated listing, if given.
pub fn page_size(query: &HashMap<String, String>) -> Result<Option<usize>> {
    query
        .get("n")
        .map(|n| {
            n.parse::<usize>().map_err(|_| {
                RegistryError::with_message(Code::Unsupported, "invalid n: the page size must be a non-negative integer").detail(serde_json::json!({ "n": n })).status(StatusCode::BAD_REQUEST)
            })
        })
        .transpose()
}

pub use manifests::media_type_of as manifests_media_type;
pub use tags::describe;
