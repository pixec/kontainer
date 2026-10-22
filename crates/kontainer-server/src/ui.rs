//! The embedded single-page web UI (built from `web/` with Vite, served at `/`). Everything the
//! API routers do not claim falls through to it; old `/ui/...` links redirect.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::Embed;

use crate::state::AppState;

#[derive(Embed)]
#[folder = "../../web/dist"]
struct Assets;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/ui", get(|| async { Redirect::permanent("/") }))
        .route("/ui/", get(|| async { Redirect::permanent("/") }))
        .route("/ui/{*path}", get(|Path(path): Path<String>, uri: axum::http::Uri| async move { Redirect::permanent(&format!("/{path}{}", uri.query().map(|q| format!("?{q}")).unwrap_or_default())) }))
        .fallback(get(asset))
}

/// Prefixes that belong to the registry and the API: an unknown path under them is a 404, not
/// the single-page app.
const RESERVED: &[&str] = &["v2", "api", "auth", "metrics", "livez", "readyz"];

async fn index() -> Response {
    serve("index.html")
}

async fn asset(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/').to_string();
    if RESERVED.iter().any(|p| path == *p || path.starts_with(&format!("{p}/"))) {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Real files (assets/*.js, fonts) are served as-is; everything else is an SPA route.
    if Assets::get(&path).is_some() {
        serve(&path)
    } else {
        serve("index.html")
    }
}

fn serve(path: &str) -> Response {
    match Assets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
            (
                [(header::CONTENT_TYPE, mime.as_ref().to_string()), (header::CACHE_CONTROL, cache.to_string())],
                file.data.into_owned(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
