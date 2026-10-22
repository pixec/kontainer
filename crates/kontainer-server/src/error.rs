//! Error codes and their HTTP mapping.
//!
//! The distribution spec's codes (`BLOB_UNKNOWN`, `DENIED`, ...) plus a few for the JSON API
//! (`BAD_REQUEST`, `NOT_FOUND`, `CONFLICT`). Under `/v2/` errors use the spec's body,
//! `{"errors": [{"code", "message", "detail"}]}`, which clients such as docker parse. Everywhere
//! else [`api_errors`] rewrites them to `{"code", "message", "details"}`.

use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    BlobUnknown,
    BlobUploadInvalid,
    BlobUploadUnknown,
    DigestInvalid,
    ManifestBlobUnknown,
    ManifestInvalid,
    ManifestUnknown,
    NameInvalid,
    NameUnknown,
    TagInvalid,
    SizeInvalid,
    Unauthorized,
    Denied,
    Unsupported,
    TooManyRequests,
    Unknown,
    /// The request is malformed or a field is invalid.
    BadRequest,
    /// The API resource (user, team, trigger, ...) does not exist.
    NotFound,
    /// The request clashes with existing state: a taken name, an immutable tag.
    Conflict,
}

impl Code {
    pub fn as_str(&self) -> &'static str {
        match self {
            Code::BlobUnknown => "BLOB_UNKNOWN",
            Code::BlobUploadInvalid => "BLOB_UPLOAD_INVALID",
            Code::BlobUploadUnknown => "BLOB_UPLOAD_UNKNOWN",
            Code::DigestInvalid => "DIGEST_INVALID",
            Code::ManifestBlobUnknown => "MANIFEST_BLOB_UNKNOWN",
            Code::ManifestInvalid => "MANIFEST_INVALID",
            Code::ManifestUnknown => "MANIFEST_UNKNOWN",
            Code::NameInvalid => "NAME_INVALID",
            Code::TagInvalid => "TAG_INVALID",
            Code::NameUnknown => "NAME_UNKNOWN",
            Code::SizeInvalid => "SIZE_INVALID",
            Code::Unauthorized => "UNAUTHORIZED",
            Code::Denied => "DENIED",
            Code::Unsupported => "UNSUPPORTED",
            Code::TooManyRequests => "TOOMANYREQUESTS",
            Code::Unknown => "UNKNOWN",
            Code::BadRequest => "BAD_REQUEST",
            Code::NotFound => "NOT_FOUND",
            Code::Conflict => "CONFLICT",
        }
    }

    pub fn default_message(&self) -> &'static str {
        match self {
            Code::BlobUnknown => "blob unknown to registry",
            Code::BlobUploadInvalid => "blob upload invalid",
            Code::BlobUploadUnknown => "blob upload unknown to registry",
            Code::DigestInvalid => "provided digest did not match uploaded content",
            Code::ManifestBlobUnknown => "manifest references a manifest or blob unknown to registry",
            Code::ManifestInvalid => "manifest invalid",
            Code::ManifestUnknown => "manifest unknown to registry",
            Code::NameInvalid => "invalid repository name",
            Code::TagInvalid => "invalid tag name",
            Code::NameUnknown => "repository name not known to registry",
            Code::SizeInvalid => "provided length did not match content length",
            Code::Unauthorized => "authentication required",
            Code::Denied => "requested access to the resource is denied",
            Code::Unsupported => "the operation is unsupported",
            Code::TooManyRequests => "too many requests",
            Code::Unknown => "unknown error",
            Code::BadRequest => "invalid request",
            Code::NotFound => "not found",
            Code::Conflict => "conflicts with the current state",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Code::BlobUnknown | Code::BlobUploadUnknown | Code::ManifestUnknown | Code::NameUnknown | Code::NotFound => StatusCode::NOT_FOUND,
            Code::BlobUploadInvalid
            | Code::DigestInvalid
            | Code::ManifestBlobUnknown
            | Code::ManifestInvalid
            | Code::NameInvalid
            | Code::TagInvalid
            | Code::SizeInvalid
            | Code::BadRequest => StatusCode::BAD_REQUEST,
            Code::Conflict => StatusCode::CONFLICT,
            Code::Unauthorized => StatusCode::UNAUTHORIZED,
            Code::Denied => StatusCode::FORBIDDEN,
            Code::Unsupported => StatusCode::METHOD_NOT_ALLOWED,
            Code::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Code::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug)]
pub struct RegistryError {
    pub code: Code,
    pub message: String,
    pub detail: Option<Box<serde_json::Value>>,
    pub headers: Vec<(&'static str, String)>,
    pub status: Option<StatusCode>,
}

impl RegistryError {
    pub fn new(code: Code) -> Self {
        Self { code, message: code.default_message().to_string(), detail: None, headers: Vec::new(), status: None }
    }
    pub fn with_message(code: Code, message: impl Into<String>) -> Self {
        Self { message: message.into(), ..Self::new(code) }
    }
    pub fn detail(mut self, detail: impl Serialize) -> Self {
        self.detail = serde_json::to_value(detail).ok().map(Box::new);
        self
    }
    pub fn header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        self.headers.push((name, value.as_ref().to_string()));
        self
    }
    pub fn status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }
    /// `400 BAD_REQUEST` with a message saying what is wrong.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::with_message(Code::BadRequest, message)
    }
    /// `404 NOT_FOUND`: "`what` not found".
    pub fn not_found(what: &str) -> Self {
        Self::with_message(Code::NotFound, format!("{what} not found"))
    }
    /// `409 CONFLICT`.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::with_message(Code::Conflict, message)
    }
    /// `500`. The error is logged with its whole cause chain (`{:#}`) and not shown to the client.
    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %format!("{err:#}"), "internal error");
        Self::new(Code::Unknown)
    }
    /// `502`: the pull-through cache's upstream failed (not "it does not exist"). Logged with
    /// its cause chain; the client gets a short message.
    pub fn upstream_unavailable(err: impl std::fmt::Display) -> Self {
        tracing::warn!(error = %format!("{err:#}"), "upstream registry unavailable");
        Self::with_message(Code::Unknown, "the upstream registry is unavailable; try again later").status(StatusCode::BAD_GATEWAY)
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for RegistryError {}

impl From<Code> for RegistryError {
    fn from(code: Code) -> Self {
        Self::new(code)
    }
}

impl From<anyhow::Error> for RegistryError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e)
    }
}

impl From<object_store::Error> for RegistryError {
    fn from(e: object_store::Error) -> Self {
        match e {
            // Not only blobs live in the object store (manifests, tags, scan reports): callers
            // that know which object it was map their own `*_UNKNOWN` code.
            object_store::Error::NotFound { .. } => Self::new(Code::NotFound),
            other => Self::internal(other),
        }
    }
}

impl From<std::io::Error> for RegistryError {
    fn from(e: std::io::Error) -> Self {
        Self::internal(e)
    }
}

impl From<kontainer_core::digest::InvalidDigest> for RegistryError {
    fn from(e: kontainer_core::digest::InvalidDigest) -> Self {
        Self::with_message(Code::DigestInvalid, e.to_string())
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    errors: [ErrorEntry<'a>; 1],
}

#[derive(Serialize)]
struct ErrorEntry<'a> {
    code: &'static str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: &'a Option<Box<serde_json::Value>>,
}

/// The error behind a response, kept so [`api_errors`] can re-render it.
#[derive(Clone)]
struct ErrorParts {
    code: &'static str,
    message: String,
    detail: Option<serde_json::Value>,
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&ErrorBody {
            errors: [ErrorEntry { code: self.code.as_str(), message: &self.message, detail: &self.detail }],
        })
        .unwrap_or_default();
        let parts = ErrorParts { code: self.code.as_str(), message: self.message.clone(), detail: self.detail.as_deref().cloned() };
        let mut headers = HeaderMap::new();
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                headers.insert(name, value);
            }
        }
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let mut resp = (self.status.unwrap_or_else(|| self.code.status()), headers, body).into_response();
        resp.extensions_mut().insert(parts);
        resp
    }
}

/// Paths whose clients expect the distribution spec's error body.
fn speaks_registry_errors(path: &str) -> bool {
    path == "/v2" || path.starts_with("/v2/") || path == "/auth/token"
}

/// The code for an error axum produced itself (bad JSON, unknown route), by status.
fn code_for_status(s: StatusCode) -> &'static str {
    match s {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY | StatusCode::UNSUPPORTED_MEDIA_TYPE | StatusCode::PAYLOAD_TOO_LARGE => Code::BadRequest.as_str(),
        StatusCode::UNAUTHORIZED => Code::Unauthorized.as_str(),
        StatusCode::FORBIDDEN => Code::Denied.as_str(),
        StatusCode::NOT_FOUND => Code::NotFound.as_str(),
        StatusCode::METHOD_NOT_ALLOWED => Code::Unsupported.as_str(),
        StatusCode::CONFLICT => Code::Conflict.as_str(),
        StatusCode::TOO_MANY_REQUESTS => Code::TooManyRequests.as_str(),
        _ => Code::Unknown.as_str(),
    }
}

/// Middleware: outside the registry API, errors are `{"code", "message", "details"}`. Covers
/// [`RegistryError`]s and axum's own plain-text rejections alike.
pub async fn api_errors(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if speaks_registry_errors(req.uri().path()) {
        return next.run(req).await;
    }
    let resp = next.run(req).await;
    let status = resp.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return resp;
    }
    let (mut head, body) = resp.into_parts();
    let (code, message, details) = match head.extensions.remove::<ErrorParts>() {
        Some(p) => (p.code, p.message, p.detail),
        None => {
            let is_json = head.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("application/json"));
            if is_json {
                return Response::from_parts(head, body);
            }
            let bytes = axum::body::to_bytes(body, 64 * 1024).await.unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes).trim().to_string();
            let message = if text.is_empty() { status.canonical_reason().unwrap_or("error").to_lowercase() } else { text };
            (code_for_status(status), message, None)
        }
    };
    // `details` is always an object: a non-object detail is wrapped as `{"value": ...}`.
    let details = match details {
        Some(serde_json::Value::Object(m)) => serde_json::Value::Object(m),
        Some(serde_json::Value::Null) | None => serde_json::json!({}),
        Some(other) => serde_json::json!({ "value": other }),
    };
    let body = serde_json::to_vec(&serde_json::json!({ "code": code, "message": message, "details": details })).unwrap_or_default();
    head.headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    head.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    Response::from_parts(head, axum::body::Body::from(body))
}

pub type Result<T, E = RegistryError> = std::result::Result<T, E>;
