//! A small OCI distribution client for talking to other registries (Docker Hub, GHCR,
//! another kontainer, ...). Used by the pull-through cache, mirrors and imports to pull, and
//! by push replication to push.
//!
//! Handles the token dance (`WWW-Authenticate: Bearer realm=...` -> token endpoint, with or
//! without credentials) and Basic auth, and streams blobs to disk while verifying digests.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use bytes::Bytes;
use futures::TryStreamExt;
use reqwest::header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Method, StatusCode};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt;

use crate::digest::Digest;

pub mod netguard;

/// Largest manifest accepted from an upstream (the same limit registries apply to pushes).
pub const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
/// Whole-request limit for small requests (manifests, tags, tokens, upload sessions). Blob
/// transfers have none: they are bounded by the idle [`READ_TIMEOUT`] instead.
/// Largest tag list page or token response accepted from an upstream.
pub const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
/// Largest blob downloaded when nothing says how large it should be (a pull-through cache
/// fetch without a manifest descriptor, when the caller has no `server.max_blob_size`).
pub const MAX_UNSIZED_BLOB_BYTES: u64 = 32 << 30;
const METADATA_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a response may go without delivering any bytes.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Why a request to an upstream registry failed, so callers can tell "it isn't there" and
/// "you may not" from an outage worth retrying.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The upstream answered 404 for this (repository, manifest, blob...).
    #[error("{0}: not found upstream")]
    NotFound(String),
    /// The upstream refused the credentials (401/403), or wants some and none are configured.
    #[error("{0}")]
    Unauthorized(String),
    /// The upstream could not be reached, timed out, or answered 408/429/5xx: worth retrying.
    #[error(transparent)]
    Transient(anyhow::Error),
    /// Anything else: a protocol violation, a digest mismatch, a local I/O error...
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl UpstreamError {
    /// Worth trying again later.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }

    /// The error for an unsuccessful `status` answered about `what`.
    fn from_status(status: StatusCode, what: &str) -> Self {
        match status {
            StatusCode::NOT_FOUND => Self::NotFound(what.to_string()),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Self::Unauthorized(format!("{what}: access denied by the upstream registry ({status})")),
            s if s.is_server_error() || s == StatusCode::TOO_MANY_REQUESTS || s == StatusCode::REQUEST_TIMEOUT => Self::Transient(anyhow!("{what}: upstream answered {s}")),
            s => Self::Other(anyhow!("{what}: upstream answered {s}")),
        }
    }

    /// A transport error, with `context` saying what was being done.
    fn transport(e: reqwest::Error, context: impl std::fmt::Display + Send + Sync + 'static) -> Self {
        let transient = is_transient_transport(&e);
        let e = anyhow::Error::new(e).context(context);
        if transient { Self::Transient(e) } else { Self::Other(e) }
    }
}

/// Connection failures, timeouts and broken bodies; not decoding or redirect errors.
fn is_transient_transport(e: &reqwest::Error) -> bool {
    e.is_connect() || e.is_timeout() || e.is_request() || e.is_body()
}

impl From<reqwest::Error> for UpstreamError {
    fn from(e: reqwest::Error) -> Self {
        if is_transient_transport(&e) { Self::Transient(e.into()) } else { Self::Other(e.into()) }
    }
}

impl From<std::io::Error> for UpstreamError {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.into())
    }
}

pub type Result<T, E = UpstreamError> = std::result::Result<T, E>;

/// Media types we ask for when fetching manifests.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

pub struct Upstream {
    base: String,
    /// `base`, parsed: the origin credentials belong to.
    origin: url::Url,
    /// TLS verification is off (or the upstream is plain HTTP): `http` token realms are accepted.
    is_insecure: bool,
    is_docker_hub: bool,
    username: Option<String>,
    password: Option<String>,
    http: reqwest::Client,
    /// For token realms on another site than the registry: no redirects, and a resolver that
    /// refuses internal addresses, so an upstream cannot point the registry at its own network.
    realm_http: reqwest::Client,
    /// Bearer tokens by scope, with their expiry.
    tokens: Mutex<HashMap<String, (String, Instant)>>,
}

#[derive(Debug, Clone)]
pub struct FetchedManifest {
    pub bytes: Bytes,
    pub media_type: String,
    pub digest: Digest,
}

fn param<'a>(challenge: &'a str, key: &str) -> Option<&'a str> {
    let i = challenge.find(&format!("{key}=\""))? + key.len() + 2;
    let rest = &challenge[i..];
    Some(&rest[..rest.find('"')?])
}

impl Upstream {
    /// `url` like `https://registry-1.docker.io` or `https://ghcr.io`. Docker Hub's
    /// `docker.io` alias is accepted.
    pub fn new(url: &str, username: Option<String>, password: Option<String>, insecure: bool) -> anyhow::Result<Self> {
        let mut base = url.trim().trim_end_matches('/').to_string();
        if !base.starts_with("http://") && !base.starts_with("https://") {
            base = format!("https://{base}");
        }
        let host = base.split("://").nth(1).unwrap_or_default().split('/').next().unwrap_or_default().to_string();
        let is_docker_hub = matches!(host.as_str(), "docker.io" | "registry-1.docker.io" | "index.docker.io");
        if is_docker_hub {
            base = "https://registry-1.docker.io".into();
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(READ_TIMEOUT)
            .danger_accept_invalid_certs(insecure)
            .user_agent(crate::USER_AGENT)
            .build()?;
        let realm_http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(READ_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(netguard::PublicOnly { hint: "token realms on another site must be public" })
            .user_agent(crate::USER_AGENT)
            .build()?;
        let origin = url::Url::parse(&base).with_context(|| format!("bad registry URL {base}"))?;
        let is_insecure = insecure || origin.scheme() == "http";
        Ok(Self { base, origin, is_insecure, is_docker_hub, username: username.filter(|u| !u.is_empty()), password, http, realm_http, tokens: Mutex::new(HashMap::new()) })
    }

    /// Docker Hub's official images live under `library/`.
    pub fn repo_path(&self, repo: &str) -> String {
        if self.is_docker_hub && !repo.contains('/') { format!("library/{repo}") } else { repo.to_string() }
    }

    async fn token(&self, challenge: &str, scope_hint: &str) -> Result<String> {
        let realm = param(challenge, "realm").ok_or_else(|| anyhow!("{}: bearer challenge without realm", self.base))?;
        let service = param(challenge, "service").unwrap_or_default();
        let scope = param(challenge, "scope").unwrap_or(scope_hint);
        let key = format!("{service}|{scope}");
        if let Some((t, exp)) = self.tokens.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            if *exp > Instant::now() {
                return Ok(t.clone());
            }
        }
        let mut params = vec![];
        if !service.is_empty() {
            params.push(("service", service));
        }
        if !scope.is_empty() {
            params.push(("scope", scope));
        }
        let url = url::Url::parse_with_params(realm, &params).context("bad token realm")?;
        match url.scheme() {
            "https" => {}
            "http" if self.is_insecure => {}
            s => return Err(anyhow!("{}: refusing token realm {realm} ({s}, not https)", self.base).into()),
        }
        // A realm on the registry's own site is trusted like the registry. One elsewhere is an
        // address the upstream chose: it must be https and public (not this machine, a private
        // network or a cloud metadata endpoint), and is asked through a client that re-checks
        // what the name resolves to and follows no redirects.
        let own_site = same_site(&self.origin, &url);
        if !own_site {
            if url.scheme() != "https" {
                return Err(anyhow!("{}: refusing token realm {realm} on another site (not https)", self.base).into());
            }
            if netguard::is_internal_literal(&url) {
                return Err(anyhow!("{}: refusing token realm {realm}: an internal address", self.base).into());
            }
        }
        let client = if own_site { &self.http } else { &self.realm_http };
        let mut req = client.get(url.clone()).timeout(METADATA_TIMEOUT);
        if let (Some(u), Some(p)) = (&self.username, &self.password) {
            // Credentials only go to the registry's own site; elsewhere a token is asked for
            // anonymously (enough for public images).
            if own_site {
                req = req.basic_auth(u, Some(p));
            } else {
                tracing::warn!(registry = %self.base, %realm, "token realm is on another site; not sending credentials to it");
            }
        }
        let resp = req.send().await.map_err(|e| UpstreamError::transport(e, "requesting a registry token"))?;
        if !resp.status().is_success() {
            return Err(UpstreamError::from_status(resp.status(), &format!("{}: token endpoint", self.base)));
        }
        let body = read_capped(resp, MAX_METADATA_BYTES).await.with_context(|| format!("{}: token endpoint", self.base))?;
        let v: serde_json::Value = serde_json::from_slice(&body).with_context(|| format!("{}: token endpoint returned invalid JSON", self.base))?;
        let token = v["token"].as_str().or_else(|| v["access_token"].as_str()).ok_or_else(|| anyhow!("token endpoint returned no token"))?.to_string();
        let ttl = v["expires_in"].as_u64().unwrap_or(60).clamp(30, 3600);
        self.tokens.lock().unwrap_or_else(|e| e.into_inner()).insert(key, (token.clone(), Instant::now() + Duration::from_secs(ttl.saturating_sub(10))));
        Ok(token)
    }

    /// Send a request, answering an auth challenge once.
    async fn send(&self, method: Method, path: &str, repo: Option<&str>, accept: Option<&str>) -> Result<reqwest::Response> {
        Ok(self.request(method, path, repo, false, accept, None, Some(METADATA_TIMEOUT)).await?.0)
    }

    /// Send a request to `path` (or a full URL), answering an auth challenge once with a token
    /// for `repo` (with push access when `push`). `body` is `(bytes, content type)`. Returns the
    /// response and the `Authorization` it was sent with, for follow-up requests. `timeout`
    /// bounds the whole exchange (leave it off for blob transfers).
    #[allow(clippy::too_many_arguments)]
    async fn request(&self, method: Method, path: &str, repo: Option<&str>, push: bool, accept: Option<&str>, body: Option<(Bytes, &str)>, timeout: Option<Duration>) -> Result<(reqwest::Response, Option<String>)> {
        let url = if path.starts_with("http://") || path.starts_with("https://") { path.to_string() } else { format!("{}{path}", self.base) };
        if !self.is_same_origin(&url) {
            return Err(anyhow!("{}: refusing to send a request to another origin ({url})", self.base).into());
        }
        let build = |auth: Option<&str>| {
            let mut r = self.http.request(method.clone(), &url);
            if let Some(t) = timeout {
                r = r.timeout(t);
            }
            if let Some(a) = accept {
                r = r.header(ACCEPT, a);
            }
            if let Some(a) = auth {
                r = r.header(AUTHORIZATION, a);
            }
            if let Some((b, ct)) = &body {
                r = r.header(reqwest::header::CONTENT_TYPE, *ct).body(b.clone());
            }
            r
        };
        let resp = build(None).send().await.map_err(|e| UpstreamError::transport(e, format!("connecting to {}", self.base)))?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok((resp, None));
        }
        let challenge = resp.headers().get(WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let auth = if challenge.to_ascii_lowercase().starts_with("bearer") {
            let scope = repo.map(|r| format!("repository:{r}:{}", if push { "pull,push" } else { "pull" })).unwrap_or_default();
            format!("Bearer {}", self.token(&challenge, &scope).await?)
        } else {
            let (Some(u), Some(p)) = (&self.username, &self.password) else { return Err(UpstreamError::Unauthorized(format!("{} requires credentials", self.base))) };
            use base64::Engine;
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))
        };
        let resp = build(Some(&auth)).send().await.map_err(|e| UpstreamError::transport(e, format!("connecting to {}", self.base)))?;
        Ok((resp, Some(auth)))
    }

    /// Is the registry reachable and speaking the distribution API? (401 counts: it answered.)
    pub async fn ping(&self) -> Result<Duration> {
        let start = Instant::now();
        let resp = self.http.get(format!("{}/v2/", self.base)).timeout(METADATA_TIMEOUT).send().await.map_err(|e| UpstreamError::transport(e, format!("connecting to {}", self.base)))?;
        match resp.status() {
            s if s.is_success() || s == StatusCode::UNAUTHORIZED => Ok(start.elapsed()),
            s => Err(UpstreamError::from_status(s, &format!("{} /v2/", self.base))),
        }
    }

    fn check(resp: &reqwest::Response, what: &str) -> Result<()> {
        match resp.status() {
            s if s.is_success() => Ok(()),
            s => Err(UpstreamError::from_status(s, what)),
        }
    }

    /// Digest of a manifest without downloading it, or `None` if it does not exist.
    pub async fn head_manifest(&self, repo: &str, reference: &str) -> Result<Option<Digest>> {
        let repo = self.repo_path(repo);
        let resp = self.send(Method::HEAD, &format!("/v2/{repo}/manifests/{reference}"), Some(&repo), Some(MANIFEST_ACCEPT)).await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::check(&resp, &format!("{repo}:{reference}"))?;
        Ok(resp.headers().get("docker-content-digest").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()))
    }

    pub async fn manifest(&self, repo: &str, reference: &str) -> Result<Option<FetchedManifest>> {
        let repo = self.repo_path(repo);
        let resp = self.send(Method::GET, &format!("/v2/{repo}/manifests/{reference}"), Some(&repo), Some(MANIFEST_ACCEPT)).await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::check(&resp, &format!("{repo}:{reference}"))?;
        let media_type = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().split(';').next().unwrap_or_default().trim().to_string();
        let bytes = read_capped(resp, MAX_MANIFEST_BYTES).await.with_context(|| format!("{repo}:{reference}"))?;
        let digest = Digest::sha256_of(&bytes);
        if let Ok(d) = reference.parse::<Digest>() {
            if d != digest {
                return Err(anyhow!("{repo}@{reference}: upstream returned content with digest {digest}").into());
            }
        }
        Ok(Some(FetchedManifest { bytes, media_type, digest }))
    }

    /// Stream a blob to `path`, verifying its sha256 digest. Returns its size. The download
    /// stops as soon as the upstream sends more than `expected_size` (from the manifest's
    /// descriptor, or the caller's size limit), or without one [`MAX_UNSIZED_BLOB_BYTES`].
    pub async fn blob_to_file(&self, repo: &str, digest: &Digest, path: &Path, expected_size: Option<u64>) -> Result<u64> {
        let repo = self.repo_path(repo);
        let (resp, _) = self.request(Method::GET, &format!("/v2/{repo}/blobs/{digest}"), Some(&repo), false, None, None, None).await?;
        Self::check(&resp, &format!("{repo}@{digest}"))?;
        let max = expected_size.unwrap_or(MAX_UNSIZED_BLOB_BYTES);
        if let Some(len) = resp.content_length() {
            if len > max {
                return Err(anyhow!("{repo}@{digest}: upstream announces {len} bytes, more than the {max} expected").into());
            }
        }
        let mut file = tokio::fs::File::create(path).await?;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.try_next().await? {
            hasher.update(&chunk);
            size += chunk.len() as u64;
            if size > max {
                return Err(anyhow!("{repo}@{digest}: upstream sent more than the {max} bytes expected").into());
            }
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        let got = format!("sha256:{}", hex::encode(hasher.finalize()));
        if got != digest.to_string() {
            return Err(anyhow!("{repo}@{digest}: downloaded content has digest {got}").into());
        }
        Ok(size)
    }

    /// Does the registry serve `digest` from `repo` to us? Asked with pull access only (the
    /// pull-through cache and imports check this before reusing a blob stored for another
    /// repository).
    pub async fn head_blob(&self, repo: &str, digest: &Digest) -> Result<bool> {
        let repo = self.repo_path(repo);
        let (resp, _) = self.request(Method::HEAD, &format!("/v2/{repo}/blobs/{digest}"), Some(&repo), false, None, None, Some(METADATA_TIMEOUT)).await?;
        match resp.status() {
            s if s.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Self::check(&resp, &format!("{repo}@{digest}")).map(|_| false),
        }
    }

    /// Does the registry have `digest` in `repo`? (Asked with push access, so a later push
    /// reuses the token.)
    pub async fn blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool> {
        let repo = self.repo_path(repo);
        let (resp, _) = self.request(Method::HEAD, &format!("/v2/{repo}/blobs/{digest}"), Some(&repo), true, None, None, Some(METADATA_TIMEOUT)).await?;
        match resp.status() {
            s if s.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Self::check(&resp, &format!("{repo}@{digest}")).map(|_| false),
        }
    }

    /// Upload a blob of `size` bytes, streamed from `body`, in one request after opening an
    /// upload session (which is also where authentication happens: a stream can't be resent).
    pub async fn push_blob(&self, repo: &str, digest: &Digest, size: u64, body: reqwest::Body) -> Result<()> {
        let repo = self.repo_path(repo);
        let (resp, auth) = self.request(Method::POST, &format!("/v2/{repo}/blobs/uploads/"), Some(&repo), true, None, None, Some(METADATA_TIMEOUT)).await?;
        Self::check(&resp, &format!("starting an upload to {repo}"))?;
        let location = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).ok_or_else(|| anyhow!("{repo}: the registry gave no upload location"))?;
        let location = if location.starts_with("http") { location.to_string() } else { format!("{}{location}", self.base) };
        let sep = if location.contains('?') { '&' } else { '?' };
        let mut req = self
            .http
            .put(format!("{location}{sep}digest={digest}"))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(body);
        // The upload location may point elsewhere (a storage frontend): credentials only go
        // back to the registry's own origin.
        if let Some(a) = auth.filter(|_| self.is_same_origin(&location)) {
            req = req.header(AUTHORIZATION, a);
        }
        let resp = req.send().await.map_err(|e| UpstreamError::transport(e, format!("uploading {digest} to {repo}")))?;
        Self::check(&resp, &format!("{repo}@{digest}"))
    }

    /// Push a manifest under `reference` (a tag or its digest). Returns the registry's digest.
    pub async fn put_manifest(&self, repo: &str, reference: &str, media_type: &str, bytes: Bytes) -> Result<Digest> {
        let repo = self.repo_path(repo);
        let expected = Digest::sha256_of(&bytes);
        let (resp, _) = self.request(Method::PUT, &format!("/v2/{repo}/manifests/{reference}"), Some(&repo), true, None, Some((bytes, media_type)), Some(METADATA_TIMEOUT)).await?;
        Self::check(&resp, &format!("{repo}:{reference}"))?;
        // A registry that stored something else (rewrote the manifest) did not store our image.
        match resp.headers().get("docker-content-digest").and_then(|v| v.to_str().ok()).map(str::parse::<Digest>) {
            Some(Ok(d)) if d != expected => Err(anyhow!("{repo}:{reference}: the registry stored {d}, but the manifest pushed is {expected}").into()),
            Some(Err(_)) => Err(anyhow!("{repo}:{reference}: the registry answered an invalid Docker-Content-Digest").into()),
            _ => Ok(expected),
        }
    }

    /// Delete a tag or manifest. `false` when it was not there. Registries that can't delete by
    /// tag answer an error.
    pub async fn delete_manifest(&self, repo: &str, reference: &str) -> Result<bool> {
        let repo = self.repo_path(repo);
        let (resp, _) = self.request(Method::DELETE, &format!("/v2/{repo}/manifests/{reference}"), Some(&repo), true, None, None, Some(METADATA_TIMEOUT)).await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        Self::check(&resp, &format!("deleting {repo}:{reference}"))?;
        Ok(true)
    }

    /// Every tag of a repository (follows `Link` pagination).
    pub async fn tags(&self, repo: &str) -> Result<Vec<String>> {
        let repo = self.repo_path(repo);
        let mut out = vec![];
        let mut path = format!("/v2/{repo}/tags/list?n=1000");
        for _ in 0..100 {
            let resp = self.send(Method::GET, &path, Some(&repo), None).await?;
            Self::check(&resp, &format!("{repo} tags"))?;
            let next = resp.headers().get(reqwest::header::LINK).and_then(|v| v.to_str().ok()).and_then(|l| l.split(';').next()).map(|l| l.trim().trim_start_matches('<').trim_end_matches('>').to_string());
            let body = read_capped(resp, MAX_METADATA_BYTES).await.with_context(|| format!("{repo} tags"))?;
            let v: serde_json::Value = serde_json::from_slice(&body).with_context(|| format!("{repo} tags: invalid JSON"))?;
            out.extend(v["tags"].as_array().into_iter().flatten().filter_map(|t| t.as_str().map(str::to_string)));
            match next {
                Some(n) if n.starts_with("/v2/") => path = n,
                Some(n) if n.starts_with("http") => path = n.split_once("/v2/").map(|(_, p)| format!("/v2/{p}")).unwrap_or_default(),
                _ => break,
            }
            if path.is_empty() {
                break;
            }
        }
        Ok(out)
    }
}

impl Upstream {
    /// Whether `url` (absolute, or a path on the registry) is on the registry's own origin.
    fn is_same_origin(&self, url: &str) -> bool {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return true;
        }
        url::Url::parse(url).is_ok_and(|u| u.origin() == self.origin.origin())
    }
}

/// Read a response body of at most `max` bytes.
async fn read_capped(resp: reqwest::Response, max: u64) -> anyhow::Result<Bytes> {
    if resp.content_length().is_some_and(|n| n > max) {
        bail!("response is larger than {max} bytes");
    }
    let mut out = bytes::BytesMut::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.try_next().await? {
        if out.len() as u64 + chunk.len() as u64 > max {
            bail!("response is larger than {max} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

/// Whether two URLs are on the same site: the same host, or the same registrable domain
/// (`registry-1.docker.io` and `auth.docker.io`). The registrable domain is approximated as the
/// last two labels, or three under a two-letter country code with a short second level
/// (`example.co.uk`). IP addresses must match exactly.
fn same_site(a: &url::Url, b: &url::Url) -> bool {
    let (Some(ha), Some(hb)) = (a.host_str(), b.host_str()) else { return false };
    let (ha, hb) = (ha.to_ascii_lowercase(), hb.to_ascii_lowercase());
    if ha == hb {
        return true;
    }
    if !matches!(a.host(), Some(url::Host::Domain(_))) || !matches!(b.host(), Some(url::Host::Domain(_))) {
        return false;
    }
    fn site(host: &str) -> Option<String> {
        let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
        let n = labels.len();
        if n < 2 {
            return None;
        }
        let take = if n >= 3 && labels[n - 1].len() == 2 && labels[n - 2].len() <= 3 { 3 } else { 2 };
        (n >= take).then(|| labels[n - take..].join("."))
    }
    site(&ha).is_some_and(|s| Some(s) == site(&hb))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_are_classified() {
        let kind = |s: StatusCode| match UpstreamError::from_status(s, "x") {
            UpstreamError::NotFound(_) => "not found",
            UpstreamError::Unauthorized(_) => "unauthorized",
            UpstreamError::Transient(_) => "transient",
            UpstreamError::Other(_) => "other",
        };
        assert_eq!(kind(StatusCode::NOT_FOUND), "not found");
        assert_eq!(kind(StatusCode::UNAUTHORIZED), "unauthorized");
        assert_eq!(kind(StatusCode::FORBIDDEN), "unauthorized");
        assert_eq!(kind(StatusCode::TOO_MANY_REQUESTS), "transient");
        assert_eq!(kind(StatusCode::BAD_GATEWAY), "transient");
        assert_eq!(kind(StatusCode::BAD_REQUEST), "other");
    }

    #[test]
    fn challenge_params() {
        let c = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
        assert_eq!(param(c, "realm"), Some("https://auth.docker.io/token"));
        assert_eq!(param(c, "service"), Some("registry.docker.io"));
        assert_eq!(param(c, "scope"), Some("repository:library/alpine:pull"));
        assert_eq!(param(c, "missing"), None);
    }

    #[test]
    fn docker_hub_paths() {
        let hub = Upstream::new("docker.io", None, None, false).unwrap();
        assert_eq!(hub.base, "https://registry-1.docker.io");
        assert_eq!(hub.repo_path("alpine"), "library/alpine");
        assert_eq!(hub.repo_path("grafana/grafana"), "grafana/grafana");
        let ghcr = Upstream::new("ghcr.io/", None, None, false).unwrap();
        assert_eq!(ghcr.base, "https://ghcr.io");
        assert_eq!(ghcr.repo_path("alpine"), "alpine");
    }

    #[test]
    fn credentials_stay_on_the_registry_site() {
        let u = |s: &str| url::Url::parse(s).unwrap();
        assert!(same_site(&u("https://registry-1.docker.io"), &u("https://auth.docker.io/token")));
        assert!(same_site(&u("https://ghcr.io"), &u("https://ghcr.io/token")));
        assert!(!same_site(&u("https://ghcr.io"), &u("https://evil.example/token")));
        assert!(!same_site(&u("https://registry.example.co.uk"), &u("https://other.co.uk/token")));
        assert!(same_site(&u("https://registry.example.co.uk"), &u("https://auth.example.co.uk/token")));
        assert!(!same_site(&u("https://10.0.0.1"), &u("https://10.0.0.2")));
    }

    #[test]
    fn upload_locations_on_other_origins_get_no_credentials() {
        let up = Upstream::new("https://registry.example.com", None, None, false).unwrap();
        assert!(up.is_same_origin("/v2/x/blobs/uploads/1"));
        assert!(up.is_same_origin("https://registry.example.com/v2/x/blobs/uploads/1"));
        assert!(!up.is_same_origin("https://storage.example.com/upload/1"));
        assert!(!up.is_same_origin("http://registry.example.com/v2/x/blobs/uploads/1"));
    }
}
