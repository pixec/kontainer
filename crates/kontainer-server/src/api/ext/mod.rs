//! Registry extension API (`/api/v1`) backing the web UI: repository browsing, manifest and
//! layer inspection, scan reports and administration.

pub mod artifacts;
mod history;

use std::collections::HashMap;

use axum::extract::{Extension, Path, Query, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde::Serialize;

use kontainer_core::perm::{Action, Global};
use crate::auth::{require, require_global, Principal};
use kontainer_core::digest::Digest;
use crate::error::{Code, RegistryError, Result};
use kontainer_core::manifest::{ImageConfig, Manifest};
use kontainer_core::names::{self, Reference};
use crate::scan::ScanReport;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/repositories", get(list_repositories))
        .route("/api/v1/repositories/{*rest}", any(dispatch))
        .route("/api/v1/gc", post(gc))
        .route("/api/v1/maintenance/{kind}/runs", get(task_runs))
        .route("/api/v1/scans/all", post(scan_everything))
        .route("/api/v1/logs", get(logs))
        .route("/api/v1/logs/export", get(logs_export))
}

#[derive(Serialize)]
struct RepoSummary {
    name: String,
    tags: usize,
    actions: Vec<Action>,
    visibility: crate::database::Visibility,
    description: String,
    topics: Vec<String>,
    updated_at: Option<String>,
    stars: i64,
    is_starred: bool,
    origin: Option<crate::api::repos::Origin>,
}

/// What a listing needs about every repository, loaded once.
struct ListingContext {
    stars: HashMap<String, i64>,
    starred: Vec<String>,
    origins: crate::api::repos::Origins,
}

impl ListingContext {
    async fn load(state: &AppState, p: &Principal) -> Result<Self> {
        let starred = match p.user_id {
            Some(uid) => state.auth.db.starred_by(uid).await?,
            None => vec![],
        };
        Ok(Self { stars: state.auth.db.star_counts().await?, starred, origins: crate::api::repos::Origins::load(&state.auth.db).await? })
    }

    async fn summary(&self, state: &AppState, p: &Principal, name: String) -> Result<RepoSummary> {
        let (tags, pushed) = state.storage.tag_summary(&name).await?;
        let meta = state.auth.db.repo_meta(&name).await?;
        Ok(RepoSummary {
            actions: p.actions_on(&name),
            visibility: meta.as_ref().map(|m| m.visibility).unwrap_or(crate::database::Visibility::Private),
            description: meta.as_ref().map(|m| m.description.clone()).unwrap_or_default(),
            topics: meta.as_ref().map(|m| m.topic_list()).unwrap_or_default(),
            // Last push; the catalogue entry's own timestamp only if nothing is tagged.
            updated_at: pushed.or(meta.map(|m| m.updated_at)).map(|t| t.to_rfc3339()),
            stars: self.stars.get(&name).copied().unwrap_or(0),
            is_starred: self.starred.contains(&name),
            origin: self.origins.get(&name),
            name,
            tags,
        })
    }
}

/// Every repository the caller can see, including ones created empty (`tags: 0`).
async fn list_repositories(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Json<Vec<RepoSummary>>> {
    let ctx = ListingContext::load(&state, &p).await?;
    let mut out = vec![];
    for name in state.repository_names().await? {
        if !p.can_see(&name) {
            continue;
        }
        out.push(ctx.summary(&state, &p, name).await?);
    }
    Ok(Json(out))
}

/// `GET /api/v1/repositories/{name}`: one repository's summary, as the listing has it. A
/// repository created empty is there with `tags: 0`.
async fn repository(state: AppState, p: Principal, name: String) -> Result<Response> {
    if !p.can_see(&name) {
        return Err(state.auth.denied(&p, Some(format!("repository:{name}:pull"))));
    }
    if !state.repository_known(&name).await? {
        return Err(RegistryError::new(Code::NameUnknown).detail(serde_json::json!({ "name": name })));
    }
    let ctx = ListingContext::load(&state, &p).await?;
    Ok(Json(ctx.summary(&state, &p, name).await?).into_response())
}

enum Route {
    Tags,
    Compare,
    Sbom(String),
    Verify(String),
    Export(String),
    Manifest(String),
    Scan(String),
    LayerFiles(String, String),
    History,
    Restore(String),
    Expiration(String),
    State,
    Repo,
    DeletePreview,
    TagDeletePreview(String),
    DeletePlan,
}

fn parse(rest: &str) -> Option<(String, Route)> {
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let n = segs.len();
    let name = |k: usize| segs[..n - k].join("/");
    if n >= 2 && segs[n - 1] == "tags" {
        return Some((name(1), Route::Tags));
    }
    if n >= 2 && segs[n - 1] == "history" {
        return Some((name(1), Route::History));
    }
    if n >= 4 && segs[n - 3] == "tags" && segs[n - 1] == "delete-preview" {
        return Some((name(3), Route::TagDeletePreview(segs[n - 2].to_string())));
    }
    if n >= 2 && segs[n - 1] == "delete-preview" {
        return Some((name(1), Route::DeletePreview));
    }
    if n >= 2 && segs[n - 1] == "delete-plan" {
        return Some((name(1), Route::DeletePlan));
    }
    if n >= 2 && segs[n - 1] == "state" {
        return Some((name(1), Route::State));
    }
    if n >= 4 && segs[n - 3] == "tags" && segs[n - 1] == "restore" {
        return Some((name(3), Route::Restore(segs[n - 2].to_string())));
    }
    if n >= 4 && segs[n - 3] == "tags" && segs[n - 1] == "expiration" {
        return Some((name(3), Route::Expiration(segs[n - 2].to_string())));
    }
    if n >= 2 && segs[n - 1] == "compare" {
        return Some((name(1), Route::Compare));
    }
    if n >= 4 && segs[n - 3] == "manifests" && segs[n - 1] == "sbom" {
        return Some((name(3), Route::Sbom(segs[n - 2].to_string())));
    }
    if n >= 4 && segs[n - 3] == "manifests" && segs[n - 1] == "export" {
        return Some((name(3), Route::Export(segs[n - 2].to_string())));
    }
    if n >= 4 && segs[n - 3] == "manifests" && segs[n - 1] == "verify" {
        return Some((name(3), Route::Verify(segs[n - 2].to_string())));
    }
    if n >= 6 && segs[n - 5] == "manifests" && segs[n - 3] == "layers" && segs[n - 1] == "files" {
        return Some((name(5), Route::LayerFiles(segs[n - 4].to_string(), segs[n - 2].to_string())));
    }
    if n >= 4 && segs[n - 3] == "manifests" && segs[n - 1] == "scan" {
        return Some((name(3), Route::Scan(segs[n - 2].to_string())));
    }
    if n >= 3 && segs[n - 2] == "manifests" {
        return Some((name(2), Route::Manifest(segs[n - 1].to_string())));
    }
    if n >= 1 {
        return Some((name(0), Route::Repo));
    }
    None
}

async fn dispatch(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(rest): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    method: Method,
    body: bytes::Bytes,
) -> Result<Response> {
    let Some((name, route)) = parse(&rest) else {
        return Err(RegistryError::with_message(Code::NotFound, "unknown endpoint"));
    };
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    match (route, method) {
        (Route::Tags, Method::GET) => tags(state, principal, name).await,
        (Route::Compare, Method::GET) => artifacts::compare(state, principal, name, query).await,
        (Route::Sbom(r), Method::GET) => artifacts::sbom(state, principal, name, r).await,
        (Route::Verify(r), Method::POST) => artifacts::verify(state, principal, name, r, &body).await,
        (Route::Export(r), Method::GET) => export(state, principal, name, r).await,
        (Route::Manifest(r), Method::GET) => manifest_detail(state, principal, name, r).await,
        (Route::Scan(r), Method::GET) => scan_get(state, principal, name, r).await,
        (Route::Scan(r), Method::POST) => scan_trigger(state, principal, name, r).await,
        (Route::LayerFiles(r, d), Method::GET) => layer_files(state, principal, name, r, d, query).await,
        (Route::History, Method::GET) => history::history(state, principal, name, query.get("tag").map(String::as_str)).await,
        (Route::Restore(t), Method::POST) => history::restore(state, principal, name, t, &body).await,
        (Route::Expiration(t), Method::PUT) => history::set_expiration(state, principal, name, t, &body).await,
        (Route::State, Method::GET) => history::repo_state(state, principal, name, None).await,
        (Route::State, Method::PUT) => history::repo_state(state, principal, name, Some(&body)).await,
        (Route::Repo, Method::GET) => repository(state, principal, name).await,
        (Route::Repo, Method::DELETE) => delete_repo(state, principal, name).await,
        (Route::DeletePreview, Method::GET) => crate::api::repos::repo_delete_preview(state, principal, name).await,
        (Route::TagDeletePreview(t), Method::GET) => crate::api::repos::tag_delete_preview(state, principal, name, t).await,
        (Route::DeletePlan, Method::POST) => crate::api::repos::create_delete_plan(state, principal, name, &body).await,
        _ => Err(RegistryError::with_message(Code::Unsupported, "method not allowed here")),
    }
}

#[derive(Serialize)]
struct TagInfo {
    tag: String,
    digest: String,
    media_type: String,
    size: u64,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pushed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan: Option<ScanBrief>,
    /// For an index: one row per platform image. For a single image: that image.
    platforms: Vec<PlatformRow>,
    artifact: kontainer_core::artifact::ArtifactInfo,
    /// For cosign `sha256-<hex>.sig|.att|.sbom` tags: the digest they are attached to.
    #[serde(skip_serializing_if = "Option::is_none")]
    attached_to: Option<String>,
}

#[derive(Serialize)]
struct PlatformRow {
    digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan: Option<ScanBrief>,
}

fn platform_label(p: &Option<kontainer_core::manifest::Platform>) -> Option<String> {
    p.as_ref().map(|p| {
        let mut s = format!("{}/{}", p.os, p.architecture);
        if let Some(v) = &p.variant {
            s.push('/');
            s.push_str(v);
        }
        s
    })
}

/// Platform rows for a manifest: index children (attestations skipped) or the image itself.
async fn platform_rows(state: &AppState, repo: &str, digest: &Digest, bytes: &[u8]) -> Result<(&'static str, Vec<PlatformRow>)> {
    let Ok((manifest, _)) = Manifest::parse(bytes, None) else { return Ok(("image", vec![])) };
    match manifest {
        Manifest::Index(ix) => {
            let mut rows = vec![];
            for c in ix.manifests.iter().filter(|c| c.platform.as_ref().is_some_and(|p| p.os != "unknown")) {
                let size = match state.storage.manifest_bytes(repo, &c.digest).await? {
                    Some(b) => Manifest::parse(&b, None).ok().map(|(m, _)| match m {
                        Manifest::Image(im) => im.config.size + im.layers.iter().map(|l| l.size).sum::<u64>(),
                        _ => c.size,
                    }).unwrap_or(c.size),
                    None => c.size,
                };
                rows.push(PlatformRow { digest: c.digest.to_string(), platform: platform_label(&c.platform), size, scan: scan_brief(state, &c.digest).await? });
            }
            Ok(("index", rows))
        }
        Manifest::Image(im) => {
            let platform = match state.storage.repo_blob_size(repo, &im.config.digest).await? {
                Some(_) => state
                    .small_blob(&im.config.digest)
                    .await?
                    .and_then(|b| serde_json::from_slice::<ImageConfig>(&b).ok())
                    .and_then(|c| match (c.os, c.architecture) {
                        (Some(os), Some(arch)) => Some(format!("{os}/{arch}")),
                        _ => None,
                    }),
                None => None,
            };
            let size = im.config.size + im.layers.iter().map(|l| l.size).sum::<u64>();
            Ok(("image", vec![PlatformRow { digest: digest.to_string(), platform, size, scan: scan_brief(state, digest).await? }]))
        }
    }
}

/// The most recently pushed tag of a repository and the platforms it covers. Cheap enough
/// for listings: one manifest read, plus one config read for a single-platform image.
#[derive(Debug, Default, Serialize)]
pub struct LatestTag {
    pub tag: Option<String>,
    pub pushed_at: Option<String>,
    pub platforms: Vec<String>,
}

pub async fn latest_tag(state: &AppState, repo: &str) -> Result<LatestTag> {
    let mut tags = state.storage.list_tags_resolved(repo).await?;
    tags.sort_by_key(|t| std::cmp::Reverse(t.pushed_at));
    let Some(t) = tags.into_iter().next() else { return Ok(LatestTag::default()) };
    let bytes = state.storage.manifest_bytes(repo, &t.digest).await?.unwrap_or_default();
    let platforms = match Manifest::parse(&bytes, None) {
        Ok((Manifest::Index(ix), _)) => ix
            .manifests
            .iter()
            .filter(|c| c.platform.as_ref().is_some_and(|p| p.os != "unknown"))
            .filter_map(|c| platform_label(&c.platform))
            .collect(),
        Ok((Manifest::Image(im), _)) => state
            .small_blob(&im.config.digest)
            .await?
            .and_then(|b| serde_json::from_slice::<ImageConfig>(&b).ok())
            .and_then(|c| Some(format!("{}/{}", c.os?, c.architecture?)))
            .into_iter()
            .collect(),
        Err(_) => vec![],
    };
    Ok(LatestTag { tag: Some(t.tag), pushed_at: t.pushed_at.map(|d| d.to_rfc3339()), platforms })
}

#[derive(Serialize)]
struct ScanBrief {
    status: crate::scan::ScanStatus,
    total: usize,
    summary: std::collections::BTreeMap<kontainer_core::config::Severity, usize>,
    max_severity: Option<kontainer_core::config::Severity>,
}

async fn scan_brief(state: &AppState, d: &Digest) -> Result<Option<ScanBrief>> {
    let Some(raw) = state.storage.get_scan(d).await? else { return Ok(None) };
    let r: ScanReport = serde_json::from_slice(&raw).map_err(RegistryError::internal)?;
    Ok(Some(ScanBrief { max_severity: r.max_severity(), status: r.status, total: r.total, summary: r.summary }))
}

async fn tags(state: AppState, p: Principal, name: String) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let mut out = vec![];
    let mut tags = state.storage.list_tags_resolved(&name).await?;
    tags.sort_by_key(|t| std::cmp::Reverse(t.pushed_at));
    let expirations: HashMap<String, String> = state.auth.db.tag_expirations(&name).await?.into_iter().map(|e| (e.tag, e.expires_at.to_rfc3339())).collect();
    for t in tags {
        let bytes = state.storage.manifest_bytes(&name, &t.digest).await?.unwrap_or_default();
        let (kind, platforms) = platform_rows(&state, &name, &t.digest, &bytes).await?;
        let artifact = match Manifest::parse(&bytes, None) {
            Ok((m, mt)) => kontainer_core::artifact::classify(&m, &mt),
            Err(_) => kontainer_core::artifact::classify_media_type(&super::v2::manifests_media_type(&bytes), None),
        };
        let attached_to = kontainer_core::artifact::cosign_tag_target(&t.tag).map(|(d, _)| d);
        out.push(TagInfo {
            expires_at: expirations.get(&t.tag).cloned(),
            artifact,
            attached_to,
            tag: t.tag,
            media_type: super::v2::manifests_media_type(&bytes),
            size: bytes.len() as u64,
            kind,
            pushed_at: t.pushed_at.map(|d| d.to_rfc3339()),
            scan: scan_brief(&state, &t.digest).await?,
            digest: t.digest.to_string(),
            platforms,
        });
    }
    Ok(Json(out).into_response())
}

#[derive(Serialize)]
struct LayerInfo {
    digest: String,
    media_type: String,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    urls: Option<Vec<String>>,
}

#[derive(Serialize)]
struct ManifestDetail {
    repository: String,
    reference: String,
    digest: String,
    media_type: String,
    size: u64,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<kontainer_core::manifest::Descriptor>,
    tags: Vec<String>,
    // image manifest
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<kontainer_core::manifest::Descriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<ImageConfig>,
    layers: Vec<LayerInfo>,
    total_size: u64,
    /// empty-layer history steps (metadata-only instructions like ENV, CMD)
    history: Vec<kontainer_core::manifest::HistoryEntry>,
    // index
    manifests: Vec<kontainer_core::manifest::Descriptor>,
    platforms: Vec<PlatformRow>,
    referrers: Vec<kontainer_core::manifest::Descriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan: Option<ScanBrief>,
    raw: serde_json::Value,
    artifact: kontainer_core::artifact::ArtifactInfo,
    /// Signatures, SBOMs and attestations attached through referrers or cosign tags.
    attached: Vec<artifacts::Attached>,
    /// For non-container artifacts (Helm charts, WASM, ...): the config blob as JSON, if small.
    #[serde(skip_serializing_if = "Option::is_none")]
    config_json: Option<serde_json::Value>,
    /// For cosign tag-style attachments: the manifest they belong to.
    #[serde(skip_serializing_if = "Option::is_none")]
    attached_to: Option<String>,
    /// Why the pull policy refuses this image; layer and config digests are then left out.
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked: Option<String>,
}

/// Download a tag (or digest) as an OCI image layout tarball.
async fn export(state: AppState, p: Principal, name: String, reference: String) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let (digest, bytes) = resolve(&state, &name, &reference).await?;
    let is_tag = !reference.contains(':');
    // An export is a pull: the namespace's pull policy applies.
    crate::policy::check_pull(&state, &p, &name, is_tag, &digest, &bytes).await?;
    let ref_name = if is_tag { reference.clone() } else { "latest".into() };
    let host = state.config.public_url().split("://").nth(1).unwrap_or_default().trim_end_matches('/').to_string();
    let image = format!("{host}/{name}:{ref_name}");
    let rx = kontainer_store::layout::export(state.storage.clone(), &name, digest.clone(), &ref_name, &image).await.map_err(RegistryError::internal)?;
    let file = format!("{}-{}.tar", name.replace('/', "_"), if is_tag { reference } else { digest.hex()[..12].to_string() });
    state.audit.record(&p, "export", Some(&name), Some(&ref_name), Some(&digest.to_string()), None);
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/x-tar".to_string()),
            (axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{file}\"")),
        ],
        axum::body::Body::from_stream(rx),
    )
        .into_response())
}

fn media_type_of(bytes: &[u8]) -> String {
    Manifest::parse(bytes, None).map(|(_, mt)| mt).unwrap_or_default()
}

async fn resolve(state: &AppState, name: &str, reference: &str) -> Result<(Digest, bytes::Bytes)> {
    let r = Reference::parse(reference).ok_or_else(|| RegistryError::new(Code::ManifestInvalid))?;
    let digest = match r {
        Reference::Digest(d) => d,
        Reference::Tag(t) => state.storage.resolve_tag(name, &t).await?.ok_or_else(|| RegistryError::new(Code::ManifestUnknown))?,
    };
    let bytes = state.storage.manifest_bytes(name, &digest).await?.ok_or_else(|| RegistryError::new(Code::ManifestUnknown))?;
    Ok((digest, bytes))
}

async fn manifest_detail(state: AppState, p: Principal, name: String, reference: String) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let (digest, bytes) = resolve(&state, &name, &reference).await?;
    let (manifest, media_type) = Manifest::parse(&bytes, None).map_err(|e| RegistryError::with_message(Code::ManifestInvalid, e.to_string()))?;
    // An image the pull policy blocks is still described (so the UI can say why), but without
    // the layer and config digests that would let a client fetch its blobs directly.
    let blocked = match crate::policy::check_pull(&state, &p, &name, Reference::parse(&reference).is_some_and(|r| matches!(r, Reference::Tag(_))), &digest, &bytes).await {
        Ok(()) => None,
        Err(e) if e.code == Code::Denied => Some(e.message),
        Err(e) => return Err(e),
    };
    let tags = state
        .storage
        .list_tags_resolved(&name)
        .await?
        .into_iter()
        .filter(|t| t.digest == digest)
        .map(|t| t.tag)
        .collect();
    let referrers: Vec<_> = state.storage.list_referrers(&name, &digest, None).await?.iter().filter_map(super::v2::describe).collect();
    let mut detail = ManifestDetail {
        repository: name.clone(),
        reference,
        digest: digest.to_string(),
        media_type,
        size: bytes.len() as u64,
        kind: "image",
        artifact_type: manifest.artifact_type(),
        annotations: manifest.annotations().cloned(),
        subject: manifest.subject().cloned(),
        tags,
        config: None,
        image: None,
        layers: vec![],
        total_size: 0,
        history: vec![],
        manifests: vec![],
        platforms: platform_rows(&state, &name, &digest, &bytes).await?.1,
        referrers,
        scan: scan_brief(&state, &digest).await?,
        raw: serde_json::from_slice(&bytes).unwrap_or_default(),
        artifact: kontainer_core::artifact::classify(&manifest, &media_type_of(&bytes)),
        attached: artifacts::attached(&state, &name, &digest).await?,
        config_json: None,
        attached_to: None,
        blocked: None,
    };
    detail.attached_to = detail.tags.iter().find_map(|t| kontainer_core::artifact::cosign_tag_target(t).map(|(d, _)| d));
    match &manifest {
        Manifest::Index(ix) => {
            detail.kind = "index";
            detail.manifests = ix.manifests.clone();
        }
        Manifest::Image(im) => {
            detail.config = Some(im.config.clone());
            let image: Option<ImageConfig> = match state.storage.repo_blob_size(&name, &im.config.digest).await? {
                Some(_) => state.small_blob(&im.config.digest).await?.and_then(|b| serde_json::from_slice(&b).ok()),
                None => None,
            };
            // Map non-empty history entries onto layers in order.
            let mut non_empty = image.as_ref().map(|i| i.history.iter().filter(|h| !h.is_empty_layer).cloned().collect::<Vec<_>>()).unwrap_or_default().into_iter();
            let diff_ids = image.as_ref().and_then(|i| i.rootfs.as_ref()).map(|r| r.diff_ids.clone()).unwrap_or_default();
            for (i, l) in im.layers.iter().enumerate() {
                let h = non_empty.next();
                detail.total_size += l.size;
                detail.layers.push(LayerInfo {
                    digest: l.digest.to_string(),
                    media_type: l.media_type.clone(),
                    size: l.size,
                    created_by: h.as_ref().and_then(|h| h.created_by.clone()),
                    created: h.as_ref().and_then(|h| h.created.clone()),
                    comment: h.as_ref().and_then(|h| h.comment.clone()),
                    diff_id: diff_ids.get(i).cloned(),
                    urls: l.urls.clone(),
                });
            }
            detail.total_size += im.config.size;
            detail.history = image.as_ref().map(|i| i.history.iter().filter(|h| h.is_empty_layer).cloned().collect()).unwrap_or_default();
            if !matches!(detail.artifact.kind, kontainer_core::artifact::ArtifactKind::Image) && im.config.size <= 64 * 1024 && state.storage.repo_blob_size(&name, &im.config.digest).await?.is_some() {
                detail.config_json = state.small_blob(&im.config.digest).await?.filter(|b| b.len() <= 64 * 1024).and_then(|b| serde_json::from_slice(&b).ok());
            }
            detail.image = image;
        }
    }
    if let Some(why) = blocked {
        detail.raw = serde_json::Value::Null;
        detail.config = None;
        detail.config_json = None;
        detail.layers.clear();
        detail.blocked = Some(why);
    }
    Ok(Json(detail).into_response())
}

async fn scan_get(state: AppState, p: Principal, name: String, reference: String) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let (digest, _) = resolve(&state, &name, &reference).await?;
    let Some(raw) = state.storage.get_scan(&digest).await? else {
        return Err(RegistryError::with_message(Code::NotFound, "no scan report for this manifest"));
    };
    let mut report: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| RegistryError::internal(anyhow::anyhow!(e)))?;
    // Which findings don't count for this namespace's pull policy.
    let ns = kontainer_core::names::namespace(&name);
    let allowed: std::collections::HashSet<String> = state.auth.db.allowed_cves(ns).await?.into_iter().collect();
    let found: Vec<&str> = report["vulnerabilities"].as_array().into_iter().flatten().filter_map(|v| v["id"].as_str()).filter(|id| allowed.contains(*id)).collect();
    let found: Vec<String> = found.into_iter().map(str::to_string).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    report["allowlisted"] = found.into();
    Ok(Json(report).into_response())
}

async fn scan_trigger(state: AppState, p: Principal, name: String, reference: String) -> Result<Response> {
    require(&state, &p, Action::Scan, &name)?;
    let Some(q) = &state.scans else {
        return Err(RegistryError::with_message(Code::Unsupported, "no scanner configured"));
    };
    let (digest, bytes) = resolve(&state, &name, &reference).await?;
    let (manifest, _) = Manifest::parse(&bytes, None).map_err(|e| RegistryError::with_message(Code::ManifestInvalid, e.to_string()))?;
    // For an index, scan each child image instead.
    let targets: Vec<Digest> = match &manifest {
        Manifest::Image(_) => vec![digest],
        Manifest::Index(ix) => ix.manifests.iter().map(|m| m.digest.clone()).collect(),
    };
    let mut queued = vec![];
    for d in targets {
        if q.enqueue(&state.storage, &name, &d).await {
            queued.push(d.to_string());
        }
    }
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "queued": queued }))).into_response())
}

async fn layer_files(state: AppState, p: Principal, name: String, reference: String, layer: String, query: HashMap<String, String>) -> Result<Response> {
    require(&state, &p, Action::Pull, &name)?;
    let (digest, bytes) = resolve(&state, &name, &reference).await?;
    // Listing a layer's files reads its content: the pull policy applies.
    crate::policy::check_pull(&state, &p, &name, !reference.contains(':'), &digest, &bytes).await?;
    let layer: Digest = layer.parse().map_err(|_| RegistryError::new(Code::DigestInvalid))?;
    let (manifest, _) = Manifest::parse(&bytes, None).map_err(|e| RegistryError::with_message(Code::ManifestInvalid, e.to_string()))?;
    let Manifest::Image(im) = manifest else {
        return Err(RegistryError::bad_request("not an image manifest"));
    };
    let Some(desc) = im.layers.iter().find(|l| l.digest == layer) else {
        return Err(RegistryError::new(Code::BlobUnknown));
    };
    if state.storage.repo_blob_size(&name, &layer).await?.is_none() {
        return Err(RegistryError::new(Code::BlobUnknown));
    }
    let limit = query.get("limit").and_then(|l| l.parse().ok()).unwrap_or(state.config.ui.max_layer_entries).min(state.config.ui.max_layer_entries);
    match kontainer_store::layerfs::list_files(&state.storage, &layer, &desc.media_type, limit).await? {
        Some(listing) => Ok(Json(listing).into_response()),
        None => Err(RegistryError::new(Code::BlobUnknown)),
    }
}

/// A repository is deleted only through a confirmed plan ([`crate::api::repos::create_delete_plan`]).
async fn delete_repo(state: AppState, p: Principal, name: String) -> Result<Response> {
    require(&state, &p, Action::DeleteRepository, &name)?;
    state.require_writable(&name).await?;
    if !state.config.features.is_delete {
        return Err(RegistryError::new(Code::Unsupported));
    }
    Err(RegistryError::bad_request(format!(
        "deleting a repository needs confirmation: POST /api/v1/repositories/{name}/delete-plan with {{\"repository\": true}}, then POST /api/v1/delete-plans/<id>/execute with {{\"confirm\": \"{name}\"}}"
    )))
}

#[derive(serde::Deserialize, Default)]
struct GcParams {
    #[serde(default, rename = "dry_run")]
    is_dry_run: bool,
    #[serde(default, rename = "delete_untagged")]
    is_delete_untagged: bool,
    /// Seconds; objects modified more recently are never collected. Defaults to
    /// `storage.upload_ttl`.
    grace_seconds: Option<u64>,
}

async fn gc(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(params): Query<GcParams>) -> Result<Response> {
    require_global(&state, &p, Global::Gc)?;
    let grace = params.grace_seconds.map(std::time::Duration::from_secs).unwrap_or(state.config.storage.upload_ttl);
    let report = crate::maintenance::gc(&state, "manual", p.name(), params.is_delete_untagged, params.is_dry_run, grace)
        .await
        .map_err(maintenance_error)?;
    if !params.is_dry_run {
        state.audit.record(&p, "gc", None, None, None, Some(format!("{} blobs, {} bytes", report.blobs_removed.len(), report.bytes_freed)));
    }
    Ok(Json(report).into_response())
}

/// A run that is already going is a conflict, not a server error.
fn maintenance_error(e: anyhow::Error) -> RegistryError {
    match e.downcast_ref::<crate::maintenance::AlreadyRunning>() {
        Some(busy) => RegistryError::with_message(Code::Conflict, busy.to_string()),
        None => RegistryError::internal(e),
    }
}

/// Recent runs of `gc` or `scan_all`, with when the schedule runs next.
async fn task_runs(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(kind): Path<String>) -> Result<Response> {
    require_global(&state, &p, Global::Gc)?;
    let interval = match kind.as_str() {
        "gc" => state.config.gc.interval.map(kontainer_core::config::format_duration),
        "scan_all" => state.config.scanner.rescan_interval.map(kontainer_core::config::format_duration),
        _ => return Err(RegistryError::not_found("maintenance task")),
    };
    let runs = state.auth.db.task_runs(&kind, 50).await?;
    Ok(Json(serde_json::json!({ "interval": interval, "runs": runs })).into_response())
}

#[derive(serde::Deserialize, Default)]
struct ScanAllParams {
    /// Only images that have never been scanned (default: also ones older than
    /// `scanner.rescan_interval`, or every image when that is unset).
    #[serde(default)]
    missing_only: bool,
}

/// Queue scans for every tagged image; returns once they are queued.
async fn scan_everything(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(q): Query<ScanAllParams>) -> Result<Response> {
    require_global(&state, &p, Global::Gc)?;
    if state.scans.is_none() {
        return Err(RegistryError::with_message(Code::Unsupported, "no scanner configured"));
    }
    // Without a rescan interval, "everything" means everything: a zero cutoff makes every
    // existing report stale.
    let stale_after = if q.missing_only { None } else { Some(state.config.scanner.rescan_interval.unwrap_or_default()) };
    let summary = crate::maintenance::scan_all(&state, "manual", p.name(), stale_after)
        .await
        .map_err(maintenance_error)?;
    state.audit.record(&p, "scan_all", None, None, None, Some(format!("{} queued", summary.queued)));
    Ok((StatusCode::ACCEPTED, Json(summary)).into_response())
}

#[derive(serde::Deserialize, Default)]
struct LogParams {
    repository: Option<String>,
    q: Option<String>,
    namespace: Option<String>,
    limit: Option<usize>,
    since: Option<String>,
    until: Option<String>,
    /// Export only: `csv` (default) or `json` (JSON Lines).
    format: Option<String>,
}

impl LogParams {
    fn filter(&self) -> crate::audit::LogFilter<'_> {
        crate::audit::LogFilter {
            repository: self.repository.as_deref(),
            search: self.q.as_deref(),
            namespace: self.namespace.as_deref(),
            since: self.since.as_deref(),
            until: self.until.as_deref(),
        }
    }
}

async fn logs(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(params): Query<LogParams>) -> Result<Response> {
    let entries = state.audit.list(&p, &params.filter(), params.limit.unwrap_or(100).min(1000)).await?;
    Ok(Json(entries).into_response())
}

fn csv_field(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) { format!("\"{}\"", v.replace('"', "\"\"")) } else { v.to_string() }
}

/// `GET /api/v1/logs/export`: everything the caller may see in the range, as a download.
async fn logs_export(State(state): State<AppState>, Extension(p): Extension<Principal>, Query(params): Query<LogParams>) -> Result<Response> {
    if p.user_id.is_none() {
        return Err(state.auth.denied(&p, None));
    }
    let entries = state.audit.list(&p, &params.filter(), params.limit.unwrap_or(100_000).min(100_000)).await?;
    let json = params.format.as_deref() == Some("json");
    let mut body = String::new();
    if json {
        for e in &entries {
            body.push_str(&serde_json::to_string(e).unwrap_or_default());
            body.push('\n');
        }
    } else {
        body.push_str("timestamp,action,actor,is_robot,repository,reference,digest,org,detail\n");
        for e in &entries {
            let row = [e.timestamp.as_str(), &e.action, &e.actor, if e.is_robot { "true" } else { "false" }, e.repository.as_deref().unwrap_or(""), e.reference.as_deref().unwrap_or(""), e.digest.as_deref().unwrap_or(""), e.org.as_deref().unwrap_or(""), e.detail.as_deref().unwrap_or("")];
            body.push_str(&row.iter().map(|v| csv_field(v)).collect::<Vec<_>>().join(","));
            body.push('\n');
        }
    }
    let scope = params.namespace.clone().or(params.repository.clone()).unwrap_or_else(|| "all".into()).replace('/', "_");
    let file = format!("activity-{scope}-{}.{}", chrono::Utc::now().format("%Y%m%d"), if json { "jsonl" } else { "csv" });
    state.audit.record(&p, "logs_exported", None, None, None, Some(format!("{} entries, {}", entries.len(), scope)));
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, if json { "application/x-ndjson".to_string() } else { "text/csv; charset=utf-8".to_string() }),
            (axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{file}\"")),
        ],
        body,
    )
        .into_response())
}
