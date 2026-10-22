//! Working with other registries: upstream endpoints, pull-through caches, mirrors, imports,
//! and the background jobs they run.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;

use kontainer_core::perm::{valid_org_name, Action, Global};
use kontainer_store::layout::ImportError;
use crate::auth::{require_global, require_user, Principal};
use crate::database::remote::{Mirror, MirrorInput, RegistryInput};
use crate::error::{Code, RegistryError, Result};
use kontainer_core::names;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/registries", get(list_registries).post(create_registry))
        .route("/api/v1/registries/{id}", put(update_registry).delete(delete_registry))
        .route("/api/v1/registries/{id}/test", post(test_registry))
        .route("/api/v1/proxy-caches", get(list_proxies).post(create_proxy))
        .route("/api/v1/proxy-caches/{ns}", axum::routing::delete(delete_proxy))
        .route("/api/v1/mirrors", get(list_mirrors).post(create_mirror))
        .route("/api/v1/mirrors/{id}", put(update_mirror).delete(delete_mirror))
        .route("/api/v1/mirrors/{id}/sync", post(sync_mirror_now))
        .route("/api/v1/import", post(import))
        .route("/api/v1/jobs", get(list_jobs))
        .route("/api/v1/jobs/{id}/cancel", post(cancel_job))
        // Archives can be large: stream them to disk, without axum's default body limit.
        .route("/api/v1/import/archive/{*name}", post(import_archive).layer(axum::extract::DefaultBodyLimit::disable()))
}

// Registries
/// Everyone signed in sees the endpoints (to pick one for a mirror or import); credentials
/// are never returned.
async fn list_registries(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    require_user(&state, &p)?;
    Ok(Json(state.auth.db.registries().await?).into_response())
}

fn validate_registry(r: &RegistryInput) -> Result<()> {
    if !valid_org_name(&r.name) {
        return Err(RegistryError::bad_request("name: letters, digits, `-`, `_`, `.`"));
    }
    if r.url.trim().is_empty() {
        return Err(RegistryError::bad_request("url is required, e.g. https://ghcr.io"));
    }
    Ok(())
}

async fn create_registry(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<RegistryInput>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    validate_registry(&body)?;
    let r = state.auth.db.create_registry(&body).await.map_err(|_| RegistryError::conflict("a registry with that name already exists"))?;
    state.audit.record(&p, "registry_created", None, None, None, Some(format!("{} {}", r.name, r.url)));
    Ok((StatusCode::CREATED, Json(r)).into_response())
}

async fn update_registry(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(body): Json<RegistryInput>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    validate_registry(&body)?;
    state.auth.db.registry(id).await?.ok_or_else(|| RegistryError::not_found("registry"))?;
    state.auth.db.update_registry(id, &body).await?;
    state.proxy.forget(id);
    state.audit.record(&p, "registry_updated", None, None, None, Some(body.name.clone()));
    Ok(Json(state.auth.db.registry(id).await?).into_response())
}

async fn delete_registry(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let r = state.auth.db.registry(id).await?.ok_or_else(|| RegistryError::not_found("registry"))?;
    state.auth.db.delete_registry(id).await?;
    state.proxy.forget(id);
    state.auth.refresh_proxies().await?;
    state.audit.record(&p, "registry_deleted", None, None, None, Some(r.name));
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize, Default)]
struct TestBody {
    /// Optionally also list this repository's tags, which checks credentials.
    #[serde(default)]
    repository: Option<String>,
}

/// Registry administrators only: the test uses the registry's stored credentials (and lists
/// tags with them), which are the instance's, not the caller's.
async fn test_registry(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, body: Option<Json<TestBody>>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let r = state.auth.db.registry(id).await?.ok_or_else(|| RegistryError::not_found("registry"))?;
    let up = r.client().map_err(RegistryError::internal)?;
    let latency = match up.ping().await {
        Ok(d) => d,
        Err(e) => return Ok(Json(serde_json::json!({ "ok": false, "message": format!("{e:#}") })).into_response()),
    };
    let mut out = serde_json::json!({ "ok": true, "latency_ms": latency.as_millis() as u64, "message": format!("reachable in {} ms", latency.as_millis()) });
    if let Some(repo) = body.and_then(|b| b.0.repository).filter(|r| !r.is_empty()) {
        match up.tags(&repo).await {
            Ok(tags) => out["tags"] = serde_json::json!(tags.into_iter().rev().take(20).collect::<Vec<_>>()),
            Err(e) => {
                out["ok"] = serde_json::json!(false);
                out["message"] = serde_json::json!(format!("{e:#}"));
            }
        }
    }
    Ok(Json(out).into_response())
}

// Pull-through caches
async fn list_proxies(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    require_user(&state, &p)?;
    Ok(Json(state.auth.db.proxy_caches().await?).into_response())
}

#[derive(Deserialize)]
struct ProxyBody {
    namespace: String,
    registry_id: i64,
    #[serde(default = "six_hours")]
    ttl_secs: i64,
    #[serde(default)]
    is_public: bool,
}
fn six_hours() -> i64 {
    6 * 3600
}

async fn create_proxy(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<ProxyBody>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    let ns = body.namespace.trim().to_lowercase();
    if !valid_org_name(&ns) {
        return Err(RegistryError::bad_request("namespace: lowercase letters, digits, `-`, `_`, `.`"));
    }
    state.auth.db.registry(body.registry_id).await?.ok_or_else(|| RegistryError::not_found("registry"))?;
    let existing = state.auth.db.proxy_cache(&ns).await?;
    if existing.is_none() && (state.auth.db.name_taken(&ns).await? || state.storage.namespace_has_repositories(&ns).await?) {
        return Err(RegistryError::conflict("that namespace is already used by a user, organization or repositories"));
    }
    if body.ttl_secs < 60 {
        return Err(RegistryError::bad_request("ttl_secs must be at least 60"));
    }
    state.auth.db.set_proxy_cache(&ns, body.registry_id, body.ttl_secs, body.is_public).await?;
    state.auth.refresh_proxies().await?;
    state.audit.record_org(&p, "proxy_cache_set", &ns, None);
    Ok((StatusCode::CREATED, Json(state.auth.db.proxy_cache(&ns).await?)).into_response())
}

/// Stops proxying. Cached repositories stay in storage (delete them, then GC, to free space).
async fn delete_proxy(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(ns): Path<String>) -> Result<Response> {
    require_global(&state, &p, Global::UsersWrite)?;
    state.auth.db.proxy_cache(&ns).await?.ok_or_else(|| RegistryError::not_found("pull-through cache"))?;
    state.auth.db.delete_proxy_cache(&ns).await?;
    state.auth.refresh_proxies().await?;
    state.audit.record_org(&p, "proxy_cache_deleted", &ns, None);
    Ok(StatusCode::NO_CONTENT.into_response())
}

// Mirrors
fn can_manage_mirror(p: &Principal, target: &str) -> bool {
    p.has_global(Global::UsersWrite) || p.allowed(Action::Mirror, target)
}

async fn list_mirrors(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    require_user(&state, &p)?;
    let mirrors: Vec<Mirror> = state.auth.db.mirrors().await?.into_iter().filter(|m| can_manage_mirror(&p, &m.target)).collect();
    Ok(Json(mirrors).into_response())
}

async fn validate_mirror(state: &AppState, p: &Principal, m: &MirrorInput) -> Result<()> {
    if !names::is_valid_repository(&m.target) || m.source.trim().is_empty() {
        return Err(RegistryError::bad_request("source and target must be repository names, e.g. library/alpine -> mirrors/alpine"));
    }
    if !can_manage_mirror(p, &m.target) {
        return Err(state.auth.denied(p, None));
    }
    if state.auth.proxies_contains(kontainer_core::names::namespace(&m.target)).await {
        return Err(RegistryError::bad_request("the target is inside a pull-through cache namespace"));
    }
    let registry = state.auth.db.registry(m.registry_id).await?.ok_or_else(|| RegistryError::not_found("registry"))?;
    // As for imports: a registry's stored credentials are for registry administrators.
    if has_credentials(&registry) && !p.has_global(Global::UsersWrite) {
        return Err(state.auth.denied(p, None));
    }
    if m.interval_secs < 300 {
        return Err(RegistryError::bad_request("interval_secs must be at least 300 (5 minutes)"));
    }
    Ok(())
}

async fn create_mirror(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<MirrorInput>) -> Result<Response> {
    require_user(&state, &p)?;
    validate_mirror(&state, &p, &body).await?;
    let m = state.auth.db.create_mirror(&body).await?;
    mirror_lock(&state, &m.target, &p).await?;
    state.audit.record(&p, "mirror_created", Some(&m.target), None, None, Some(m.source.clone()));
    Ok((StatusCode::CREATED, Json(m)).into_response())
}

/// A mirror target only takes writes from its sync.
async fn mirror_lock(state: &AppState, target: &str, p: &Principal) -> Result<()> {
    if state.auth.db.repo_state(target).await?.is_none() {
        state.auth.db.set_repo_state(target, "mirror", None, p.name()).await?;
    }
    Ok(())
}

/// Back to normal once no mirror writes to it (a deliberate read-only state is kept).
async fn mirror_unlock(state: &AppState, target: &str, p: &Principal) -> Result<()> {
    let still = state.auth.db.mirrors().await?.iter().any(|m| m.target == target);
    if !still && state.auth.db.repo_state(target).await?.is_some_and(|s| s.state == "mirror") {
        state.auth.db.set_repo_state(target, "normal", None, p.name()).await?;
    }
    Ok(())
}

async fn mirror_for(state: &AppState, p: &Principal, id: i64) -> Result<Mirror> {
    let m = state.auth.db.mirror(id).await?.ok_or_else(|| RegistryError::not_found("mirror"))?;
    if can_manage_mirror(p, &m.target) { Ok(m) } else { Err(state.auth.denied(p, None)) }
}

async fn update_mirror(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>, Json(body): Json<MirrorInput>) -> Result<Response> {
    let old = mirror_for(&state, &p, id).await?;
    validate_mirror(&state, &p, &body).await?;
    state.auth.db.update_mirror(id, &body).await?;
    if old.target != body.target {
        mirror_unlock(&state, &old.target, &p).await?;
        mirror_lock(&state, &body.target, &p).await?;
    }
    Ok(Json(state.auth.db.mirror(id).await?).into_response())
}

async fn delete_mirror(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let m = mirror_for(&state, &p, id).await?;
    state.auth.db.delete_mirror(id).await?;
    mirror_unlock(&state, &m.target, &p).await?;
    state.audit.record(&p, "mirror_deleted", Some(&m.target), None, None, None);
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn sync_mirror_now(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<i64>) -> Result<Response> {
    let m = mirror_for(&state, &p, id).await?;
    let s = state.clone();
    let job = state.spawn_job("mirror", format!("Sync {} → {}", m.source, m.target), p.name().to_string(), async move { crate::sync::sync_mirror(&s, &m).await }).await?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "job": job }))).into_response())
}

// Imports
#[derive(Deserialize)]
struct ImportBody {
    registry_id: i64,
    /// Repository on the registry, e.g. `library/alpine` or `alpine` on Docker Hub.
    source: String,
    /// Tag or digest.
    reference: String,
    /// Local repository.
    target: String,
    /// Local tag; defaults to `reference` (or `latest` when importing by digest).
    #[serde(default)]
    tag: Option<String>,
}

async fn import(State(state): State<AppState>, Extension(p): Extension<Principal>, Json(body): Json<ImportBody>) -> Result<Response> {
    require_user(&state, &p)?;
    if !names::is_valid_repository(&body.target) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    let mut p = p;
    state.auth.confirm_new_repo(&mut p, &body.target).await?;
    if !p.allowed(Action::Push, &body.target) {
        return Err(state.auth.denied(&p, None));
    }
    state.require_writable(&body.target).await?;
    if kontainer_core::names::Reference::parse(&body.reference).is_none() {
        return Err(RegistryError::bad_request("reference: a tag or a digest"));
    }
    let registry = state.auth.db.registry(body.registry_id).await?.ok_or_else(|| RegistryError::not_found("registry"))?;
    // Stored credentials belong to whoever configured the registry (registry administrators):
    // importing with them could reach private upstream images, so it takes the same permission.
    // Anonymous registries only need push access to the target.
    if has_credentials(&registry) && !p.has_global(Global::UsersWrite) {
        return Err(state.auth.denied(&p, None));
    }
    let tag = body.tag.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| if body.reference.contains(':') { "latest".into() } else { body.reference.clone() });
    // The same rule as a tag in a push (`Reference::parse`).
    if !names::is_valid_tag(&tag) {
        return Err(RegistryError::bad_request("tag: letters, digits, `_`, `.` and `-`, at most 128 characters, not starting with `.` or `-`"));
    }
    let up = state.proxy.upstream(&registry).map_err(RegistryError::internal)?;
    let quota = state.quota_check(&body.target).await?;
    let (s, actor) = (state.clone(), p.clone());
    let title = format!("Import {}/{}:{} → {}:{tag}", registry.name, body.source, body.reference, body.target);
    let job = state.spawn_job("import", title, p.name().to_string(), async move {
        // The checks a push gets: an immutable tag is not re-pointed, and the namespace quota
        // holds. Both need the upstream manifest, so they run here rather than in the request.
        crate::state::job_progress("Reading the manifest");
        let top = up.manifest(&body.source, &body.reference).await?.ok_or_else(|| anyhow::anyhow!("{}:{} not found upstream", body.source, body.reference))?;
        s.check_tag_change(&body.target, &tag, &top.digest).await?;
        if let Some(q) = &quota {
            let blobs = crate::sync::import_contents(&up, &body.source, &top).await?;
            s.admit_write(q, &body.target, blobs, 0, actor.name()).await?;
        }
        crate::state::job_progress("Copying layers");
        let (digest, stats) = crate::sync::copy_tag(&s, &up, &crate::sync::TagCopy { src_repo: &body.source, reference: &body.reference, dst_repo: &body.target, dst_tag: &tag, action: "import", actor: actor.name() }).await?;
        if let Err(e) = s.auth.db.record_import(&body.target, "registry", Some(&registry.name), &format!("{}{}{}", body.source, if body.reference.contains(':') { "@" } else { ":" }, body.reference), actor.name()).await {
            tracing::warn!(repository = %body.target, error = %e, "recording an import's origin");
        }
        s.audit.record(&actor, "import", Some(&body.target), Some(&tag), Some(&digest.to_string()), Some(format!("from {}/{}:{}", registry.name, body.source, body.reference)));
        Ok(format!("{} manifests, {} new layers ({}) → {}:{tag}", stats.manifests, stats.blobs_downloaded, kontainer_store::usage::human(stats.bytes_downloaded), body.target))
    })
    .await?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "job": job }))).into_response())
}

/// Whether pulling from `r` would use credentials stored with it.
fn has_credentials(r: &crate::database::remote::Registry) -> bool {
    r.username.as_deref().is_some_and(|u| !u.is_empty()) || r.password.as_deref().is_some_and(|p| !p.is_empty())
}

#[derive(Deserialize)]
struct ArchiveQuery {
    #[serde(default)]
    tag: Option<String>,
    /// The uploaded file's name, remembered as the repository's origin.
    #[serde(default)]
    filename: Option<String>,
}

/// Import an OCI image layout tarball (as made by `docker save` on Docker 25+, `skopeo copy
/// ... oci-archive:` or this registry's export) into a repository.
async fn import_archive(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(name): Path<String>,
    axum::extract::Query(q): axum::extract::Query<ArchiveQuery>,
    body: axum::body::Body,
) -> Result<Response> {
    use futures::TryStreamExt;
    use tokio::io::AsyncWriteExt;
    if !names::is_valid_repository(&name) {
        return Err(RegistryError::new(Code::NameInvalid));
    }
    let mut p = p;
    state.auth.confirm_new_repo(&mut p, &name).await?;
    if !p.allowed(Action::Push, &name) {
        return Err(state.auth.denied(&p, None));
    }
    state.require_writable(&name).await?;
    let tag = q.tag.as_deref().filter(|t| !t.is_empty());
    if tag.is_some_and(|t| !names::is_valid_tag(t)) {
        return Err(RegistryError::bad_request("tag: letters, digits, `_`, `.` and `-`, at most 128 characters, not starting with `.` or `-`"));
    }
    let archive = state.storage.uploads.temp_path().await?;
    let work = state.storage.uploads.temp_path().await?;
    let result = async {
        let mut file = tokio::fs::File::create(&archive).await?;
        let mut stream = body.into_data_stream();
        let mut size = 0u64;
        while let Some(chunk) = stream.try_next().await.map_err(|_| RegistryError::bad_request("the upload was interrupted"))? {
            size += chunk.len() as u64;
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        // Quota: the archive's size bounds what it can add (its blobs, stored as they are).
        if let Some(q) = state.quota_check(&name).await? {
            state.admit_write(&q, &name, vec![], size, p.name()).await?;
        }
        tokio::fs::create_dir_all(&work).await?;
        kontainer_store::layout::import(&state.storage, &name, &archive, &work, tag).await.map_err(import_error)
    }
    .await;
    for (what, r) in [("archive", tokio::fs::remove_file(&archive).await), ("work directory", tokio::fs::remove_dir_all(&work).await)] {
        match r {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => tracing::warn!(error = %e, what, "removing an import's temporary files"),
            _ => {}
        }
    }
    let imported = result?;
    // Immutable tags: check every tag before moving any.
    for (tag, digest) in &imported.roots {
        state.check_tag_change(&name, tag, digest).await?;
    }
    for (tag, digest) in &imported.roots {
        crate::tags::set(&state, &name, tag, digest, "import", p.name()).await?;
    }
    state.auth.note_repo(&name, true).await;
    state.reindex(&name).await;
    let file = q.filename.as_deref().map(|f| f.rsplit(['/', '\\']).next().unwrap_or(f).chars().take(200).collect::<String>()).filter(|f| !f.is_empty()).unwrap_or_else(|| "uploaded archive".into());
    if let Err(e) = state.auth.db.record_import(&name, "archive", None, &file, p.name()).await {
        tracing::warn!(repository = %name, error = %e, "recording an import's origin");
    }
    state.audit.record(&p, "import_archive", Some(&name), Some(&imported.tags.join(",")), None, Some(format!("{} manifests, {} blobs", imported.manifests, imported.blobs)));
    Ok((StatusCode::CREATED, Json(imported)).into_response())
}

/// An archive import failed: the archive's fault (400, with a short message and no file
/// paths) or ours (500, logged).
fn import_error(e: ImportError) -> RegistryError {
    match e {
        ImportError::Storage(e) => RegistryError::internal(e),
        // tar's I/O errors carry paths in our temp directory: logged, not shown.
        ImportError::Unreadable(e) => {
            tracing::debug!(error = %e, "archive import refused");
            RegistryError::bad_request("the archive could not be read: expected an OCI image layout tar (optionally gzip-compressed)")
        }
        ImportError::Invalid(message) => {
            tracing::debug!(error = %message, "archive import refused");
            RegistryError::bad_request(message)
        }
    }
}

/// Recent jobs of every instance: everything for instance administrators, otherwise your own.
async fn list_jobs(State(state): State<AppState>, Extension(p): Extension<Principal>) -> Result<Response> {
    require_user(&state, &p)?;
    let all = p.has_global(Global::UsersRead);
    Ok(Json(state.list_jobs((!all).then(|| p.name())).await?).into_response())
}

/// Cancel a running job, whichever instance runs it: yours, or anyone's for instance
/// administrators. 202 when another instance was asked to stop it (within seconds).
async fn cancel_job(State(state): State<AppState>, Extension(p): Extension<Principal>, Path(id): Path<String>) -> Result<Response> {
    require_user(&state, &p)?;
    let job = state.auth.db.job(&id).await?.filter(|j| j.actor == p.name() || p.has_global(Global::UsersRead)).ok_or_else(|| RegistryError::not_found("job"))?;
    if job.actor != p.name() && !p.has_global(Global::UsersWrite) {
        return Err(state.auth.denied(&p, None));
    }
    let status = match state.cancel_job(&id).await? {
        crate::state::Cancel::Stopped => StatusCode::NO_CONTENT,
        crate::state::Cancel::Requested => StatusCode::ACCEPTED,
        crate::state::Cancel::NotRunning => return Err(RegistryError::conflict("the job is not running")),
    };
    state.audit.record(&p, "job_cancelled", None, None, None, Some(format!("{} ({})", job.subject, job.id)));
    Ok(status.into_response())
}
