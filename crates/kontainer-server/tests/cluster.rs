//! Several registry instances on one database and one object store, as behind a load balancer:
//! what one instance changes must hold on the others.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use kontainer_core::config::{AuthMode, Config, StorageDriver};
use kontainer_core::digest::Digest;
use kontainer_core::manifest::OCI_MANIFEST;
use kontainer_core::perm::TeamRole;
use kontainer_server::state::AppState;

/// One instance's config: a database and a storage directory shared with the others.
fn instance_config(database_url: &str, storage: &std::path::Path) -> Config {
    let mut cfg = Config::default();
    cfg.storage.driver = StorageDriver::Filesystem;
    cfg.storage.filesystem.root = storage.to_path_buf();
    // Temporary files are per instance.
    cfg.storage.upload_dir = tempfile::tempdir().unwrap().keep();
    cfg.auth.database_url = database_url.to_string().into();
    cfg.auth.database_pool = 4;
    cfg.auth.mode = AuthMode::Basic;
    cfg.server.log = "warn".into();
    cfg.server.public_url = Some("http://registry.test".into());
    cfg
}

/// Two instances sharing a fresh database and storage directory.
async fn two_instances() -> (AppState, AppState) {
    let url = kontainer_server::database::test_support::fresh_database_url();
    let storage = tempfile::tempdir().unwrap().keep();
    let a = kontainer_server::build_state(instance_config(&url, &storage)).await.unwrap();
    let b = kontainer_server::build_state(instance_config(&url, &storage)).await.unwrap();
    (a, b)
}

async fn send(app: &Router, method: Method, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = app.clone().oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    (status, res.into_body().collect().await.unwrap().to_bytes().to_vec(), headers)
}

fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")))
}

fn manifest(config: &Digest, len: usize) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config.to_string(), "size": len },
        "layers": [],
    }))
    .unwrap()
}

/// Push a config blob and a manifest tagged `tag` through `app`: the manifest's status.
async fn push_image(app: &Router, auth: &str, repo: &str, tag: &str) -> StatusCode {
    if auth.is_empty() {
        return push_image_with(app, &[], repo, tag).await;
    }
    push_image_with(app, &[("authorization", auth)], repo, tag).await
}

async fn push_image_with(app: &Router, h: &[(&str, &str)], repo: &str, tag: &str) -> StatusCode {
    let cfg = format!("{{\"repo\":\"{repo}\"}}").into_bytes();
    let digest = Digest::sha256_of(&cfg);
    let (status, _, headers) = send(app, Method::POST, &format!("/v2/{repo}/blobs/uploads/"), h, vec![]).await;
    if status != StatusCode::ACCEPTED {
        return status;
    }
    let loc = headers.get("location").unwrap().to_str().unwrap().to_string();
    let with = |extra: (&'static str, &'static str)| h.iter().copied().chain([extra]).collect::<Vec<_>>();
    let (status, _, _) = send(app, Method::PUT, &format!("{loc}?digest={digest}"), &with(("content-type", "application/octet-stream")), cfg.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(app, Method::PUT, &format!("/v2/{repo}/manifests/{tag}"), &with(("content-type", OCI_MANIFEST)), manifest(&digest, cfg.len())).await;
    status
}

async fn eventually<F, Fut>(mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..250 {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// A Creator team may push a repository into existence (and becomes its admin), never into one
/// that exists. An instance that missed the repository's creation must not take it for new.
#[tokio::test]
async fn a_stale_repository_set_never_lets_a_creator_take_over_an_existing_repository() {
    let (a, b) = two_instances().await;
    let db = &a.auth.db;
    let org = db.create_org("acme", None, "").await.unwrap();
    let team = db.create_team(org.id, "builders", "", TeamRole::Creator, None).await.unwrap();
    let hash = kontainer_server::auth::password::hash("password123").unwrap();
    let cat = db.create_user("cat", Some(&hash), None, None, false, None, false).await.unwrap();
    db.add_team_member(team.id, cat.id).await.unwrap();
    let cat_auth = basic("cat", "password123");

    // acme/api gets content through another instance whose notification b never received:
    // written straight to the shared storage, nothing announced.
    let body = b"{}".to_vec();
    let digest = Digest::sha256_of(&body);
    let m = kontainer_store::metadata::StoredManifest::new(digest.clone(), OCI_MANIFEST, body.into());
    a.storage.put_manifest("acme/api", &m, &[], &[], Some("v1")).await.unwrap();
    assert!(!b.auth.anonymous().await.known_repos.contains("acme/api"), "b's set is stale");

    let app_b = kontainer_server::build_router(b.clone());
    assert_eq!(push_image(&app_b, &cat_auth, "acme/api", "v2").await, StatusCode::FORBIDDEN, "acme/api exists: not the Creator team's to push to");
    assert!(b.auth.db.repo_grants("acme/api").await.unwrap().is_empty(), "and nobody became its admin");
    assert!(b.auth.anonymous().await.known_repos.contains("acme/api"), "b learned it exists");
    // The same through a token request: no push granted.
    let (status, body, _) = send(&app_b, Method::GET, "/auth/token?service=registry.test&scope=repository:acme/api:pull,push", &[("authorization", &cat_auth)], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let claims = String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["token"].as_str().unwrap().split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert!(!claims.contains("push"), "{claims}");

    // A repository that is really new: created through b, its creator becomes its admin, and
    // instance a hears about it.
    assert_eq!(push_image(&app_b, &cat_auth, "acme/tool", "v1").await, StatusCode::CREATED);
    let grants = b.auth.db.repo_grants("acme/tool").await.unwrap();
    assert_eq!(grants.len(), 1);
    assert!(eventually(|| async { a.auth.anonymous().await.known_repos.contains("acme/tool") }).await, "a was notified of acme/tool");
    // ...and indexed it for search.
    assert!(eventually(|| async { !a.search.is_empty() }).await, "a's search index follows");
}

/// Two instances without accounts (anyone may push), sharing a database and a storage
/// directory; also returns the storage directory.
async fn two_open_instances() -> (AppState, AppState, std::path::PathBuf) {
    let url = kontainer_server::database::test_support::fresh_database_url();
    let storage = tempfile::tempdir().unwrap().keep();
    let open = || {
        let mut cfg = instance_config(&url, &storage);
        cfg.auth.mode = AuthMode::None;
        cfg.features.is_delete = true;
        cfg
    };
    let a = kontainer_server::build_state(open()).await.unwrap();
    let b = kontainer_server::build_state(open()).await.unwrap();
    (a, b, storage)
}

fn json_of(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or(serde_json::Value::Null)
}

/// Manifests and tags are rows in the shared database: what one instance pushes, the other
/// serves at once (no storage listing, cache or notification in between), and a delete on
/// either is equally immediate.
#[tokio::test]
async fn a_push_on_one_instance_is_visible_on_another_at_once() {
    let (a, b, _) = two_open_instances().await;
    let (app_a, app_b) = (kontainer_server::build_router(a), kontainer_server::build_router(b));
    let cfg = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
    let cd = Digest::sha256_of(&cfg);
    let (status, _, _) = send(&app_a, Method::POST, &format!("/v2/acme/app/blobs/uploads/?digest={cd}"), &[("content-type", "application/octet-stream")], cfg.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let m = manifest(&cd, cfg.len());
    let md = Digest::sha256_of(&m);
    let (status, _, _) = send(&app_a, Method::PUT, "/v2/acme/app/manifests/v1", &[("content-type", OCI_MANIFEST)], m.clone()).await;
    assert_eq!(status, StatusCode::CREATED);

    // Straight away on b.
    let (status, body, headers) = send(&app_b, Method::GET, "/v2/acme/app/manifests/v1", &[], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, m);
    assert_eq!(headers.get("docker-content-digest").unwrap().to_str().unwrap(), md.to_string());
    assert_eq!(headers.get("content-type").unwrap().to_str().unwrap(), OCI_MANIFEST);
    let (_, body, _) = send(&app_b, Method::GET, "/v2/acme/app/tags/list", &[], vec![]).await;
    assert_eq!(json_of(&body), json!({ "name": "acme/app", "tags": ["v1"] }));
    let (_, body, _) = send(&app_b, Method::GET, "/v2/_catalog", &[], vec![]).await;
    assert_eq!(json_of(&body), json!({ "repositories": ["acme/app"] }));
    let (status, body, _) = send(&app_b, Method::GET, &format!("/v2/acme/app/blobs/{cd}"), &[], vec![]).await;
    assert_eq!((status, body), (StatusCode::OK, cfg.clone()));

    // Another tag through b, then a delete through b: a sees both at once.
    let (status, _, _) = send(&app_b, Method::PUT, "/v2/acme/app/manifests/v2", &[("content-type", OCI_MANIFEST)], m.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, body, _) = send(&app_a, Method::GET, "/v2/acme/app/tags/list?n=1&last=v1", &[], vec![]).await;
    assert_eq!(json_of(&body)["tags"], json!(["v2"]));
    let (status, _, _) = send(&app_b, Method::DELETE, &format!("/v2/acme/app/manifests/{md}"), &[], vec![]).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _, _) = send(&app_a, Method::GET, "/v2/acme/app/manifests/v1", &[], vec![]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body, _) = send(&app_a, Method::GET, "/v2/acme/app/tags/list", &[], vec![]).await;
    assert_eq!((status, json_of(&body)["errors"][0]["code"].clone()), (StatusCode::NOT_FOUND, json!("NAME_UNKNOWN")), "no manifest left: as before, links alone are not a repository");
}

/// Garbage collection on one instance while another uploads the very blob it is collecting
/// (content that already exists, unreferenced, so the upload only links it): however they
/// interleave, a blob the repository links afterwards is in storage. (Whether the link
/// itself survives depends on the order: with no grace window, an unreferenced link the
/// collection saw before it started is fair game.)
#[tokio::test]
async fn gc_never_deletes_a_blob_linked_by_a_concurrent_push() {
    let (a, b, _) = two_open_instances().await;
    let app_b = kontainer_server::build_router(b.clone());
    let (mut linked, mut collected, mut restored) = (0, 0, 0);
    for i in 0..40 {
        let content = format!("shared layer {i}").into_bytes();
        let d = Digest::sha256_of(&content);
        // Old, unreferenced content: what the collection is about to delete.
        a.storage.blob_put(&d, content.clone().into()).await.unwrap();
        let gc = {
            let a = a.clone();
            tokio::spawn(async move { kontainer_store::gc::run(&a.storage, false, false, Duration::ZERO, &Default::default()).await.unwrap() })
        };
        // Vary where the upload lands relative to the collection's mark and sweep.
        tokio::time::sleep(Duration::from_micros(250 * (i % 8))).await;
        let (status, body, _) = send(&app_b, Method::POST, &format!("/v2/acme/app/blobs/uploads/?digest={d}"), &[("content-type", "application/octet-stream")], content.clone()).await;
        assert_eq!(status, StatusCode::CREATED, "iteration {i}: {}", String::from_utf8_lossy(&body));
        let report = gc.await.unwrap();
        // Deleted by the sweep, and stored again by the upload that found it gone.
        restored += usize::from(report.blobs_removed.contains(&d.to_string()) && b.storage.blob_size(&d).await.unwrap().is_some());
        if b.storage.repo_blob_size("acme/app", &d).await.unwrap().is_some() {
            linked += 1;
            let (status, body, _) = send(&app_b, Method::GET, &format!("/v2/acme/app/blobs/{d}"), &[], vec![]).await;
            assert_eq!((status, body), (StatusCode::OK, content), "iteration {i}: linked, so it must be readable");
        } else {
            collected += 1;
        }
    }
    eprintln!("{linked} uploads kept their link ({restored} of their blobs swept and stored again), {collected} links were collected afterwards");
}

/// `kontainer migrate-metadata` on a filesystem store written in the old layout, into the
/// database: afterwards every instance serves the same manifests, tags and links.
#[tokio::test]
async fn migrate_metadata_from_an_old_filesystem_layout() {
    let (a, b, root) = two_open_instances().await;
    let write = |rel: String, data: &[u8]| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    };
    let blob = |d: &Digest| format!("blobs/{}/{}/data", d.algorithm().as_str(), d.hex());
    let link = |d: &Digest| format!("{}/{}/link", d.algorithm().as_str(), d.hex());
    let cfg = br#"{"architecture":"arm64","os":"linux"}"#.to_vec();
    let cd = Digest::sha256_of(&cfg);
    // No `mediaType` in the body: pushed as a Docker manifest, which the sidecar remembers.
    let m = serde_json::to_vec(&json!({ "schemaVersion": 2, "config": { "mediaType": "application/vnd.docker.container.image.v1+json", "digest": cd.to_string(), "size": cfg.len() }, "layers": [] })).unwrap();
    let md = Digest::sha256_of(&m);
    write(blob(&cd), &cfg);
    write(blob(&md), &m);
    write(format!("repositories/acme/old/_layers/{}", link(&cd)), cd.to_string().as_bytes());
    write(format!("repositories/acme/old/_manifests/revisions/{}", link(&md)), md.to_string().as_bytes());
    write(format!("repositories/acme/old/_manifests/revisions/{}/{}/mediatype", md.algorithm().as_str(), md.hex()), b"application/vnd.docker.distribution.manifest.v2+json");
    write("repositories/acme/old/_manifests/tags/stable/current/link".into(), md.to_string().as_bytes());

    // Before: the database knows nothing, and collection refuses to run on it.
    assert!(a.storage.list_repositories().await.unwrap().is_empty());
    let err = kontainer_store::gc::run(&a.storage, false, true, Duration::ZERO, &Default::default()).await.unwrap_err();
    assert!(err.to_string().contains("migrate-metadata"), "{err}");

    let counts = kontainer_store::legacy::migrate(&a.storage).await.unwrap();
    assert_eq!((counts.repositories, counts.manifests, counts.tags, counts.blob_links, counts.skipped), (1, 1, 1, 1, 0));
    assert_eq!(kontainer_store::legacy::migrate(&a.storage).await.unwrap().manifests, 0, "idempotent");

    let app_b = kontainer_server::build_router(b);
    let (status, body, headers) = send(&app_b, Method::GET, "/v2/acme/old/manifests/stable", &[], vec![]).await;
    assert_eq!((status, body), (StatusCode::OK, m));
    assert_eq!(headers.get("content-type").unwrap().to_str().unwrap(), "application/vnd.docker.distribution.manifest.v2+json");
    let (_, body, _) = send(&app_b, Method::GET, "/v2/acme/old/tags/list", &[], vec![]).await;
    assert_eq!(json_of(&body)["tags"], json!(["stable"]));
    let (_, body, _) = send(&app_b, Method::GET, "/v2/_catalog", &[], vec![]).await;
    assert_eq!(json_of(&body)["repositories"], json!(["acme/old"]));
    let (status, body, _) = send(&app_b, Method::GET, &format!("/v2/acme/old/blobs/{cd}"), &[], vec![]).await;
    assert_eq!((status, body), (StatusCode::OK, cfg));
    // Collection now runs; the old manifest body under blobs/ is a leftover it removes.
    let report = kontainer_store::gc::run(&a.storage, false, false, Duration::ZERO, &Default::default()).await.unwrap();
    assert_eq!(report.blobs_removed, vec![md.to_string()], "{report:?}");
    assert!(root.join(blob(&cd)).exists());
}

/// Two instances in different regions, on one database: `a` prefers location `eu`, `b`
/// prefers `us` (two directories, as two buckets would be). Returns the instances and the two
/// locations' directories.
async fn two_regions() -> (AppState, AppState, std::path::PathBuf, std::path::PathBuf) {
    use kontainer_core::config::LocationConfig;
    let url = kontainer_server::database::test_support::fresh_database_url();
    let (eu, us) = (tempfile::tempdir().unwrap().keep(), tempfile::tempdir().unwrap().keep());
    let region = |preferred: &str| {
        let mut cfg = instance_config(&url, &eu);
        cfg.auth.mode = AuthMode::None;
        cfg.features.is_delete = true;
        cfg.storage.location = preferred.into();
        cfg.storage.region_header = Some("X-Region".into());
        let mut locations = vec![];
        for (name, dir, regions) in [("eu", &eu, vec!["eu-*".to_string(), "DE".into()]), ("us", &us, vec!["us-*".to_string()])] {
            let mut l = LocationConfig { name: name.into(), driver: StorageDriver::Filesystem, regions, is_redirect: false, ..Default::default() };
            l.filesystem.root = dir.clone();
            locations.push(l);
        }
        cfg.storage.locations = locations;
        cfg
    };
    let a = kontainer_server::build_state(region("eu")).await.unwrap();
    let b = kontainer_server::build_state(region("us")).await.unwrap();
    (a, b, eu, us)
}

fn blob_file(root: &std::path::Path, d: &Digest) -> std::path::PathBuf {
    root.join(format!("blobs/sha256/{}/data", d.hex()))
}

/// Make every copy due now through `state`'s worker. Returns how many succeeded and failed.
async fn replicate(state: &AppState, retry: kontainer_server::locations::Retry) -> (usize, usize) {
    let w = kontainer_server::locations::Worker::new(state.storage.clone(), state.auth.db.clone(), retry);
    let (mut ok, mut failed) = (0, 0);
    while let Some(r) = w.run_once().await.unwrap() {
        if r.is_ok() { ok += 1 } else { failed += 1 }
    }
    (ok, failed)
}

/// Every region writes locally and reads what any other wrote at once: a blob pushed in `eu`
/// is pulled in `us` straight from `eu` (found through its placement), and once copied, from
/// `us` itself. Uploads continue across regions, the region header picks the location, garbage
/// collection deletes from both, and a backfill queues only what is missing.
#[tokio::test]
async fn regions_write_locally_and_read_each_others_blobs() {
    use kontainer_store::placement::Placements;
    let (a, b, eu, us) = two_regions().await;
    let (app_a, app_b) = (kontainer_server::build_router(a.clone()), kontainer_server::build_router(b.clone()));
    let cfg = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
    let cd = Digest::sha256_of(&cfg);
    let (status, _, _) = send(&app_a, Method::POST, &format!("/v2/acme/app/blobs/uploads/?digest={cd}"), &[("content-type", "application/octet-stream")], cfg.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(&app_a, Method::PUT, "/v2/acme/app/manifests/v1", &[("content-type", OCI_MANIFEST)], manifest(&cd, cfg.len())).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(blob_file(&eu, &cd).exists() && !blob_file(&us, &cd).exists(), "written in eu only");
    assert_eq!(a.auth.db.placements(&cd).await.unwrap(), [("eu".to_string(), cfg.len() as u64)]);

    // Pullable in us at once, from eu; HEAD answers from the placements.
    let (status, body, _) = send(&app_b, Method::GET, &format!("/v2/acme/app/blobs/{cd}"), &[], vec![]).await;
    assert_eq!((status, body), (StatusCode::OK, cfg.clone()));
    let (status, _, headers) = send(&app_b, Method::HEAD, &format!("/v2/acme/app/blobs/{cd}"), &[], vec![]).await;
    assert_eq!((status, headers.get("content-length").unwrap().to_str().unwrap()), (StatusCode::OK, cfg.len().to_string().as_str()));
    let names = |s: Vec<(&kontainer_store::Location, u64)>| s.into_iter().map(|(l, _)| l.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(b.storage.blob_sources(&cd, Some("us-east-1")).await.unwrap()), ["eu"], "only eu has it yet");

    // The copy is made (by any instance's worker); then us has its own placement and serves
    // locally, even with eu unreadable.
    let (ok, failed) = replicate(&b, Default::default()).await;
    assert!(ok >= 1 && failed == 0, "{ok} {failed}");
    assert_eq!(std::fs::read(blob_file(&us, &cd)).unwrap(), cfg);
    assert_eq!(b.auth.db.placements(&cd).await.unwrap().len(), 2);
    assert_eq!(names(b.storage.blob_sources(&cd, None).await.unwrap()), ["us", "eu"], "the preferred location first");
    assert_eq!(names(b.storage.blob_sources(&cd, Some("eu-west-1")).await.unwrap()), ["eu", "us"], "the region's location first");
    assert_eq!(names(a.storage.blob_sources(&cd, Some("US-East-2")).await.unwrap()), ["us", "eu"]);
    assert_eq!(names(a.storage.blob_sources(&cd, Some("JP")).await.unwrap()), ["eu", "us"], "no region match: the preferred location");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(eu.join("blobs"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let (status, body, _) = send(&app_b, Method::GET, &format!("/v2/acme/app/blobs/{cd}"), &[("x-region", "DE")], vec![]).await;
    let (status_a, body_a, _) = send(&app_a, Method::GET, &format!("/v2/acme/app/blobs/{cd}"), &[], vec![]).await;
    std::fs::set_permissions(eu.join("blobs"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!((status, body), (StatusCode::OK, cfg.clone()), "eu fails: read from us");
    assert_eq!((status_a, body_a), (StatusCode::OK, cfg.clone()), "even in eu");

    // An upload started in eu and completed in us: each chunk is read from where it was written.
    let layer = b"a layer in two chunks".to_vec();
    let ld = Digest::sha256_of(&layer);
    let (status, _, headers) = send(&app_a, Method::POST, "/v2/acme/app/blobs/uploads/", &[], vec![]).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let loc = headers.get("location").unwrap().to_str().unwrap().to_string();
    let (status, _, _) = send(&app_a, Method::PATCH, &loc, &[("content-type", "application/octet-stream")], layer[..8].to_vec()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _, _) = send(&app_b, Method::PATCH, &loc, &[("content-type", "application/octet-stream")], layer[8..12].to_vec()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _, _) = send(&app_b, Method::PUT, &format!("{loc}?digest={ld}"), &[("content-type", "application/octet-stream")], layer[12..].to_vec()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(std::fs::read(blob_file(&us, &ld)).unwrap(), layer, "completed in us: stored in us");
    assert!(!blob_file(&eu, &ld).exists());
    assert_eq!(a.storage.blob_bytes(&ld).await.unwrap().unwrap(), layer, "and read from us in eu");

    // A backfill queues only what a location is missing (the new layer is queued already).
    replicate(&a, Default::default()).await;
    assert!(blob_file(&eu, &ld).exists());
    assert_eq!(a.storage.backfill("eu").await.unwrap(), 0);
    assert_eq!(a.storage.backfill("us").await.unwrap(), 0, "both blobs are in both locations");
    std::fs::remove_file(blob_file(&eu, &ld)).unwrap();
    a.auth.db.unplace(&ld, "eu").await.unwrap();
    assert_eq!(a.storage.backfill("us").await.unwrap(), 0);
    assert_eq!(a.storage.backfill("eu").await.unwrap(), 1, "just the lost layer");
    assert_eq!(a.storage.backfill("eu").await.unwrap(), 0, "already queued");
    replicate(&b, Default::default()).await;
    assert_eq!(std::fs::read(blob_file(&eu, &ld)).unwrap(), layer);

    // Garbage collection deletes from both locations, and the placements with them.
    a.storage.delete_repository("acme/app").await.unwrap();
    let report = kontainer_store::gc::run(&a.storage, false, false, Duration::ZERO, &Default::default()).await.unwrap();
    assert!(report.blobs_removed.contains(&cd.to_string()) && report.blobs_removed.contains(&ld.to_string()), "{report:?}");
    for d in [&cd, &ld] {
        assert!(!blob_file(&eu, d).exists() && !blob_file(&us, d).exists());
        assert!(a.auth.db.placements(d).await.unwrap().is_empty());
    }
    let (status, _, _) = send(&app_b, Method::HEAD, &format!("/v2/acme/app/blobs/{cd}"), &[], vec![]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A copy that keeps failing is retried with a delay, then given up on and reported (with its
/// error) until a backfill queues it again.
#[tokio::test]
async fn failed_copies_are_retried_then_recorded() {
    use std::os::unix::fs::PermissionsExt;
    let (a, b, _eu, us) = two_regions().await;
    let app_a = kontainer_server::build_router(a.clone());
    let data = b"replicate me".to_vec();
    let d = Digest::sha256_of(&data);
    // us cannot be written to.
    std::fs::set_permissions(&us, std::fs::Permissions::from_mode(0o555)).unwrap();
    let (status, _, _) = send(&app_a, Method::POST, &format!("/v2/acme/app/blobs/uploads/?digest={d}"), &[("content-type", "application/octet-stream")], data.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    let retry = kontainer_server::locations::Retry { attempts: 2, backoff: Duration::ZERO };
    let (ok, failed) = replicate(&b, retry).await;
    assert!(ok == 0 && failed >= 2, "every job tried twice: {ok} {failed}");
    let counts = a.auth.db.location_counts().await.unwrap();
    let us_counts = counts.iter().find(|c| c.location == "us").unwrap();
    assert!(us_counts.failed >= 1 && us_counts.pending == 0, "{us_counts:?}");
    assert!(us_counts.last_error.as_deref().is_some_and(|e| !e.is_empty()), "{us_counts:?}");
    let jobs = a.auth.db.failed_replication_jobs("us", 10).await.unwrap();
    let job = jobs.iter().find(|j| j.1 == d.to_string()).expect("the blob's copy is recorded as failed");
    assert_eq!(job.2, 2, "after two attempts");
    assert!(b.storage.replication.stats("us").failed >= 2);
    // The admin page shows it.
    let app_b = kontainer_server::build_router(b.clone());
    let (_, body, _) = send(&app_b, Method::GET, "/api/v1/admin/storage", &[], vec![]).await;
    let st = json_of(&body);
    assert!(st["failed"].as_i64().unwrap() >= 1, "{st}");
    assert_eq!(st["primary"]["name"], "us");

    // Fixed: a backfill queues it afresh and it goes through.
    std::fs::set_permissions(&us, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(a.storage.backfill("us").await.unwrap(), 1);
    let (ok, _) = replicate(&b, Default::default()).await;
    assert!(ok >= 1);
    assert_eq!(std::fs::read(blob_file(&us, &d)).unwrap(), data);
    let us_counts = a.auth.db.location_counts().await.unwrap().into_iter().find(|c| c.location == "us").unwrap();
    assert_eq!(us_counts.blobs, 1);
}

/// A location removed from the configuration keeps its placements (reported as unknown) until
/// `forget-location`; blobs only it holds do not count as stored.
#[tokio::test]
async fn a_removed_location_is_unknown_until_forgotten() {
    use kontainer_store::placement::Placements;
    let (a, _b, _eu, _us) = two_regions().await;
    let d = Digest::sha256_of(b"only on mars");
    a.auth.db.place(&d, "mars", 12).await.unwrap();
    assert!(a.storage.blob_size(&d).await.unwrap().is_none(), "an unconfigured location's blobs are not readable");
    let app = kontainer_server::build_router(a.clone());
    let (_, body, _) = send(&app, Method::GET, "/api/v1/admin/storage", &[], vec![]).await;
    let st = json_of(&body);
    assert_eq!(st["unknown_locations"], json!(["mars"]), "{st}");
    let mars = st["locations"].as_array().unwrap().iter().find(|l| l["name"] == "mars").unwrap();
    assert_eq!((mars["configured"].clone(), mars["driver"].clone(), mars["blobs"].clone()), (json!(false), json!("unknown"), json!(1)));
    assert_eq!(a.auth.db.forget_location("mars").await.unwrap(), (1, 0));
    let (_, body, _) = send(&app, Method::GET, "/api/v1/admin/storage", &[], vec![]).await;
    assert_eq!(json_of(&body)["unknown_locations"], json!([]));
}

/// `scanner.max_auto_per_hour` is one budget for the cluster: scans on push through either
/// instance count against it, and beyond it they are skipped (counted, not queued). A scan a
/// user asks for is not held to it, and an administrator can lift it for a while.
#[tokio::test]
async fn the_automatic_scan_budget_is_shared_by_every_instance() {
    let url = kontainer_server::database::test_support::fresh_database_url();
    let storage = tempfile::tempdir().unwrap().keep();
    let scanning = || {
        let mut cfg = instance_config(&url, &storage);
        cfg.auth.mode = AuthMode::None;
        // A scanner that cannot run: its scans fail and wait 30s for a retry, so they stay queued.
        cfg.scanner.kind = kontainer_core::config::ScannerKind::Trivy;
        cfg.scanner.binary = Some("/nonexistent/trivy".into());
        cfg.scanner.max_auto_per_hour = 3;
        cfg
    };
    let a = kontainer_server::build_router(kontainer_server::build_state(scanning()).await.unwrap());
    let b = kontainer_server::build_router(kontainer_server::build_state(scanning()).await.unwrap());
    let status = |app: &Router| {
        let app = app.clone();
        async move { json_of(&send(&app, Method::GET, "/api/v1/admin/scanning", &[], vec![]).await.1) }
    };
    let s = status(&a).await;
    assert_eq!((s["enabled"].as_bool(), s["limit"].as_u64(), s["used"].as_i64(), s["max_queue"].as_u64()), (Some(true), Some(3), Some(0), Some(10_000)), "{s}");
    assert!(s["window_resets_at"].is_null(), "no window open yet: {s}");

    // Two pushes through a, two through b: three scans fit the budget, the fourth is skipped.
    for (app, repo) in [(&a, "acme/one"), (&b, "acme/two"), (&a, "acme/three"), (&b, "acme/four")] {
        assert_eq!(push_image(app, "", repo, "v1").await, StatusCode::CREATED);
    }
    for app in [&a, &b] {
        let s = status(app).await;
        assert_eq!((s["used"].as_i64(), s["skipped_in_window"].as_i64(), s["queue_depth"].as_i64()), (Some(3), Some(1), Some(3)), "{s}");
        assert!(s["window_resets_at"].is_string(), "{s}");
    }
    let skipped_on_b = status(&b).await["skipped_since_start"]["budget"].as_u64().unwrap_or(0);
    assert!(skipped_on_b >= 1, "b counted its skip");

    // A user's scan of the skipped image is queued anyway, and costs no budget.
    let (st, body, _) = send(&b, Method::POST, "/api/v1/repositories/acme/four/manifests/v1/scan", &[], vec![]).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json_of(&body)["queued"].as_array().map(Vec::len), Some(1), "{}", String::from_utf8_lossy(&body));
    let s = status(&a).await;
    assert_eq!((s["used"].as_i64(), s["queue_depth"].as_i64()), (Some(3), Some(4)), "{s}");

    // The override, set on a, lifts the budget on b too.
    let (st, body, _) = send(&a, Method::POST, "/api/v1/admin/scanning/override", &[("content-type", "application/json")], serde_json::to_vec(&json!({ "hours": 2 })).unwrap()).await;
    assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(json_of(&body)["override_until"].is_string());
    assert_eq!(push_image(&b, "", "acme/five", "v1").await, StatusCode::CREATED);
    let s = status(&b).await;
    assert_eq!((s["used"].as_i64(), s["skipped_in_window"].as_i64(), s["queue_depth"].as_i64()), (Some(4), Some(1), Some(5)), "queued past the limit: {s}");
    assert!(s["override_until"].is_string() && s["override_by"].is_string(), "{s}");
    // Ending it restores the limit.
    let (st, _, _) = send(&b, Method::POST, "/api/v1/admin/scanning/override", &[("content-type", "application/json")], serde_json::to_vec(&json!({ "hours": 0 })).unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(push_image(&a, "", "acme/six", "v1").await, StatusCode::CREATED);
    let s = status(&a).await;
    assert_eq!((s["used"].as_i64(), s["skipped_in_window"].as_i64(), s["override_until"].is_null()), (Some(4), Some(2), true), "{s}");
    // The override was audited.
    assert!(
        eventually(|| async {
            let logs = json_of(&send(&a, Method::GET, "/api/v1/logs?limit=50", &[], vec![]).await.1);
            logs.as_array().is_some_and(|l| l.iter().filter(|e| e["action"] == "scan_budget_override").count() == 2)
        })
        .await,
        "both overrides are in the audit log"
    );
}

/// `scanner.max_queue` stops every new scan, a user's included, while the queue is full.
#[tokio::test]
async fn a_full_scan_queue_skips_even_requested_scans() {
    let url = kontainer_server::database::test_support::fresh_database_url();
    let storage = tempfile::tempdir().unwrap().keep();
    let mut cfg = instance_config(&url, &storage);
    cfg.auth.mode = AuthMode::None;
    cfg.scanner.kind = kontainer_core::config::ScannerKind::Trivy;
    cfg.scanner.binary = Some("/nonexistent/trivy".into());
    cfg.scanner.is_scan_on_push = false;
    cfg.scanner.max_queue = 1;
    let app = kontainer_server::build_router(kontainer_server::build_state(cfg).await.unwrap());
    for repo in ["acme/one", "acme/two"] {
        assert_eq!(push_image(&app, "", repo, "v1").await, StatusCode::CREATED);
    }
    let scan = |repo: &str| {
        let (app, uri) = (app.clone(), format!("/api/v1/repositories/{repo}/manifests/v1/scan"));
        async move { json_of(&send(&app, Method::POST, &uri, &[], vec![]).await.1)["queued"].as_array().map(Vec::len) }
    };
    assert_eq!(scan("acme/one").await, Some(1));
    assert_eq!(scan("acme/two").await, Some(0), "the queue is full");
    let s = json_of(&send(&app, Method::GET, "/api/v1/admin/scanning", &[], vec![]).await.1);
    assert_eq!((s["queue_depth"].as_i64(), s["used"].as_i64(), s["skipped_in_window"].as_i64()), (Some(1), Some(0), Some(1)), "{s}");
    assert!(s["skipped_since_start"]["queue_full"].as_u64().unwrap_or(0) >= 1, "{s}");
}
