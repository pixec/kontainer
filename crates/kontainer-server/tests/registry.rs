//! End-to-end tests driving the axum router against the in-memory backend.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kontainer_core::perm::{Action, Global, Role, Rule};
use kontainer_core::config::{AuthMode, BootstrapAdmin, Config, ImmutableTagRule, StorageDriver, User};
use kontainer_core::digest::Digest;
use kontainer_core::manifest::{OCI_INDEX, OCI_MANIFEST};

fn base_config() -> Config {
    let mut cfg = Config::default();
    let dir = tempfile::tempdir().unwrap().keep();
    cfg.storage.driver = StorageDriver::Memory;
    cfg.storage.upload_dir = dir.join("uploads");
    // A new PostgreSQL database per test (see `kontainer_server::database::test_support`).
    cfg.auth.database_url = kontainer_server::database::test_support::fresh_database_url().into();
    cfg.auth.database_pool = 4;
    cfg.server.log = "warn".into();
    cfg.server.public_url = Some("http://registry.test".into());
    // Most tests exercise the registry without accounts.
    cfg.auth.mode = AuthMode::None;
    cfg
}

fn role(name: &str, repos: &[&str], actions: &[Action]) -> Role {
    Role {
        name: name.into(),
        description: String::new(),
        rules: vec![Rule { repositories: repos.iter().map(|s| s.to_string()).collect(), actions: actions.to_vec() }],
        global: vec![],
        is_managed: false,
    }
}

async fn app(cfg: Config) -> Router {
    kontainer_server::build_router(kontainer_server::build_state(cfg).await.unwrap())
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn header(&self, name: &str) -> String {
        self.headers.get(name).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }
}

async fn send(app: &Router, method: Method, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Resp {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = app.clone().oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    Resp { status, headers, body }
}

fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")))
}

/// Push a blob with the chunked flow and return its digest.
async fn push_blob(app: &Router, repo: &str, data: &[u8], auth: Option<&str>) -> Digest {
    let digest = Digest::sha256_of(data);
    let mut h: Vec<(&str, &str)> = vec![];
    if let Some(a) = auth {
        h.push(("authorization", a));
    }
    let r = send(app, Method::POST, &format!("/v2/{repo}/blobs/uploads/"), &h, vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&r.body));
    let loc = r.header("location");
    assert_eq!(r.header("range"), "0-0");
    let (a, b) = data.split_at(data.len() / 2);
    let mut ph = h.clone();
    ph.push(("content-type", "application/octet-stream"));
    let r = send(app, Method::PATCH, &loc, &ph, a.to_vec()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert_eq!(r.header("range"), format!("0-{}", a.len().saturating_sub(1)));
    // wrong offset is rejected
    let mut bad = ph.clone();
    bad.push(("content-range", "0-5"));
    let r = send(app, Method::PATCH, &loc, &bad, b.to_vec()).await;
    assert_eq!(r.status, StatusCode::RANGE_NOT_SATISFIABLE);
    let r = send(app, Method::PUT, &format!("{loc}?digest={digest}"), &ph, b.to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.header("docker-content-digest"), digest.to_string());
    digest
}

fn image_manifest(config: &Digest, config_len: usize, layers: &[(Digest, usize)]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config.to_string(), "size": config_len },
        "layers": layers.iter().map(|(d, n)| json!({ "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d.to_string(), "size": n })).collect::<Vec<_>>(),
    }))
    .unwrap()
}

fn gzip_tar_layer() -> Vec<u8> {
    use std::io::Write;
    let mut tar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(5);
    h.set_mode(0o644);
    h.set_cksum();
    tar.append_data(&mut h, "etc/hello.txt", &b"hello"[..]).unwrap();
    let mut d = tar::Header::new_gnu();
    d.set_entry_type(tar::EntryType::Directory);
    d.set_size(0);
    d.set_mode(0o755);
    d.set_cksum();
    tar.append_data(&mut d, "usr/bin/", &b""[..]).unwrap();
    let mut w = tar::Header::new_gnu();
    w.set_size(0);
    w.set_mode(0o644);
    w.set_cksum();
    tar.append_data(&mut w, "etc/.wh.old.conf", &b""[..]).unwrap();
    let raw = tar.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap()
}

#[tokio::test]
async fn version_check_and_unknown_routes() {
    let app = app(base_config()).await;
    let r = send(&app, Method::GET, "/v2/", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("docker-distribution-api-version"), "registry/2.0");
    let r = send(&app, Method::GET, "/v2/nope/manifests/latest", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.json()["errors"][0]["code"], "MANIFEST_UNKNOWN");
    let r = send(&app, Method::GET, "/v2/Bad_Name/manifests/latest", &[], vec![]).await;
    assert_eq!(r.json()["errors"][0]["code"], "NAME_INVALID");
    let r = send(&app, Method::GET, "/v2/x/blobs/sha256:zz", &[], vec![]).await;
    assert_eq!(r.json()["errors"][0]["code"], "DIGEST_INVALID");
}

#[tokio::test]
async fn full_push_pull_flow() {
    // No Time Machine: this test checks that GC collects a manifest as soon as it is untagged.
    let mut cfg = base_config();
    cfg.policy.time_machine = std::time::Duration::ZERO;
    let app = app(cfg).await;
    let repo = "library/app";
    let config = br#"{"architecture":"amd64","os":"linux","config":{"Cmd":["/bin/sh"],"Env":["A=1"]},"rootfs":{"type":"layers","diff_ids":["sha256:aaaa"]},"history":[{"created_by":"/bin/sh -c #(nop) ADD file in /","empty_layer":false},{"created_by":"/bin/sh -c #(nop) CMD [\"/bin/sh\"]","empty_layer":true}]}"#;
    let layer = gzip_tar_layer();
    let config_d = push_blob(&app, repo, config, None).await;
    let layer_d = push_blob(&app, repo, &layer, None).await;

    // Blob HEAD/GET and range.
    let r = send(&app, Method::HEAD, &format!("/v2/{repo}/blobs/{layer_d}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-length"), layer.len().to_string());
    let r = send(&app, Method::GET, &format!("/v2/{repo}/blobs/{layer_d}"), &[], vec![]).await;
    assert_eq!(r.body, layer);
    let r = send(&app, Method::GET, &format!("/v2/{repo}/blobs/{layer_d}"), &[("range", "bytes=2-5")], vec![]).await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.body, &layer[2..6]);
    assert_eq!(r.header("content-range"), format!("bytes 2-5/{}", layer.len()));
    // Blob is repo-scoped.
    let r = send(&app, Method::HEAD, &format!("/v2/other/blobs/{layer_d}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Manifest referencing a missing blob is rejected.
    let bogus = Digest::sha256_of(b"missing");
    let m = image_manifest(&config_d, config.len(), &[(bogus.clone(), 1)]);
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v1"), &[("content-type", OCI_MANIFEST)], m).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.json()["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");

    // Good manifest.
    let m = image_manifest(&config_d, config.len(), &[(layer_d.clone(), layer.len())]);
    let md = Digest::sha256_of(&m);
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v1"), &[("content-type", OCI_MANIFEST)], m.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.header("docker-content-digest"), md.to_string());
    // Same manifest under a digest reference, and a mismatching digest reference.
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{md}"), &[("content-type", OCI_MANIFEST)], m.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{bogus}"), &[("content-type", OCI_MANIFEST)], m.clone()).await;
    assert_eq!(r.json()["errors"][0]["code"], "DIGEST_INVALID");

    // Pull by tag and digest.
    let r = send(&app, Method::GET, &format!("/v2/{repo}/manifests/v1"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-type"), OCI_MANIFEST);
    assert_eq!(r.header("docker-content-digest"), md.to_string());
    assert_eq!(r.body, m);
    let r = send(&app, Method::HEAD, &format!("/v2/{repo}/manifests/{md}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-length"), m.len().to_string());
    assert!(r.body.is_empty());

    // Tags & catalog with pagination.
    send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v2"), &[("content-type", OCI_MANIFEST)], m.clone()).await;
    let r = send(&app, Method::GET, &format!("/v2/{repo}/tags/list"), &[], vec![]).await;
    assert_eq!(r.json(), json!({ "name": repo, "tags": ["v1", "v2"] }));
    let r = send(&app, Method::GET, &format!("/v2/{repo}/tags/list?n=1"), &[], vec![]).await;
    assert_eq!(r.json()["tags"], json!(["v1"]));
    assert!(r.header("link").contains("last=v1"));
    let r = send(&app, Method::GET, &format!("/v2/{repo}/tags/list?n=1&last=v1"), &[], vec![]).await;
    assert_eq!(r.json()["tags"], json!(["v2"]));
    assert!(r.header("link").is_empty());
    let r = send(&app, Method::GET, "/v2/_catalog", &[], vec![]).await;
    assert_eq!(r.json(), json!({ "repositories": [repo] }));

    // Index referencing the image.
    let idx = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_INDEX,
        "manifests": [{ "mediaType": OCI_MANIFEST, "digest": md.to_string(), "size": m.len(), "platform": { "os": "linux", "architecture": "amd64" } }]
    })).unwrap();
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/multi"), &[("content-type", OCI_INDEX)], idx.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(&app, Method::GET, &format!("/v2/{repo}/manifests/multi"), &[], vec![]).await;
    assert_eq!(r.header("content-type"), OCI_INDEX);

    // Referrers (OCI 1.1).
    let sbom = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/spdx+json",
        "config": { "mediaType": "application/vnd.oci.empty.v1+json", "digest": config_d.to_string(), "size": config.len() },
        "layers": [{ "mediaType": "application/spdx+json", "digest": layer_d.to_string(), "size": layer.len() }],
        "subject": { "mediaType": OCI_MANIFEST, "digest": md.to_string(), "size": m.len() },
        "annotations": { "org.example": "yes" }
    })).unwrap();
    let sbom_d = Digest::sha256_of(&sbom);
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{sbom_d}"), &[("content-type", OCI_MANIFEST)], sbom).await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(r.header("oci-subject"), md.to_string());
    let r = send(&app, Method::GET, &format!("/v2/{repo}/referrers/{md}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-type"), OCI_INDEX);
    let refs = r.json();
    assert_eq!(refs["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(refs["manifests"][0]["artifactType"], "application/spdx+json");
    assert_eq!(refs["manifests"][0]["annotations"]["org.example"], "yes");
    let r = send(&app, Method::GET, &format!("/v2/{repo}/referrers/{md}?artifactType=nope"), &[], vec![]).await;
    assert_eq!(r.json()["manifests"].as_array().unwrap().len(), 0);
    assert_eq!(r.header("oci-filters-applied"), "artifactType");

    // Cross-repo mount and monolithic upload.
    let r = send(&app, Method::POST, &format!("/v2/mirror/blobs/uploads/?mount={layer_d}&from={repo}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(r.header("location"), format!("/v2/mirror/blobs/{layer_d}"));
    let r = send(&app, Method::HEAD, &format!("/v2/mirror/blobs/{layer_d}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let mono = b"monolithic blob";
    let mono_d = Digest::sha256_of(mono);
    let r = send(&app, Method::POST, &format!("/v2/mirror/blobs/uploads/?digest={mono_d}"), &[("content-type", "application/octet-stream")], mono.to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(&app, Method::POST, &format!("/v2/mirror/blobs/uploads/?digest={bogus}"), &[], mono.to_vec()).await;
    assert_eq!(r.json()["errors"][0]["code"], "DIGEST_INVALID");

    // Extension API: manifest detail with layers mapped to history, config parsed.
    let r = send(&app, Method::GET, &format!("/api/v1/repositories/{repo}/manifests/v1"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let d = r.json();
    assert_eq!(d["kind"], "image");
    assert_eq!(d["tags"], json!(["v1", "v2"]));
    assert_eq!(d["layers"][0]["created_by"], "/bin/sh -c #(nop) ADD file in /");
    assert_eq!(d["layers"][0]["diff_id"], "sha256:aaaa");
    assert_eq!(d["history"].as_array().unwrap().len(), 1);
    assert_eq!(d["image"]["config"]["Cmd"], json!(["/bin/sh"]));
    assert_eq!(d["referrers"].as_array().unwrap().len(), 1);
    assert_eq!(d["total_size"], (config.len() + layer.len()) as u64);

    // Layer file listing.
    let r = send(&app, Method::GET, &format!("/api/v1/repositories/{repo}/manifests/v1/layers/{layer_d}/files"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let l = r.json();
    assert_eq!(l["compression"], "gzip");
    let entries = l["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["path"], "etc/hello.txt");
    assert_eq!(entries[0]["size"], 5);
    assert_eq!(entries[0]["mode"], "644");
    assert_eq!(entries[1]["type"], "dir");
    assert_eq!(entries[2]["is_whiteout"], true);

    let r = send(&app, Method::GET, "/api/v1/repositories", &[], vec![]).await;
    assert_eq!(r.json()[0]["name"], repo);
    assert_eq!(r.json()[0]["tags"], 3);
    let r = send(&app, Method::GET, &format!("/api/v1/repositories/{repo}/tags"), &[], vec![]).await;
    assert_eq!(r.json().as_array().unwrap().len(), 3);

    // Delete tag, then manifest by digest; GC then frees the layer in repo but the mirror keeps it.
    let r = send(&app, Method::DELETE, &format!("/v2/{repo}/manifests/v2"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::GET, &format!("/v2/{repo}/tags/list"), &[], vec![]).await;
    assert_eq!(r.json()["tags"], json!(["multi", "v1"]));
    let r = send(&app, Method::DELETE, &format!("/v2/{repo}/manifests/{md}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::GET, &format!("/v2/{repo}/manifests/v1"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = send(&app, Method::GET, &format!("/v2/{repo}/referrers/{md}"), &[], vec![]).await;
    assert_eq!(r.json()["manifests"].as_array().unwrap().len(), 1, "referrer survives subject deletion");

    // With the default grace window nothing freshly written is touched.
    let r = send(&app, Method::POST, "/api/v1/gc?dry_run=true", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let g = r.json();
    assert_eq!(g["blobs_removed"], json!([]), "{g}");
    assert!(g["skipped_recent"].as_u64().unwrap() > 0);
    // Without it the unlinked image manifest and the dangling mirror links go.
    let r = send(&app, Method::POST, "/api/v1/gc?dry_run=true&grace_seconds=0", &[], vec![]).await;
    let g = r.json();
    // `md` is still a child of the tagged index, so only the orphan monolithic blob goes.
    assert_eq!(g["blobs_removed"], json!([mono_d.to_string()]), "{g}");
    assert!(g["links_removed"].as_array().unwrap().contains(&json!(format!("mirror@{mono_d}"))), "{g}");
    assert!(g["manifests_removed"].as_array().unwrap().is_empty());
    // The SBOM's subject is reachable through the tagged index, so is_delete_untagged keeps it.
    let r = send(&app, Method::POST, "/api/v1/gc?delete_untagged=true&dry_run=true&grace_seconds=0", &[], vec![]).await;
    let g = r.json();
    assert_eq!(g["manifests_removed"], json!([]), "{g}");
    assert_eq!(g["manifests_kept"], 2);
    // Drop the last tag: the index, its child and the referrer all become unreachable.
    send(&app, Method::DELETE, &format!("/v2/{repo}/manifests/multi"), &[], vec![]).await;
    let r = send(&app, Method::POST, "/api/v1/gc?delete_untagged=true&grace_seconds=0", &[], vec![]).await;
    let g = r.json();
    let removed = g["manifests_removed"].as_array().unwrap();
    assert!(removed.iter().any(|m| m.as_str().unwrap().ends_with(&sbom_d.to_string())), "{g}");
    assert_eq!(removed.len(), 2, "{g}");
    assert!(g["blobs_removed"].as_array().unwrap().contains(&json!(layer_d.to_string())), "{g}");
    let r = send(&app, Method::GET, &format!("/v2/mirror/blobs/{layer_d}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "dangling link removed");
    let r = send(&app, Method::GET, &format!("/v2/{repo}/blobs/{layer_d}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "unreferenced link removed");
    let r = send(&app, Method::GET, "/v2/_catalog", &[], vec![]).await;
    assert_eq!(r.json()["repositories"], json!([]), "empty repos disappear");
}

#[tokio::test]
async fn upload_sessions() {
    let app = app(base_config()).await;
    let r = send(&app, Method::POST, "/v2/a/blobs/uploads/", &[], vec![]).await;
    let loc = r.header("location");
    let uuid = r.header("docker-upload-uuid");
    assert!(loc.ends_with(&uuid));
    send(&app, Method::PATCH, &loc, &[], b"abc".to_vec()).await;
    let r = send(&app, Method::GET, &loc, &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(r.header("range"), "0-2");
    // Sessions are bound to their repository.
    let r = send(&app, Method::GET, &loc.replace("/v2/a/", "/v2/b/"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = send(&app, Method::DELETE, &loc, &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = send(&app, Method::GET, &loc, &[], vec![]).await;
    assert_eq!(r.json()["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN");
    // Completing without a digest is an error.
    let r = send(&app, Method::POST, "/v2/a/blobs/uploads/", &[], vec![]).await;
    let r = send(&app, Method::PUT, &r.header("location"), &[], b"x".to_vec()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

fn rbac_config() -> Config {
    let mut cfg = base_config();
    cfg.auth.mode = AuthMode::Basic;
    cfg.auth.public_repositories = vec!["public/**".into()];
    cfg.auth.roles = vec![
        role("reader", &["**"], &[Action::Pull]),
        role("team-a", &["team-a/**"], &[Action::Push, Action::Pull, Action::Delete]),
        Role { global: vec![Global::System], ..role("admin", &[], &[]) },
    ];
    cfg.auth.users = vec![
        User { username: "alice".into(), password: Some("pw".into()), password_hash: None, roles: vec!["reader".into(), "team-a".into()], is_robot: false, email: None },
        User { username: "ci+bot".into(), password: None, password_hash: Some(bcrypt::hash("secret", 4).unwrap()), roles: vec!["admin".into()], is_robot: true, email: None },
    ];
    cfg.policy.immutable_tags = vec![ImmutableTagRule { repositories: vec!["team-a/**".into()], tags: vec!["v*".into()] }];
    cfg
}

#[tokio::test]
async fn rbac_and_policies() {
    let app = app(rbac_config()).await;
    let alice = basic("alice", "pw");
    let bot = basic("ci+bot", "secret");

    // Anonymous: 401 with challenge; wrong password: 401.
    let r = send(&app, Method::GET, "/v2/", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("www-authenticate").starts_with("Basic realm="));
    let r = send(&app, Method::POST, "/v2/team-a/app/blobs/uploads/", &[("authorization", &basic("alice", "nope"))], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Alice can push to team-a but not elsewhere (403, not 401).
    let r = send(&app, Method::POST, "/v2/team-a/app/blobs/uploads/", &[("authorization", &alice)], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::POST, "/v2/team-b/app/blobs/uploads/", &[("authorization", &alice)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.json()["errors"][0]["code"], "DENIED");

    // Robot admin pushes an image to team-a and public.
    for repo in ["team-a/app", "public/hello", "secret/thing"] {
        let cfg = b"{}";
        let cd = push_blob(&app, repo, cfg, Some(&bot)).await;
        let m = image_manifest(&cd, cfg.len(), &[]);
        let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v1"), &[("authorization", &bot), ("content-type", OCI_MANIFEST)], m).await;
        assert_eq!(r.status, StatusCode::CREATED);
    }

    // Public repos are pullable anonymously; private ones are not.
    let r = send(&app, Method::GET, "/v2/public/hello/manifests/v1", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::GET, "/v2/secret/thing/manifests/v1", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Alice (reader) can pull it, catalog shows everything she can see.
    let r = send(&app, Method::GET, "/v2/secret/thing/manifests/v1", &[("authorization", &alice)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::GET, "/v2/_catalog", &[], vec![]).await;
    assert_eq!(r.json()["repositories"], json!(["public/hello"]));
    let r = send(&app, Method::GET, "/api/v1/repositories", &[("authorization", &alice)], vec![]).await;
    let names: Vec<&str> = r.json().as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap().to_string()).collect::<Vec<_>>().leak().iter().map(|s| s.as_str()).collect();
    assert_eq!(names, ["public/hello", "secret/thing", "team-a/app"]);

    // Immutable tag: cannot be re-pointed or deleted, other tags can.
    let cfg2 = b"{\"os\":\"linux\"}";
    let cd2 = push_blob(&app, "team-a/app", cfg2, Some(&alice)).await;
    let m2 = image_manifest(&cd2, cfg2.len(), &[]);
    let r = send(&app, Method::PUT, "/v2/team-a/app/manifests/v1", &[("authorization", &alice), ("content-type", OCI_MANIFEST)], m2.clone()).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = send(&app, Method::PUT, "/v2/team-a/app/manifests/latest", &[("authorization", &alice), ("content-type", OCI_MANIFEST)], m2).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(&app, Method::DELETE, "/v2/team-a/app/manifests/v1", &[("authorization", &alice)], vec![]).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = send(&app, Method::DELETE, "/v2/team-a/app/manifests/latest", &[("authorization", &alice)], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);

    // GC is admin-only; /me reflects the principal.
    let r = send(&app, Method::POST, "/api/v1/gc?dry_run=true", &[("authorization", &alice)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::POST, "/api/v1/gc?dry_run=true", &[("authorization", &bot)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::GET, "/api/v1/me", &[("authorization", &bot)], vec![]).await;
    assert_eq!(r.json()["is_robot"], true);
    assert_eq!(r.json()["admin"], true);
    assert_eq!(r.json()["method"], "password");
    assert_eq!(r.json()["is_managed"], true);

    // Audit log: alice sees only repos she can pull; the bot sees everything.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let r = send(&app, Method::GET, "/api/v1/logs", &[("authorization", &bot)], vec![]).await;
    let logs = r.json();
    let actions: Vec<&str> = logs.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"push") && actions.contains(&"delete_tag"), "{actions:?}");
    assert_eq!(logs[0]["action"], "delete_tag", "newest first: {logs}");
}

#[tokio::test]
async fn ui_is_served() {
    let app = app(base_config()).await;
    let r = send(&app, Method::GET, "/", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.header(header::CONTENT_TYPE.as_str()).starts_with("text/html"));
    let r = send(&app, Method::GET, "/r/some/repo", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "SPA fallback");
    let r = send(&app, Method::GET, "/ui/r/some/repo?tab=tags", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::PERMANENT_REDIRECT, "old /ui links still work");
    assert_eq!(r.header("location"), "/r/some/repo?tab=tags");
    let r = send(&app, Method::GET, "/api/v1/nope", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "unknown API paths are not the app");
    let r = send(&app, Method::GET, "/v2/nope", &[], vec![]).await;
    assert_ne!(r.header(header::CONTENT_TYPE.as_str()), "text/html", "the registry namespace is never the app");
}

fn accounts_config() -> Config {
    let mut cfg = base_config();
    cfg.auth.mode = AuthMode::Token;
    cfg.auth.bootstrap_admin = Some(BootstrapAdmin { username: "root".into(), password: "rootpass123".into() });
    cfg.auth.public_repositories = vec!["public/**".into()];
    cfg
}

/// Log in through the web API and return the session cookie header value.
async fn web_login(app: &Router, user: &str, pass: &str, otp: Option<&str>) -> Resp {
    let body = serde_json::to_vec(&json!({ "username": user, "password": pass, "otp": otp })).unwrap();
    send(app, Method::POST, "/api/v1/auth/login", &[("content-type", "application/json")], body).await
}

fn cookie_of(r: &Resp) -> String {
    let sc = r.header("set-cookie");
    sc.split(';').next().unwrap().to_string()
}

/// Every cookie a response sets, as one `Cookie` header value.
fn cookies_of(r: &Resp) -> String {
    r.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string()).collect::<Vec<_>>().join("; ")
}

/// The `Set-Cookie` header setting `name`.
fn set_cookie(r: &Resp, name: &str) -> String {
    r.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).find(|v| v.starts_with(&format!("{name}="))).unwrap_or_default()
}

/// Delete a repository the confirmed way: a plan, then its execution with the name typed back.
async fn delete_repository_confirmed(app: &Router, cookie: &str, name: &str) {
    let jh = ("content-type", "application/json");
    let r = send(app, Method::POST, &format!("/api/v1/repositories/{name}/delete-plan"), &[("cookie", cookie), jh], serde_json::to_vec(&json!({ "repository": true })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let id = r.json()["id"].as_str().unwrap().to_string();
    let r = send(app, Method::POST, &format!("/api/v1/delete-plans/{id}/execute"), &[("cookie", cookie), jh], serde_json::to_vec(&json!({ "confirm": name })).unwrap()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
}

#[tokio::test]
async fn accounts_sessions_tokens_mfa_and_docker_login() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");

    // Bootstrap admin signs in with a session cookie.
    let r = web_login(&app, "root", "wrong", None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = web_login(&app, "root", "rootpass123", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let root = cookie_of(&r);
    assert!(root.starts_with("kontainer_session="));
    let sc = set_cookie(&r, "kontainer_session");
    assert!(sc.contains("; SameSite=Strict") && sc.contains("; HttpOnly") && sc.contains("; Path=/;") && !sc.contains("Lax"), "{sc}");
    assert!(!sc.contains("Secure"), "plain http public_url: no Secure");
    let r = send(&app, Method::GET, "/api/v1/me", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()["username"], "root");
    assert_eq!(r.json()["admin"], true);
    assert_eq!(r.json()["method"], "session");

    // Admin creates a fine-grained role and a user.
    let body = serde_json::to_vec(&json!({ "name": "dev", "description": "team dev", "rules": [{ "repositories": ["team/**"], "actions": ["pull", "push", "scan"] }], "global": ["catalog"] })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/roles", &[("cookie", &root), jh], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let body = serde_json::to_vec(&json!({ "username": "bob", "password": "bobpass123", "email": "bob@example.com", "roles": ["dev"] })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let bob_id = r.json()["id"].as_i64().unwrap();
    assert_eq!(r.json()["roles"], json!(["dev"]));

    // Bob signs in; cannot manage roles (no roles:write) and can only grant what he holds.
    let r = web_login(&app, "bob", "bobpass123", None).await;
    assert_eq!(r.status, StatusCode::OK);
    let bob = cookie_of(&r);
    let r = send(&app, Method::POST, "/api/v1/roles", &[("cookie", &bob), jh], b"{\"name\":\"x\"}".to_vec()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::GET, "/api/v1/users", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // Personal access token: works as a Basic password on /v2 within bob's permissions.
    let body = serde_json::to_vec(&json!({ "name": "laptop", "expires_in_days": 30 })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &bob), jh], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let pat = r.json()["token"].as_str().unwrap().to_string();
    assert!(pat.starts_with("kontainer_"));
    assert_eq!(r.json()["hint"], pat[..12]);
    // Timestamps keep the API's RFC 3339 form, `+00:00` rather than `Z`.
    let expires = r.json()["expires_at"].as_str().unwrap().to_string();
    assert!(expires.ends_with("+00:00") && chrono::DateTime::parse_from_rfc3339(&expires).is_ok(), "{expires}");
    let bob_pat = basic("bob", &pat);
    let r = send(&app, Method::POST, "/v2/team/app/blobs/uploads/", &[("authorization", &bob_pat)], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::POST, "/v2/other/app/blobs/uploads/", &[("authorization", &bob_pat)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Tokens act as the user; scoping them is no longer supported (use a robot instead).
    let body = serde_json::to_vec(&json!({ "name": "ro", "scopes": [{ "repositories": ["team/app"], "actions": ["pull"] }] })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &bob), jh], body).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = send(&app, Method::GET, "/api/v1/auth/tokens", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    assert_eq!(r.json()[0]["hint"], pat[..12]);
    assert!(r.json()[0].get("prefix").is_none());
    assert_eq!(r.json()[0]["expires_at"], expires.as_str());
    assert!(r.json()[0]["created_at"].as_str().unwrap().ends_with("+00:00"));
    // Tokens cannot mint tokens.
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("authorization", &bob_pat), jh], b"{\"name\":\"x\"}".to_vec()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Docker login flow: challenge, token endpoint, bearer-restricted access.
    let r = send(&app, Method::GET, "/v2/", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let ch = r.header("www-authenticate");
    assert!(ch.starts_with("Bearer realm=\"http://registry.test/auth/token\",service=\"registry.test\""), "{ch}");
    let r = send(&app, Method::GET, "/v2/team/app/manifests/latest", &[], vec![]).await;
    assert!(r.header("www-authenticate").contains("scope=\"repository:team/app:pull\""));
    let r = send(&app, Method::GET, "/auth/token?service=registry.test&scope=repository:team/app:pull,push&scope=repository:other/app:pull,push&scope=registry:catalog:*", &[("authorization", &bob_pat)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let jwt = r.json()["token"].as_str().unwrap().to_string();
    assert!(r.json()["expires_in"].as_u64().unwrap() > 0);
    let bearer = format!("Bearer {jwt}");
    let r = send(&app, Method::POST, "/v2/team/app/blobs/uploads/", &[("authorization", &bearer)], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::POST, "/v2/other/app/blobs/uploads/", &[("authorization", &bearer)], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "not granted in token: a challenge names the missing scope so the client fetches a wider token");
    assert!(r.header("www-authenticate").contains("repository:other/app:pull,push"), "{}", r.header("www-authenticate"));
    let r = send(&app, Method::GET, "/v2/_catalog", &[("authorization", &bearer)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    // The OAuth2 form (Docker POSTs to the realm): credentials in the body.
    let form = format!("grant_type=password&username=bob&password={pat}&service=registry.test&scope=repository:team/app:pull,push+repository:other/x:pull&client_id=docker");
    let r = send(&app, Method::POST, "/auth/token", &[("content-type", "application/x-www-form-urlencoded")], form.into_bytes()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let oauth = format!("Bearer {}", r.json()["access_token"].as_str().unwrap());
    let r = send(&app, Method::POST, "/v2/team/app/blobs/uploads/", &[("authorization", &oauth)], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "password grant tokens carry the user's access");
    let form = "grant_type=password&username=bob&password=wrong&service=registry.test".to_string();
    let r = send(&app, Method::POST, "/auth/token", &[("content-type", "application/x-www-form-urlencoded")], form.into_bytes()).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Anonymous tokens only get public repos.
    let r = send(&app, Method::GET, "/auth/token?service=registry.test&scope=repository:public/x:pull,push", &[], vec![]).await;
    let anon_jwt = r.json()["token"].as_str().unwrap().to_string();
    let r = send(&app, Method::GET, "/v2/public/x/manifests/latest", &[("authorization", &format!("Bearer {anon_jwt}"))], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "pull allowed, nothing there");
    let r = send(&app, Method::POST, "/v2/public/x/blobs/uploads/", &[("authorization", &format!("Bearer {anon_jwt}"))], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = send(&app, Method::GET, "/v2/", &[("authorization", "Bearer not.a.jwt")], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Robot account owned by bob: no access until granted, never bob's own access.
    let body = serde_json::to_vec(&json!({ "name": "ci" })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/robots", &[("cookie", &bob), jh], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["username"], "bob+ci");
    let robot_id = r.json()["id"].as_i64().unwrap();
    let robot = basic("bob+ci", r.json()["token"].as_str().unwrap());
    let r = send(&app, Method::POST, "/v2/team/app/blobs/uploads/", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "robots do not inherit the owner's roles");
    let r = send(&app, Method::POST, "/v2/bob/scratch/blobs/uploads/", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "nor the owner's namespace");
    // Bob administers his namespace, so he can grant the robot write on one repository.
    let grant = serde_json::to_vec(&json!({ "kind": "user", "name": "bob+ci", "level": "write" })).unwrap();
    let r = send(&app, Method::PUT, "/api/v1/repository-permissions/bob/scratch", &[("cookie", &bob), jh], grant).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["grants"][0]["name"], "bob+ci");
    assert_eq!(r.json()["grants"][0]["level"], "write");
    let r = send(&app, Method::POST, "/v2/bob/scratch/blobs/uploads/", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::POST, "/v2/bob/other/blobs/uploads/", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "only the granted repository");
    let r = send(&app, Method::GET, "/api/v1/users", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "robots never get admin powers");
    // Scoped robots are gone too; listing shows each robot's grants.
    let body = serde_json::to_vec(&json!({ "name": "ro", "scopes": [{ "repositories": ["team/**"], "actions": ["pull"] }] })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/robots", &[("cookie", &bob), jh], body).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = send(&app, Method::GET, "/api/v1/auth/robots", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    assert_eq!(r.json()[0]["repositories"], json!([{ "repository": "bob/scratch", "level": "write" }]));
    let r = send(&app, Method::POST, &format!("/api/v1/auth/robots/{robot_id}/rotate"), &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::POST, "/v2/team/app/blobs/uploads/", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "old robot token revoked");

    // MFA enrollment.
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/setup", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let abandoned = r.json()["secret"].as_str().unwrap().to_string();
    // A setup in progress is not MFA: the password alone still signs in.
    let r = send(&app, Method::GET, "/api/v1/me", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.json()["is_mfa_enabled"], false);
    assert_eq!(web_login(&app, "bob", "bobpass123", None).await.status, StatusCode::OK);
    // Setting up again replaces the pending secret.
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/setup", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let secret = r.json()["secret"].as_str().unwrap().to_string();
    assert_ne!(secret, abandoned);
    assert!(r.json()["qr_svg"].as_str().unwrap().contains("<svg"));
    // Each code works once: later sign-ins use the next time step (accepted as clock skew).
    let code_at = |secret: &str, steps_ahead: u64| {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        totp_rs::Builder::new()
            .with_secret(totp_rs::Secret::try_from_base32(secret).unwrap())
            .with_account_name("bob")
            .build_noncompliant()
            .generate(now + 30 * steps_ahead)
            .to_string()
    };
    let code = |secret: &str| code_at(secret, 0);
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/enable", &[("cookie", &bob), jh], b"{\"code\":\"000000\"}".to_vec()).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let body = serde_json::to_vec(&json!({ "code": code(&abandoned) })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/enable", &[("cookie", &bob), jh], body).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "the replaced secret no longer counts");
    let used = code(&secret);
    let body = serde_json::to_vec(&json!({ "code": used })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/enable", &[("cookie", &bob), jh], body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let recovery: Vec<String> = serde_json::from_value(r.json()["recovery_codes"].clone()).unwrap();
    assert_eq!(recovery.len(), 8);
    let r = send(&app, Method::GET, "/api/v1/me", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.json()["is_mfa_enabled"], true);
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/setup", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "already enabled");
    let body = serde_json::to_vec(&json!({ "code": code_at(&secret, 1) })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/enable", &[("cookie", &bob), jh], body).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "nothing pending once enabled");
    // Password alone is no longer enough on the web...
    let r = web_login(&app, "bob", "bobpass123", None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.json()["mfa_required"], true);
    let r = web_login(&app, "bob", "bobpass123", Some(&used)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "the code that enabled MFA cannot be replayed");
    let r = web_login(&app, "bob", "bobpass123", Some(&code_at(&secret, 1))).await;
    assert_eq!(r.status, StatusCode::OK);
    // ...nor on the CLI: MFA users must use access tokens.
    let r = send(&app, Method::GET, "/auth/token?service=registry.test&scope=repository:team/app:pull", &[("authorization", &basic("bob", "bobpass123"))], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.json()["errors"][0]["message"].as_str().unwrap().contains("access token"));
    let r = send(&app, Method::GET, "/v2/team/app/tags/list", &[("authorization", &bob_pat)], vec![]).await;
    assert_ne!(r.status, StatusCode::UNAUTHORIZED);
    // Recovery codes are single use.
    let body = serde_json::to_vec(&json!({ "username": "bob", "password": "bobpass123", "recovery_code": recovery[0] })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/login", &[jh], body.clone()).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::POST, "/api/v1/auth/login", &[jh], body).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Turning MFA off (with the password: both codes from now were used) clears it.
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/disable", &[("cookie", &bob), jh], b"{\"password\":\"bobpass123\"}".to_vec()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::GET, "/api/v1/me", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.json()["is_mfa_enabled"], false);
    assert_eq!(web_login(&app, "bob", "bobpass123", None).await.status, StatusCode::OK);
    let r = send(&app, Method::POST, "/api/v1/auth/mfa/recovery-codes", &[("cookie", &bob), jh], b"{\"code\":\"000000\"}".to_vec()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "not enabled");

    // Logout kills the session; disabling the user kills tokens too.
    let r = send(&app, Method::POST, "/api/v1/auth/logout", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = send(&app, Method::GET, "/api/v1/me", &[("cookie", &bob)], vec![]).await;
    assert_eq!(r.json()["username"], Value::Null);
    let r = send(&app, Method::PATCH, &format!("/api/v1/users/{bob_id}"), &[("cookie", &root), jh], b"{\"is_disabled\":true}".to_vec()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::GET, "/v2/team/app/tags/list", &[("authorization", &bob_pat)], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = web_login(&app, "bob", "bobpass123", Some(&code(&secret))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Admin safety rails and audit trail.
    let r = send(&app, Method::DELETE, "/api/v1/users/1", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "cannot delete self");
    let r = send(&app, Method::GET, "/api/v1/permissions", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()["actions"].as_array().unwrap().len(), 13);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let r = send(&app, Method::GET, "/api/v1/logs?limit=200", &[("cookie", &root)], vec![]).await;
    let actions: Vec<String> = r.json().as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap().to_string()).collect();
    for expected in ["login", "login_failed", "role_created", "user_created", "token_created", "token_issued", "robot_created", "is_mfa_enabled", "logout", "user_updated"] {
        assert!(actions.contains(&expected.to_string()), "missing {expected} in {actions:?}");
    }
}

#[tokio::test]
async fn organizations_teams_and_public_repositories() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);

    // Users who may create orgs, and plain members.
    let body = serde_json::to_vec(&json!({ "name": "founder", "rules": [], "global": ["orgs:create"] })).unwrap();
    send(&app, Method::POST, "/api/v1/roles", &[("cookie", &root), jh], body).await;
    for (u, roles) in [("ann", vec!["founder"]), ("ben", vec![]), ("cat", vec![])] {
        let body = serde_json::to_vec(&json!({ "username": u, "password": "password123", "roles": roles })).unwrap();
        let r = send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    let ann = cookie_of(&web_login(&app, "ann", "password123", None).await);
    let ben = cookie_of(&web_login(&app, "ben", "password123", None).await);
    let cat = cookie_of(&web_login(&app, "cat", "password123", None).await);

    // Ben cannot create orgs; Ann can and becomes its admin. Names share a namespace with users.
    let body = serde_json::to_vec(&json!({ "name": "acme", "display_name": "ACME" })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &ben), jh], body.clone()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &ann), jh], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "name": "ben" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "username": "acme", "password": "password123" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = send(&app, Method::GET, "/api/v1/orgs/acme", &[("cookie", &ann)], vec![]).await;
    assert_eq!(r.json()["is_admin"], true);
    assert_eq!(r.json()["teams"][0]["name"], "owners");
    // Non-members cannot see the org.
    let r = send(&app, Method::GET, "/api/v1/orgs/acme", &[("cookie", &ben)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // Ann (org admin) can push anywhere under acme/, Ben cannot.
    let push = |cookie: &str, repo: &str| {
        let c = cookie.to_string();
        let repo = repo.to_string();
        let app = app.clone();
        async move { send(&app, Method::POST, &format!("/v2/{repo}/blobs/uploads/"), &[("cookie", &c)], vec![]).await.status }
    };
    assert_eq!(push(&ann, "acme/api").await, StatusCode::ACCEPTED);
    assert_eq!(push(&ben, "acme/api").await, StatusCode::FORBIDDEN);

    // A member team with base read on every org repository, plus write granted on one.
    let body = serde_json::to_vec(&json!({ "name": "backend", "role": "member", "base_permission": "read" })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/orgs/acme/teams", &[("cookie", &ann), jh], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::POST, "/api/v1/orgs/acme/teams/backend/members", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "username": "ben" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(push(&ben, "acme/api").await, StatusCode::FORBIDDEN, "base read is not push");
    let r = send(&app, Method::GET, "/v2/acme/web/tags/list", &[("cookie", &ben)], vec![]).await;
    assert_ne!(r.status, StatusCode::FORBIDDEN, "base read pulls every org repo");
    let grant = serde_json::to_vec(&json!({ "kind": "team", "name": "backend", "level": "write" })).unwrap();
    let r = send(&app, Method::PUT, "/api/v1/repository-permissions/acme/api", &[("cookie", &ben), jh], grant.clone()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "only repo admins manage permissions");
    let r = send(&app, Method::PUT, "/api/v1/repository-permissions/acme/api", &[("cookie", &ann), jh], grant).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(push(&ben, "acme/api").await, StatusCode::ACCEPTED);
    assert_eq!(push(&ben, "acme/api/v2").await, StatusCode::FORBIDDEN, "grants are per repository");
    assert_eq!(push(&ben, "acme/web").await, StatusCode::FORBIDDEN);
    assert_eq!(push(&ben, "other/api").await, StatusCode::FORBIDDEN, "teams never reach outside the org");
    let r = send(&app, Method::GET, "/api/v1/repository-permissions/acme/api", &[("cookie", &ann)], vec![]).await;
    assert_eq!(r.json()["grants"], json!([{ "kind": "team", "name": "backend", "display_name": null, "is_robot": false, "level": "write" }]));
    let inherited: Vec<String> = r.json()["inherited"].as_array().unwrap().iter().map(|i| format!("{}:{}:{}", i["source"].as_str().unwrap(), i["team"].as_str().unwrap(), i["level"].as_str().unwrap())).collect();
    assert_eq!(inherited, vec!["Base permission:backend:read", "Admin team:owners:admin"]);
    // Teams can only be granted on their own org's repositories.
    let grant = serde_json::to_vec(&json!({ "kind": "team", "name": "backend", "level": "read" })).unwrap();
    let r = send(&app, Method::PUT, "/api/v1/repository-permissions/ann/x", &[("cookie", &ann), jh], grant).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Everyone owns their personal namespace; robots do not.
    assert_eq!(push(&ben, "ben/scratch").await, StatusCode::ACCEPTED);
    assert_eq!(push(&cat, "ben/scratch").await, StatusCode::FORBIDDEN);
    // Ben is a member but not an admin.
    let r = send(&app, Method::GET, "/api/v1/orgs/acme", &[("cookie", &ben)], vec![]).await;
    assert_eq!(r.json()["is_admin"], false);
    let r = send(&app, Method::POST, "/api/v1/orgs/acme/teams", &[("cookie", &ben), jh], b"{\"name\":\"x\"}".to_vec()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // Org robot joins the team and gets its grants on the CLI.
    let body = serde_json::to_vec(&json!({ "name": "ci", "teams": ["backend"] })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/orgs/acme/robots", &[("cookie", &ann), jh], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["username"], "acme+ci");
    let robot = basic("acme+ci", r.json()["token"].as_str().unwrap());
    let r = send(&app, Method::POST, "/v2/acme/api/blobs/uploads/", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::POST, "/v2/acme/web/blobs/uploads/", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Robots are only granted inside their own namespace.
    let grant = serde_json::to_vec(&json!({ "kind": "user", "name": "acme+ci", "level": "read" })).unwrap();
    let r = send(&app, Method::PUT, "/api/v1/repository-permissions/ann/x", &[("cookie", &ann), jh], grant).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Safety rails: last admin cannot be removed; last admin team cannot drop the flag.
    let r = send(&app, Method::DELETE, "/api/v1/orgs/acme/teams/owners/members/ann", &[("cookie", &ann)], vec![]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let body = serde_json::to_vec(&json!({ "description": "", "role": "member" })).unwrap();
    let r = send(&app, Method::PUT, "/api/v1/orgs/acme/teams/owners", &[("cookie", &ann), jh], body).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Repository metadata and visibility: push an image, make it public, explore it.
    let cfg = b"{}";
    let cd = push_blob(&app, "acme/api", cfg, Some(&robot)).await;
    let m = image_manifest(&cd, cfg.len(), &[]);
    let r = send(&app, Method::PUT, "/v2/acme/api/manifests/v1", &[("authorization", &robot), ("content-type", OCI_MANIFEST)], m).await;
    assert_eq!(r.status, StatusCode::CREATED);
    // Creator teams may push new repositories (and become their admin), not existing ones.
    let body = serde_json::to_vec(&json!({ "name": "builders", "role": "creator" })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/orgs/acme/teams", &[("cookie", &ann), jh], body).await.status, StatusCode::CREATED);
    let body = serde_json::to_vec(&json!({ "username": "cat" })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/orgs/acme/teams/builders/members", &[("cookie", &ann), jh], body).await.status, StatusCode::NO_CONTENT);
    assert_eq!(push(&cat, "acme/api").await, StatusCode::FORBIDDEN, "acme/api already exists");
    let cat_basic = basic("cat", "password123");
    let cd2 = push_blob(&app, "acme/tool", cfg, Some(&cat_basic)).await;
    let m2 = image_manifest(&cd2, cfg.len(), &[]);
    let r = send(&app, Method::PUT, "/v2/acme/tool/manifests/v1", &[("authorization", &cat_basic), ("content-type", OCI_MANIFEST)], m2).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::GET, "/api/v1/repository-permissions/acme/tool", &[("cookie", &cat)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "the creator administers what they created");
    assert_eq!(r.json()["grants"][0]["name"], "cat");
    assert_eq!(r.json()["grants"][0]["level"], "admin");
    let r = send(&app, Method::GET, "/v2/acme/api/manifests/v1", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "private by default");
    let r = send(&app, Method::GET, "/api/v1/explore", &[], vec![]).await;
    assert_eq!(r.json()["repositories"], json!([]));
    // Only repo admins (Ann) may edit metadata.
    let body = serde_json::to_vec(&json!({ "visibility": "public", "description": "The API", "topics": ["go", "api"], "readme": "# API\n\nHello." })).unwrap();
    let r = send(&app, Method::PATCH, "/api/v1/repository-meta/acme/api", &[("cookie", &ben), jh], body.clone()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::PATCH, "/api/v1/repository-meta/acme/api", &[("cookie", &ann), jh], body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["topics"], json!(["go", "api"]));
    let r = send(&app, Method::GET, "/v2/acme/api/manifests/v1", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "public: anonymous pull");
    let r = send(&app, Method::POST, "/v2/acme/api/blobs/uploads/", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "public never means push");
    let r = send(&app, Method::GET, "/api/v1/explore?topic=go", &[], vec![]).await;
    assert_eq!(r.json()["repositories"][0]["name"], "acme/api");
    assert_eq!(r.json()["repositories"][0]["org"], "acme");
    assert_eq!(r.json()["repositories"][0]["tags"], 1);
    assert_eq!(r.json()["repositories"][0]["latest"]["tag"], "v1");
    assert!(r.json()["repositories"][0]["latest"]["pushed_at"].is_string());
    assert_eq!(r.json()["topics"], json!(["api", "go"]));
    let r = send(&app, Method::GET, "/api/v1/explore?q=&topic=", &[], vec![]).await;
    assert_eq!(r.json()["repositories"].as_array().unwrap().len(), 1, "empty filters are no filters");
    let r = send(&app, Method::GET, "/api/v1/explore?q=nothing", &[], vec![]).await;
    assert_eq!(r.json()["repositories"], json!([]));
    let r = send(&app, Method::GET, "/api/v1/repository-meta/acme/api", &[("cookie", &cat)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "anyone who can pull sees the README");
    assert_eq!(r.json()["actions"], json!(["pull"]));
    assert!(r.json()["readme"].as_str().unwrap().starts_with("# API"));
    let r = send(&app, Method::PATCH, "/api/v1/repository-meta/acme/api", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "topics": ["Bad Topic"] })).unwrap()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Back to private.
    send(&app, Method::PATCH, "/api/v1/repository-meta/acme/api", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "visibility": "private" })).unwrap()).await;
    let r = send(&app, Method::GET, "/v2/acme/api/manifests/v1", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Usage log scoped to the org workspace: org events are visible to org admins only.
    // Audit writes are asynchronous, so wait for them to land.
    let logs = |cookie: &str, query: &str| {
        let (app, c, q) = (app.clone(), cookie.to_string(), query.to_string());
        async move { send(&app, Method::GET, &format!("/api/v1/logs?{q}"), &[("cookie", &c)], vec![]).await.json() }
    };
    let mut entries = Value::Null;
    for _ in 0..50 {
        entries = logs(&ann, "namespace=acme").await;
        if entries.as_array().unwrap().iter().any(|e| e["action"] == "repository_updated") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let actions: Vec<&str> = entries.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"team_created") && actions.contains(&"org_created"), "{actions:?}");
    assert!(entries.as_array().unwrap().iter().all(|e| e["org"] == "acme" || e["repository"].as_str().unwrap_or("").starts_with("acme/")));
    let ben_view = logs(&ben, "namespace=acme").await;
    assert!(ben_view.as_array().unwrap().iter().all(|e| e["action"] != "team_created"), "non-admins do not see org management");
    // Partial repository search.
    let found = logs(&ann, "q=API").await;
    assert!(!found.as_array().unwrap().is_empty());
    assert!(found.as_array().unwrap().iter().all(|e| e["repository"] == "acme/api"));
}

#[tokio::test]
async fn profiles_and_stars() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "username": "dan", "password": "password123" })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);

    // Profile: blanks become null, website and email are validated, gravatar feeds /me.
    let r = send(&app, Method::GET, "/api/v1/auth/profile", &[("cookie", &dan)], vec![]).await;
    assert_eq!(r.json(), json!({ "display_name": null, "company": null, "location": null, "website": null, "gravatar_email": null }));
    let body = serde_json::to_vec(&json!({ "display_name": " Dan D ", "company": "", "website": "ftp://x" })).unwrap();
    assert_eq!(send(&app, Method::PUT, "/api/v1/auth/profile", &[("cookie", &dan), jh], body).await.status, StatusCode::BAD_REQUEST);
    let body = serde_json::to_vec(&json!({ "display_name": " Dan D ", "company": "", "location": "KL", "website": "https://dan.dev", "gravatar_email": "Dan@Example.com" })).unwrap();
    let r = send(&app, Method::PUT, "/api/v1/auth/profile", &[("cookie", &dan), jh], body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["display_name"], "Dan D");
    assert_eq!(r.json()["company"], Value::Null);
    let r = send(&app, Method::GET, "/api/v1/me", &[("cookie", &dan)], vec![]).await;
    assert_eq!(r.json()["display_name"], "Dan D");
    assert!(r.json()["avatar_url"].as_str().unwrap().starts_with("https://gravatar.com/avatar/"));
    let r = send(&app, Method::GET, "/api/v1/auth/profile", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Stars: root pushes a private repo; dan cannot star it until it is public.
    let auth = basic("root", "rootpass123");
    let cfg = b"{}";
    let cd = push_blob(&app, "root/app", cfg, Some(&auth)).await;
    let m = image_manifest(&cd, cfg.len(), &[]);
    let r = send(&app, Method::PUT, "/v2/root/app/manifests/v1", &[("authorization", &auth), ("content-type", OCI_MANIFEST)], m).await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(send(&app, Method::PUT, "/api/v1/stars/root/app", &[("cookie", &dan)], vec![]).await.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::PUT, "/api/v1/stars/root/app", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json(), json!({ "stars": 1, "is_starred": true }));
    // Starring twice is idempotent.
    let r = send(&app, Method::PUT, "/api/v1/stars/root/app", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()["stars"], 1);
    let body = serde_json::to_vec(&json!({ "visibility": "public" })).unwrap();
    assert_eq!(send(&app, Method::PATCH, "/api/v1/repository-meta/root/app", &[("cookie", &root), jh], body).await.status, StatusCode::OK);
    let r = send(&app, Method::PUT, "/api/v1/stars/root/app", &[("cookie", &dan)], vec![]).await;
    assert_eq!(r.json(), json!({ "stars": 2, "is_starred": true }));

    let r = send(&app, Method::GET, "/api/v1/stars", &[("cookie", &dan)], vec![]).await;
    assert_eq!(r.json()[0]["name"], "root/app");
    assert_eq!(r.json()[0]["stars"], 2);
    let r = send(&app, Method::GET, "/api/v1/repository-meta/root/app", &[("cookie", &dan)], vec![]).await;
    assert_eq!((r.json()["stars"].clone(), r.json()["is_starred"].clone()), (json!(2), json!(true)));
    let r = send(&app, Method::GET, "/api/v1/explore", &[], vec![]).await;
    assert_eq!(r.json()["repositories"][0]["stars"], 2);
    let r = send(&app, Method::GET, "/api/v1/repositories", &[("cookie", &root)], vec![]).await;
    let row = r.json().as_array().unwrap().iter().find(|x| x["name"] == "root/app").cloned().unwrap();
    assert_eq!((row["stars"].clone(), row["is_starred"].clone()), (json!(2), json!(true)));

    let r = send(&app, Method::DELETE, "/api/v1/stars/root/app", &[("cookie", &dan)], vec![]).await;
    assert_eq!(r.json(), json!({ "stars": 1, "is_starred": false }));
    let r = send(&app, Method::GET, "/api/v1/stars", &[("cookie", &dan)], vec![]).await;
    assert_eq!(r.json(), json!([]));
    // Anonymous visitors cannot star.
    assert_eq!(send(&app, Method::PUT, "/api/v1/stars/root/app", &[], vec![]).await.status, StatusCode::UNAUTHORIZED);

    // Signing out other sessions keeps the one making the request.
    let other = cookie_of(&web_login(&app, "dan", "password123", None).await);
    let r = send(&app, Method::GET, "/api/v1/auth/sessions", &[("cookie", &dan)], vec![]).await;
    assert_eq!(r.json().as_array().unwrap().len(), 2);
    assert_eq!(send(&app, Method::DELETE, "/api/v1/auth/sessions/others", &[("cookie", &dan)], vec![]).await.status, StatusCode::NO_CONTENT);
    let r = send(&app, Method::GET, "/api/v1/auth/sessions", &[("cookie", &dan)], vec![]).await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    assert_eq!(r.json()[0]["is_current"], true);
    let r = send(&app, Method::GET, "/api/v1/me", &[("cookie", &other)], vec![]).await;
    assert_eq!(r.json()["username"], Value::Null);
}

/// Push a manifest body as-is and return its digest.
async fn put_manifest(app: &Router, repo: &str, reference: &str, body: Vec<u8>) -> Digest {
    let d = Digest::sha256_of(&body);
    let r = send(app, Method::PUT, &format!("/v2/{repo}/manifests/{reference}"), &[("content-type", OCI_MANIFEST)], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    d
}

#[tokio::test]
async fn artifacts_sboms_signatures_and_compare() {
    use base64::Engine;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::EncodePublicKey;
    let app = app(base_config()).await;
    let repo = "acme/app";
    let api = |path: &str| format!("/api/v1/repositories/{repo}/{path}");

    // Two versions: v2 keeps layer 1, adds layer 2, and changes env and cmd.
    let cfg1 = br#"{"architecture":"amd64","os":"linux","config":{"Env":["A=1"],"Cmd":["serve"]},"history":[{"created_by":"ADD base"}]}"#;
    let cfg2 = br#"{"architecture":"amd64","os":"linux","config":{"Env":["A=2","B=3"],"Cmd":["serve","--fast"]},"history":[{"created_by":"ADD base"},{"created_by":"RUN build"}]}"#;
    let (l1, l2) = (b"layer-one".to_vec(), b"layer-two".to_vec());
    let (c1, c2) = (push_blob(&app, repo, cfg1, None).await, push_blob(&app, repo, cfg2, None).await);
    let (d1, d2) = (push_blob(&app, repo, &l1, None).await, push_blob(&app, repo, &l2, None).await);
    let v1 = put_manifest(&app, repo, "v1", image_manifest(&c1, cfg1.len(), &[(d1.clone(), l1.len())])).await;
    put_manifest(&app, repo, "v2", image_manifest(&c2, cfg2.len(), &[(d1.clone(), l1.len()), (d2.clone(), l2.len())])).await;

    let r = send(&app, Method::GET, &api("compare?a=v1&b=v2"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let c = r.json();
    let statuses: Vec<(&str, &str)> = c["layers"].as_array().unwrap().iter().map(|l| (l["status"].as_str().unwrap(), l["created_by"].as_str().unwrap_or(""))).collect();
    assert_eq!(statuses, vec![("shared", "ADD base"), ("added", "RUN build")]);
    let changed: Vec<&str> = c["changes"].as_array().unwrap().iter().map(|x| x["field"].as_str().unwrap()).collect();
    assert_eq!(changed, vec!["Cmd", "Env A", "Env B"]);
    assert_eq!(c["shared_bytes"], l1.len());
    assert_eq!(c["size_delta"], (cfg2.len() + l2.len()) as i64 - cfg1.len() as i64);
    assert_eq!(send(&app, Method::GET, &api("compare?a=v1"), &[], vec![]).await.status, StatusCode::BAD_REQUEST);

    // An SBOM attached to v1 through the referrers API.
    let empty = push_blob(&app, repo, b"{}", None).await;
    let sbom = br#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"openssl","version":"3.1.4","purl":"pkg:apk/alpine/openssl@3.1.4"}]}"#;
    let sbom_blob = push_blob(&app, repo, sbom, None).await;
    let sbom_manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/vnd.cyclonedx+json",
        "config": { "mediaType": "application/vnd.oci.empty.v1+json", "digest": empty.to_string(), "size": 2 },
        "layers": [{ "mediaType": "application/vnd.cyclonedx+json", "digest": sbom_blob.to_string(), "size": sbom.len() }],
        "subject": { "mediaType": OCI_MANIFEST, "digest": v1.to_string(), "size": 1 },
    })).unwrap();
    let sbom_digest = put_manifest(&app, repo, &Digest::sha256_of(&sbom_manifest).to_string(), sbom_manifest).await;
    let r = send(&app, Method::GET, &api("manifests/v1"), &[], vec![]).await;
    assert_eq!(r.json()["artifact"]["kind"], "image");
    assert_eq!(r.json()["attached"][0]["kind"], "sbom");
    assert_eq!(r.json()["attached"][0]["label"], "SBOM (CycloneDX)");
    let r = send(&app, Method::GET, &api(&format!("manifests/{sbom_digest}/sbom")), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["sbom"]["packages"][0]["name"], "openssl");
    assert_eq!(r.json()["sbom"]["packages"][0]["version"], "3.1.4");

    // A cosign key-based signature stored under the `sha256-<hex>.sig` tag convention.
    let sk = p256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap();
    let payload = serde_json::to_vec(&json!({ "critical": { "identity": { "docker-reference": format!("registry.test/{repo}") }, "image": { "docker-manifest-digest": v1.to_string() }, "type": "cosign container image signature" }, "optional": null })).unwrap();
    let sig: p256::ecdsa::Signature = sk.sign(&payload);
    let payload_blob = push_blob(&app, repo, &payload, None).await;
    let sig_manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": empty.to_string(), "size": 2 },
        "layers": [{ "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": payload_blob.to_string(), "size": payload.len(),
            "annotations": { "dev.cosignproject.cosign/signature": base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()) } }],
    })).unwrap();
    let sig_tag = format!("sha256-{}.sig", v1.to_string().trim_start_matches("sha256:"));
    put_manifest(&app, repo, &sig_tag, sig_manifest).await;
    let r = send(&app, Method::GET, &api("tags"), &[], vec![]).await;
    let sig_row = r.json().as_array().unwrap().iter().find(|t| t["tag"] == sig_tag.as_str()).cloned().unwrap();
    assert_eq!((sig_row["artifact"]["kind"].as_str(), sig_row["attached_to"].as_str()), (Some("signature"), Some(v1.to_string().as_str())));
    let r = send(&app, Method::GET, &api("manifests/v1"), &[], vec![]).await;
    let kinds: Vec<String> = r.json()["attached"].as_array().unwrap().iter().map(|a| a["kind"].as_str().unwrap().to_string()).collect();
    assert_eq!(kinds, vec!["sbom", "signature"]);

    let pem = sk.verifying_key().to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap();
    let verify = |pem: String, target: &str| {
        let (app, path) = (app.clone(), api(&format!("manifests/{target}/verify")));
        async move { send(&app, Method::POST, &path, &[("content-type", "application/json")], serde_json::to_vec(&json!({ "public_key": pem })).unwrap()).await }
    };
    let r = verify(pem.clone(), "v1").await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["verified"], true);
    assert_eq!(r.json()["signatures"][0]["status"], "verified");
    let other = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap().verifying_key().to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap();
    let r = verify(other, "v1").await;
    assert_eq!((r.json()["verified"].as_bool(), r.json()["signatures"][0]["status"].as_str()), (Some(false), Some("invalid")));
    let r = verify(pem, "v2").await;
    assert_eq!(r.json()["signatures"], json!([]), "v2 is unsigned");
    assert_eq!(verify("not a key".into(), "v1").await.status, StatusCode::BAD_REQUEST);

    // A Helm chart is recognised from its config media type.
    let chart_cfg = br#"{"name":"web","version":"1.2.0","appVersion":"2.0","description":"A web app"}"#;
    let cc = push_blob(&app, "acme/charts/web", chart_cfg, None).await;
    let tgz = push_blob(&app, "acme/charts/web", b"chart-tgz", None).await;
    let chart = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": cc.to_string(), "size": chart_cfg.len() },
        "layers": [{ "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": tgz.to_string(), "size": 9 }],
    })).unwrap();
    put_manifest(&app, "acme/charts/web", "1.2.0", chart).await;
    let r = send(&app, Method::GET, "/api/v1/repositories/acme/charts/web/manifests/1.2.0", &[], vec![]).await;
    assert_eq!(r.json()["artifact"]["kind"], "helm_chart");
    assert_eq!(r.json()["config_json"]["appVersion"], "2.0");
}

#[tokio::test]
async fn renaming_namespaces_moves_everything() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "name": "founder", "rules": [], "global": ["orgs:create"] })).unwrap();
    send(&app, Method::POST, "/api/v1/roles", &[("cookie", &root), jh], body).await;
    for (u, roles) in [("ann", vec!["founder"]), ("ben", vec![])] {
        let body = serde_json::to_vec(&json!({ "username": u, "password": "password123", "roles": roles })).unwrap();
        assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    }
    let ann = cookie_of(&web_login(&app, "ann", "password123", None).await);
    let ben = cookie_of(&web_login(&app, "ben", "password123", None).await);
    assert_eq!(send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "name": "acme" })).unwrap()).await.status, StatusCode::CREATED);

    // An org robot pushes acme/api; ben's team gets write on it; ann stars it and documents it.
    let r = send(&app, Method::POST, "/api/v1/orgs/acme/robots", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let token = r.json()["token"].as_str().unwrap().to_string();
    let grant = serde_json::to_vec(&json!({ "kind": "user", "name": "acme+ci", "level": "write" })).unwrap();
    assert_eq!(send(&app, Method::PUT, "/api/v1/repository-permissions/acme/api", &[("cookie", &ann), jh], grant).await.status, StatusCode::OK);
    let robot = basic("acme+ci", &token);
    let cfg = b"{}";
    let cd = push_blob(&app, "acme/api", cfg, Some(&robot)).await;
    let r = send(&app, Method::PUT, "/v2/acme/api/manifests/v1", &[("authorization", &robot), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg.len(), &[])).await;
    assert_eq!(r.status, StatusCode::CREATED);
    send(&app, Method::POST, "/api/v1/orgs/acme/teams", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "name": "dev" })).unwrap()).await;
    send(&app, Method::POST, "/api/v1/orgs/acme/teams/dev/members", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "username": "ben" })).unwrap()).await;
    let grant = serde_json::to_vec(&json!({ "kind": "team", "name": "dev", "level": "write" })).unwrap();
    send(&app, Method::PUT, "/api/v1/repository-permissions/acme/api", &[("cookie", &ann), jh], grant).await;
    send(&app, Method::PUT, "/api/v1/stars/acme/api", &[("cookie", &ann)], vec![]).await;
    send(&app, Method::PATCH, "/api/v1/repository-meta/acme/api", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "description": "The API" })).unwrap()).await;

    // Validation: taken names, existing namespaces and uppercase are refused; members cannot rename.
    let rename = |cookie: &str, to: &str| {
        let (app, c, b) = (app.clone(), cookie.to_string(), serde_json::to_vec(&json!({ "name": to })).unwrap());
        async move { send(&app, Method::PATCH, "/api/v1/orgs/acme", &[("cookie", &c), ("content-type", "application/json")], b).await }
    };
    assert_eq!(rename(&ann, "ben").await.status, StatusCode::CONFLICT);
    assert_eq!(rename(&ann, "Acme-Corp").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(rename(&ben, "acme-corp").await.status, StatusCode::FORBIDDEN);

    let r = rename(&ann, "acme-corp").await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["name"], "acme-corp");
    // Images moved; the old name is gone.
    let robot = basic("acme-corp+ci", &token);
    let r = send(&app, Method::GET, "/v2/acme-corp/api/manifests/v1", &[("authorization", &robot)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "robot renamed with its namespace; credential still valid");
    assert_eq!(send(&app, Method::GET, "/v2/acme/api/manifests/v1", &[("cookie", &ann)], vec![]).await.status, StatusCode::FORBIDDEN, "ann no longer administers `acme`");
    assert_eq!(send(&app, Method::GET, "/v2/acme/api/manifests/v1", &[("cookie", &root)], vec![]).await.status, StatusCode::NOT_FOUND, "nothing left under the old name");
    // Grants, stars and metadata followed.
    assert_eq!(send(&app, Method::POST, "/v2/acme-corp/api/blobs/uploads/", &[("cookie", &ben)], vec![]).await.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::GET, "/api/v1/repository-meta/acme-corp/api", &[("cookie", &ann)], vec![]).await;
    assert_eq!((r.json()["description"].as_str(), r.json()["stars"].as_i64(), r.json()["is_starred"].as_bool()), (Some("The API"), Some(1), Some(true)));
    let r = send(&app, Method::GET, "/api/v1/repositories", &[("cookie", &ann)], vec![]).await;
    let names: Vec<String> = r.json().as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, vec!["acme-corp/api"]);
    // A new namespace can now reuse the old name.
    assert_eq!(send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &ann), jh], serde_json::to_vec(&json!({ "name": "acme" })).unwrap()).await.status, StatusCode::CREATED);

    // Renaming yourself moves your personal namespace too.
    let cd = push_blob(&app, "ben/tool", cfg, Some(&basic("ben", "password123"))).await;
    send(&app, Method::PUT, "/v2/ben/tool/manifests/v1", &[("authorization", &basic("ben", "password123")), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg.len(), &[])).await;
    let r = send(&app, Method::POST, "/api/v1/auth/username", &[("cookie", &ben), jh], serde_json::to_vec(&json!({ "username": "acme" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = send(&app, Method::POST, "/api/v1/auth/username", &[("cookie", &ben), jh], serde_json::to_vec(&json!({ "username": "benjamin" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(send(&app, Method::GET, "/api/v1/me", &[("cookie", &ben)], vec![]).await.json()["username"], "benjamin");
    let r = send(&app, Method::GET, "/v2/benjamin/tool/manifests/v1", &[("authorization", &basic("benjamin", "password123"))], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn full_text_search() {
    let mut cfg = accounts_config();
    cfg.features.is_delete = true;
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "username": "dan", "password": "password123" })).unwrap();
    send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await;
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);
    let auth = basic("root", "rootpass123");
    let push = |repo: &'static str, tag: &'static str| {
        let (app, auth) = (app.clone(), auth.clone());
        async move {
            let cfg = format!("{{\"repo\":\"{repo}\"}}").into_bytes();
            let cd = push_blob(&app, repo, &cfg, Some(&auth)).await;
            let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{tag}"), &[("authorization", &auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg.len(), &[])).await;
            assert_eq!(r.status, StatusCode::CREATED);
        }
    };
    push("root/billing-api", "v1").await;
    push("root/web", "v1").await;
    let search = |cookie: &str, q: &str| {
        let (app, c, path) = (app.clone(), cookie.to_string(), format!("/api/v1/search?q={}", q.replace(' ', "%20")));
        async move { send(&app, Method::GET, &path, &[("cookie", &c)], vec![]).await.json().as_array().unwrap().iter().map(|h| h["name"].as_str().unwrap().to_string()).collect::<Vec<_>>() }
    };
    // Indexed on push; names are split into words and matched by prefix.
    assert_eq!(search(&root, "billing").await, vec!["root/billing-api"]);
    assert_eq!(search(&root, "bill").await, vec!["root/billing-api"]);
    assert!(search(&dan, "billing").await.is_empty(), "private repositories stay hidden");
    // Metadata edits are searchable at once; explore ranks public matches.
    let meta = serde_json::to_vec(&json!({ "description": "Invoices and payment webhooks", "visibility": "public", "topics": ["payments"] })).unwrap();
    send(&app, Method::PATCH, "/api/v1/repository-meta/root/web", &[("cookie", &root), jh], meta).await;
    assert_eq!(search(&dan, "invoices").await, vec!["root/web"]);
    assert_eq!(search(&dan, "payments").await, vec!["root/web"]);
    let r = send(&app, Method::GET, "/api/v1/explore?q=payment", &[], vec![]).await;
    assert_eq!(r.json()["repositories"][0]["name"], "root/web");
    let r = send(&app, Method::GET, "/api/v1/explore?q=billing", &[], vec![]).await;
    assert_eq!(r.json()["repositories"], json!([]), "explore only searches public repositories");
    // Found by what is inside: platforms (with aliases) from the pushed image config.
    let cfg = br#"{"os":"linux","architecture":"arm64","config":{"Labels":{"org.opencontainers.image.vendor":"Initech"}}}"#;
    let cd = push_blob(&app, "root/tools", cfg, Some(&auth)).await;
    let r = send(&app, Method::PUT, "/v2/root/tools/manifests/v1", &[("authorization", &auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg.len(), &[])).await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(search(&root, "arm64 tools").await, vec!["root/tools"]);
    assert_eq!(search(&root, "aarch64").await, vec!["root/tools"]);
    assert_eq!(search(&root, "arch:arm64").await, vec!["root/tools"]);
    assert_eq!(search(&root, "initech").await, vec!["root/tools"], "image labels");
    assert!(search(&root, "amd64 tools").await.is_empty());
    // Deleting the repository removes it from search.
    delete_repository_confirmed(&app, &root, "root/billing-api").await;
    assert!(search(&root, "billing").await.is_empty());
}

#[tokio::test]
async fn storage_quotas_retention_and_metrics() {
    let mut cfg = accounts_config();
    cfg.features.is_delete = true;
    cfg.metrics.token = Some("scrape-secret".into());
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    // An access token: password checks (Argon2) are slow in debug builds.
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("root", r.json()["token"].as_str().unwrap());
    let body = serde_json::to_vec(&json!({ "username": "dan", "password": "password123" })).unwrap();
    send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await;
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);

    // root/app and root/other share a 1000-byte base layer.
    let base = vec![7u8; 1000];
    let push = |repo: &'static str, tag: String, extra: Vec<u8>| {
        let (app, auth, base) = (app.clone(), auth.clone(), base.clone());
        async move {
            let cfg = format!("{{\"tag\":\"{tag}\"}}").into_bytes();
            // Blob uploads are quota-checked too: a refused one is the push's answer.
            let cd = match push_blob_if_missing(&app, repo, &cfg, Some(&auth)).await { Ok(d) => d, Err(r) => return r };
            let bd = match push_blob_if_missing(&app, repo, &base, Some(&auth)).await { Ok(d) => d, Err(r) => return r };
            let ed = match push_blob_if_missing(&app, repo, &extra, Some(&auth)).await { Ok(d) => d, Err(r) => return r };
            let m = image_manifest(&cd, cfg.len(), &[(bd, base.len()), (ed, extra.len())]);
            send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{tag}"), &[("authorization", &auth), ("content-type", OCI_MANIFEST)], m).await
        }
    };
    for (i, tag) in ["v1", "v2", "v3", "latest"].iter().enumerate() {
        assert_eq!(push("root/app", tag.to_string(), vec![i as u8; 100]).await.status, StatusCode::CREATED);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(push("root/other", "v1".into(), vec![9u8; 50]).await.status, StatusCode::CREATED);

    // Storage report: the base layer is stored once but counted by both repositories.
    assert_eq!(send(&app, Method::GET, "/api/v1/storage", &[("cookie", &dan)], vec![]).await.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::GET, "/api/v1/storage?refresh=1", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let rep = r.json();
    assert!(rep["dedup_savings"].as_u64().unwrap() >= 1000, "{rep}");
    assert_eq!(rep["shared_layers"][0]["size"], 1000);
    assert_eq!(rep["shared_layers"][0]["repositories"].as_array().unwrap().len(), 2);
    let app_usage = rep["repositories"].as_array().unwrap().iter().find(|x| x["name"] == "root/app").cloned().unwrap();
    assert_eq!(app_usage["tags"], 4);
    assert!(app_usage["bytes"].as_u64().unwrap() > app_usage["unique_bytes"].as_u64().unwrap(), "shared base excluded from unique bytes");
    let r = send(&app, Method::GET, "/api/v1/namespaces/root/storage", &[("cookie", &root)], vec![]).await;
    let used = r.json()["bytes"].as_u64().unwrap();
    assert!(used > 1400);
    assert_eq!(send(&app, Method::GET, "/api/v1/namespaces/root/storage", &[("cookie", &dan)], vec![]).await.status, StatusCode::FORBIDDEN);

    // Quota: only instance admins set it; a push that would exceed it is refused.
    let quota = |cookie: &str, max: serde_json::Value| {
        let (app, c) = (app.clone(), cookie.to_string());
        async move { send(&app, Method::PUT, "/api/v1/namespaces/root/quota", &[("cookie", &c), ("content-type", "application/json")], serde_json::to_vec(&json!({ "max_bytes": max })).unwrap()).await.status }
    };
    assert_eq!(quota(&dan, json!(used)).await, StatusCode::FORBIDDEN);
    assert_eq!(quota(&root, json!(used + 10)).await, StatusCode::OK);
    let r = push("root/app", "big".into(), vec![1u8; 500]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json()["errors"][0]["message"].as_str().unwrap().contains("quota exceeded"));
    assert_eq!(push("root/app", "v1".into(), vec![0u8; 100]).await.status, StatusCode::CREATED, "re-pushing existing content adds nothing");
    assert_eq!(quota(&root, json!(null)).await, StatusCode::OK);
    assert_eq!(push("root/app", "big".into(), vec![1u8; 500]).await.status, StatusCode::CREATED);
    send(&app, Method::DELETE, "/v2/root/app/manifests/big", &[("authorization", &auth)], vec![]).await;

    // A cosign signature on v2 follows it when retention deletes v2.
    let v2 = send(&app, Method::HEAD, "/v2/root/app/manifests/v2", &[("authorization", &auth)], vec![]).await.header("docker-content-digest");
    let sig_tag = format!("{}.sig", v2.replace(':', "-"));
    assert_eq!(push("root/app", sig_tag.clone(), vec![42u8; 10]).await.status, StatusCode::CREATED);

    // Retention: keep the newest 2 (latest is protected and does not count), preview, then run.
    let policy = serde_json::to_vec(&json!({ "keep_last": 2, "protect": ["latest"] })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/namespaces/root/retention", &[("cookie", &dan), jh], policy.clone()).await.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::POST, "/api/v1/namespaces/root/retention", &[("cookie", &root), jh], policy).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let id = r.json()["id"].as_i64().unwrap();
    let r = send(&app, Method::POST, &format!("/api/v1/namespaces/root/retention/{id}/preview"), &[("cookie", &root)], vec![]).await;
    let doomed: Vec<String> = r.json()["deletions"].as_array().unwrap().iter().map(|d| format!("{}:{}", d["repository"].as_str().unwrap(), d["tag"].as_str().unwrap())).collect();
    // Newest first: v1 (re-pushed above), latest (protected, not counted), v3, v2.
    assert_eq!(doomed, vec!["root/app:v2".to_string(), format!("root/app:{sig_tag}")], "v1 and v3 kept, latest protected, root/other has one tag");
    let tags = |app: Router, auth: String| async move { send(&app, Method::GET, "/v2/root/app/tags/list", &[("authorization", &auth)], vec![]).await.json()["tags"].clone() };
    assert_eq!(tags(app.clone(), auth.clone()).await.as_array().unwrap().len(), 5, "preview deletes nothing");
    let r = send(&app, Method::POST, &format!("/api/v1/namespaces/root/retention/{id}/run"), &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(tags(app.clone(), auth.clone()).await, json!(["latest", "v1", "v3"]));
    let r = send(&app, Method::GET, "/api/v1/namespaces/root/retention", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()[0]["last_deleted"], 2);
    // Age-based rules never touch fresh tags.
    let r = send(&app, Method::PUT, &format!("/api/v1/namespaces/root/retention/{id}"), &[("cookie", &root), jh], serde_json::to_vec(&json!({ "max_age_days": 30 })).unwrap()).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::POST, &format!("/api/v1/namespaces/root/retention/{id}/preview"), &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()["deletions"], json!([]));
    assert_eq!(send(&app, Method::POST, "/api/v1/namespaces/root/retention", &[("cookie", &root), jh], b"{}".to_vec()).await.status, StatusCode::BAD_REQUEST);

    // Metrics: token-protected Prometheus text with request and storage figures.
    assert_eq!(send(&app, Method::GET, "/metrics", &[], vec![]).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, Method::GET, "/metrics", &[("authorization", "Bearer scrape-secreT")], vec![]).await.status, StatusCode::UNAUTHORIZED);
    let r = send(&app, Method::GET, "/metrics", &[("authorization", "Bearer scrape-secret")], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let text = String::from_utf8(r.body).unwrap();
    assert!(text.contains("kontainer_pushes_total"), "{text}");
    assert!(text.contains(r#"kontainer_http_requests_total{method="PUT",route="manifest",status="2xx"}"#));
    assert!(text.contains("kontainer_storage_physical_bytes"));
    assert!(text.contains(r#"kontainer_namespace_bytes{namespace="root"}"#));
}

/// Wait for a background job to finish and return it.
async fn wait_job(app: &Router, cookie: &str, id: &str) -> Value {
    for _ in 0..200 {
        let r = send(app, Method::GET, "/api/v1/jobs", &[("cookie", cookie)], vec![]).await;
        if let Some(j) = r.json().as_array().unwrap().iter().find(|j| j["id"] == id) {
            if j["status"] != "running" {
                return j.clone();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("job {id} did not finish");
}

#[tokio::test]
async fn pull_through_cache_mirrors_and_imports() {
    // An upstream registry on a real port: another kontainer with anonymous access.
    let upstream = app(base_config()).await;
    let cfg = br#"{"architecture":"amd64","os":"linux"}"#;
    let layer = b"upstream layer bytes".to_vec();
    let cd = push_blob(&upstream, "team/app", cfg, None).await;
    let ld = push_blob(&upstream, "team/app", &layer, None).await;
    let r = send(&upstream, Method::PUT, "/v2/team/app/manifests/v1", &[("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg.len(), &[(ld.clone(), layer.len())])).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/registries", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "up", "url": format!("http://{addr}") })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let reg = r.json()["id"].as_i64().unwrap();
    let r = send(&app, Method::POST, &format!("/api/v1/registries/{reg}/test"), &[("cookie", &root), jh], serde_json::to_vec(&json!({ "repository": "team/app" })).unwrap()).await;
    assert_eq!(r.json()["ok"], true, "{}", r.json());
    assert_eq!(r.json()["tags"], json!(["v1"]));

    // Pull-through cache: `cache/team/app` is fetched from upstream `team/app` on demand.
    let r = send(&app, Method::POST, "/api/v1/proxy-caches", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "namespace": "cache", "registry_id": reg })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "cache" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "the cache namespace is taken");
    assert_eq!(send(&app, Method::GET, "/v2/cache/team/app/manifests/v1", &[], vec![]).await.status, StatusCode::UNAUTHORIZED, "not public");
    let r = send(&app, Method::GET, "/v2/cache/team/app/manifests/v1", &[("cookie", &root), ("accept", OCI_MANIFEST)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::GET, &format!("/v2/cache/team/app/blobs/{ld}"), &[("cookie", &root)], vec![]).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::OK, layer.clone()), "layer fetched from upstream and served");
    assert_eq!(send(&app, Method::GET, "/v2/cache/team/app/manifests/v9", &[("cookie", &root)], vec![]).await.status, StatusCode::NOT_FOUND);
    // Any signed-in user pulls from a cache; only instance roles may write to it.
    let body = serde_json::to_vec(&json!({ "username": "dan", "password": "password123" })).unwrap();
    send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await;
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);
    assert_eq!(send(&app, Method::GET, "/v2/cache/team/app/manifests/v1", &[("cookie", &dan)], vec![]).await.status, StatusCode::OK);
    assert_eq!(send(&app, Method::POST, "/v2/cache/team/app/blobs/uploads/", &[("cookie", &dan)], vec![]).await.status, StatusCode::FORBIDDEN);

    // Mirror: copy every upstream tag into root/mirror; a second sync finds nothing to do.
    let body = serde_json::to_vec(&json!({ "registry_id": reg, "source": "team/app", "target": "root/mirror" })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/mirrors", &[("cookie", &root), jh], body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let mirror = r.json()["id"].as_i64().unwrap();
    let r = send(&app, Method::POST, &format!("/api/v1/mirrors/{mirror}/sync"), &[("cookie", &root)], vec![]).await;
    let job = wait_job(&app, &root, r.json()["job"].as_str().unwrap()).await;
    assert_eq!(job["status"], "done", "{job}");
    assert!(job["message"].as_str().unwrap().starts_with("1 updated"), "{job}");
    let r = send(&app, Method::GET, "/v2/root/mirror/tags/list", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()["tags"], json!(["v1"]));
    let r = send(&app, Method::POST, &format!("/api/v1/mirrors/{mirror}/sync"), &[("cookie", &root)], vec![]).await;
    let job = wait_job(&app, &root, r.json()["job"].as_str().unwrap()).await;
    assert!(job["message"].as_str().unwrap().starts_with("0 updated, 1 up to date"), "{job}");
    let r = send(&app, Method::GET, "/api/v1/mirrors", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()[0]["last_status"], "ok");
    // The target is in mirror state: the sync writes, nobody else does.
    let meta = send(&app, Method::GET, "/api/v1/repository-meta/root/mirror", &[("cookie", &root)], vec![]).await.json();
    assert_eq!(meta["state"]["state"], "mirror");
    assert_eq!(send(&app, Method::POST, "/v2/root/mirror/blobs/uploads/", &[("cookie", &root)], vec![]).await.status, StatusCode::METHOD_NOT_ALLOWED);

    // One-off import under a new tag; failures surface on the job.
    let body = serde_json::to_vec(&json!({ "registry_id": reg, "source": "team/app", "reference": "v1", "target": "root/imported", "tag": "stable" })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/import", &[("cookie", &root), jh], body).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let job = wait_job(&app, &root, r.json()["job"].as_str().unwrap()).await;
    assert_eq!(job["status"], "done", "{job}");
    let r = send(&app, Method::GET, &format!("/v2/root/imported/blobs/{ld}"), &[("cookie", &root)], vec![]).await;
    assert_eq!(r.body, layer);

    // Each repository says where it came from.
    let origin = |name: &str| {
        let (app, root) = (app.clone(), root.clone());
        let name = name.to_string();
        async move { send(&app, Method::GET, &format!("/api/v1/repository-meta/{name}"), &[("cookie", &root)], vec![]).await.json()["origin"].clone() }
    };
    let o = origin("cache/team/app").await;
    assert_eq!((o["kind"].as_str(), o["source"].as_str(), o["registry"].as_str()), (Some("cache"), Some("team/app"), Some("up")), "{o}");
    let o = origin("root/mirror").await;
    assert_eq!((o["kind"].as_str(), o["status"].as_str(), o["mirror_id"].as_i64()), (Some("mirror"), Some("ok"), Some(mirror)), "{o}");
    let o = origin("root/imported").await;
    assert_eq!((o["kind"].as_str(), o["via"].as_str(), o["source"].as_str(), o["actor"].as_str()), (Some("import"), Some("registry"), Some("team/app:v1"), Some("root")), "{o}");
    let r = send(&app, Method::GET, "/api/v1/repositories", &[("cookie", &root)], vec![]).await;
    let list = r.json();
    let kind = |n: &str| list.as_array().unwrap().iter().find(|x| x["name"] == n).map(|x| x["origin"]["kind"].clone());
    assert_eq!(kind("root/mirror"), Some(json!("mirror")));

    let body = serde_json::to_vec(&json!({ "registry_id": reg, "source": "team/missing", "reference": "v1", "target": "root/nothing" })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/import", &[("cookie", &root), jh], body).await;
    let job = wait_job(&app, &root, r.json()["job"].as_str().unwrap()).await;
    assert_eq!(job["status"], "failed");
    assert!(job["message"].as_str().unwrap().contains("not found"), "{job}");
}

#[tokio::test]
async fn archive_export_import_and_health() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("root", r.json()["token"].as_str().unwrap());
    let cfg = br#"{"architecture":"arm64","os":"linux"}"#;
    let layer = gzip_tar_layer();
    let cd = push_blob(&app, "root/src", cfg, Some(&auth)).await;
    let ld = push_blob(&app, "root/src", &layer, Some(&auth)).await;
    let r = send(&app, Method::PUT, "/v2/root/src/manifests/v1", &[("authorization", &auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg.len(), &[(ld.clone(), layer.len())])).await;
    assert_eq!(r.status, StatusCode::CREATED);

    // Export: an OCI image layout tar with a Docker manifest.json alongside.
    let r = send(&app, Method::GET, "/api/v1/repositories/root/src/manifests/v1/export", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.header("content-disposition").contains("root_src-v1.tar"));
    let tarball = r.body.clone();
    let mut names = vec![];
    let mut index = Value::Null;
    for e in tar::Archive::new(&tarball[..]).entries().unwrap() {
        let mut e = e.unwrap();
        let path = e.path().unwrap().to_string_lossy().to_string();
        if path == "index.json" {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut e, &mut s).unwrap();
            index = serde_json::from_str(&s).unwrap();
        }
        names.push(path);
    }
    assert!(names.contains(&"oci-layout".to_string()) && names.contains(&"manifest.json".to_string()));
    assert!(names.contains(&format!("blobs/sha256/{}", ld.to_string().trim_start_matches("sha256:"))));
    assert_eq!(index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"], "v1");

    // Import into another repository under a new tag; content round-trips.
    let r = send(&app, Method::POST, "/api/v1/import/archive/root/copy?tag=restored&filename=C:%5Cexports%5Capp.tar", &[("cookie", &root), ("content-type", "application/x-tar")], tarball.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["tags"], json!(["restored"]));
    let r = send(&app, Method::GET, &format!("/v2/root/copy/blobs/{ld}"), &[("authorization", &auth)], vec![]).await;
    assert_eq!(r.body, layer);
    let o = send(&app, Method::GET, "/api/v1/repository-meta/root/copy", &[("cookie", &root)], vec![]).await.json()["origin"].clone();
    assert_eq!((o["kind"].as_str(), o["via"].as_str(), o["source"].as_str()), (Some("import"), Some("archive"), Some("app.tar")), "{o}");
    let r = send(&app, Method::GET, "/v2/root/copy/manifests/restored", &[("authorization", &auth), ("accept", OCI_MANIFEST)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    // A corrupted archive is refused.
    let mut bad = tarball.clone();
    let pos = bad.windows(layer.len().min(16)).position(|w| w == &layer[..layer.len().min(16)]).unwrap();
    bad[pos] ^= 0xff;
    let r = send(&app, Method::POST, "/api/v1/import/archive/root/broken", &[("cookie", &root)], bad).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.json()["message"].as_str().unwrap().contains("corrupt"), "{}", r.json());
    let r = send(&app, Method::POST, "/api/v1/import/archive/root/junk", &[("cookie", &root)], b"not a tar".to_vec()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Health: unauthenticated probes, admin-only report.
    assert_eq!(send(&app, Method::GET, "/livez", &[], vec![]).await.status, StatusCode::OK);
    assert_eq!(send(&app, Method::GET, "/readyz", &[], vec![]).await.status, StatusCode::OK);
    assert_eq!(send(&app, Method::GET, "/api/v1/health", &[], vec![]).await.status, StatusCode::UNAUTHORIZED);
    // Metrics stay closed until a token is configured.
    assert_eq!(send(&app, Method::GET, "/metrics", &[], vec![]).await.status, StatusCode::FORBIDDEN);
    // About (version, build) is for administrators only.
    assert_eq!(send(&app, Method::GET, "/api/v1/about", &[], vec![]).await.status, StatusCode::UNAUTHORIZED);
    let a = send(&app, Method::GET, "/api/v1/about", &[("cookie", &root)], vec![]).await.json();
    assert_eq!((a["name"].as_str(), a["license"].as_str()), (Some("kontainer"), Some("AGPL-3.0-only")));
    assert!(a["license_text"].as_str().unwrap().contains("GNU AFFERO GENERAL PUBLIC LICENSE"));
    assert!(a["runtime"]["storage"].is_string() && a.get("copyright").is_none());
    let r = send(&app, Method::GET, "/api/v1/health", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let checks: Vec<(String, String)> = r.json()["checks"].as_array().unwrap().iter().map(|c| (c["name"].as_str().unwrap().to_string(), c["status"].as_str().unwrap().to_string())).collect();
    assert!(checks.contains(&("Database".into(), "ok".into())), "{checks:?}");
    assert!(checks.contains(&("Storage".into(), "ok".into())), "{checks:?}");
}

#[tokio::test]
async fn tag_history_time_machine_expiry_and_states() {
    let mut cfg = base_config();
    cfg.features.is_delete = true;
    let state = kontainer_server::build_state(cfg).await.unwrap();
    let app = kontainer_server::build_router(state.clone());
    let repo = "acme/app";
    let api = |path: &str| format!("/api/v1/repositories/{repo}/{path}");
    let jh = ("content-type", "application/json");

    // v1, then `latest` moves from v1's image to v2's.
    let image = |n: u8| {
        let app = app.clone();
        async move {
            let cfg = format!(r#"{{"architecture":"amd64","os":"linux","config":{{"Labels":{{"n":"{n}"}}}}}}"#).into_bytes();
            let layer = vec![n; 64];
            let c = push_blob(&app, repo, &cfg, None).await;
            let l = push_blob(&app, repo, &layer, None).await;
            image_manifest(&c, cfg.len(), &[(l, layer.len())])
        }
    };
    let m1 = image(1).await;
    let m2 = image(2).await;
    let d1 = put_manifest(&app, repo, "latest", m1.clone()).await;
    let d2 = put_manifest(&app, repo, "latest", m2).await;
    assert_eq!(send(&app, Method::DELETE, &format!("/v2/{repo}/manifests/latest"), &[], vec![]).await.status, StatusCode::ACCEPTED);

    let h = send(&app, Method::GET, &api("history?tag=latest"), &[], vec![]).await.json();
    let actions: Vec<&str> = h["events"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, vec!["delete", "move", "push"], "{h}");
    assert_eq!(h["events"][0]["previous"], d2.to_string());
    assert_eq!(h["events"][1]["previous"], d1.to_string());
    assert_eq!(h["events"][0]["is_restorable"], true);
    assert!(h["time_machine_secs"].as_i64().unwrap() > 0);

    // GC with delete-untagged keeps both images: the Time Machine can still bring them back.
    let r = send(&app, Method::POST, "/api/v1/gc?dry_run=true&delete_untagged=true&grace_seconds=0", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json()["manifests_removed"].as_array().unwrap().is_empty(), "{}", r.json());

    // Restore `latest` to v1 (what it pointed at before the move).
    let r = send(&app, Method::POST, &api("tags/latest/restore"), &[jh], serde_json::to_vec(&json!({ "digest": d1.to_string() })).unwrap()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::HEAD, &format!("/v2/{repo}/manifests/latest"), &[], vec![]).await;
    assert_eq!(r.header("docker-content-digest"), d1.to_string());
    // Only digests from the tag's own history.
    let r = send(&app, Method::POST, &api("tags/other/restore"), &[jh], serde_json::to_vec(&json!({ "digest": d1.to_string() })).unwrap()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Expiration: set in the UI, shown on the tag list, and applied by the background loop.
    let soon = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let r = send(&app, Method::PUT, &api("tags/latest/expiration"), &[jh], serde_json::to_vec(&json!({ "expires_at": soon })).unwrap()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let tags = send(&app, Method::GET, &api("tags"), &[], vec![]).await.json();
    assert!(tags[0]["expires_at"].is_string(), "{tags}");
    let past = chrono::Utc::now() - chrono::Duration::seconds(1);
    state.auth.db.set_tag_expiration(repo, "latest", Some(past), "test").await.unwrap();
    assert_eq!(kontainer_server::tags::expire_due(&state).await.unwrap(), 1);
    assert_eq!(send(&app, Method::HEAD, &format!("/v2/{repo}/manifests/latest"), &[], vec![]).await.status, StatusCode::NOT_FOUND);
    let h = send(&app, Method::GET, &api("history?tag=latest"), &[], vec![]).await.json();
    assert_eq!(h["events"][0]["action"], "expire");

    // `quay.expires-after` on the image sets the expiration at push.
    let cfg = br#"{"architecture":"amd64","os":"linux","config":{"Labels":{"quay.expires-after":"2d"}}}"#;
    let c = push_blob(&app, repo, cfg, None).await;
    put_manifest(&app, repo, "temp", image_manifest(&c, cfg.len(), &[])).await;
    let tags = send(&app, Method::GET, &api("tags"), &[], vec![]).await.json();
    let temp = tags.as_array().unwrap().iter().find(|t| t["tag"] == "temp").unwrap();
    let at = chrono::DateTime::parse_from_rfc3339(temp["expires_at"].as_str().unwrap()).unwrap();
    assert!((at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_hours() >= 47);

    // Read-only: no pushes, no deletes, until set back to normal.
    let r = send(&app, Method::PUT, &api("state"), &[jh], serde_json::to_vec(&json!({ "state": "read_only", "reason": "release freeze" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/frozen"), &[("content-type", OCI_MANIFEST)], m1.clone()).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(String::from_utf8_lossy(&r.body).contains("release freeze"));
    assert_eq!(send(&app, Method::POST, &format!("/v2/{repo}/blobs/uploads/"), &[], vec![]).await.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(send(&app, Method::GET, &format!("/v2/{repo}/manifests/temp"), &[("accept", OCI_MANIFEST)], vec![]).await.status, StatusCode::OK, "pulls still work");
    let meta = send(&app, Method::GET, &format!("/api/v1/repository-meta/{repo}"), &[], vec![]).await.json();
    assert_eq!(meta["state"]["state"], "read_only");
    send(&app, Method::PUT, &api("state"), &[jh], serde_json::to_vec(&json!({ "state": "normal" })).unwrap()).await;
    put_manifest(&app, repo, "thawed", m1).await;
}

#[tokio::test]
async fn keyless_robot_login_with_oidc() {
    use base64::Engine;
    use p256::pkcs8::EncodePrivateKey;
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);

    // A fake CI issuer: discovery document plus a JWKS with one P-256 key.
    let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let jwk = json!({ "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig", "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let iss = issuer.clone();
    let idp = axum::Router::new()
        .route("/.well-known/openid-configuration", axum::routing::get(move || { let iss = iss.clone(); async move { axum::Json(json!({ "issuer": iss, "jwks_uri": format!("{iss}/jwks") })) } }))
        .route("/jwks", axum::routing::get(move || { let jwk = jwk.clone(); async move { axum::Json(json!({ "keys": [jwk] })) } }));
    tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });
    let enc = jsonwebtoken::EncodingKey::from_ec_pem(sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap().as_bytes()).unwrap();
    let mint = |sub: &str, aud: &str, key: &jsonwebtoken::EncodingKey| {
        let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        h.kid = Some("k1".into());
        let now = chrono::Utc::now().timestamp();
        jsonwebtoken::encode(&h, &json!({ "iss": issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + 300 }), key).unwrap()
    };

    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/robots", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let robot_id = r.json()["id"].as_i64().unwrap();
    let grant = serde_json::to_vec(&json!({ "kind": "user", "name": "root+ci", "level": "write" })).unwrap();
    assert_eq!(send(&app, Method::PUT, "/api/v1/repository-permissions/root/app", &[("cookie", &root), jh], grant).await.status, StatusCode::OK);

    // No rules yet: refused.
    let good = mint("repo:acme/api:ref:refs/heads/main", "kontainer", &enc);
    let r = send(&app, Method::POST, "/v2/root/app/blobs/uploads/", &[("authorization", &basic("root+ci", &good))], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // A bare `*` subject is rejected; a pinned repository and branch is fine.
    let rules = |sub: &str| serde_json::to_vec(&json!({ "rules": [{ "issuer": issuer, "subject": sub, "audience": "kontainer" }] })).unwrap();
    assert_eq!(send(&app, Method::PUT, &format!("/api/v1/robots/{robot_id}/federation"), &[("cookie", &root), jh], rules("*")).await.status, StatusCode::BAD_REQUEST);
    let r = send(&app, Method::PUT, &format!("/api/v1/robots/{robot_id}/federation"), &[("cookie", &root), jh], rules("repo:acme/api:ref:refs/heads/*")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));

    // Direct login with the OIDC token as the password.
    let r = send(&app, Method::POST, "/v2/root/app/blobs/uploads/", &[("authorization", &basic("root+ci", &good))], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&r.body));
    // Exchange for an hour-long robot token.
    let r = send(&app, Method::POST, "/api/v1/auth/federation/token", &[("authorization", &basic("root+ci", &good))], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let tok = r.json()["token"].as_str().unwrap().to_string();
    assert_eq!(r.json()["expires_in"], 3600);
    assert_eq!(send(&app, Method::POST, "/v2/root/app/blobs/uploads/", &[("authorization", &basic("root+ci", &tok))], vec![]).await.status, StatusCode::ACCEPTED);

    // Wrong subject, wrong audience, forged signature, or a user (not a robot): refused.
    for (who, jwt) in [
        ("root+ci", mint("repo:evil/fork:ref:refs/heads/main", "kontainer", &enc)),
        ("root+ci", mint("repo:acme/api:ref:refs/heads/main", "someone-else", &enc)),
        ("root+ci", mint("repo:acme/api:ref:refs/heads/main", "kontainer", &jsonwebtoken::EncodingKey::from_ec_pem(p256::ecdsa::SigningKey::from_slice(&[4u8; 32]).unwrap().to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap().as_bytes()).unwrap())),
        ("root", good.clone()),
    ] {
        let r = send(&app, Method::POST, "/v2/root/app/blobs/uploads/", &[("authorization", &basic(who, &jwt))], vec![]).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{who}: {}", String::from_utf8_lossy(&r.body));
    }
    // A federated login cannot change the robot's own rules.
    let r = send(&app, Method::GET, &format!("/api/v1/robots/{robot_id}/federation"), &[("authorization", &basic("root+ci", &good))], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn organization_sso_and_team_sync() {
    use base64::Engine;
    use p256::pkcs8::EncodePrivateKey;
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);

    // A fake IdP: discovery, JWKS, and a token endpoint handing out whatever ID token the test
    // prepared (it needs the nonce from the authorize redirect).
    let sk = p256::ecdsa::SigningKey::from_slice(&[11u8; 32]).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let jwk = json!({ "kty": "EC", "crv": "P-256", "kid": "k", "alg": "ES256", "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let next_token = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let (iss, tok) = (issuer.clone(), next_token.clone());
    let idp = axum::Router::new()
        .route("/.well-known/openid-configuration", axum::routing::get(move || { let i = iss.clone(); async move { axum::Json(json!({ "issuer": i, "authorization_endpoint": format!("{i}/authorize"), "token_endpoint": format!("{i}/token"), "jwks_uri": format!("{i}/jwks") })) } }))
        .route("/jwks", axum::routing::get(move || { let jwk = jwk.clone(); async move { axum::Json(json!({ "keys": [jwk] })) } }))
        // Like a real provider: client authentication is the Basic header, and it must carry the
        // real secret (a redacted placeholder is exactly what a Display-based bug would send).
        .route("/token", axum::routing::post(move |h: axum::http::HeaderMap| { let t = tok.lock().unwrap().clone(); async move {
            let want = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("kontainer:s3cret"));
            if h.get("authorization").and_then(|v| v.to_str().ok()) != Some(want.as_str()) {
                return axum::response::IntoResponse::into_response((StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "invalid_client" }))));
            }
            axum::response::IntoResponse::into_response(axum::Json(json!({ "id_token": t, "token_type": "Bearer" })))
        } }));
    tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });
    let enc = jsonwebtoken::EncodingKey::from_ec_pem(sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap().as_bytes()).unwrap();

    let mut cfg = accounts_config();
    // The fake IdP is on loopback, which an org's issuer may only be on a loopback-bound server.
    cfg.server.bind = "127.0.0.1:0".into();
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "acme" })).unwrap()).await;
    send(&app, Method::POST, "/api/v1/orgs/acme/teams", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "devs" })).unwrap()).await;

    // Configure the org's provider, then sync `devs` from its `engineering` group.
    let sso = json!({ "issuer": issuer, "client_id": "kontainer", "client_secret": "s3cret", "display_name": "Acme SSO", "groups_claim": "groups" });
    let r = send(&app, Method::PUT, "/api/v1/orgs/acme/sso", &[("cookie", &root), jh], serde_json::to_vec(&sso).unwrap()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json()["provider"].get("client_secret").is_none(), "secret never returned");
    let r = send(&app, Method::PUT, "/api/v1/orgs/acme/teams/devs/sync", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "source": "org-oidc", "group": "engineering" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(send(&app, Method::PUT, "/api/v1/orgs/acme/teams/devs/sync", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "source": "ldap", "group": "x" })).unwrap()).await.status, StatusCode::BAD_REQUEST, "no LDAP configured");

    // One sign-in through the org provider: `link` is the session of a user linking the identity
    // (started with the signed-in POST); `query` is added to the GET login URL. The callback
    // comes from the same browser (its login cookie) plus `callback_session`, if any.
    let attempt = |sub: &'static str, username: &'static str, email: &'static str, groups: Vec<&'static str>, link: Option<String>, query: &'static str, callback_session: Option<String>| {
        let (app, enc, issuer, next_token) = (app.clone(), enc.clone(), issuer.clone(), next_token.clone());
        async move {
            let (authorize, login_cookie) = match &link {
                Some(session) => {
                    let body = serde_json::to_vec(&json!({ "redirect": "/settings/security" })).unwrap();
                    let r = send(&app, Method::POST, "/api/v1/auth/oidc/orgs/acme/link", &[("cookie", session.as_str()), ("content-type", "application/json")], body).await;
                    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
                    // The login cookie and the link cookie that stands in for the session.
                    let link_cookie = set_cookie(&r, "kontainer_oidc_link");
                    assert!(link_cookie.contains("SameSite=Lax") && link_cookie.contains("Path=/auth/oidc") && link_cookie.contains("HttpOnly") && link_cookie.contains("Max-Age=900"), "{link_cookie}");
                    (r.json()["url"].as_str().unwrap().to_string(), cookies_of(&r))
                }
                None => {
                    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/login{query}"), &[], vec![]).await;
                    (r.header("location"), cookie_of(&r))
                }
            };
            assert!(login_cookie.starts_with("kontainer_oidc="), "{login_cookie}");
            let loc = url::Url::parse(&authorize).unwrap();
            assert!(loc.as_str().starts_with(&format!("{issuer}/authorize")), "{loc}");
            let q: std::collections::HashMap<String, String> = loc.query_pairs().into_owned().collect();
            assert_eq!(q["redirect_uri"], "http://registry.test/auth/oidc/orgs/acme/callback");
            let now = chrono::Utc::now().timestamp();
            let claims = json!({ "iss": issuer, "aud": "kontainer", "sub": sub, "preferred_username": username, "email": email, "email_verified": true, "nonce": q["nonce"], "groups": groups, "iat": now, "exp": now + 300 });
            let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            h.kid = Some("k".into());
            *next_token.lock().unwrap() = jsonwebtoken::encode(&h, &claims, &enc).unwrap();
            let cookies = match &callback_session { Some(c) => format!("{login_cookie}; {c}"), None => login_cookie };
            (send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={}", q["state"]), &[("cookie", cookies.as_str())], vec![]).await, q["state"].clone())
        }
    };
    let ok = |r: &Resp| {
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", String::from_utf8_lossy(&r.body));
        assert!(!r.header("location").contains("error"), "{}", r.header("location"));
        cookie_of(r)
    };
    let sign_in = |sub: &'static str, username: &'static str, email: &'static str, groups: Vec<&'static str>| {
        async move { ok(&attempt(sub, username, email, groups, None, "", None).await.0) }
    };
    let link = |sub: &'static str, session: String| {
        async move {
            // The provider's redirect back is cross-site: the Strict session cookie is not sent.
            let (r, _) = attempt(sub, "whatever", "x@example.com", vec!["engineering"], Some(session), "", None).await;
            assert_eq!(r.status, StatusCode::SEE_OTHER);
            assert_eq!(r.header("location"), "/settings/security", "linking returns to the settings page");
            assert!(set_cookie(&r, "kontainer_session").is_empty(), "linking issues no new session");
            assert!(set_cookie(&r, "kontainer_oidc_link").contains("Max-Age=0"), "the link cookie is cleared");
        }
    };

    // The provider claims to be root (same username and email): it gets a new account instead.
    let c = sign_in("u-1", "root", "root@example.com", vec!["engineering"]).await;
    let me = send(&app, Method::GET, "/api/v1/me", &[("cookie", &c)], vec![]).await.json();
    assert_ne!(me["username"], "root", "an org provider can never take over an existing account");
    let username = me["username"].as_str().unwrap().to_string();
    let org = send(&app, Method::GET, "/api/v1/orgs/acme", &[("cookie", &root)], vec![]).await.json();
    let devs = org["teams"].as_array().unwrap().iter().find(|t| t["name"] == "devs").unwrap().clone();
    assert_eq!(devs["members"][0]["username"], username.as_str(), "joined through the group");
    assert_eq!(devs["sync"]["group_name"], "engineering");
    // Synced teams are not edited by hand.
    let r = send(&app, Method::POST, "/api/v1/orgs/acme/teams/devs/members", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "username": "root" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Same identity, group removed in the IdP: next sign-in drops the membership.
    sign_in("u-1", "root", "root@example.com", vec!["sales"]).await;
    let org = send(&app, Method::GET, "/api/v1/orgs/acme", &[("cookie", &root)], vec![]).await.json();
    let devs = org["teams"].as_array().unwrap().iter().find(|t| t["name"] == "devs").unwrap().clone();
    assert!(devs["members"].as_array().unwrap().is_empty(), "{devs}");

    // A user links a different identity explicitly while signed in; signing in with it is them.
    let body = serde_json::to_vec(&json!({ "username": "dana", "password": "danapass123" })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    let dana = cookie_of(&web_login(&app, "dana", "danapass123", None).await);
    link("u-dana", dana.clone()).await;
    let c = sign_in("u-dana", "whatever", "x@example.com", vec!["engineering"]).await;
    assert_eq!(send(&app, Method::GET, "/api/v1/me", &[("cookie", &c)], vec![]).await.json()["username"], "dana");

    // Root (an instance admin) may link, but an org provider never signs it in.
    link("u-root", root.clone()).await;
    let (r, _) = attempt("u-root", "whatever", "x@example.com", vec![], None, "", None).await;
    assert!(r.header("location").starts_with("/login?error="), "{}", r.header("location"));
    assert!(!r.header("set-cookie").contains("kontainer_session=") || r.header("set-cookie").contains("kontainer_session=;"));
}

#[tokio::test]
async fn organization_sso_link_and_login_csrf() {
    use base64::Engine;
    use p256::pkcs8::EncodePrivateKey;
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let sk = p256::ecdsa::SigningKey::from_slice(&[12u8; 32]).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let jwk = json!({ "kty": "EC", "crv": "P-256", "kid": "k", "alg": "ES256", "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let next_token = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let (iss, tok) = (issuer.clone(), next_token.clone());
    let idp = axum::Router::new()
        .route("/.well-known/openid-configuration", axum::routing::get(move || { let i = iss.clone(); async move { axum::Json(json!({ "issuer": i, "authorization_endpoint": format!("{i}/authorize"), "token_endpoint": format!("{i}/token"), "jwks_uri": format!("{i}/jwks") })) } }))
        .route("/jwks", axum::routing::get(move || { let jwk = jwk.clone(); async move { axum::Json(json!({ "keys": [jwk] })) } }))
        // Like a real provider: client authentication is the Basic header, and it must carry the
        // real secret (a redacted placeholder is exactly what a Display-based bug would send).
        .route("/token", axum::routing::post(move |h: axum::http::HeaderMap| { let t = tok.lock().unwrap().clone(); async move {
            let want = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("kontainer:s3cret"));
            if h.get("authorization").and_then(|v| v.to_str().ok()) != Some(want.as_str()) {
                return axum::response::IntoResponse::into_response((StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "invalid_client" }))));
            }
            axum::response::IntoResponse::into_response(axum::Json(json!({ "id_token": t, "token_type": "Bearer" })))
        } }));
    tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });
    let enc = jsonwebtoken::EncodingKey::from_ec_pem(sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap().as_bytes()).unwrap();

    let mut cfg = accounts_config();
    cfg.server.bind = "127.0.0.1:0".into();
    // The instance provider too (same IdP), to check states do not cross between callbacks.
    cfg.auth.oidc.is_enabled = true;
    cfg.auth.oidc.issuer = issuer.clone();
    cfg.auth.oidc.client_id = "kontainer".into();
    cfg.auth.oidc.client_secret = "s3cret".into();
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "acme" })).unwrap()).await;
    let sso = json!({ "issuer": issuer, "client_id": "kontainer", "client_secret": "s3cret" });
    assert_eq!(send(&app, Method::PUT, "/api/v1/orgs/acme/sso", &[("cookie", &root), jh], serde_json::to_vec(&sso).unwrap()).await.status, StatusCode::OK);
    let body = serde_json::to_vec(&json!({ "username": "dana", "password": "danapass123" })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    let dana = cookie_of(&web_login(&app, "dana", "danapass123", None).await);

    // The ID token the IdP hands out for the next code exchange, bound to `authorize`'s nonce.
    let prepare = |authorize: &str, sub: &str| {
        let q: std::collections::HashMap<String, String> = url::Url::parse(authorize).unwrap().query_pairs().into_owned().collect();
        let now = chrono::Utc::now().timestamp();
        let claims = json!({ "iss": issuer, "aud": "kontainer", "sub": sub, "preferred_username": sub, "nonce": q["nonce"], "iat": now, "exp": now + 300 });
        let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        h.kid = Some("k".into());
        *next_token.lock().unwrap() = jsonwebtoken::encode(&h, &claims, &enc).unwrap();
        q["state"].clone()
    };
    let me = |c: String| { let app = app.clone(); async move { send(&app, Method::GET, "/api/v1/me", &[("cookie", &c)], vec![]).await.json()["username"].clone() } };

    // `?link=true` on the GET is ignored, even with a session: it signs in a new account.
    let r = send(&app, Method::GET, "/auth/oidc/orgs/acme/login?link=true", &[("cookie", &dana)], vec![]).await;
    let (authorize, login_cookie) = (r.header("location"), cookie_of(&r));
    let state = prepare(&authorize, "s-get");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &format!("{login_cookie}; {dana}"))], vec![]).await;
    assert!(r.header("set-cookie").starts_with("kontainer_session="), "{}", r.header("location"));
    assert_ne!(me(cookie_of(&r)).await, "dana");

    // A link started by dana but completed in another browser (the attacker's, or dana's own
    // browser without her session): refused, nothing linked.
    // `cookie_of` keeps only the login cookie: the link cookie (the session's stand-in) is left
    // behind, as in a browser other than the one that started the link.
    let start_link = || { let (app, dana) = (app.clone(), dana.clone()); async move {
        let r = send(&app, Method::POST, "/api/v1/auth/oidc/orgs/acme/link", &[("cookie", &dana), ("content-type", "application/json")], b"{}".to_vec()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
        (r.json()["url"].as_str().unwrap().to_string(), cookie_of(&r), cookies_of(&r))
    } };
    let (authorize, login_cookie, _) = start_link().await;
    let state = prepare(&authorize, "s-attacker");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &login_cookie)], vec![]).await;
    assert!(r.header("location").starts_with("/login?error="), "{}", r.header("location"));
    let (authorize, login_cookie, _) = start_link().await;
    let state = prepare(&authorize, "s-attacker");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &format!("{login_cookie}; {root}"))], vec![]).await;
    assert!(r.header("location").starts_with("/login?error="), "another user's session does not count: {}", r.header("location"));
    // Even dana's own session is not enough without the link cookie of that very link: one
    // from another link of hers does not match.
    let (_, _, other_link) = start_link().await;
    let other_link = other_link.split("; ").find(|c| c.starts_with("kontainer_oidc_link=")).unwrap().to_string();
    let (authorize, login_cookie, _) = start_link().await;
    let state = prepare(&authorize, "s-attacker");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &format!("{login_cookie}; {other_link}; {dana}"))], vec![]).await;
    assert!(r.header("location").starts_with("/login?error="), "a mismatched link cookie: {}", r.header("location"));
    // The attacker's identity was never linked to dana: it signs in as a new account.
    let r = send(&app, Method::GET, "/auth/oidc/orgs/acme/login", &[], vec![]).await;
    let (authorize, login_cookie) = (r.header("location"), cookie_of(&r));
    let state = prepare(&authorize, "s-attacker");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &login_cookie)], vec![]).await;
    assert_ne!(me(cookie_of(&r)).await, "dana");

    // With the link cookie, the link completes without the (Strict, so absent) session cookie,
    // and the identity signs in as dana from then on.
    let (authorize, _, cookies) = start_link().await;
    let state = prepare(&authorize, "s-dana");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &cookies)], vec![]).await;
    assert_eq!(r.header("location"), "/settings/security", "{}", r.header("location"));
    assert!(set_cookie(&r, "kontainer_session").is_empty(), "a link issues no session");
    assert!(set_cookie(&r, "kontainer_oidc_link").contains("Max-Age=0") && set_cookie(&r, "kontainer_oidc").contains("Max-Age=0"), "both cookies are single use");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &cookies)], vec![]).await;
    assert!(r.header("location").starts_with("/login?error="), "the state is single use too");
    let r = send(&app, Method::GET, "/auth/oidc/orgs/acme/login", &[], vec![]).await;
    let (authorize, login_cookie) = (r.header("location"), cookie_of(&r));
    let state = prepare(&authorize, "s-dana");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &login_cookie)], vec![]).await;
    assert!(set_cookie(&r, "kontainer_session").contains("SameSite=Strict"), "{}", set_cookie(&r, "kontainer_session"));
    assert_eq!(me(cookie_of(&r)).await, "dana");

    // Linking needs a JSON POST from a session.
    assert!(send(&app, Method::POST, "/api/v1/auth/oidc/orgs/acme/link", &[("cookie", &dana), ("content-type", "application/x-www-form-urlencoded")], b"redirect=/".to_vec()).await.status.is_client_error(), "a form post cannot start a link");
    assert_ne!(send(&app, Method::POST, "/api/v1/auth/oidc/orgs/acme/link", &[jh], b"{}".to_vec()).await.status, StatusCode::OK);

    // Login CSRF: a callback without the browser's login cookie is refused.
    let r = send(&app, Method::GET, "/auth/oidc/orgs/acme/login", &[], vec![]).await;
    let state = prepare(&r.header("location"), "s-csrf");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[], vec![]).await;
    assert!(r.header("location").starts_with("/login?error="), "{}", r.header("location"));
    assert!(!r.header("set-cookie").starts_with("kontainer_session="));

    // States do not cross callbacks: an org state on the instance callback, and back.
    let r = send(&app, Method::GET, "/auth/oidc/orgs/acme/login", &[], vec![]).await;
    let (authorize, login_cookie) = (r.header("location"), cookie_of(&r));
    let state = prepare(&authorize, "s-cross");
    let r = send(&app, Method::GET, &format!("/auth/oidc/callback?code=c&state={state}"), &[("cookie", &login_cookie)], vec![]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.header("location"));
    let r = send(&app, Method::GET, "/auth/oidc/login", &[], vec![]).await;
    let (authorize, login_cookie) = (r.header("location"), cookie_of(&r));
    let state = prepare(&authorize, "s-cross");
    let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &login_cookie)], vec![]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Open redirects are dropped for the default destination.
    for evil in ["/%5Cevil.example", "//evil.example", "/%09/evil.example"] {
        let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/login?redirect={evil}"), &[], vec![]).await;
        let (authorize, login_cookie) = (r.header("location"), cookie_of(&r));
        let state = prepare(&authorize, "s-redirect");
        let r = send(&app, Method::GET, &format!("/auth/oidc/orgs/acme/callback?code=c&state={state}"), &[("cookie", &login_cookie)], vec![]).await;
        assert_eq!(r.header("location"), "/orgs/acme", "{evil}");
    }

    // Unknown org: back to the login page with a message.
    let r = send(&app, Method::GET, "/auth/oidc/orgs/nope/login", &[], vec![]).await;
    assert!(r.header("location").starts_with("/login?error="));
}

/// Needs an LDAP server seeded with `docs/ldap-test.ldif`; set KONTAINER_TEST_LDAP_URL
/// (e.g. `ldap://127.0.0.1:3389` with `docker run -p 3389:389 osixia/openldap:1.5.0`).
#[tokio::test]
async fn ldap_sign_in_roles_and_team_sync() {
    let Ok(url) = std::env::var("KONTAINER_TEST_LDAP_URL") else {
        eprintln!("skipping: KONTAINER_TEST_LDAP_URL not set");
        return;
    };
    let mut cfg = accounts_config();
    cfg.auth.ldap = kontainer_core::config::LdapConfig {
        is_enabled: true,
        url,
        bind_dn: "cn=admin,dc=example,dc=org".into(),
        bind_password: "admin".into(),
        user_base_dn: "ou=people,dc=example,dc=org".into(),
        group_base_dn: "ou=groups,dc=example,dc=org".into(),
        group_roles: [("engineering".to_string(), vec!["pusher".to_string()])].into(),
        ..Default::default()
    };
    cfg.auth.roles.push(role("pusher", &["**"], &[Action::Pull, Action::Push]));
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "acme" })).unwrap()).await;
    send(&app, Method::POST, "/api/v1/orgs/acme/teams", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "eng" })).unwrap()).await;
    let r = send(&app, Method::PUT, "/api/v1/orgs/acme/teams/eng/sync", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "source": "ldap", "group": "Engineering" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&r.body));

    // Wrong and empty passwords fail; the right one creates the account.
    assert_eq!(web_login(&app, "alice", "nope", None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(web_login(&app, "alice", "", None).await.status, StatusCode::UNAUTHORIZED);
    let r = web_login(&app, "alice", "wonderland", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let alice = cookie_of(&r);
    let me = send(&app, Method::GET, "/api/v1/me", &[("cookie", &alice)], vec![]).await.json();
    assert_eq!(me["username"], "alice");
    assert_eq!(me["display_name"], "Alice Liddell");
    assert_eq!(me["roles"], json!(["pusher"]), "group -> role");
    let org = send(&app, Method::GET, "/api/v1/orgs/acme", &[("cookie", &root)], vec![]).await.json();
    assert_eq!(org["teams"].as_array().unwrap().iter().find(|t| t["name"] == "eng").unwrap()["members"][0]["username"], "alice", "group -> team (case-insensitive)");
    // docker login works with the directory password too.
    assert_eq!(send(&app, Method::GET, "/v2/", &[("authorization", &basic("alice", "wonderland"))], vec![]).await.status, StatusCode::OK);
    // Local accounts keep their own password even when LDAP is on.
    assert_eq!(web_login(&app, "root", "rootpass123", None).await.status, StatusCode::OK);
}

/// Runs a real `docker build`; set KONTAINER_TEST_BUILDS=1 (needs Docker 25+ with the
/// containerd image store). With KONTAINER_TEST_BUILDKIT_ADDR set, builds with `buildctl`
/// against that `buildkitd` instead (`buildctl` must be on PATH).
#[tokio::test]
async fn build_from_git_webhook() {
    if std::env::var("KONTAINER_TEST_BUILDS").is_err() {
        eprintln!("skipping: KONTAINER_TEST_BUILDS not set");
        return;
    }
    // A Git repository with a tiny Dockerfile.
    let repo_dir = tempfile::tempdir().unwrap().keep();
    let git = |args: &[&str]| { let o = std::process::Command::new("git").arg("-C").arg(&repo_dir).args(args).output().unwrap(); assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr)); String::from_utf8_lossy(&o.stdout).trim().to_string() };
    git(&["init", "-q", "-b", "main"]);
    std::fs::write(repo_dir.join("hello.txt"), "hi\n").unwrap();
    std::fs::create_dir_all(repo_dir.join("docker")).unwrap();
    std::fs::write(repo_dir.join("docker/Dockerfile"), "FROM scratch\nCOPY hello.txt /hello.txt\n").unwrap();
    git(&["add", "."]);
    git(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"]);
    let sha = git(&["rev-parse", "HEAD"]);

    let mut cfg = base_config();
    cfg.builds.is_enabled = true;
    cfg.builds.is_allow_file_urls = true;
    cfg.builds.runners = vec![kontainer_core::config::ConfigRunner { name: "local".into(), token: "runner-token-0123456789".into(), namespaces: vec![] }];
    let state = kontainer_server::build_state(cfg).await.unwrap();
    kontainer_server::start_background(&state).await;
    let app = kontainer_server::build_router(state);
    // A real runner, building in this process, talking to the registry over HTTP.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let serve = axum::serve(listener, app.clone());
    tokio::spawn(async move { serve.await });
    let mut rc = kontainer_core::config::RunnerConfig { server, token: Some("runner-token-0123456789".into()), name: Some("test".into()), work_dir: tempfile::tempdir().unwrap().keep(), poll: std::time::Duration::from_millis(200), ..Default::default() };
    if let Ok(addr) = std::env::var("KONTAINER_TEST_BUILDKIT_ADDR") {
        rc.backend = kontainer_core::config::BuildBackend::Buildctl;
        rc.buildkit_addr = addr;
    }
    let runner = kontainer_server::runner::worker::Runner::new(&rc).unwrap();
    tokio::spawn(async move { runner.serve(&rc).await });
    let jh = ("content-type", "application/json");
    let body = json!({ "repository": "acme/hello", "name": "main", "git_url": format!("file://{}", repo_dir.display()), "branches": ["main"], "dockerfile": "docker/Dockerfile", "tags": ["{branch}", "{sha7}", "latest"] });
    let r = send(&app, Method::POST, "/api/v1/build-triggers", &[jh], serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let (id, secret) = (r.json()["id"].as_i64().unwrap(), r.json()["secret"].as_str().unwrap().to_string());

    // Wrong secret, then a push to another branch (ignored), then the real one.
    let hook = |secret: String, r#ref: &str| { let app = app.clone(); let b = serde_json::to_vec(&json!({ "ref": r#ref, "after": sha })).unwrap(); async move { send(&app, Method::POST, &format!("/api/v1/build-triggers/{id}/webhook?secret={secret}"), &[jh], b).await } };
    assert_eq!(hook("nope".into(), "refs/heads/main").await.status, StatusCode::UNAUTHORIZED);
    let r = hook(secret.clone(), "refs/heads/other").await;
    assert!(r.json()["message"].as_str().unwrap().contains("does not match"), "{}", r.json());
    let r = hook(secret, "refs/heads/main").await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&r.body));
    let build = r.json()["build"].as_i64().unwrap();

    let mut b = Value::Null;
    for _ in 0..180 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        b = send(&app, Method::GET, &format!("/api/v1/builds/{build}"), &[], vec![]).await.json();
        if !matches!(b["status"].as_str(), Some("queued" | "running")) { break; }
    }
    assert_eq!(b["status"], "succeeded", "{}\n{}", b["message"], b["log"].as_str().unwrap_or_default());
    eprintln!("BUILD LOG:\n{}", b["log"].as_str().unwrap_or_default());
    assert_eq!(b["commit_sha"], sha.as_str());
    assert_eq!(b["tags"], json!(["main", &sha[..7], "latest"]));
    for t in ["main", &sha[..7], "latest"] {
        let r = send(&app, Method::HEAD, &format!("/v2/acme/hello/manifests/{t}"), &[("accept", "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json")], vec![]).await;
        assert_eq!(r.status, StatusCode::OK, "{t}");
        assert_eq!(r.header("docker-content-digest"), b["digest"].as_str().unwrap());
    }
    let h = send(&app, Method::GET, "/api/v1/repositories/acme/hello/history?tag=latest", &[], vec![]).await.json();
    assert_eq!(h["events"][0]["action"], "build");
    assert_eq!(h["events"][0]["actor"], format!("build #{build}"));
}

/// Two filesystem locations, `us` (preferred) and a standby `dr`: a push lands in `us` and is
/// queued for `dr`, a worker copies it, "sync now" queues what `dr` is missing, and reads fail
/// over to `dr` when `us` cannot be read. With KONTAINER_TEST_S3_ENDPOINT (a bucket
/// `kontainer-eu`, keys in KONTAINER_TEST_S3_KEY / KONTAINER_TEST_S3_SECRET), also checks region
/// redirects to presigned URLs in an S3 location.
#[tokio::test]
async fn geo_replication_redirects_and_failover() {
    use kontainer_core::config::LocationConfig;
    let dir = tempfile::tempdir().unwrap().keep();
    let (primary, dr) = (dir.join("primary"), dir.join("dr"));
    let mut cfg = accounts_config();
    cfg.storage.driver = StorageDriver::Filesystem;
    cfg.storage.filesystem.root = primary.clone();
    cfg.storage.location = "us".into();
    cfg.storage.region_header = Some("X-Region".into());
    let mut fs = LocationConfig { name: "dr".into(), driver: StorageDriver::Filesystem, is_redirect: false, ..Default::default() };
    fs.filesystem.root = dr.clone();
    cfg.storage.replicas.push(fs);
    let s3 = std::env::var("KONTAINER_TEST_S3_ENDPOINT").ok();
    if let Some(endpoint) = &s3 {
        let mut r = LocationConfig { name: "eu".into(), driver: StorageDriver::S3, regions: vec!["eu-*".into(), "DE".into()], ..Default::default() };
        r.s3.bucket = "kontainer-eu".into();
        r.s3.endpoint = Some(endpoint.clone());
        r.s3.region = Some("us-east-1".into());
        r.s3.is_allow_http = true;
        r.s3.access_key_id = std::env::var("KONTAINER_TEST_S3_KEY").ok();
        r.s3.secret_access_key = std::env::var("KONTAINER_TEST_S3_SECRET").ok().map(Into::into);
        cfg.storage.replicas.push(r);
    }
    let state = kontainer_server::build_state(cfg).await.unwrap();
    let worker = kontainer_server::locations::Worker::new(state.storage.clone(), state.auth.db.clone(), Default::default());
    let drain = || async {
        let mut n = 0;
        while let Some(r) = worker.run_once().await.unwrap() {
            r.unwrap();
            n += 1;
        }
        n
    };
    let storage = state.storage.clone();
    let app = kontainer_server::build_router(state);
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("root", r.json()["token"].as_str().unwrap());

    let cfgb = br#"{"architecture":"arm64","os":"linux"}"#;
    let layer = gzip_tar_layer();
    let cd = push_blob(&app, "root/geo", cfgb, Some(&auth)).await;
    let ld = push_blob(&app, "root/geo", &layer, Some(&auth)).await;
    let r = send(&app, Method::PUT, "/v2/root/geo/manifests/v1", &[("authorization", &auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfgb.len(), &[(ld.clone(), layer.len())])).await;
    assert_eq!(r.status, StatusCode::CREATED);

    // Written to the preferred location and recorded there; copies queued for the others.
    let blob_in = |root: &std::path::Path, d: &Digest| root.join(format!("blobs/sha256/{}/data", d.to_string().trim_start_matches("sha256:")));
    assert!(blob_in(&primary, &ld).exists() && !blob_in(&dr, &ld).exists());
    assert_eq!(storage.placements().placements(&ld).await.unwrap(), [("us".to_string(), layer.len() as u64)]);
    let st = send(&app, Method::GET, "/api/v1/admin/storage", &[("cookie", &root)], vec![]).await.json();
    // Both blobs for each other location (and the audit log, written the same way).
    assert!(st["replicas"][0]["pending"].as_i64().unwrap() >= 2, "{st}");
    assert!(drain().await >= 2);
    assert_eq!(std::fs::read(blob_in(&dr, &ld)).unwrap(), layer);
    assert!(storage.placements().placements(&ld).await.unwrap().iter().any(|(l, _)| l == "dr"));
    // Manifests and tags are in the database, which every region reads: neither location has them.
    assert!(!primary.join("repositories").exists() && !dr.join("repositories").exists(), "no metadata in object storage");

    let r = send(&app, Method::GET, "/api/v1/admin/storage", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let st = r.json();
    assert_eq!(st["primary"]["name"], "us");
    assert_eq!(st["primary"]["preferred"], true);
    assert_eq!(st["replicas"][0]["name"], "dr");
    assert_eq!(st["replicas"][0]["redirect"], false, "filesystem locations cannot presign");
    assert_eq!(st["replicas"][0]["blobs"], 2, "{st}");
    assert_eq!(st["replicas"][0]["pending"], 0, "{st}");
    assert!(st["replicas"][0]["stats"]["copied"].as_u64().unwrap() >= 2);
    assert_eq!(st["locations"].as_array().unwrap().len(), 2 + usize::from(s3.is_some()));
    assert_eq!((st["pending"].as_i64(), st["failed"].as_i64()), (Some(0), Some(0)));

    // `dr` loses a blob (and its record): "sync now" queues just that one.
    std::fs::remove_file(blob_in(&dr, &ld)).unwrap();
    storage.placements().unplace(&ld, "dr").await.unwrap();
    let r = send(&app, Method::POST, "/api/v1/admin/storage/sync", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&r.body));
    let job = wait_job(&app, &root, r.json()["job"].as_str().unwrap()).await;
    assert_eq!(job["status"], "done", "{job}");
    assert!(job["message"].as_str().unwrap().contains("dr: 1 queued"), "{job}");
    assert!(drain().await >= 1, "the blob (and the audit log of the sync)");
    assert_eq!(std::fs::read(blob_in(&dr, &ld)).unwrap(), layer);
    let health = send(&app, Method::GET, "/api/v1/health", &[("cookie", &root)], vec![]).await.json();
    let check = health["checks"].as_array().unwrap().iter().find(|c| c["name"] == "Location dr").cloned().unwrap();
    assert_eq!(check["status"], "ok", "{check}");

    // No region (and a filesystem location): streamed as usual.
    let r = send(&app, Method::GET, &format!("/v2/root/geo/blobs/{ld}"), &[("authorization", &auth)], vec![]).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::OK, layer.clone()));

    if s3.is_some() {
        let r = send(&app, Method::GET, &format!("/v2/root/geo/blobs/{ld}"), &[("authorization", &auth), ("x-region", "eu-west-1")], vec![]).await;
        assert_eq!(r.status, StatusCode::TEMPORARY_REDIRECT, "{}", String::from_utf8_lossy(&r.body));
        let url = r.header("location");
        assert!(url.contains("kontainer-eu") && url.contains("X-Amz-Signature"), "{url}");
        let got = reqwest::get(&url).await.unwrap();
        assert_eq!(got.status(), 200);
        assert_eq!(got.bytes().await.unwrap().to_vec(), layer);
        // A tampered URL is refused by the bucket: the signature is what grants access.
        let bad = reqwest::get(url.replace("X-Amz-Signature=", "X-Amz-Signature=0")).await.unwrap();
        assert_eq!(bad.status(), 403);
        // Regions no location serves are read from the preferred location (streamed).
        let r = send(&app, Method::GET, &format!("/v2/root/geo/blobs/{ld}"), &[("authorization", &auth), ("x-region", "JP")], vec![]).await;
        assert_eq!(r.status, StatusCode::OK);
    }

    // The preferred location fails: blob reads come from the next location holding the blob.
    use std::os::unix::fs::PermissionsExt;
    let blobs = primary.join("blobs");
    std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o000)).unwrap();
    let r = send(&app, Method::GET, &format!("/v2/root/geo/blobs/{ld}"), &[("authorization", &auth)], vec![]).await;
    std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.body, layer);
}

/// Outside `/v2/`, every error is `{"code", "message", "details"}`; `/v2/` keeps the spec body.
#[tokio::test]
async fn api_error_format() {
    let app = app(accounts_config()).await;
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let jh = ("content-type", "application/json");
    let flat = |r: &Resp, code: &str| {
        let v = r.json();
        assert_eq!(v["code"], code, "{v}");
        assert!(v["message"].as_str().is_some_and(|m| !m.is_empty()), "{v}");
        assert!(v["details"].is_object(), "{v}");
        assert!(v.get("errors").is_none(), "{v}");
    };
    let r = send(&app, Method::GET, "/api/v1/orgs/nope", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    flat(&r, "NOT_FOUND");
    // axum's own rejection (malformed JSON) gets the same shape.
    let r = send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &root), jh], b"{not json".to_vec()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    flat(&r, "BAD_REQUEST");
    let r = send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "root" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    flat(&r, "CONFLICT");
    let r = send(&app, Method::GET, "/api/v1/users", &[], vec![]).await;
    flat(&r, "UNAUTHORIZED");
    let r = send(&app, Method::GET, "/v2/nope/manifests/latest", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()["errors"][0]["code"], "MANIFEST_UNKNOWN", "{}", r.json());
}

/// Repository grants can be any mix of actions; each setting checks its own action, and the
/// Docker token flow grants exactly what the same rules allow.
#[tokio::test]
async fn fine_grained_repository_permissions() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let root_auth = basic("root", r.json()["token"].as_str().unwrap());
    let cfgb = br#"{"architecture":"amd64","os":"linux"}"#;
    let cd = push_blob(&app, "root/app", cfgb, Some(&root_auth)).await;
    let r = send(&app, Method::PUT, "/v2/root/app/manifests/v1", &[("authorization", &root_auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfgb.len(), &[])).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "username": "dana", "password": "password123" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let dana = cookie_of(&web_login(&app, "dana", "password123", None).await);

    let grant = |level: Value| serde_json::to_vec(&json!({ "kind": "user", "name": "dana", "level": level })).unwrap();
    let r = send(&app, Method::PUT, "/api/v1/repository-permissions/root/app", &[("cookie", &root), jh], grant(json!("pull,fly"))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "unknown actions are refused");
    assert_eq!(r.json()["code"], "BAD_REQUEST");
    let r = send(&app, Method::PUT, "/api/v1/repository-permissions/root/app", &[("cookie", &root), jh], grant(json!(["pull", "metadata"]))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["grants"][0]["level"], "pull,metadata");

    let meta = send(&app, Method::GET, "/api/v1/repository-meta/root/app", &[("cookie", &dana)], vec![]).await.json();
    assert_eq!(meta["actions"], json!(["pull", "metadata"]));
    let patch = |body: Value| { let app = app.clone(); let dana = dana.clone(); async move { send(&app, Method::PATCH, "/api/v1/repository-meta/root/app", &[("cookie", &dana), jh], serde_json::to_vec(&body).unwrap()).await.status } };
    assert_eq!(patch(json!({ "description": "Dana's words" })).await, StatusCode::OK);
    assert_eq!(patch(json!({ "visibility": "public" })).await, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, Method::GET, "/api/v1/repository-permissions/root/app", &[("cookie", &dana)], vec![]).await.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::PUT, "/api/v1/repositories/root/app/state", &[("cookie", &dana), jh], serde_json::to_vec(&json!({ "state": "read_only" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // docker login + pull/push: the token carries only what the grant allows.
    let r = send(&app, Method::GET, "/auth/token?service=registry.test&scope=repository:root/app:pull,push", &[("authorization", &basic("dana", "password123"))], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let bearer = format!("Bearer {}", r.json()["token"].as_str().unwrap());
    let claims: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(bearer.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(claims["access"][0]["actions"], json!(["pull"]));
    let r = send(&app, Method::GET, "/v2/root/app/manifests/v1", &[("authorization", &bearer), ("accept", OCI_MANIFEST)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::POST, "/v2/root/app/blobs/uploads/", &[("authorization", &bearer)], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "push was not granted: the challenge names the scope, and a retry gets a token without it");
    assert!(r.header("www-authenticate").contains("repository:root/app:pull,push"), "{}", r.header("www-authenticate"));

    // The pickers' directory: people by name for anyone signed in; robots only for their namespace.
    let r = send(&app, Method::GET, "/api/v1/directory?kind=user&q=DAN", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json().as_array().unwrap().iter().map(|e| e["name"].clone()).collect::<Vec<_>>(), vec![json!("dana")], "{}", r.json());
    assert_eq!(send(&app, Method::GET, "/api/v1/directory?kind=user&q=", &[("cookie", &root)], vec![]).await.json(), json!([]));
    send(&app, Method::POST, "/api/v1/auth/robots", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let r = send(&app, Method::GET, "/api/v1/directory?kind=robot&namespace=root", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.json()[0]["name"], "root+ci", "{}", r.json());
    let r = send(&app, Method::GET, "/api/v1/directory?kind=robot&namespace=root", &[("cookie", &dana)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "someone else's robots are not listed");
    assert_eq!(send(&app, Method::GET, "/api/v1/directory?kind=user&q=dana", &[], vec![]).await.status, StatusCode::UNAUTHORIZED);

    // `admin` still means everything, including actions added later.
    send(&app, Method::PUT, "/api/v1/repository-permissions/root/app", &[("cookie", &root), jh], grant(json!("admin"))).await;
    let meta = send(&app, Method::GET, "/api/v1/repository-meta/root/app", &[("cookie", &dana)], vec![]).await.json();
    assert_eq!(meta["actions"].as_array().unwrap().len(), 13, "{meta}");
    assert_eq!(patch(json!({ "visibility": "public" })).await, StatusCode::OK);
}

/// The external build agent protocol, with the test playing the agent (no Docker needed): claim,
/// spec, check-ins, commit, image upload; bad tokens; cancelling a running build.
#[tokio::test]
async fn external_build_agents() {
    let mut cfg = base_config();
    cfg.builds.is_enabled = true;
    cfg.builds.runners = vec![kontainer_core::config::ConfigRunner { name: "ci".into(), token: "agent-token-0123456789".into(), namespaces: vec![] }];
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let agent_auth = ("authorization", "Bearer agent-token-0123456789");

    // Something to stand in for the build result: an exported image.
    let cfg_blob = br#"{"architecture":"amd64","os":"linux"}"#;
    let layer = gzip_tar_layer();
    let cd = push_blob(&app, "acme/src", cfg_blob, None).await;
    let ld = push_blob(&app, "acme/src", &layer, None).await;
    let r = send(&app, Method::PUT, "/v2/acme/src/manifests/v1", &[("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg_blob.len(), &[(ld, layer.len())])).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let archive = send(&app, Method::GET, "/api/v1/repositories/acme/src/manifests/v1/export", &[], vec![]).await.body;

    let body = json!({ "repository": "acme/hello", "name": "main", "git_url": "https://git.example.com/acme/hello.git", "git_token": "s3cret-git-token", "branches": ["main"], "tags": ["{branch}", "{sha7}"] });
    let r = send(&app, Method::POST, "/api/v1/build-triggers", &[jh], serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let trigger = r.json()["id"].as_i64().unwrap();
    let run = || { let app = app.clone(); async move { send(&app, Method::POST, &format!("/api/v1/build-triggers/{trigger}/run"), &[jh], b"{}".to_vec()).await } };
    let build = run().await.json()["build"].as_i64().unwrap();

    // Claiming needs the agent token.
    let claim = |auth: (&'static str, &'static str)| { let app = app.clone(); async move { send(&app, Method::POST, "/api/v1/runner/claim", &[jh, auth], br#"{"hostname":"ci-1"}"#.to_vec()).await } };
    assert_eq!(claim(("authorization", "Bearer wrong")).await.status, StatusCode::UNAUTHORIZED);
    let r = claim(agent_auth).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["id"], build);
    let token = r.json()["token"].as_str().unwrap().to_string();
    let bt = format!("Bearer {token}");
    let ba = ("authorization", bt.as_str());
    assert_eq!(claim(agent_auth).await.status, StatusCode::NO_CONTENT, "nothing else is queued");

    // The spec carries the Git credentials; another build's token gets nothing.
    let r = send(&app, Method::GET, &format!("/api/v1/runner/builds/{build}"), &[ba], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["git_url"], "https://git.example.com/acme/hello.git");
    assert_eq!(r.json()["git_token"], "s3cret-git-token");
    assert_eq!(r.json()["target"], "refs/heads/main");
    assert_eq!(send(&app, Method::GET, &format!("/api/v1/runner/builds/{build}"), &[("authorization", "Bearer nope")], vec![]).await.status, StatusCode::UNAUTHORIZED);

    // Check in, commit, upload. (The whole log at once, as runners before chunked logs send it;
    // `build_logs_stream_live_across_instances` covers chunks.)
    let r = send(&app, Method::POST, &format!("/api/v1/runner/builds/{build}/log"), &[jh, ba], br#"{"log":"==> Fetching\n"}"#.to_vec()).await;
    assert_eq!(r.json()["stop"], false);
    let b = send(&app, Method::GET, &format!("/api/v1/builds/{build}"), &[], vec![]).await.json();
    assert_eq!((b["status"].as_str(), b["agent"].as_str(), b["log"].as_str()), (Some("running"), Some("ci (ci-1)"), Some("==> Fetching\n")));
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let r = send(&app, Method::POST, &format!("/api/v1/runner/builds/{build}/commit"), &[jh, ba], serde_json::to_vec(&json!({ "sha": sha })).unwrap()).await;
    assert_eq!(r.json()["tags"], json!(["main", "0123456"]));
    let r = send(&app, Method::PUT, &format!("/api/v1/runner/builds/{build}/image"), &[ba, ("content-type", "application/x-tar")], archive.to_vec()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json()["summary"].as_str().unwrap().contains("as main and 0123456"));
    let b = send(&app, Method::GET, &format!("/api/v1/builds/{build}"), &[], vec![]).await.json();
    assert_eq!(b["status"], "succeeded", "{}", b["message"]);
    assert_eq!(b["commit_sha"], sha);
    assert!(b["log"].as_str().unwrap().starts_with("==> Fetching\n"));
    for t in ["main", "0123456"] {
        let r = send(&app, Method::HEAD, &format!("/v2/acme/hello/manifests/{t}"), &[("accept", OCI_MANIFEST)], vec![]).await;
        assert_eq!(r.status, StatusCode::OK, "{t}");
    }
    // The token dies with the build.
    let r = send(&app, Method::POST, &format!("/api/v1/runner/builds/{build}/commit"), &[jh, ba], serde_json::to_vec(&json!({ "sha": sha })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CONFLICT);

    // Cancelling a running build: the agent hears it at its next check-in and reports back.
    let build2 = run().await.json()["build"].as_i64().unwrap();
    let token2 = claim(agent_auth).await.json()["token"].as_str().unwrap().to_string();
    let bt2 = format!("Bearer {token2}");
    let ba2 = ("authorization", bt2.as_str());
    assert_eq!(send(&app, Method::POST, &format!("/api/v1/builds/{build2}/cancel"), &[], vec![]).await.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::POST, &format!("/api/v1/runner/builds/{build2}/log"), &[jh, ba2], br#"{"log":"working\n"}"#.to_vec()).await;
    assert_eq!(r.json()["stop"], true);
    let r = send(&app, Method::POST, &format!("/api/v1/runner/builds/{build2}/finish"), &[jh, ba2], serde_json::to_vec(&json!({ "status": "cancelled", "message": "cancelled", "log": "working\n==> cancelled\n" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(send(&app, Method::GET, &format!("/api/v1/builds/{build2}"), &[], vec![]).await.json()["status"], "cancelled");

    // A queued build is cancelled on the spot and never handed out.
    let build3 = run().await.json()["build"].as_i64().unwrap();
    assert_eq!(send(&app, Method::POST, &format!("/api/v1/builds/{build3}/cancel"), &[], vec![]).await.status, StatusCode::ACCEPTED);
    assert_eq!(claim(agent_auth).await.status, StatusCode::NO_CONTENT);

    // A build started by hand can bring its own tags; nonsense is refused before it queues.
    let run_with = |body: Value| { let app = app.clone(); async move { send(&app, Method::POST, &format!("/api/v1/build-triggers/{trigger}/run"), &[jh], serde_json::to_vec(&body).unwrap()).await } };
    assert_eq!(run_with(json!({ "ref": "main", "tags": ["not a tag!"] })).await.status, StatusCode::BAD_REQUEST);
    let build4 = run_with(json!({ "ref": "main", "tags": ["rc-{sha7}", "candidate"] })).await.json()["build"].as_i64().unwrap();
    let token4 = claim(agent_auth).await.json()["token"].as_str().unwrap().to_string();
    let bt4 = format!("Bearer {token4}");
    let r = send(&app, Method::POST, &format!("/api/v1/runner/builds/{build4}/commit"), &[jh, ("authorization", bt4.as_str())], serde_json::to_vec(&json!({ "sha": sha })).unwrap()).await;
    assert_eq!(r.json()["tags"], json!(["rc-0123456", "candidate"]));
}

/// The build queue: a newer build of the same trigger and ref replaces queued ones, namespaces
/// take turns and stop at `max_per_namespace`, and queued builds say where they stand.
#[tokio::test]
async fn build_queue() {
    let mut cfg = base_config();
    cfg.builds.is_enabled = true;
    cfg.builds.runners = vec![kontainer_core::config::ConfigRunner { name: "ci".into(), token: "agent-token-0123456789".into(), namespaces: vec![] }];
    cfg.builds.max_per_namespace = 1;
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let trigger = |repo: &'static str| {
        let app = app.clone();
        async move {
            let body = json!({ "repository": repo, "name": "main", "git_url": "https://git.example.com/x.git", "branches": ["**"] });
            send(&app, Method::POST, "/api/v1/build-triggers", &[jh], serde_json::to_vec(&body).unwrap()).await.json()["id"].as_i64().unwrap()
        }
    };
    let (a, c, b) = (trigger("acme/a").await, trigger("acme/c").await, trigger("beta/b").await);
    let run = |t: i64, r#ref: &'static str| { let app = app.clone(); async move { send(&app, Method::POST, &format!("/api/v1/build-triggers/{t}/run"), &[jh], serde_json::to_vec(&json!({ "ref": r#ref })).unwrap()).await.json() } };
    let get = |id: i64| { let app = app.clone(); async move { send(&app, Method::GET, &format!("/api/v1/builds/{id}"), &[], vec![]).await.json() } };
    let claim = || { let app = app.clone(); async move { send(&app, Method::POST, "/api/v1/runner/claim", &[jh, ("authorization", "Bearer agent-token-0123456789")], br#"{"hostname":"ci"}"#.to_vec()).await } };

    // Superseding: only the newest queued build of a trigger and ref survives.
    let b1 = run(a, "main").await["build"].as_i64().unwrap();
    let r = run(a, "main").await;
    let b2 = r["build"].as_i64().unwrap();
    assert_eq!(r["superseded"], json!([b1]));
    let old = get(b1).await;
    assert_eq!((old["status"].as_str(), old["message"].as_str()), (Some("cancelled"), Some(format!("Superseded by build #{b2}").as_str())));
    let b3 = run(a, "dev").await;
    assert_eq!(b3["superseded"], json!([]), "another branch is another build");
    let b3 = b3["build"].as_i64().unwrap();
    let b4 = run(c, "main").await["build"].as_i64().unwrap();
    let b5 = run(b, "main").await["build"].as_i64().unwrap();

    // Queue position.
    let q = &get(b4).await["queue"];
    assert_eq!((q["ahead"].as_i64(), q["namespace"].as_str(), q["namespace_limit"].as_i64()), (Some(2), Some("acme"), Some(1)));

    // acme's oldest goes first; then acme is at its limit, so beta jumps ahead of acme's others.
    assert_eq!(claim().await.json()["id"], b2);
    assert_eq!(claim().await.json()["id"], b5);
    assert_eq!(claim().await.status, StatusCode::NO_CONTENT, "acme waits for its running build");
    let q = &get(b3).await["queue"];
    assert_eq!((q["ahead"].as_i64(), q["namespace_running"].as_i64()), (Some(0), Some(1)));
    assert_eq!(get(b2).await["queue"], Value::Null, "only queued builds have a place in the queue");

    // A running build still holds acme's slot until its agent reports back.
    send(&app, Method::POST, &format!("/api/v1/builds/{b2}/cancel"), &[], vec![]).await;
    assert_eq!(claim().await.status, StatusCode::NO_CONTENT);
}

/// Runners: no runner, no builds; namespaces register their own, superusers share theirs with
/// chosen namespaces, and each runner only gets builds of the namespaces it serves.
#[tokio::test]
async fn runners() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    for u in ["dan", "eve"] {
        let body = serde_json::to_vec(&json!({ "username": u, "password": "password123" })).unwrap();
        assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    }
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);
    let eve = cookie_of(&web_login(&app, "eve", "password123", None).await);
    let post = |who: String, path: &'static str, body: Value| { let app = app.clone(); async move { send(&app, Method::POST, path, &[("cookie", &who), jh], serde_json::to_vec(&body).unwrap()).await } };
    let meta = |who: String, repo: &'static str| { let app = app.clone(); async move { send(&app, Method::GET, &format!("/api/v1/repository-meta/{repo}"), &[("cookie", &who)], vec![]).await.json() } };
    let trigger = |repo: &'static str| json!({ "repository": repo, "name": "main", "git_url": "https://git.example.com/x.git", "branches": ["main"] });

    // No runner: no builds, and no triggers.
    assert_eq!(meta(dan.clone(), "dan/app").await["builds"], false);
    let r = post(dan.clone(), "/api/v1/build-triggers", trigger("dan/app")).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&r.body));

    // Dan registers a self-hosted runner for his namespace; nobody else's, and no shared ones.
    assert_eq!(post(eve.clone(), "/api/v1/runners", json!({ "name": "x", "namespace": "dan" })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(post(dan.clone(), "/api/v1/runners", json!({ "name": "x", "all_namespaces": true })).await.status, StatusCode::FORBIDDEN);
    let r = post(dan.clone(), "/api/v1/runners", json!({ "name": "laptop", "namespace": "dan" })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let dan_runner = r.json()["id"].as_i64().unwrap();
    let dan_token = format!("Bearer {}", r.json()["token"].as_str().unwrap());
    assert!(r.json()["token"].as_str().unwrap().starts_with("kr_"));
    assert_eq!(r.json()["status"], "never");
    assert_eq!(meta(dan.clone(), "dan/app").await["builds"], true);
    assert_eq!(meta(eve.clone(), "eve/app").await["builds"], false, "dan's runner is dan's");

    // The superuser shares a runner with eve only.
    let r = post(root.clone(), "/api/v1/runners", json!({ "name": "shared", "namespaces": ["eve"] })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let shared_token = format!("Bearer {}", r.json()["token"].as_str().unwrap());
    assert_eq!(r.json()["namespaces"], json!(["eve"]));
    assert_eq!(meta(eve.clone(), "eve/app").await["builds"], true);

    // Builds for both; each runner only gets its own namespaces' builds.
    let dt = post(dan.clone(), "/api/v1/build-triggers", trigger("dan/app")).await.json()["id"].as_i64().unwrap();
    let et = post(eve.clone(), "/api/v1/build-triggers", trigger("eve/app")).await.json()["id"].as_i64().unwrap();
    let eb = send(&app, Method::POST, &format!("/api/v1/build-triggers/{et}/run"), &[("cookie", &eve), jh], b"{}".to_vec()).await.json()["build"].as_i64().unwrap();
    let db = send(&app, Method::POST, &format!("/api/v1/build-triggers/{dt}/run"), &[("cookie", &dan), jh], b"{}".to_vec()).await.json()["build"].as_i64().unwrap();
    let claim = |token: String| { let app = app.clone(); async move { send(&app, Method::POST, "/api/v1/runner/claim", &[jh, ("authorization", &token)], br#"{"hostname":"box","version":"0.2.0","executor":"local","concurrency":2}"#.to_vec()).await } };
    let r = claim(dan_token.clone()).await;
    assert_eq!(r.json()["id"], db, "eve's older build is not for dan's runner");
    assert_eq!(claim(dan_token.clone()).await.status, StatusCode::NO_CONTENT);
    assert_eq!(claim(shared_token.clone()).await.json()["id"], eb);
    assert_eq!(claim("Bearer kr_nope".into()).await.status, StatusCode::UNAUTHORIZED);

    // The namespace sees its own runner's state, and the shared runner without its other details.
    let r = send(&app, Method::GET, "/api/v1/namespaces/dan/runners", &[("cookie", &dan)], vec![]).await.json();
    let list = r["runners"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{r}");
    assert_eq!((list[0]["name"].as_str(), list[0]["status"].as_str(), list[0]["hostname"].as_str(), list[0]["executor"].as_str()), (Some("laptop"), Some("online"), Some("box"), Some("local")));
    let r = send(&app, Method::GET, "/api/v1/namespaces/eve/runners", &[("cookie", &eve)], vec![]).await.json();
    assert_eq!(r["runners"][0]["name"], "shared");
    assert_eq!(r["runners"][0]["namespaces"], Value::Null);
    assert_eq!(send(&app, Method::GET, "/api/v1/namespaces/dan/runners", &[("cookie", &eve)], vec![]).await.status, StatusCode::FORBIDDEN);

    // Disabled or replaced tokens stop working.
    let body = serde_json::to_vec(&json!({ "name": "laptop", "is_enabled": false })).unwrap();
    assert_eq!(send(&app, Method::PUT, &format!("/api/v1/runners/{dan_runner}"), &[("cookie", &dan), jh], body).await.status, StatusCode::OK);
    assert_eq!(claim(dan_token.clone()).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(meta(dan.clone(), "dan/app").await["builds"], false);
}

/// Default quotas apply to namespaces without one of their own; an administrator can exempt one.
#[tokio::test]
async fn default_quotas() {
    let mut cfg = accounts_config();
    cfg.policy.default_user_quota = Some("1500".into());
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "username": "dan", "password": "password123" })).unwrap();
    send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await;
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &dan), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("dan", r.json()["token"].as_str().unwrap());
    let push = |tag: &'static str, layer: Vec<u8>| {
        let (app, auth) = (app.clone(), auth.clone());
        async move {
            let cfg = format!("{{\"tag\":\"{tag}\"}}").into_bytes();
            // Blob uploads are quota-checked too: a refused one is the push's answer.
            let cd = match push_blob_if_missing(&app, "dan/app", &cfg, Some(&auth)).await { Ok(d) => d, Err(r) => return r };
            let ld = match push_blob_if_missing(&app, "dan/app", &layer, Some(&auth)).await { Ok(d) => d, Err(r) => return r };
            send(&app, Method::PUT, &format!("/v2/dan/app/manifests/{tag}"), &[("authorization", &auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg.len(), &[(ld, layer.len())])).await
        }
    };
    assert_eq!(push("v1", vec![1u8; 1000]).await.status, StatusCode::CREATED);
    let r = push("v2", vec![2u8; 1000]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "the default quota applies");
    assert!(r.json()["errors"][0]["message"].as_str().unwrap().contains("quota exceeded"));
    let s = send(&app, Method::GET, "/api/v1/namespaces/dan/storage", &[("cookie", &dan)], vec![]).await.json();
    assert_eq!((s["quota"].as_u64(), s["quota_source"].as_str(), s["default_quota"].as_u64()), (Some(1500), Some("default"), Some(1500)));

    // 0 = no limit, even with a default; null = back to the default.
    let quota = |max: Value| { let (app, root) = (app.clone(), root.clone()); async move { send(&app, Method::PUT, "/api/v1/namespaces/dan/quota", &[("cookie", &root), ("content-type", "application/json")], serde_json::to_vec(&json!({ "max_bytes": max })).unwrap()).await.status } };
    assert_eq!(quota(json!(0)).await, StatusCode::OK);
    let s = send(&app, Method::GET, "/api/v1/namespaces/dan/storage", &[("cookie", &dan)], vec![]).await.json();
    assert_eq!((s["quota"].as_u64(), s["quota_source"].as_str()), (None, Some("namespace")));
    assert_eq!(push("v2", vec![2u8; 1000]).await.status, StatusCode::CREATED);
    assert_eq!(quota(json!(null)).await, StatusCode::OK);
    assert_eq!(push("v3", vec![3u8; 1000]).await.status, StatusCode::FORBIDDEN);
}

/// Namespace webhooks against a real receiver: filtering, signatures, formats, history,
/// test and redeliver, permissions, and refusing internal targets.
#[tokio::test]
async fn namespace_webhooks() {
    use std::sync::{Arc, Mutex};
    // A receiver recording what arrives.
    let got: Arc<Mutex<Vec<(axum::http::HeaderMap, String)>>> = Arc::default();
    let rec = got.clone();
    let receiver = axum::Router::new().route("/hook", axum::routing::post(move |h: axum::http::HeaderMap, body: String| {
        let rec = rec.clone();
        async move { rec.lock().unwrap().push((h, body)); "ok" }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, receiver).await.unwrap() });

    let mut cfg = accounts_config();
    cfg.policy.is_webhooks_allow_private_targets = true; // the receiver is on localhost
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    for u in ["dan", "eve"] {
        send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "username": u, "password": "password123" })).unwrap()).await;
    }
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);
    let eve = cookie_of(&web_login(&app, "eve", "password123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &dan), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("dan", r.json()["token"].as_str().unwrap());

    let hook = json!({ "name": "ci", "url": url, "events": ["push"], "repositories": ["app"], "secret": "s3cret", "auth_header": "Bearer xyz" });
    assert_eq!(send(&app, Method::POST, "/api/v1/namespaces/dan/webhooks", &[("cookie", &eve), jh], serde_json::to_vec(&hook).unwrap()).await.status, StatusCode::FORBIDDEN);
    let r = send(&app, Method::POST, "/api/v1/namespaces/dan/webhooks", &[("cookie", &dan), jh], serde_json::to_vec(&hook).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let id = r.json()["id"].as_i64().unwrap();
    assert_eq!((r.json()["has_secret"].as_bool(), r.json().get("secret")), (Some(true), None), "secrets are never returned");
    let bad = json!({ "name": "x", "url": url, "events": ["nope"] });
    assert_eq!(send(&app, Method::POST, "/api/v1/namespaces/dan/webhooks", &[("cookie", &dan), jh], serde_json::to_vec(&bad).unwrap()).await.status, StatusCode::BAD_REQUEST);

    let push = |repo: &'static str, tag: &'static str| {
        let (app, auth) = (app.clone(), auth.clone());
        async move {
            let cfg = format!("{{\"t\":\"{repo}{tag}\"}}").into_bytes();
            let cd = push_blob(&app, repo, &cfg, Some(&auth)).await;
            send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{tag}"), &[("authorization", &auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfg.len(), &[])).await.status
        }
    };
    assert_eq!(push("dan/other", "v1").await, StatusCode::CREATED, "filtered out by repository");
    assert_eq!(push("dan/app", "v1").await, StatusCode::CREATED);
    let wait = |n: usize| { let got = got.clone(); async move { for _ in 0..100 { if got.lock().unwrap().len() >= n { return; } tokio::time::sleep(std::time::Duration::from_millis(50)).await; } } };
    wait(1).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    {
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 1, "only dan/app matched");
        let (h, body) = &got[0];
        let e: Value = serde_json::from_str(body).unwrap();
        assert_eq!((e["type"].as_str(), e["repository"].as_str(), e["tag"].as_str(), e["actor"].as_str()), (Some("push"), Some("dan/app"), Some("v1"), Some("dan")));
        assert_eq!(h["authorization"], "Bearer xyz");
        assert_eq!(h["x-kontainer-event"], "push");
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"s3cret").unwrap();
        mac.update(body.as_bytes());
        assert_eq!(h["x-kontainer-signature"].to_str().unwrap(), format!("sha256={}", hex::encode(mac.finalize().into_bytes())));
    }
    // History, then a test ping, then redelivering the push.
    let ds = send(&app, Method::GET, &format!("/api/v1/namespaces/dan/webhooks/{id}/deliveries"), &[("cookie", &dan)], vec![]).await.json();
    assert_eq!((ds[0]["event"].as_str(), ds[0]["status"].as_str(), ds[0]["response_code"].as_i64()), (Some("push"), Some("succeeded"), Some(200)));
    let r = send(&app, Method::POST, &format!("/api/v1/namespaces/dan/webhooks/{id}/test"), &[("cookie", &dan)], vec![]).await.json();
    assert_eq!((r["event"].as_str(), r["status"].as_str()), (Some("ping"), Some("succeeded")));
    let push_delivery = ds[0]["id"].as_i64().unwrap();
    let r = send(&app, Method::POST, &format!("/api/v1/namespaces/dan/webhooks/{id}/deliveries/{push_delivery}/redeliver"), &[("cookie", &dan)], vec![]).await.json();
    assert_eq!(r["status"], "succeeded");
    {
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[2].1, got[0].1, "redelivery sends the same payload");
    }

    // Slack and CloudEvents formats.
    let edit = |format: &'static str| json!({ "name": "ci", "url": url, "format": format, "events": ["push"] });
    assert_eq!(send(&app, Method::PUT, &format!("/api/v1/namespaces/dan/webhooks/{id}"), &[("cookie", &dan), jh], serde_json::to_vec(&edit("slack")).unwrap()).await.status, StatusCode::OK);
    assert_eq!(push("dan/app", "v2").await, StatusCode::CREATED);
    wait(4).await;
    let (h, body) = got.lock().unwrap()[3].clone();
    let slack: Value = serde_json::from_str(&body).unwrap();
    assert!(slack["text"].as_str().unwrap().contains("`dan/app:v2`"), "{slack}");
    assert!(h.get("x-kontainer-signature").is_some(), "an update without `secret` keeps it");
    send(&app, Method::PUT, &format!("/api/v1/namespaces/dan/webhooks/{id}"), &[("cookie", &dan), jh], serde_json::to_vec(&edit("cloudevents")).unwrap()).await;
    assert_eq!(push("dan/app", "v3").await, StatusCode::CREATED);
    wait(5).await;
    let (h, body) = got.lock().unwrap()[4].clone();
    let ce: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(h["content-type"], "application/cloudevents+json");
    assert_eq!((ce["specversion"].as_str(), ce["type"].as_str(), ce["data"]["tag"].as_str()), (Some("1.0"), Some("dev.kontainer.push"), Some("v3")));

    assert_eq!(send(&app, Method::GET, "/api/v1/namespaces/dan/webhooks", &[("cookie", &eve)], vec![]).await.status, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, Method::DELETE, &format!("/api/v1/namespaces/dan/webhooks/{id}"), &[("cookie", &dan)], vec![]).await.status, StatusCode::NO_CONTENT);

    // With the default policy, internal targets are refused.
    let app2 = self::app(accounts_config()).await;
    let root2 = cookie_of(&web_login(&app2, "root", "rootpass123", None).await);
    let r = send(&app2, Method::POST, "/api/v1/namespaces/root/webhooks", &[("cookie", &root2), jh], serde_json::to_vec(&json!({ "name": "x", "url": "http://169.254.169.254/latest" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&r.body).contains("internal address"), "{}", String::from_utf8_lossy(&r.body));
}

/// Robot hygiene: default and explicit expiry, owners disabling and editing their robots,
/// rotation keeping the credential's lifetime, and the same for org robots.
#[tokio::test]
async fn robot_lifecycle() {
    let mut cfg = accounts_config();
    cfg.policy.robot_expiry_days = Some(30);
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "username": "dan", "password": "password123" })).unwrap()).await;
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);
    let days_left = |v: &Value| v["expires_at"].as_str().map(|e| (chrono::DateTime::parse_from_rfc3339(e).unwrap().to_utc() - chrono::Utc::now()).num_days());

    // The default applies; 0 means never.
    let r = send(&app, Method::POST, "/api/v1/auth/robots", &[("cookie", &dan), jh], br#"{"name":"ci"}"#.to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let (ci, token) = (r.json()["id"].as_i64().unwrap(), r.json()["token"].as_str().unwrap().to_string());
    let r = send(&app, Method::POST, "/api/v1/auth/robots", &[("cookie", &dan), jh], br#"{"name":"forever","expires_in_days":0}"#.to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let robots = send(&app, Method::GET, "/api/v1/auth/robots", &[("cookie", &dan)], vec![]).await.json();
    let find = |name: &str| robots.as_array().unwrap().iter().find(|r| r["username"] == name).cloned().unwrap();
    assert!(matches!(days_left(&find("dan+ci")), Some(29 | 30)));
    assert_eq!(find("dan+forever")["expires_at"], Value::Null);

    // The owner disables it: its credential stops working; enabling restores it.
    let login = |t: String| { let app = app.clone(); async move { send(&app, Method::GET, "/v2/", &[("authorization", &basic("dan+ci", &t))], vec![]).await.status } };
    assert_eq!(login(token.clone()).await, StatusCode::OK);
    let r = send(&app, Method::PATCH, &format!("/api/v1/auth/robots/{ci}"), &[("cookie", &dan), jh], br#"{"is_disabled":true,"description":"deploys"}"#.to_vec()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!((r.json()["is_disabled"].as_bool(), r.json()["display_name"].as_str()), (Some(true), Some("deploys")));
    assert_eq!(login(token.clone()).await, StatusCode::UNAUTHORIZED);
    send(&app, Method::PATCH, &format!("/api/v1/auth/robots/{ci}"), &[("cookie", &dan), jh], br#"{"is_disabled":false}"#.to_vec()).await;
    assert_eq!(login(token.clone()).await, StatusCode::OK);

    // Rotation keeps the lifetime unless told otherwise; the old credential stops working.
    let r = send(&app, Method::POST, &format!("/api/v1/auth/robots/{ci}/rotate"), &[("cookie", &dan), jh], b"{}".to_vec()).await;
    let new_token = r.json()["token"].as_str().unwrap().to_string();
    assert_eq!(login(token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(login(new_token).await, StatusCode::OK);
    let robots = send(&app, Method::GET, "/api/v1/auth/robots", &[("cookie", &dan)], vec![]).await.json();
    assert!(matches!(days_left(&robots.as_array().unwrap().iter().find(|r| r["username"] == "dan+ci").cloned().unwrap()), Some(29 | 30)));
    send(&app, Method::POST, &format!("/api/v1/auth/robots/{ci}/rotate"), &[("cookie", &dan), jh], br#"{"expires_in_days":5}"#.to_vec()).await;
    let robots = send(&app, Method::GET, "/api/v1/auth/robots", &[("cookie", &dan)], vec![]).await.json();
    assert!(matches!(days_left(&robots.as_array().unwrap().iter().find(|r| r["username"] == "dan+ci").cloned().unwrap()), Some(4 | 5)));

    // Someone else's robot is out of reach.
    send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "username": "eve", "password": "password123" })).unwrap()).await;
    let eve = cookie_of(&web_login(&app, "eve", "password123", None).await);
    assert_eq!(send(&app, Method::PATCH, &format!("/api/v1/auth/robots/{ci}"), &[("cookie", &eve), jh], br#"{"is_disabled":true}"#.to_vec()).await.status, StatusCode::NOT_FOUND);

    // Org robots: created with an expiry, disabled by an org admin.
    send(&app, Method::POST, "/api/v1/orgs", &[("cookie", &root), jh], br#"{"name":"acme"}"#.to_vec()).await;
    let r = send(&app, Method::POST, "/api/v1/orgs/acme/robots", &[("cookie", &root), jh], br#"{"name":"deploy","expires_in_days":90}"#.to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let id = r.json()["id"].as_i64().unwrap();
    let r = send(&app, Method::PATCH, &format!("/api/v1/orgs/acme/robots/{id}"), &[("cookie", &root), jh], br#"{"is_disabled":true}"#.to_vec()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["is_disabled"], true);
    assert!(matches!(days_left(&r.json()), Some(89 | 90)));
    assert_eq!(send(&app, Method::PATCH, &format!("/api/v1/orgs/acme/robots/{id}"), &[("cookie", &dan), jh], br#"{"is_disabled":false}"#.to_vec()).await.status, StatusCode::FORBIDDEN);
}

/// Maintenance runs are recorded with who started them and what they did.
#[tokio::test]
async fn maintenance_history() {
    let mut cfg = base_config();
    cfg.gc.interval = Some(std::time::Duration::from_secs(86400));
    let app = app(cfg).await;
    let r = send(&app, Method::POST, "/api/v1/gc?dry_run=true&grace_seconds=0", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::POST, "/api/v1/gc?grace_seconds=0", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let h = send(&app, Method::GET, "/api/v1/maintenance/gc/runs", &[], vec![]).await.json();
    assert_eq!(h["interval"], "24h");
    let runs = h["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!((runs[0]["status"].as_str(), runs[0]["trigger"].as_str()), (Some("succeeded"), Some("manual")));
    assert!(runs[0]["summary"].as_str().unwrap().starts_with("freed"), "{}", runs[0]);
    assert!(runs[1]["summary"].as_str().unwrap().starts_with("Dry run: would free"), "{}", runs[1]);
    assert_eq!(send(&app, Method::GET, "/api/v1/maintenance/nope/runs", &[], vec![]).await.status, StatusCode::NOT_FOUND);
    // Scanning everything needs a scanner.
    assert_eq!(send(&app, Method::POST, "/api/v1/scans/all", &[], vec![]).await.status, StatusCode::METHOD_NOT_ALLOWED);
}

/// Pull policies: blocking on vulnerabilities (with allowlists), unscanned images, and
/// signatures; the scanner itself is never blocked.
#[tokio::test]
async fn security_policies() {
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::EncodePublicKey;
    let mut cfg = accounts_config();
    cfg.scanner.block_pull_at = Some(kontainer_core::config::Severity::High);
    let state = kontainer_server::build_state(cfg).await.unwrap();
    let app = kontainer_server::build_router(state.clone());
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("root", r.json()["token"].as_str().unwrap());
    let push = |tag: String, body: Vec<u8>| { let (app, auth) = (app.clone(), auth.clone()); async move {
        let r = send(&app, Method::PUT, &format!("/v2/root/app/manifests/{tag}"), &[("authorization", &auth), ("content-type", OCI_MANIFEST)], body).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
        r.header("docker-content-digest").parse::<Digest>().unwrap()
    } };
    let image = |seed: &'static str| { let (app, auth) = (app.clone(), auth.clone()); async move {
        let cfg = format!("{{\"seed\":\"{seed}\"}}").into_bytes();
        let cd = push_blob(&app, "root/app", &cfg, Some(&auth)).await;
        image_manifest(&cd, cfg.len(), &[])
    } };
    let d1 = push("v1".into(), image("v1").await).await;
    let pull = |tag: &'static str| { let (app, auth) = (app.clone(), auth.clone()); async move {
        send(&app, Method::GET, &format!("/v2/root/app/manifests/{tag}"), &[("authorization", &auth), ("accept", OCI_MANIFEST)], vec![]).await
    } };
    // A finished scan with one high vulnerability.
    let report = json!({ "status": "done", "scanner": "trivy", "digest": d1.to_string(), "repository": "root/app", "summary": { "high": 1 }, "total": 1,
        "vulnerabilities": [{ "id": "CVE-2024-0001", "severity": "high", "package": "openssl" }] });
    state.storage.put_scan(&d1, serde_json::to_vec(&report).unwrap()).await.unwrap();

    // The registry default blocks it; a namespace allowlist entry lets it through.
    let r = pull("v1").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&r.body).contains("CVE-2024-0001"), "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::POST, "/api/v1/namespaces/root/cve-allowlist", &[("cookie", &root), jh], br#"{"cve":"CVE-2024-0001","reason":"not reachable"}"#.to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let entry = r.json()["id"].as_i64().unwrap();
    assert_eq!(pull("v1").await.status, StatusCode::OK);
    send(&app, Method::DELETE, &format!("/api/v1/namespaces/root/cve-allowlist/{entry}"), &[("cookie", &root)], vec![]).await;
    assert_eq!(pull("v1").await.status, StatusCode::FORBIDDEN);

    // The namespace turns blocking off; back on, a registry-wide entry works too.
    let policy = |body: Value| { let (app, root) = (app.clone(), root.clone()); async move {
        send(&app, Method::PUT, "/api/v1/namespaces/root/security", &[("cookie", &root), ("content-type", "application/json")], serde_json::to_vec(&body).unwrap()).await
    } };
    assert_eq!(policy(json!({ "block_severity": "none" })).await.status, StatusCode::OK);
    assert_eq!(pull("v1").await.status, StatusCode::OK);
    assert_eq!(policy(json!({ "block_severity": "bogus" })).await.status, StatusCode::BAD_REQUEST);
    policy(json!({ "block_severity": null })).await;
    assert_eq!(send(&app, Method::POST, "/api/v1/cve-allowlist", &[("cookie", &root), jh], br#"{"cve":"CVE-2024-0001"}"#.to_vec()).await.status, StatusCode::CREATED);
    assert_eq!(pull("v1").await.status, StatusCode::OK);

    // Unscanned images.
    push("v2".into(), image("v2").await).await;
    assert_eq!(pull("v2").await.status, StatusCode::OK);
    policy(json!({ "is_block_unscanned": true })).await;
    let r = pull("v2").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&r.body).contains("has not been scanned"));

    // Signatures from a trusted key.
    let sk = p256::ecdsa::SigningKey::from_slice(&[21u8; 32]).unwrap();
    let pem = sk.verifying_key().to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap();
    assert_eq!(policy(json!({ "is_require_signature": true, "signing_keys": ["not a key"] })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(policy(json!({ "is_require_signature": true, "signing_keys": [pem] })).await.status, StatusCode::OK);
    let r = pull("v1").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&r.body).contains("trusted keys"));
    let payload = serde_json::to_vec(&json!({ "critical": { "identity": { "docker-reference": "registry.test/root/app" }, "image": { "docker-manifest-digest": d1.to_string() }, "type": "cosign container image signature" }, "optional": null })).unwrap();
    let sig: p256::ecdsa::Signature = sk.sign(&payload);
    let payload_blob = push_blob(&app, "root/app", &payload, Some(&auth)).await;
    let empty = push_blob(&app, "root/app", b"{}", Some(&auth)).await;
    let sig_manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": empty.to_string(), "size": 2 },
        "layers": [{ "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": payload_blob.to_string(), "size": payload.len(),
            "annotations": { "dev.cosignproject.cosign/signature": base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()) } }],
    })).unwrap();
    push(format!("sha256-{}.sig", d1.to_string().trim_start_matches("sha256:")), sig_manifest).await;
    assert_eq!(pull("v1").await.status, StatusCode::OK, "signed with the trusted key");
    // A different trusted key: the same signature no longer counts.
    let other = p256::ecdsa::SigningKey::from_slice(&[22u8; 32]).unwrap().verifying_key().to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap();
    policy(json!({ "is_require_signature": true, "signing_keys": [other] })).await;
    assert_eq!(pull("v1").await.status, StatusCode::FORBIDDEN);
    // Any signature will do without keys.
    policy(json!({ "is_require_signature": true })).await;
    assert_eq!(pull("v1").await.status, StatusCode::OK);

    // The scanner is never blocked (or it could never scan).
    let mut cfg = accounts_config();
    cfg.scanner.block_pull_at = Some(kontainer_core::config::Severity::High);
    cfg.scanner.username = Some("root".into());
    let state2 = kontainer_server::build_state(cfg).await.unwrap();
    let app2 = kontainer_server::build_router(state2.clone());
    let root2 = cookie_of(&web_login(&app2, "root", "rootpass123", None).await);
    let r = send(&app2, Method::POST, "/api/v1/auth/tokens", &[("cookie", &root2), jh], serde_json::to_vec(&json!({ "name": "s" })).unwrap()).await;
    let auth2 = basic("root", r.json()["token"].as_str().unwrap());
    let cfgb = br#"{"x":1}"#;
    let cd = push_blob(&app2, "root/app", cfgb, Some(&auth2)).await;
    let r = send(&app2, Method::PUT, "/v2/root/app/manifests/v1", &[("authorization", &auth2), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfgb.len(), &[])).await;
    let d = r.header("docker-content-digest").parse::<Digest>().unwrap();
    state2.storage.put_scan(&d, serde_json::to_vec(&json!({ "status": "done", "scanner": "trivy", "digest": d.to_string(), "repository": "root/app", "summary": { "critical": 1 }, "total": 1, "vulnerabilities": [{ "id": "CVE-1", "severity": "critical", "package": "x" }] })).unwrap()).await.unwrap();
    assert_eq!(send(&app2, Method::GET, "/v2/root/app/manifests/v1", &[("authorization", &auth2), ("accept", OCI_MANIFEST)], vec![]).await.status, StatusCode::OK);
}

/// Push replication to a second, real registry: on push (with signatures following), a full
/// run with a tag filter and a destination prefix, and deletions.
#[tokio::test]
async fn push_replication() {
    // The target: another kontainer over real HTTP.
    let mut tcfg = base_config();
    tcfg.features.is_delete = true;
    let target = kontainer_server::build_router(kontainer_server::build_state(tcfg).await.unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let t = target.clone();
    tokio::spawn(async move { axum::serve(listener, t).await.unwrap() });

    let mut cfg = base_config();
    cfg.features.is_delete = true;
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let r = send(&app, Method::POST, "/api/v1/registries", &[jh], serde_json::to_vec(&json!({ "name": "dr", "url": url })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let reg = r.json()["id"].as_i64().unwrap();
    let rule = json!({ "name": "to-dr", "registry_id": reg, "repositories": ["acme/**"], "trigger": "push", "is_replicate_deletes": true });
    let r = send(&app, Method::POST, "/api/v1/replication-rules", &[jh], serde_json::to_vec(&rule).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let id = r.json()["id"].as_i64().unwrap();
    let bad = json!({ "name": "x", "registry_id": reg, "trigger": "schedule", "interval_secs": 5 });
    assert_eq!(send(&app, Method::POST, "/api/v1/replication-rules", &[jh], serde_json::to_vec(&bad).unwrap()).await.status, StatusCode::BAD_REQUEST);

    let push = |repo: &'static str, tag: String, seed: &'static str| { let app = app.clone(); async move {
        let cfg = format!("{{\"seed\":\"{seed}\"}}").into_bytes();
        let layer = format!("layer {seed}").into_bytes();
        let cd = push_blob(&app, repo, &cfg, None).await;
        let ld = push_blob(&app, repo, &layer, None).await;
        put_manifest(&app, repo, &tag, image_manifest(&cd, cfg.len(), &[(ld, layer.len())])).await
    } };
    let on_target = |path: String| { let t = target.clone(); async move { send(&t, Method::HEAD, &path, &[("accept", OCI_MANIFEST)], vec![]).await } };
    let wait_for = |path: String, present: bool| { async move {
        for _ in 0..100 {
            if (on_target(path.clone()).await.status == StatusCode::OK) == present { return true; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    } };

    // On push: the image, its blobs and its signature arrive.
    let d = push("acme/api", "v1".into(), "a").await;
    assert!(wait_for("/v2/acme/api/manifests/v1".into(), true).await, "replicated on push");
    assert_eq!(on_target("/v2/acme/api/manifests/v1".into()).await.header("docker-content-digest"), d.to_string());
    let sig_tag = format!("{}.sig", d.to_string().replace(':', "-"));
    push("acme/api", sig_tag.clone(), "sig").await;
    assert!(wait_for(format!("/v2/acme/api/manifests/{sig_tag}"), true).await, "signatures follow");
    push("other/app", "v1".into(), "o").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(on_target("/v2/other/app/manifests/v1".into()).await.status, StatusCode::NOT_FOUND, "not covered by the rule");

    // Deletions follow.
    assert_eq!(send(&app, Method::DELETE, "/v2/acme/api/manifests/v1", &[], vec![]).await.status, StatusCode::ACCEPTED);
    assert!(wait_for("/v2/acme/api/manifests/v1".into(), false).await, "deletion replicated");

    // A manual full run with a tag filter and a destination prefix.
    push("acme/api", "v2".into(), "b").await;
    push("acme/api", "dev".into(), "c").await;
    let manual = json!({ "name": "to-dr", "registry_id": reg, "repositories": ["acme/**"], "tags": ["v*"], "destination": "mirror", "trigger": "manual" });
    assert_eq!(send(&app, Method::PUT, &format!("/api/v1/replication-rules/{id}"), &[jh], serde_json::to_vec(&manual).unwrap()).await.status, StatusCode::OK);
    assert_eq!(send(&app, Method::POST, &format!("/api/v1/replication-rules/{id}/run"), &[], vec![]).await.status, StatusCode::ACCEPTED);
    assert!(wait_for("/v2/mirror/acme/api/manifests/v2".into(), true).await, "full run copies matching tags under the prefix");
    assert_eq!(on_target("/v2/mirror/acme/api/manifests/dev".into()).await.status, StatusCode::NOT_FOUND, "tag filter");
    // History: push runs, the delete, and the manual run (the newest may still be finishing).
    let mut runs = Value::Null;
    for _ in 0..100 {
        runs = send(&app, Method::GET, &format!("/api/v1/replication-rules/{id}/runs"), &[], vec![]).await.json();
        if runs[0]["status"] != "running" && runs[0]["trigger"] == "manual" { break; }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!((runs[0]["trigger"].as_str(), runs[0]["status"].as_str()), (Some("manual"), Some("succeeded")), "{runs}");
    assert!(runs[0]["summary"].as_str().unwrap().starts_with("1 tags copied"), "{}", runs[0]);
    assert!(runs.as_array().unwrap().iter().any(|r| r["trigger"] == "delete" && r["status"] == "succeeded"));
    let rules = send(&app, Method::GET, "/api/v1/replication-rules", &[], vec![]).await.json();
    assert_eq!(rules[0]["last_status"], "succeeded");
}

/// A manifest whose `mediaType` is not a media type (here with a header-splitting newline) is
/// refused at push, so it can never reach a `Content-Type` header on pull.
#[tokio::test]
async fn invalid_manifest_media_type_is_rejected() {
    let app = app(base_config()).await;
    let repo = "library/mt";
    let cfg = br#"{"os":"linux","architecture":"amd64"}"#;
    let cd = push_blob(&app, repo, cfg, None).await;
    for bad in ["application/vnd.oci.image.manifest.v1+json\r\nX-Evil: 1", "not a media type", "application/"] {
        let m = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": bad,
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd.to_string(), "size": cfg.len() },
            "layers": [],
        }))
        .unwrap();
        let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v1"), &[], m).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad:?}: {}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["errors"][0]["code"], "MANIFEST_INVALID");
    }
    // Nothing was stored under the tag.
    let r = send(&app, Method::GET, &format!("/v2/{repo}/manifests/v1"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // A well-formed one with parameters is fine and served back as pushed.
    let m = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd.to_string(), "size": cfg.len() },
        "layers": [],
    }))
    .unwrap();
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v1"), &[("content-type", OCI_MANIFEST)], m).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(&app, Method::GET, &format!("/v2/{repo}/manifests/v1"), &[], vec![]).await;
    assert_eq!(r.header("content-type"), OCI_MANIFEST);
    // A bad page size is a 400 with a code from the spec's table.
    let r = send(&app, Method::GET, &format!("/v2/{repo}/tags/list?n=lots"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.json()["errors"][0]["code"], "UNSUPPORTED");
}

/// The pull policy covers the UI's ways of getting at image content: export and layer file
/// listings are refused, and the manifest detail leaves out layer and config digests.
#[tokio::test]
async fn pull_policy_applies_to_export_and_layer_listing() {
    let mut cfg = accounts_config();
    cfg.scanner.block_pull_at = Some(kontainer_core::config::Severity::High);
    let state = kontainer_server::build_state(cfg).await.unwrap();
    let app = kontainer_server::build_router(state.clone());
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("root", r.json()["token"].as_str().unwrap());
    let cfgb = br#"{"architecture":"amd64","os":"linux"}"#;
    let layer = gzip_tar_layer();
    let cd = push_blob(&app, "root/app", cfgb, Some(&auth)).await;
    let ld = push_blob(&app, "root/app", &layer, Some(&auth)).await;
    let r = send(&app, Method::PUT, "/v2/root/app/manifests/v1", &[("authorization", &auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfgb.len(), &[(ld.clone(), layer.len())])).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let d: Digest = r.header("docker-content-digest").parse().unwrap();

    // Allowed while clean.
    let ch = [("cookie", root.as_str())];
    let export = || send(&app, Method::GET, "/api/v1/repositories/root/app/manifests/v1/export", &ch, vec![]);
    assert_eq!(export().await.status, StatusCode::OK);
    let files = format!("/api/v1/repositories/root/app/manifests/v1/layers/{ld}/files");
    assert_eq!(send(&app, Method::GET, &files, &[("cookie", &root)], vec![]).await.status, StatusCode::OK);

    // A high vulnerability: the registry default blocks pulls, and the UI routes with them.
    let report = json!({ "status": "done", "scanner": "trivy", "digest": d.to_string(), "repository": "root/app", "summary": { "high": 1 }, "total": 1,
        "vulnerabilities": [{ "id": "CVE-2024-0002", "severity": "high", "package": "zlib" }] });
    state.storage.put_scan(&d, serde_json::to_vec(&report).unwrap()).await.unwrap();
    let r = send(&app, Method::GET, "/v2/root/app/manifests/v1", &[("authorization", &auth), ("accept", OCI_MANIFEST)], vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = export().await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("CVE-2024-0002"));
    assert_eq!(send(&app, Method::GET, &format!("/api/v1/repositories/root/app/manifests/{d}/export"), &[("cookie", &root)], vec![]).await.status, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, Method::GET, &files, &[("cookie", &root)], vec![]).await.status, StatusCode::FORBIDDEN);
    let detail = send(&app, Method::GET, "/api/v1/repositories/root/app/manifests/v1", &[("cookie", &root)], vec![]).await;
    assert_eq!(detail.status, StatusCode::OK);
    let detail = detail.json();
    assert!(detail["blocked"].as_str().is_some_and(|m| m.contains("CVE-2024-0002")), "{detail}");
    assert_eq!(detail["layers"], json!([]));
    assert!(detail["raw"].is_null() && detail.get("config").is_none());
    assert!(!detail.to_string().contains(&ld.to_string()), "layer digest leaked: {detail}");
}

/// Archive imports go through the same gates as pushes: immutable tags and read-only
/// repositories.
#[tokio::test]
async fn archive_import_respects_immutable_tags_and_repository_state() {
    let mut cfg = accounts_config();
    cfg.policy.immutable_tags = vec![ImmutableTagRule { repositories: vec!["root/locked".into()], tags: vec!["v*".into()] }];
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("root", r.json()["token"].as_str().unwrap());
    let push_image = |repo: &'static str, seed: &'static str| {
        let (app, auth) = (app.clone(), auth.clone());
        async move {
            let cfgb = format!("{{\"os\":\"linux\",\"architecture\":\"amd64\",\"seed\":\"{seed}\"}}").into_bytes();
            let cd = push_blob(&app, repo, &cfgb, Some(&auth)).await;
            let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v1"), &[("authorization", &auth), ("content-type", OCI_MANIFEST)], image_manifest(&cd, cfgb.len(), &[])).await;
            assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
            r.header("docker-content-digest")
        }
    };
    let src = push_image("root/src", "a").await;
    let locked = push_image("root/locked", "b").await;
    assert_ne!(src, locked);
    let tarball = send(&app, Method::GET, "/api/v1/repositories/root/src/manifests/v1/export", &[("cookie", &root)], vec![]).await.body;

    // Re-pointing the immutable tag by import is refused, and the tag stays put.
    let r = send(&app, Method::POST, "/api/v1/import/archive/root/locked?tag=v1", &[("cookie", &root)], tarball.clone()).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json()["message"].as_str().unwrap().contains("immutable"));
    let r = send(&app, Method::HEAD, "/v2/root/locked/manifests/v1", &[("authorization", &auth), ("accept", OCI_MANIFEST)], vec![]).await;
    assert_eq!(r.header("docker-content-digest"), locked);
    // A tag the rule does not cover imports fine.
    let r = send(&app, Method::POST, "/api/v1/import/archive/root/locked?tag=latest", &[("cookie", &root)], tarball.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    // An invalid tag is a 400 before anything is read.
    let r = send(&app, Method::POST, "/api/v1/import/archive/root/locked?tag=-bad", &[("cookie", &root)], tarball.clone()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Read-only repositories take no imports (and no blob deletes).
    let r = send(&app, Method::PUT, "/api/v1/repositories/root/src/state", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "state": "read_only" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::POST, "/api/v1/import/archive/root/src?tag=restored", &[("cookie", &root)], tarball).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::DELETE, "/api/v1/repositories/root/src", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "{}", String::from_utf8_lossy(&r.body));
}

#[tokio::test]
async fn blob_uploads_respect_max_blob_size() {
    let mut cfg = base_config();
    cfg.server.max_blob_size = Some("16".into());
    let app = app(cfg).await;
    let oct = ("content-type", "application/octet-stream");

    // Within the limit (exactly 16 bytes): accepted.
    let ok = b"sixteen bytes!!!";
    let ok_d = Digest::sha256_of(ok);
    let r = send(&app, Method::POST, &format!("/v2/big/blobs/uploads/?digest={ok_d}"), &[oct], ok.to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));

    // Monolithic, no Content-Length: refused while streaming.
    let big = b"seventeen bytes!!";
    let big_d = Digest::sha256_of(big);
    let r = send(&app, Method::POST, &format!("/v2/big/blobs/uploads/?digest={big_d}"), &[oct], big.to_vec()).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["errors"][0]["code"], "SIZE_INVALID");
    assert_eq!(r.json()["errors"][0]["detail"]["max_blob_size"], 16);
    let r = send(&app, Method::HEAD, &format!("/v2/big/blobs/{big_d}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Chunked: each PATCH fits, together they don't. The session is dropped.
    let r = send(&app, Method::POST, "/v2/big/blobs/uploads/", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let loc = r.header("location");
    let r = send(&app, Method::PATCH, &loc, &[oct], b"0123456789".to_vec()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::PATCH, &loc, &[oct], b"0123456789".to_vec()).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let r = send(&app, Method::GET, &loc, &[], vec![]).await;
    assert_eq!(r.json()["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN", "an oversized upload can't be resumed");

    // A declared Content-Length over the limit is refused before the body is read, also on
    // the final PUT.
    let r = send(&app, Method::POST, "/v2/big/blobs/uploads/", &[], vec![]).await;
    let loc = r.header("location");
    let r = send(&app, Method::PUT, &format!("{loc}?digest={big_d}"), &[oct, ("content-length", "17")], big.to_vec()).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// Push a blob unless the repository already has it (what real clients do: `HEAD` first).
/// `Err` carries the response that refused the upload.
async fn push_blob_if_missing(app: &Router, repo: &str, data: &[u8], auth: Option<&str>) -> Result<Digest, Resp> {
    let digest = Digest::sha256_of(data);
    let h: Vec<(&str, &str)> = auth.map(|a| ("authorization", a)).into_iter().collect();
    if send(app, Method::HEAD, &format!("/v2/{repo}/blobs/{digest}"), &h, vec![]).await.status == StatusCode::OK {
        return Ok(digest);
    }
    let r = send(app, Method::POST, &format!("/v2/{repo}/blobs/uploads/"), &h, vec![]).await;
    if r.status != StatusCode::ACCEPTED {
        return Err(r);
    }
    let loc = r.header("location");
    let mut ph = h.clone();
    ph.push(("content-type", "application/octet-stream"));
    let (a, b) = data.split_at(data.len() / 2);
    let r = send(app, Method::PATCH, &loc, &ph, a.to_vec()).await;
    if r.status != StatusCode::ACCEPTED {
        return Err(r);
    }
    let r = send(app, Method::PUT, &format!("{loc}?digest={digest}"), &ph, b.to_vec()).await;
    if r.status != StatusCode::CREATED {
        return Err(r);
    }
    Ok(digest)
}

/// A chunk's `Content-Range` must start at the session's offset and span exactly its body;
/// anything else is `416` and leaves the session as it was.
#[tokio::test]
async fn chunk_content_range_is_validated() {
    let app = app(base_config()).await;
    let r = send(&app, Method::POST, "/v2/a/blobs/uploads/", &[], vec![]).await;
    let loc = r.header("location");
    let oct = ("content-type", "application/octet-stream");
    let r = send(&app, Method::PATCH, &loc, &[oct, ("content-range", "0-2")], b"abc".to_vec()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.header("range"), "0-2");
    for bad in ["0-2", "3-5", "3-3", "2-3", "x-y", "5-3"] {
        let r = send(&app, Method::PATCH, &loc, &[oct, ("content-range", bad)], b"de".to_vec()).await;
        assert_eq!(r.status, StatusCode::RANGE_NOT_SATISFIABLE, "{bad}");
        assert_eq!(r.json()["errors"][0]["code"], "BLOB_UPLOAD_INVALID", "{bad}");
        assert_eq!(r.header("range"), "0-2", "{bad}: nothing of the chunk was kept");
    }
    // A declared Content-Length that disagrees with the range is refused up front.
    let r = send(&app, Method::PATCH, &loc, &[oct, ("content-range", "3-4"), ("content-length", "3")], b"de".to_vec()).await;
    assert_eq!(r.status, StatusCode::RANGE_NOT_SATISFIABLE);
    let r = send(&app, Method::PATCH, &loc, &[oct, ("content-range", "3-4")], b"de".to_vec()).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert_eq!(r.header("range"), "0-4");
    let d = Digest::sha256_of(b"abcde");
    let r = send(&app, Method::PUT, &format!("{loc}?digest={d}"), &[oct], vec![]).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
}

/// Two registry instances on one database and one (filesystem) store, each with its own local
/// `upload_dir`.
async fn two_instances() -> (kontainer_server::state::AppState, kontainer_server::state::AppState, std::path::PathBuf) {
    let mut cfg = base_config();
    let root = tempfile::tempdir().unwrap().keep();
    cfg.storage.driver = StorageDriver::Filesystem;
    cfg.storage.filesystem.root = root.join("store");
    let mut other = cfg.clone();
    other.storage.upload_dir = root.join("uploads-b");
    let a = kontainer_server::build_state(cfg).await.unwrap();
    let b = kontainer_server::build_state(other).await.unwrap();
    (a, b, root.join("store"))
}

/// Chunk objects of upload `id` on disk.
fn staged_chunks(store: &std::path::Path, id: &str) -> usize {
    std::fs::read_dir(store.join("_upload_chunks").join(id)).map(|d| d.count()).unwrap_or(0)
}

/// Behind a load balancer every request of a chunked upload may reach another instance: the
/// session is in the database and the chunks in the shared store, so that works.
#[tokio::test]
async fn chunked_upload_across_instances() {
    let (a, b, store) = two_instances().await;
    let states = [a, b];
    // A fresh router per request, alternating instances.
    let via = |i: usize| kontainer_server::build_router(states[i % 2].clone());
    let oct = ("content-type", "application/octet-stream");
    let data = b"hello across instances".to_vec();
    let r = send(&via(0), Method::POST, "/v2/acme/app/blobs/uploads/", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let loc = r.header("location");
    let id = r.header("docker-upload-uuid");
    let mut offset = 0;
    for (i, part) in data.chunks(5).enumerate() {
        let range = format!("{}-{}", offset, offset + part.len() - 1);
        let r = send(&via(i + 1), Method::PATCH, &loc, &[oct, ("content-range", &range)], part.to_vec()).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "chunk {i}: {}", String::from_utf8_lossy(&r.body));
        offset += part.len();
        assert_eq!(r.header("range"), format!("0-{}", offset - 1));
        // Status from the other instance.
        let r = send(&via(i), Method::GET, &loc, &[], vec![]).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        assert_eq!(r.header("range"), format!("0-{}", offset - 1));
    }
    assert_eq!(staged_chunks(&store, &id), data.chunks(5).count());
    // A stale chunk replayed on the other instance is refused.
    let r = send(&via(1), Method::PATCH, &loc, &[oct, ("content-range", "0-4")], data[..5].to_vec()).await;
    assert_eq!(r.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(r.header("range"), format!("0-{}", data.len() - 1));
    let d = Digest::sha256_of(&data);
    let r = send(&via(0), Method::PUT, &format!("{loc}?digest={d}"), &[oct], vec![]).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&via(1), Method::GET, &format!("/v2/acme/app/blobs/{d}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, data);
    assert_eq!(staged_chunks(&store, &id), 0, "staging objects are removed");
    assert_eq!(send(&via(1), Method::GET, &loc, &[], vec![]).await.status, StatusCode::NOT_FOUND);

    // Cancelling works from any instance too.
    let r = send(&via(0), Method::POST, "/v2/acme/app/blobs/uploads/", &[], vec![]).await;
    let (loc, id) = (r.header("location"), r.header("docker-upload-uuid"));
    assert_eq!(send(&via(1), Method::PATCH, &loc, &[oct], b"abc".to_vec()).await.status, StatusCode::ACCEPTED);
    assert_eq!(send(&via(0), Method::DELETE, &loc, &[], vec![]).await.status, StatusCode::NO_CONTENT);
    assert_eq!(send(&via(1), Method::GET, &loc, &[], vec![]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(staged_chunks(&store, &id), 0);
}

/// Abandoned uploads are purged after `storage.upload_ttl`: the session and its chunk objects.
#[tokio::test]
async fn expired_uploads_lose_their_staging_objects() {
    let (a, b, store) = two_instances().await;
    let oct = ("content-type", "application/octet-stream");
    let app = kontainer_server::build_router(a.clone());
    let r = send(&app, Method::POST, "/v2/acme/app/blobs/uploads/", &[], vec![]).await;
    let (loc, id) = (r.header("location"), r.header("docker-upload-uuid"));
    assert_eq!(send(&app, Method::PATCH, &loc, &[oct], b"abc".to_vec()).await.status, StatusCode::ACCEPTED);
    assert_eq!(send(&app, Method::PATCH, &loc, &[oct], b"def".to_vec()).await.status, StatusCode::ACCEPTED);
    assert_eq!(staged_chunks(&store, &id), 2);
    // Not stale yet.
    assert_eq!(b.storage.purge_stale_uploads(std::time::Duration::from_secs(3600)).await.unwrap().sessions, 0);
    assert_eq!(staged_chunks(&store, &id), 2);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    // The other instance's reaper sees the session too.
    let purged = b.storage.purge_stale_uploads(std::time::Duration::ZERO).await.unwrap();
    assert_eq!(purged.sessions, 1, "{purged:?}");
    assert_eq!(staged_chunks(&store, &id), 0);
    let r = send(&app, Method::GET, &loc, &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.json()["errors"][0]["code"], "BLOB_UPLOAD_UNKNOWN");
}

/// Concurrent PATCHes for the same offset, on different instances: exactly one is recorded.
#[tokio::test]
async fn concurrent_chunks_for_one_offset() {
    let (a, b, store) = two_instances().await;
    let oct = ("content-type", "application/octet-stream");
    let (app_a, app_b) = (kontainer_server::build_router(a), kontainer_server::build_router(b));
    for round in 0..5 {
        let r = send(&app_a, Method::POST, "/v2/acme/app/blobs/uploads/", &[], vec![]).await;
        let (loc, id) = (r.header("location"), r.header("docker-upload-uuid"));
        let (x, y) = (format!("xxxx{round}").into_bytes(), format!("yyyy{round}").into_bytes());
        let h = [oct, ("content-range", "0-4")];
        let (ra, rb) = tokio::join!(send(&app_a, Method::PATCH, &loc, &h, x.clone()), send(&app_b, Method::PATCH, &loc, &h, y.clone()));
        let ok: Vec<_> = [(&ra, &x), (&rb, &y)].into_iter().filter(|(r, _)| r.status == StatusCode::ACCEPTED).collect();
        assert_eq!(ok.len(), 1, "round {round}: {} and {}", ra.status, rb.status);
        let loser = if ra.status == StatusCode::ACCEPTED { &rb } else { &ra };
        assert_eq!(loser.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(loser.header("range"), "0-4");
        assert_eq!(staged_chunks(&store, &id), 1, "the losing chunk's object is deleted");
        let won = ok[0].1;
        let d = Digest::sha256_of(won);
        let r = send(&app_b, Method::PUT, &format!("{loc}?digest={d}"), &[oct], vec![]).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    }
}

/// Manifest PUT: the body's mediaType must match a manifest Content-Type; digests are checked
/// with their own algorithm; a body without mediaType is served with its push-time type.
#[tokio::test]
async fn manifest_put_media_type_and_digest_algorithm() {
    use kontainer_core::digest::Algorithm;
    use kontainer_core::manifest::DOCKER_MANIFEST;
    let app = app(base_config()).await;
    let repo = "acme/app";
    let cfgb = br#"{"architecture":"amd64","os":"linux"}"#;
    let layer = b"layer".to_vec();
    let cd = push_blob(&app, repo, cfgb, None).await;
    let ld = push_blob(&app, repo, &layer, None).await;
    let m = image_manifest(&cd, cfgb.len(), &[(ld.clone(), layer.len())]);

    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v1"), &[("content-type", OCI_INDEX)], m.clone()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["errors"][0]["code"], "MANIFEST_INVALID");
    // Parameters and case do not make a mismatch; a non-manifest Content-Type is not compared.
    for ct in ["application/vnd.oci.image.manifest.v1+json; charset=utf-8", "application/json"] {
        let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/v1"), &[("content-type", ct)], m.clone()).await;
        assert_eq!(r.status, StatusCode::CREATED, "{ct}: {}", String::from_utf8_lossy(&r.body));
    }

    // By sha512 digest.
    let mut h = Digest::hasher(Algorithm::Sha512);
    h.update(&m);
    let d512 = h.finalize();
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{d512}"), &[("content-type", OCI_MANIFEST)], m.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.header("docker-content-digest"), d512.to_string());
    let r = send(&app, Method::GET, &format!("/v2/{repo}/manifests/{d512}"), &[], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, m);
    let mut wrong = m.clone();
    wrong.push(b'\n');
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{d512}"), &[("content-type", OCI_MANIFEST)], wrong).await;
    assert_eq!(r.json()["errors"][0]["code"], "DIGEST_INVALID");

    // No mediaType in the body: GET answers with the Content-Type it was pushed with.
    let bare = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "config": { "mediaType": "application/vnd.docker.container.image.v1+json", "digest": cd.to_string(), "size": cfgb.len() },
        "layers": [{ "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": ld.to_string(), "size": layer.len() }],
    }))
    .unwrap();
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/docker"), &[("content-type", DOCKER_MANIFEST)], bare).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::GET, &format!("/v2/{repo}/manifests/docker"), &[], vec![]).await;
    assert_eq!(r.header("content-type"), DOCKER_MANIFEST);
    let r = send(&app, Method::HEAD, &format!("/v2/{repo}/manifests/docker"), &[], vec![]).await;
    assert_eq!(r.header("content-type"), DOCKER_MANIFEST);
}

/// The SBOM view reads only a document the repository links, and limits by its stored size.
#[tokio::test]
async fn sbom_document_must_be_linked_in_the_repository() {
    let mut cfg = base_config();
    cfg.features.is_delete = true;
    let app = app(cfg).await;
    let repo = "acme/sbom";
    let empty = push_blob(&app, repo, b"{}", None).await;
    let sbom = br#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;
    let sbom_blob = push_blob(&app, repo, sbom, None).await;
    let m = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/vnd.cyclonedx+json",
        "config": { "mediaType": "application/vnd.oci.empty.v1+json", "digest": empty.to_string(), "size": 2 },
        "layers": [{ "mediaType": "application/vnd.cyclonedx+json", "digest": sbom_blob.to_string(), "size": 1 }],
    }))
    .unwrap();
    let md = put_manifest(&app, repo, "sbom", m).await;
    let url = format!("/api/v1/repositories/{repo}/manifests/{md}/sbom");
    assert_eq!(send(&app, Method::GET, &url, &[], vec![]).await.status, StatusCode::OK);
    // Unlinked from the repository (the blob itself still exists globally): not readable here.
    assert_eq!(send(&app, Method::DELETE, &format!("/v2/{repo}/blobs/{sbom_blob}"), &[], vec![]).await.status, StatusCode::ACCEPTED);
    let r = send(&app, Method::GET, &url, &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("BLOB_UNKNOWN"), "{}", String::from_utf8_lossy(&r.body));
}

/// Blob uploads are refused once they would take the namespace past its quota, and uploads
/// into a read-only repository are refused at every step.
#[tokio::test]
async fn blob_uploads_respect_quota_and_read_only() {
    let mut cfg = accounts_config();
    cfg.policy.default_user_quota = Some("100".into());
    let app = app(cfg).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "username": "dan", "password": "password123" })).unwrap();
    send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await;
    let dan = cookie_of(&web_login(&app, "dan", "password123", None).await);
    let r = send(&app, Method::POST, "/api/v1/auth/tokens", &[("cookie", &dan), jh], serde_json::to_vec(&json!({ "name": "ci" })).unwrap()).await;
    let auth = basic("dan", r.json()["token"].as_str().unwrap());
    let a = ("authorization", auth.as_str());
    let oct = ("content-type", "application/octet-stream");

    // Small blobs fit.
    assert!(push_blob_if_missing(&app, "dan/app", b"small", Some(&auth)).await.is_ok());
    // Monolithic with a declared length past the quota: refused before reading.
    let big = vec![5u8; 200];
    let big_d = Digest::sha256_of(&big);
    let r = send(&app, Method::POST, &format!("/v2/dan/app/blobs/uploads/?digest={big_d}"), &[a, oct, ("content-length", "200")], big.clone()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json()["errors"][0]["message"].as_str().unwrap().contains("quota exceeded"));
    // Without a declared length: refused at completion, nothing stored.
    let r = send(&app, Method::POST, &format!("/v2/dan/app/blobs/uploads/?digest={big_d}"), &[a, oct], big.clone()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(send(&app, Method::HEAD, &format!("/v2/dan/app/blobs/{big_d}"), &[a], vec![]).await.status, StatusCode::NOT_FOUND);
    // Chunked: refused at the chunk that goes past it.
    let r = push_blob_if_missing(&app, "dan/app", &big, Some(&auth)).await.unwrap_err();
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.json()["errors"][0]["code"], "DENIED");

    // Read-only: a session opened before the switch can take no more data nor complete.
    let r = send(&app, Method::POST, "/v2/dan/app/blobs/uploads/", &[a], vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let loc = r.header("location");
    let r = send(&app, Method::PUT, "/api/v1/repositories/dan/app/state", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "state": "read_only" })).unwrap()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(send(&app, Method::PATCH, &loc, &[a, oct], b"x".to_vec()).await.status, StatusCode::METHOD_NOT_ALLOWED);
    let d = Digest::sha256_of(b"x");
    assert_eq!(send(&app, Method::PUT, &format!("{loc}?digest={d}"), &[a, oct], b"x".to_vec()).await.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn wrong_one_time_codes_lock_out_even_with_the_right_password() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "username": "erin", "password": "erinpass123" })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    let erin = cookie_of(&web_login(&app, "erin", "erinpass123", None).await);
    let secret = send(&app, Method::POST, "/api/v1/auth/mfa/setup", &[("cookie", &erin)], vec![]).await.json()["secret"].as_str().unwrap().to_string();
    let code_at = |steps_ahead: u64| {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        totp_rs::Builder::new().with_secret(totp_rs::Secret::try_from_base32(&secret).unwrap()).with_account_name("erin").build_noncompliant().generate(now + 30 * steps_ahead).to_string()
    };
    let body = serde_json::to_vec(&json!({ "code": code_at(0) })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/auth/mfa/enable", &[("cookie", &erin), jh], body).await.status, StatusCode::OK);

    // Each attempt has the right password and a wrong code: the password must not reset the count.
    let mut locked = false;
    for _ in 0..30 {
        let r = web_login(&app, "erin", "erinpass123", Some("000000")).await;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            locked = true;
            break;
        }
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert!(locked, "wrong codes lock the account out");
    let r = web_login(&app, "erin", "erinpass123", Some(&code_at(1))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "still locked, even with a right code");
}

#[tokio::test]
async fn role_patterns_cannot_escalate_past_your_own() {
    let app = app(accounts_config()).await;
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "name": "role-admin", "rules": [{ "repositories": ["team-a/**"], "actions": ["pull", "push"] }], "global": ["roles:write"] })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/roles", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    // A user named `x`: the old check stood `**` in for `x/y`, which `x`'s namespace covers.
    let body = serde_json::to_vec(&json!({ "username": "x", "password": "xpassword1", "roles": ["role-admin"] })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    let x = cookie_of(&web_login(&app, "x", "xpassword1", None).await);
    let try_role = |name: &str, repos: &[&str], actions: &[&str]| {
        let body = serde_json::to_vec(&json!({ "name": name, "rules": [{ "repositories": repos, "actions": actions }] })).unwrap();
        let (app, x) = (app.clone(), x.clone());
        async move { send(&app, Method::POST, "/api/v1/roles", &[("cookie", &x), jh], body).await.status }
    };
    for (repos, actions) in [(&["**"][..], &["pull"][..]), (&["*"], &["pull"]), (&["*/**"], &["pull"]), (&["x*/**"], &["pull"]), (&["team-*/**"], &["pull"]), (&["team-a/**"], &["delete"])] {
        assert_eq!(try_role("grab", repos, actions).await, StatusCode::BAD_REQUEST, "{repos:?} {actions:?}");
    }
    assert_eq!(try_role("mine", &["x/**"], &["pull", "push", "delete"]).await, StatusCode::CREATED, "own namespace");
    assert_eq!(try_role("team", &["team-a/*", "team-a/**/prod"], &["pull"]).await, StatusCode::CREATED, "narrower than a held pattern");
}

#[tokio::test]
async fn scanner_tokens_pull_one_repository_and_nothing_else() {
    let mut cfg = base_config();
    cfg.auth.mode = AuthMode::Token;
    cfg.auth.bootstrap_admin = Some(BootstrapAdmin { username: "root".into(), password: "rootpass123".into() });
    let state = kontainer_server::build_state(cfg).await.unwrap();
    let app = kontainer_server::build_router(state.clone());
    let root = basic("root", "rootpass123");
    let layer = push_blob(&app, "acme/app", b"scan me", Some(&root)).await;
    let other = push_blob(&app, "acme/other", b"not yours", Some(&root)).await;

    let token = state.auth.issue_scanner_token("acme/app").unwrap();
    let bearer = format!("Bearer {token}");
    let r = send(&app, Method::GET, &format!("/v2/acme/app/blobs/{layer}"), &[("authorization", &bearer)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "the scanner pulls the repository its token names");
    let r = send(&app, Method::GET, &format!("/v2/acme/other/blobs/{other}"), &[("authorization", &bearer)], vec![]).await;
    assert!(r.status == StatusCode::FORBIDDEN || r.status == StatusCode::UNAUTHORIZED, "another repository: {}", r.status);
    let r = send(&app, Method::POST, "/v2/acme/app/blobs/uploads/", &[("authorization", &bearer)], vec![]).await;
    assert!(r.status == StatusCode::FORBIDDEN || r.status == StatusCode::UNAUTHORIZED, "the scanner cannot push: {}", r.status);
    let r = send(&app, Method::GET, "/api/v1/users", &[("authorization", &bearer)], vec![]).await;
    assert!(r.status.is_client_error(), "the scanner reaches no management API: {}", r.status);
}

/// Reads server-sent events from a streaming response body.
struct Events {
    body: axum::body::Body,
    buf: String,
}

/// One server-sent event: its `id`, `event` and `data` fields.
#[derive(Debug, Default)]
struct Sse {
    id: Option<String>,
    event: Option<String>,
    data: String,
}

impl Events {
    async fn open(app: &Router, build: i64, last_event_id: Option<&str>) -> Self {
        let mut req = Request::builder().uri(format!("/api/v1/builds/{build}/log/stream"));
        if let Some(id) = last_event_id {
            req = req.header("last-event-id", id);
        }
        let res = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["content-type"], "text/event-stream");
        Self { body: res.into_body(), buf: String::new() }
    }

    /// The next event (comments skipped); `None` once the stream ends.
    async fn next(&mut self) -> Option<Sse> {
        loop {
            if let Some(end) = self.buf.find("\n\n") {
                let block: String = self.buf.drain(..end + 2).collect();
                let mut e = Sse::default();
                for line in block.lines() {
                    match line.split_once(':') {
                        Some(("id", v)) => e.id = Some(v.trim().to_string()),
                        Some(("event", v)) => e.event = Some(v.trim().to_string()),
                        Some(("data", v)) => e.data.push_str(v.strip_prefix(' ').unwrap_or(v)),
                        _ => {}
                    }
                }
                if e.id.is_some() || e.event.is_some() || !e.data.is_empty() {
                    return Some(e);
                }
                continue;
            }
            let frame = tokio::time::timeout(std::time::Duration::from_secs(10), self.body.frame()).await.expect("an event in time")?.unwrap();
            if let Ok(data) = frame.into_data() {
                self.buf.push_str(std::str::from_utf8(&data).unwrap());
            }
        }
    }

    /// The next event, which must be log chunk `seq` with `data`.
    async fn chunk(&mut self, seq: i64, data: &str) {
        let e = self.next().await.expect("a chunk");
        assert_eq!((e.id.as_deref(), e.event.as_deref()), (Some(seq.to_string().as_str()), None), "{e:?}");
        assert_eq!(serde_json::from_str::<Value>(&e.data).unwrap(), json!({ "seq": seq, "data": data }));
    }
}

/// The chunked log protocol and the live log stream: check-ins append at the stored length, a
/// follower on one instance gets chunks a runner sends to another as they arrive, then `done`;
/// a reconnecting one resumes after its `Last-Event-ID`.
#[tokio::test]
async fn build_logs_stream_live_across_instances() {
    let mut cfg = base_config();
    cfg.builds.is_enabled = true;
    cfg.builds.runners = vec![kontainer_core::config::ConfigRunner { name: "ci".into(), token: "agent-token-0123456789".into(), namespaces: vec![] }];
    let follower = app(cfg.clone()).await;
    let runner_side = app(cfg).await;
    let jh = ("content-type", "application/json");
    let body = json!({ "repository": "acme/hello", "name": "main", "git_url": "https://git.example.com/acme/hello.git", "branches": ["main"] });
    let trigger = send(&runner_side, Method::POST, "/api/v1/build-triggers", &[jh], serde_json::to_vec(&body).unwrap()).await.json()["id"].as_i64().unwrap();
    let build = send(&runner_side, Method::POST, &format!("/api/v1/build-triggers/{trigger}/run"), &[jh], b"{}".to_vec()).await.json()["build"].as_i64().unwrap();
    let token = send(&runner_side, Method::POST, "/api/v1/runner/claim", &[jh, ("authorization", "Bearer agent-token-0123456789")], b"{}".to_vec()).await.json()["token"].as_str().unwrap().to_string();
    let bearer = format!("Bearer {token}");
    let check_in = |offset: u64, data: &'static str| {
        let (app, bearer) = (runner_side.clone(), bearer.clone());
        async move { send(&app, Method::POST, &format!("/api/v1/runner/builds/{build}/log"), &[jh, ("authorization", bearer.as_str())], serde_json::to_vec(&json!({ "offset": offset, "data": data })).unwrap()).await.json() }
    };

    assert_eq!(check_in(0, "one\n").await, json!({ "stop": false, "length": 4 }));
    assert_eq!(check_in(4, "two\n").await["length"], 8);
    // A resend after a lost reply: refused, with where the log stands.
    assert_eq!(check_in(4, "two\n").await["length"], 8);
    let b = send(&follower, Method::GET, &format!("/api/v1/builds/{build}"), &[], vec![]).await.json();
    assert_eq!((b["status"].as_str(), b["log"].as_str()), (Some("running"), Some("one\ntwo\n")), "a running build's log, from its chunks");

    // The chunks so far, then one appended while following, through the other instance.
    let mut events = Events::open(&follower, build, None).await;
    events.chunk(1, "one\n").await;
    events.chunk(2, "two\n").await;
    let live = tokio::spawn(check_in(8, "three\n"));
    events.chunk(3, "three\n").await;
    assert_eq!(live.await.unwrap()["length"], 14);

    // The runner reports a failure with a last line: that chunk, then `done`, then the end.
    let finish = json!({ "status": "failed", "message": "Boom", "line": "==> Boom" });
    let r = send(&runner_side, Method::POST, &format!("/api/v1/runner/builds/{build}/finish"), &[jh, ("authorization", bearer.as_str())], serde_json::to_vec(&finish).unwrap()).await;
    assert_eq!(r.status, StatusCode::OK);
    events.chunk(4, "==> Boom\n").await;
    let done = events.next().await.unwrap();
    assert_eq!(done.event.as_deref(), Some("done"));
    assert_eq!(serde_json::from_str::<Value>(&done.data).unwrap(), json!({ "status": "failed", "message": "Boom" }));
    assert!(events.next().await.is_none(), "the stream ends after done");
    let b = send(&follower, Method::GET, &format!("/api/v1/builds/{build}"), &[], vec![]).await.json();
    assert_eq!(b["log"], "one\ntwo\nthree\n==> Boom\n", "the finished build's cached log");

    // Reconnecting after chunk 2: chunks 3 and 4 only, then done.
    let mut events = Events::open(&follower, build, Some("2")).await;
    events.chunk(3, "three\n").await;
    events.chunk(4, "==> Boom\n").await;
    assert_eq!(events.next().await.unwrap().event.as_deref(), Some("done"));
    assert!(events.next().await.is_none());
    let mut events = Events::open(&follower, build, Some("4")).await;
    assert_eq!(events.next().await.unwrap().event.as_deref(), Some("done"), "nothing sent twice");
    // Following needs read access like the build itself.
    let r = send(&follower, Method::GET, "/api/v1/builds/999999/log/stream", &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

/// containerd using this registry as a mirror sends `?ns=<upstream host>`: a pull of a
/// repository that is not here is served from the pull-through cache for that host, and a
/// local repository of the same name wins.
#[tokio::test]
async fn containerd_ns_pulls_go_through_the_cache_for_that_upstream() {
    let upstream = app(base_config()).await;
    let cfg = br#"{"architecture":"amd64","os":"linux","upstream":true}"#;
    let layer = b"alpine from upstream".to_vec();
    let cd = push_blob(&upstream, "library/alpine", cfg, None).await;
    let ld = push_blob(&upstream, "library/alpine", &layer, None).await;
    let up_manifest = image_manifest(&cd, cfg.len(), &[(ld.clone(), layer.len())]);
    let r = send(&upstream, Method::PUT, "/v2/library/alpine/manifests/latest", &[("content-type", OCI_MANIFEST)], up_manifest.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(&upstream, Method::PUT, "/v2/library/alpine/manifests/edge", &[("content-type", OCI_MANIFEST)], up_manifest.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let mut config = base_config();
    config.auth.mode = AuthMode::Token;
    config.auth.bootstrap_admin = Some(BootstrapAdmin { username: "root".into(), password: "rootpass123".into() });
    let state = kontainer_server::build_state(config.clone()).await.unwrap();
    let app = kontainer_server::build_router(state.clone());
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let r = send(&app, Method::POST, "/api/v1/registries", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "name": "up", "url": format!("http://{addr}") })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let reg = r.json()["id"].as_i64().unwrap();
    let r = send(&app, Method::POST, "/api/v1/proxy-caches", &[("cookie", &root), jh], serde_json::to_vec(&json!({ "namespace": "hub", "registry_id": reg })).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let h = [("cookie", root.as_str()), ("accept", OCI_MANIFEST)];

    // Without `ns`, or with another host's, there is no such repository here.
    assert_eq!(send(&app, Method::GET, "/v2/library/alpine/manifests/latest", &h, vec![]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, Method::GET, "/v2/library/alpine/manifests/latest?ns=ghcr.io", &h, vec![]).await.status, StatusCode::NOT_FOUND);
    // With the upstream's host: served (and cached) from `hub/library/alpine`.
    let ns = format!("ns={addr}");
    let r = send(&app, Method::GET, &format!("/v2/library/alpine/manifests/latest?{ns}"), &h, vec![]).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::OK, up_manifest.clone()), "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::HEAD, &format!("/v2/library/alpine/manifests/latest?{ns}"), &h, vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::GET, &format!("/v2/library/alpine/blobs/{ld}?{ns}"), &h, vec![]).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::OK, layer.clone()));
    let r = send(&app, Method::GET, "/v2/hub/library/alpine/tags/list", &h, vec![]).await;
    assert_eq!(r.json()["tags"], json!(["latest"]), "cached in the proxy namespace");
    // The host is matched as containerd writes it: case and an explicit default port aside.
    let r = send(&app, Method::GET, &format!("/v2/library/alpine/tags/list?ns={}", addr.to_string().to_uppercase()), &h, vec![]).await;
    assert_eq!(r.json()["tags"], json!(["latest"]));
    // A rewritten request names the namespace that answered it, and the tag list keeps the
    // repository name the client asked for, in the body and in the next page's link (with `ns`).
    let r = send(&app, Method::GET, &format!("/v2/library/alpine/tags/list?{ns}"), &h, vec![]).await;
    assert_eq!(r.header("oci-namespace"), addr.to_string());
    assert_eq!(r.json()["name"], "library/alpine");
    let r = send(&app, Method::GET, &format!("/v2/library/alpine/manifests/latest?{ns}"), &h, vec![]).await;
    assert_eq!(r.header("oci-namespace"), addr.to_string());
    let r = send(&app, Method::GET, &format!("/v2/library/alpine/manifests/edge?{ns}"), &h, vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::GET, &format!("/v2/library/alpine/tags/list?{ns}&n=1"), &h, vec![]).await;
    assert_eq!((r.json()["name"].clone(), r.json()["tags"].clone()), (json!("library/alpine"), json!(["edge"])));
    let encoded: String = url::form_urlencoded::byte_serialize(addr.to_string().as_bytes()).collect();
    let link = r.header("link");
    assert_eq!(link, format!("</v2/library/alpine/tags/list?ns={encoded}&n=1&last=edge>; rel=\"next\""));
    let next = link.trim_start_matches('<').split('>').next().unwrap().to_string();
    let r = send(&app, Method::GET, &next, &h, vec![]).await;
    assert_eq!((r.json()["name"].clone(), r.json()["tags"].clone()), (json!("library/alpine"), json!(["latest"])));
    // Not rewritten (no upstream for that host): no `OCI-Namespace`.
    let r = send(&app, Method::GET, "/v2/hub/library/alpine/tags/list?ns=ghcr.io", &h, vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.headers.get("oci-namespace").is_none());
    // Pushes are never redirected.
    let r = send(&app, Method::POST, &format!("/v2/library/alpine/blobs/uploads/?{ns}"), &h, vec![]).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let loc = r.header("location");
    assert!(loc.starts_with("/v2/library/alpine/"), "{loc}");

    // A local repository of the same name wins over the cache.
    let local_cfg = br#"{"architecture":"amd64","os":"linux","local":true}"#;
    let lcd = push_blob(&app, "library/alpine", local_cfg, Some(&basic("root", "rootpass123"))).await;
    let local_manifest = image_manifest(&lcd, local_cfg.len(), &[]);
    let r = send(&app, Method::PUT, "/v2/library/alpine/manifests/latest", &[("cookie", &root), ("content-type", OCI_MANIFEST)], local_manifest.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::GET, &format!("/v2/library/alpine/manifests/latest?{ns}"), &h, vec![]).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::OK, local_manifest), "the local repository is served");

    // `features.containerd_ns = false` turns it off.
    let mut off = config;
    off.features.is_containerd_ns = false;
    let app_off = kontainer_server::build_router(kontainer_server::build_state(off).await.unwrap());
    let root_off = cookie_of(&web_login(&app_off, "root", "rootpass123", None).await);
    let r = send(&app_off, Method::GET, &format!("/v2/library/other/manifests/latest?{ns}"), &[("cookie", &root_off)], vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = send(&app, Method::GET, &format!("/v2/library/other/manifests/latest?{ns}"), &h, vec![]).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "rewritten, but upstream has no such image either");
}

/// Secrets at rest: an upstream registry's password is unreadable in its column, yet used
/// to sign in upstream; an instance without the key refuses to start on that database.
#[tokio::test]
async fn upstream_password_is_encrypted_at_rest() {
    // An upstream that needs credentials, with an image only they can pull.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut ucfg = accounts_config();
    ucfg.server.public_url = Some(format!("http://{addr}"));
    let upstream = app(ucfg).await;
    let rootb = basic("root", "rootpass123");
    let blob = br#"{"architecture":"amd64","os":"linux"}"#;
    let cd = push_blob(&upstream, "root/app", blob, Some(&rootb)).await;
    let r = send(&upstream, Method::PUT, "/v2/root/app/manifests/v1", &[("authorization", &rootb), ("content-type", OCI_MANIFEST)], image_manifest(&cd, blob.len(), &[])).await;
    assert_eq!(r.status, StatusCode::CREATED);
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let mut cfg = accounts_config();
    cfg.auth.encryption_key = Some("an-encryption-key-of-32-bytes-or-more".into());
    let url = cfg.auth.database_url.clone();
    let state = kontainer_server::build_state(cfg.clone()).await.unwrap();
    let key = state.auth.db.keyring().current_id().unwrap().to_string();
    let app = kontainer_server::build_router(state.clone());
    let jh = ("content-type", "application/json");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = json!({ "name": "up", "url": format!("http://{addr}"), "username": "root", "password": "rootpass123" });
    let r = send(&app, Method::POST, "/api/v1/registries", &[("cookie", &root), jh], serde_json::to_vec(&body).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json().get("password").is_none());
    let reg = r.json()["id"].as_i64().unwrap();

    let stored: String = sqlx::query_scalar("SELECT password FROM registries WHERE id = $1").bind(reg).fetch_one(state.auth.db.pool()).await.unwrap();
    assert!(stored.starts_with(&format!("enc:v1:{key}:")) && !stored.contains("rootpass123"), "{stored}");
    // The signing secret in `meta` is sealed too.
    let jwt: String = sqlx::query_scalar("SELECT value FROM meta WHERE key = 'jwt_secret'").fetch_one(state.auth.db.pool()).await.unwrap();
    assert!(jwt.starts_with(&format!("enc:v1:{key}:")), "{jwt}");
    // Decrypted for use: the test signs in upstream with it.
    let r = send(&app, Method::POST, &format!("/api/v1/registries/{reg}/test"), &[("cookie", &root), jh], serde_json::to_vec(&json!({ "repository": "root/app" })).unwrap()).await;
    assert_eq!(r.json()["ok"], true, "{}", r.json());
    assert_eq!(r.json()["tags"], json!(["v1"]));

    let r = send(&app, Method::GET, "/api/v1/health", &[("cookie", &root)], vec![]).await;
    let check = r.json()["checks"].as_array().unwrap().iter().find(|c| c["name"] == "Secrets at rest").cloned().unwrap();
    assert_eq!((check["status"].as_str(), check["message"].as_str().map(String::from)), (Some("ok"), Some(format!("encrypted with key {key}"))));

    // Without the key, the database's secrets can't be read: refuse to start, naming the key.
    let mut keyless = cfg.clone();
    keyless.auth.encryption_key = None;
    keyless.auth.database_url = url;
    let err = format!("{:#}", kontainer_server::build_state(keyless).await.err().expect("refused"));
    assert!(err.contains(&key) && err.contains("registries.password"), "{err}");
}

#[tokio::test]
async fn passkeys_register_sign_in_and_count_as_two_factors() {
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

    // Authenticators (browsers) take passkeys only from https origins (or localhost).
    let mut cfg = accounts_config();
    cfg.server.public_url = Some("https://registry.test".into());
    let state = kontainer_server::build_state(cfg).await.unwrap();
    let db = state.auth.db.clone();
    let app = kontainer_server::build_router(state);
    let jh = ("content-type", "application/json");
    let origin = Url::parse("https://registry.test").unwrap();
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "username": "erin", "password": "erinpass123" })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    let erin = cookie_of(&web_login(&app, "erin", "erinpass123", None).await);
    assert_eq!(send(&app, Method::GET, "/api/v1/me", &[], vec![]).await.json()["passkeys"], true);

    // Erin turns on TOTP: a password sign-in now needs a code.
    let secret = send(&app, Method::POST, "/api/v1/auth/mfa/setup", &[("cookie", &erin)], vec![]).await.json()["secret"].as_str().unwrap().to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let code = totp_rs::Builder::new().with_secret(totp_rs::Secret::try_from_base32(&secret).unwrap()).with_account_name("erin").build_noncompliant().generate(now).to_string();
    assert_eq!(send(&app, Method::POST, "/api/v1/auth/mfa/enable", &[("cookie", &erin), jh], serde_json::to_vec(&json!({ "code": code })).unwrap()).await.status, StatusCode::OK);
    assert_eq!(web_login(&app, "erin", "erinpass123", None).await.json()["mfa_required"], true);

    // Registering needs a browser session.
    let start = serde_json::to_vec(&json!({ "name": "laptop" })).unwrap();
    assert_ne!(send(&app, Method::POST, "/api/v1/auth/passkeys/register/start", &[jh], start.clone()).await.status, StatusCode::OK);
    assert_ne!(send(&app, Method::POST, "/api/v1/auth/passkeys/register/start", &[("authorization", &basic("erin", "erinpass123")), jh], start.clone()).await.status, StatusCode::OK);

    // Register with a software authenticator (it claims user verification, as a passkey does).
    let authenticator = std::rc::Rc::new(std::cell::RefCell::new(WebauthnAuthenticator::new(SoftPasskey::new(true))));
    let r = send(&app, Method::POST, "/api/v1/auth/passkeys/register/start", &[("cookie", &erin), jh], start.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let challenge = r.json()["challenge_id"].as_str().unwrap().to_string();
    let options = r.json()["options"].clone();
    assert_eq!(options["publicKey"]["rp"]["id"], "registry.test");
    assert_eq!(options["publicKey"]["authenticatorSelection"]["residentKey"], "preferred");
    assert_eq!(options["publicKey"]["authenticatorSelection"]["userVerification"], "required");
    let handle = options["publicKey"]["user"]["id"].as_str().unwrap().to_string();
    let ccr: CreationChallengeResponse = serde_json::from_value(options).unwrap();
    let credential = authenticator.borrow_mut().do_registration(origin.clone(), ccr).unwrap();
    let cred_id = serde_json::to_value(&credential).unwrap()["rawId"].as_str().unwrap().to_string();
    let finish = serde_json::to_vec(&json!({ "challenge_id": challenge, "credential": credential })).unwrap();
    let r = send(&app, Method::POST, "/api/v1/auth/passkeys/register/finish", &[("cookie", &erin), jh], finish.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["name"], "laptop");
    assert!(r.json().get("credential").is_none(), "the stored credential is not echoed");
    let passkey_id = r.json()["id"].as_i64().unwrap();
    // A ceremony works once.
    assert_eq!(send(&app, Method::POST, "/api/v1/auth/passkeys/register/finish", &[("cookie", &erin), jh], finish).await.status, StatusCode::BAD_REQUEST);
    let list = send(&app, Method::GET, "/api/v1/auth/passkeys", &[("cookie", &erin)], vec![]).await.json();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(send(&app, Method::GET, "/api/v1/auth/passkeys", &[("cookie", &root)], vec![]).await.json().as_array().unwrap().is_empty(), "only your own");

    // Sign in with it, naming the account: a session, and no one-time code asked although TOTP is on.
    let sign_in = |username: Option<&'static str>| {
        let (app, cred_id, handle, origin, authenticator) = (app.clone(), cred_id.clone(), handle.clone(), origin.clone(), authenticator.clone());
        async move {
            let r = send(&app, Method::POST, "/api/v1/auth/passkeys/login/start", &[jh], serde_json::to_vec(&json!({ "username": username })).unwrap()).await;
            assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
            let challenge = r.json()["challenge_id"].as_str().unwrap().to_string();
            let mut options = r.json()["options"].clone();
            assert!(options.get("mediation").is_none_or(|m| m.is_null()), "a modal dialog, not autofill");
            let discoverable = options["publicKey"]["allowCredentials"].as_array().is_none_or(|a| a.is_empty());
            if discoverable {
                // The software authenticator needs to be told its credential, and returns no user
                // handle: add what a platform authenticator would.
                options["publicKey"]["allowCredentials"] = json!([{ "type": "public-key", "id": cred_id }]);
            }
            let rcr: RequestChallengeResponse = serde_json::from_value(options).unwrap();
            let mut assertion = serde_json::to_value(authenticator.borrow_mut().do_authentication(origin, rcr).unwrap()).unwrap();
            if discoverable {
                assertion["response"]["userHandle"] = json!(handle);
            }
            (challenge, assertion, discoverable)
        }
    };
    let finish_login = |challenge: String, assertion: Value| {
        let app = app.clone();
        async move { send(&app, Method::POST, "/api/v1/auth/passkeys/login/finish", &[jh], serde_json::to_vec(&json!({ "challenge_id": challenge, "credential": assertion })).unwrap()).await }
    };
    let (challenge, assertion, discoverable) = sign_in(Some("erin")).await;
    assert!(!discoverable, "erin's passkeys are offered");
    let r = finish_login(challenge.clone(), assertion.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let session = cookie_of(&r);
    assert!(set_cookie(&r, "kontainer_session").contains("SameSite=Strict") && set_cookie(&r, "kontainer_session").ends_with("; Secure"), "https: Secure");
    let me = send(&app, Method::GET, "/api/v1/me", &[("cookie", &session)], vec![]).await.json();
    assert_eq!((me["username"].as_str(), me["method"].as_str(), me["is_mfa_enabled"].as_bool()), (Some("erin"), Some("session"), Some(true)));
    assert_eq!(finish_login(challenge, assertion).await.status, StatusCode::UNAUTHORIZED, "a challenge works once");
    let list = send(&app, Method::GET, "/api/v1/auth/passkeys", &[("cookie", &erin)], vec![]).await.json();
    assert!(list[0]["last_used_at"].is_string() && list[0]["sign_count"].as_i64().unwrap() >= 1, "{list}");

    // Without a username: a discoverable credential names the account itself.
    let (challenge, assertion, discoverable) = sign_in(None).await;
    assert!(discoverable);
    let r = finish_login(challenge, assertion).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(send(&app, Method::GET, "/api/v1/me", &[("cookie", &cookie_of(&r))], vec![]).await.json()["username"], "erin");
    // An unknown username gets a discoverable challenge too (no account enumeration).
    assert!(sign_in(Some("nobody")).await.2);

    // A response for another account's challenge, or a forged user handle, is refused.
    let (challenge, assertion, _) = sign_in(Some("erin")).await;
    let r = send(&app, Method::POST, "/api/v1/auth/passkeys/login/start", &[jh], serde_json::to_vec(&json!({ "username": "root" })).unwrap()).await;
    let roots = r.json()["challenge_id"].as_str().unwrap().to_string();
    assert_eq!(finish_login(roots, assertion).await.status, StatusCode::UNAUTHORIZED);
    drop(challenge);
    let (challenge, mut assertion, _) = sign_in(None).await;
    assertion["response"]["userHandle"] = json!("AAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(finish_login(challenge, assertion).await.status, StatusCode::UNAUTHORIZED);

    // A disabled account cannot sign in with its passkey.
    let erin_id = send(&app, Method::GET, "/api/v1/users", &[("cookie", &root)], vec![]).await.json().as_array().unwrap().iter().find(|u| u["username"] == "erin").unwrap()["id"].as_i64().unwrap();
    let r = send(&app, Method::PATCH, &format!("/api/v1/users/{erin_id}"), &[("cookie", &root), jh], serde_json::to_vec(&json!({ "is_disabled": true })).unwrap()).await;
    assert!(r.status.is_success(), "{}", String::from_utf8_lossy(&r.body));
    let (challenge, assertion, _) = sign_in(Some("erin")).await;
    assert_eq!(finish_login(challenge, assertion).await.status, StatusCode::UNAUTHORIZED);
    let r = send(&app, Method::PATCH, &format!("/api/v1/users/{erin_id}"), &[("cookie", &root), jh], serde_json::to_vec(&json!({ "is_disabled": false })).unwrap()).await;
    assert!(r.status.is_success());

    // Failed attempts count toward the lockout, which also stops passkey sign-ins.
    let mut locked = false;
    for _ in 0..60 {
        let r = send(&app, Method::POST, "/api/v1/auth/passkeys/login/start", &[jh], serde_json::to_vec(&json!({ "username": "erin" })).unwrap()).await;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            locked = true;
            break;
        }
        let challenge = r.json()["challenge_id"].as_str().unwrap().to_string();
        let r = finish_login(challenge, json!({ "id": cred_id, "rawId": cred_id, "type": "public-key", "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA", "signature": "AAAA", "userHandle": null } })).await;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            locked = true;
            break;
        }
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert!(locked, "bad passkey responses lock the account out");
    // Once the lockout is over, the passkey works again.
    sqlx::query("DELETE FROM login_failures").execute(db.pool()).await.unwrap();
    let (challenge, assertion, _) = sign_in(Some("erin")).await;
    let r = finish_login(challenge, assertion).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let erin = cookie_of(&r);

    // Removing it: only its owner can.
    assert_eq!(send(&app, Method::DELETE, &format!("/api/v1/auth/passkeys/{passkey_id}"), &[("cookie", &root)], vec![]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, Method::DELETE, &format!("/api/v1/auth/passkeys/{passkey_id}"), &[("cookie", &erin)], vec![]).await.status, StatusCode::NO_CONTENT);
    assert!(send(&app, Method::GET, "/api/v1/auth/passkeys", &[("cookie", &erin)], vec![]).await.json().as_array().unwrap().is_empty());
}

#[tokio::test]
async fn deletion_previews_and_confirmed_plans() {
    let state = kontainer_server::build_state(accounts_config()).await.unwrap();
    let db = state.auth.db.clone();
    let app = kontainer_server::build_router(state);
    let jh = ("content-type", "application/json");
    let auth = basic("root", "rootpass123");
    let root = cookie_of(&web_login(&app, "root", "rootpass123", None).await);
    let body = serde_json::to_vec(&json!({ "username": "bob", "password": "bobpass123" })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    let bob = cookie_of(&web_login(&app, "bob", "bobpass123", None).await);
    let put = |reference: String, media_type: &'static str, body: Vec<u8>| {
        let (app, auth) = (app.clone(), auth.clone());
        async move {
            let r = send(&app, Method::PUT, &format!("/v2/root/app/manifests/{reference}"), &[("authorization", &auth), ("content-type", media_type)], body.clone()).await;
            assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
            (Digest::sha256_of(&body), body.len())
        }
    };

    // v1, latest and stable on one image; v2 on another; an index over the first; a signature-like
    // referrer of the first.
    let cfg = br#"{"architecture":"amd64","os":"linux"}"#;
    let cd = push_blob(&app, "root/app", cfg, Some(&auth)).await;
    let empty = push_blob(&app, "root/app", b"{}", Some(&auth)).await;
    let (m1, m1_len) = put("v1".into(), OCI_MANIFEST, image_manifest(&cd, cfg.len(), &[])).await;
    for t in ["latest", "stable"] {
        put(t.into(), OCI_MANIFEST, image_manifest(&cd, cfg.len(), &[])).await;
    }
    let other = serde_json::to_vec(&json!({ "schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd.to_string(), "size": cfg.len() }, "layers": [], "annotations": { "v": "2" } })).unwrap();
    let (m2, _) = put("v2".into(), OCI_MANIFEST, other).await;
    let index = serde_json::to_vec(&json!({ "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [{ "mediaType": OCI_MANIFEST, "digest": m1.to_string(), "size": m1_len, "platform": { "architecture": "amd64", "os": "linux" } }] })).unwrap();
    let (ix, _) = put("multi".into(), OCI_INDEX, index).await;
    let referrer = serde_json::to_vec(&json!({ "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "application/example", "config": { "mediaType": "application/vnd.oci.empty.v1+json", "digest": empty.to_string(), "size": 2 }, "layers": [], "subject": { "mediaType": OCI_MANIFEST, "digest": m1.to_string(), "size": m1_len } })).unwrap();
    let referrer_digest = Digest::sha256_of(&referrer);
    put(referrer_digest.to_string(), OCI_MANIFEST, referrer).await;

    // Tag preview: the digest, the aliases that keep the manifest, its index and referrer.
    let r = send(&app, Method::GET, "/api/v1/repositories/root/app/tags/v1/delete-preview", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    let p = r.json();
    assert_eq!(p["digest"], m1.to_string());
    assert_eq!(p["other_tags"], json!(["latest", "stable"]));
    assert_eq!(p["index_parents"], json!([ix.to_string()]));
    assert_eq!(p["referrers"], 1);
    assert_eq!(p["is_immutable"], false);
    let p = send(&app, Method::GET, "/api/v1/repositories/root/app/tags/v2/delete-preview", &[("cookie", &root)], vec![]).await.json();
    assert_eq!((p["digest"].as_str(), p["other_tags"].clone(), p["index_parents"].clone(), p["referrers"].as_i64()), (Some(m2.to_string().as_str()), json!([]), json!([]), Some(0)));
    assert_eq!(send(&app, Method::GET, "/api/v1/repositories/root/app/tags/nope/delete-preview", &[("cookie", &root)], vec![]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, Method::GET, "/api/v1/repositories/root/app/tags/v1/delete-preview", &[("cookie", &bob)], vec![]).await.status, StatusCode::FORBIDDEN, "previews need the delete permission");

    // Repository preview: counts and sizes.
    let p = send(&app, Method::GET, "/api/v1/repositories/root/app/delete-preview", &[("cookie", &root)], vec![]).await.json();
    assert_eq!((p["tags"].as_i64(), p["manifests"].as_i64()), (Some(5), Some(4)), "{p}");
    assert!(p["bytes"].as_i64().unwrap() > 0 && p["blob_bytes"].as_i64().unwrap() >= cfg.len() as i64, "{p}");

    // The repository is not deleted without a plan.
    let r = send(&app, Method::DELETE, "/api/v1/repositories/root/app", &[("cookie", &root)], vec![]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("delete-plan"));

    // A plan for two tags, with each one's preview.
    let plan = |who: String, targets: Value| {
        let app = app.clone();
        async move { send(&app, Method::POST, "/api/v1/repositories/root/app/delete-plan", &[("cookie", &who), jh], serde_json::to_vec(&targets).unwrap()).await }
    };
    let execute = |who: String, id: String, confirm: &'static str| {
        let app = app.clone();
        async move { send(&app, Method::POST, &format!("/api/v1/delete-plans/{id}/execute"), &[("cookie", &who), jh], serde_json::to_vec(&json!({ "confirm": confirm })).unwrap()).await }
    };
    let too_many: Vec<String> = (0..101).map(|i| format!("t{i}")).collect();
    assert_eq!(plan(root.clone(), json!({ "tags": too_many })).await.status, StatusCode::BAD_REQUEST, "at most 100 tags");
    assert_eq!(plan(root.clone(), json!({ "tags": [] })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(plan(root.clone(), json!({ "tags": ["v1", "v1"] })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(plan(root.clone(), json!({ "tags": ["v1", "nope"] })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(plan(bob.clone(), json!({ "tags": ["v1", "v2"] })).await.status, StatusCode::FORBIDDEN);
    let r = plan(root.clone(), json!({ "tags": ["stable", "v2"] })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let id = r.json()["id"].as_str().unwrap().to_string();
    assert_eq!(r.json()["preview"]["tags"][0]["other_tags"], json!(["latest", "v1"]));
    assert!(r.json()["expires_at"].is_string());

    // Refused: the wrong name, another user (even an admin's plan is the admin's own).
    let r = execute(root.clone(), id.clone(), "root/ap").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&r.body));
    let body = serde_json::to_vec(&json!({ "username": "carol", "password": "carolpass123", "roles": ["system"] })).unwrap();
    assert_eq!(send(&app, Method::POST, "/api/v1/users", &[("cookie", &root), jh], body).await.status, StatusCode::CREATED);
    let carol = cookie_of(&web_login(&app, "carol", "carolpass123", None).await);
    assert_eq!(execute(carol.clone(), id.clone(), "root/app").await.status, StatusCode::NOT_FOUND, "another user's plan");
    assert_eq!(execute(bob.clone(), id.clone(), "root/app").await.status, StatusCode::NOT_FOUND);
    // Nothing was deleted by the refusals.
    assert_eq!(send(&app, Method::GET, "/v2/root/app/manifests/stable", &[("authorization", &auth), ("accept", OCI_MANIFEST)], vec![]).await.status, StatusCode::OK);
    // The right name: executed, once.
    let r = execute(root.clone(), id.clone(), "root/app").await;
    assert_eq!(r.status, StatusCode::OK, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["deleted"]["tags"], json!(["stable", "v2"]));
    assert_eq!(send(&app, Method::GET, "/v2/root/app/manifests/stable", &[("authorization", &auth), ("accept", OCI_MANIFEST)], vec![]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, Method::GET, "/v2/root/app/manifests/v1", &[("authorization", &auth), ("accept", OCI_MANIFEST)], vec![]).await.status, StatusCode::OK, "aliases stay");
    let r = execute(root.clone(), id.clone(), "root/app").await;
    assert_eq!(r.status, StatusCode::CONFLICT, "reuse: {}", String::from_utf8_lossy(&r.body));

    // An expired plan is refused.
    let r = plan(root.clone(), json!({ "repository": true })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["preview"]["tags"], 3);
    let id = r.json()["id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE delete_plans SET expires_at = now() - interval '1 second' WHERE id = $1").bind(&id).execute(db.pool()).await.unwrap();
    let r = execute(root.clone(), id, "root/app").await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("expired"));
    assert_eq!(send(&app, Method::GET, "/v2/root/app/manifests/v1", &[("authorization", &auth), ("accept", OCI_MANIFEST)], vec![]).await.status, StatusCode::OK);

    // A fresh repository plan deletes everything; both steps are in the audit log.
    delete_repository_confirmed(&app, &root, "root/app").await;
    assert_eq!(send(&app, Method::GET, "/v2/root/app/tags/list", &[("authorization", &auth)], vec![]).await.status, StatusCode::NOT_FOUND);
    let logs = send(&app, Method::GET, "/api/v1/logs?limit=200", &[("cookie", &root)], vec![]).await;
    let text = String::from_utf8_lossy(&logs.body).to_string();
    assert!(text.contains("delete_plan_created") && text.contains("delete_plan_executed"), "{text}");
}

#[tokio::test]
async fn manifest_push_by_digest_accepts_tag_parameters() {
    let app = app(base_config()).await;
    let repo = "acme/tagged";
    let cfg = br#"{"architecture":"amd64","os":"linux","config":{}}"#.to_vec();
    let layer = vec![7u8; 32];
    let c = push_blob(&app, repo, &cfg, None).await;
    let l = push_blob(&app, repo, &layer, None).await;
    let body = image_manifest(&c, cfg.len(), &[(l, layer.len())]);
    let digest = Digest::sha256_of(&body);
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{digest}?tag=1.2.3&tag=1.2&tag=latest"), &[("content-type", OCI_MANIFEST)], body.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let tags: Vec<String> = r.headers.get_all("OCI-Tag").iter().map(|v| v.to_str().unwrap().to_string()).collect();
    assert_eq!(tags, ["1.2.3", "1.2", "latest"], "one OCI-Tag header per accepted tag");
    let r = send(&app, Method::GET, &format!("/v2/{repo}/tags/list"), &[], vec![]).await;
    assert_eq!(r.json()["tags"], json!(["1.2", "1.2.3", "latest"]));
    let r = send(&app, Method::GET, &format!("/v2/{repo}/manifests/1.2"), &[("accept", OCI_MANIFEST)], vec![]).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{digest}?tag=not%20valid"), &[("content-type", OCI_MANIFEST)], body.clone()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.json()["errors"][0]["code"], "TAG_INVALID");
    let many: String = (0..65).map(|i| format!("tag=t{i}")).collect::<Vec<_>>().join("&");
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{digest}?{many}"), &[("content-type", OCI_MANIFEST)], body).await;
    assert_eq!(r.status, StatusCode::URI_TOO_LONG);
}

#[tokio::test]
async fn the_scanner_gets_a_token_realm_on_its_own_host() {
    let mut cfg = base_config();
    cfg.auth.mode = AuthMode::Token;
    cfg.auth.bootstrap_admin = Some(BootstrapAdmin { username: "root".into(), password: "rootpass123".into() });
    cfg.scanner.registry_host = Some("127.0.0.1:5000".into());
    cfg.scanner.is_insecure = true;
    let app = app(cfg).await;
    // Anyone else sees the public realm.
    let r = send(&app, Method::GET, "/v2/", &[("host", "registry.test")], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("www-authenticate").contains("realm=\"http://registry.test/auth/token\""), "{}", r.header("www-authenticate"));
    // The scanner, reaching the registry on loopback, is told to fetch its token there too.
    let r = send(&app, Method::GET, "/v2/", &[("host", "127.0.0.1:5000")], vec![]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.header("www-authenticate").contains("realm=\"http://127.0.0.1:5000/auth/token\""), "{}", r.header("www-authenticate"));
    assert!(r.header("www-authenticate").contains("service=\"registry.test\""), "the service, and so the token audience, is unchanged");
}

/// `OCI-Subject` is only sent when the referrers API is on: it tells the client not to keep
/// the `sha256-<hex>` fallback tag up to date. An empty `artifactType` counts as absent.
#[tokio::test]
async fn referrers_subject_header_and_artifact_type_fallback() {
    async fn subject_and_referrer(app: &Router, repo: &str, artifact_type: &str, config_type: &str) -> (Digest, Resp) {
        let cfg = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
        let c = push_blob(app, repo, &cfg, None).await;
        let subject = image_manifest(&c, cfg.len(), &[]);
        let sd = put_manifest(app, repo, "v1", subject.clone()).await;
        let referrer = serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": artifact_type,
            "config": { "mediaType": config_type, "digest": c.to_string(), "size": cfg.len() },
            "layers": [],
            "subject": { "mediaType": OCI_MANIFEST, "digest": sd.to_string(), "size": subject.len() },
        }))
        .unwrap();
        let rd = Digest::sha256_of(&referrer);
        let r = send(app, Method::PUT, &format!("/v2/{repo}/manifests/{rd}"), &[("content-type", OCI_MANIFEST)], referrer).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
        (sd, r)
    }
    let config_type = "application/vnd.example.sbom.config.v1+json";

    let mut cfg = base_config();
    cfg.features.is_referrers = false;
    let off = app(cfg).await;
    let (_, r) = subject_and_referrer(&off, "acme/off", "application/spdx+json", config_type).await;
    assert!(r.headers.get("oci-subject").is_none(), "no OCI-Subject without the referrers API");

    let app = app(base_config()).await;
    let repo = "acme/refs";
    let (sd, r) = subject_and_referrer(&app, repo, "", config_type).await;
    assert_eq!(r.header("oci-subject"), sd.to_string());
    let r = send(&app, Method::GET, &format!("/v2/{repo}/referrers/{sd}"), &[], vec![]).await;
    assert_eq!(r.json()["manifests"][0]["artifactType"], config_type, "empty artifactType falls back to the config media type");
    let r = send(&app, Method::GET, &format!("/v2/{repo}/referrers/{sd}?artifactType={}", config_type.replace('+', "%2B")), &[], vec![]).await;
    assert_eq!(r.json()["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(r.header("oci-filters-applied"), "artifactType");
    let r = send(&app, Method::GET, &format!("/v2/{repo}/referrers/{sd}?artifactType="), &[], vec![]).await;
    assert_eq!(r.json()["manifests"].as_array().unwrap().len(), 1);
    assert!(r.headers.get("oci-filters-applied").is_none(), "an empty filter is no filter");

    // An index with an empty artifactType has none.
    let index = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_INDEX, "artifactType": "", "manifests": [],
        "subject": { "mediaType": OCI_MANIFEST, "digest": sd.to_string(), "size": 1 },
    }))
    .unwrap();
    let id = Digest::sha256_of(&index);
    let r = send(&app, Method::PUT, &format!("/v2/{repo}/manifests/{id}"), &[("content-type", OCI_INDEX)], index).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&r.body));
    let r = send(&app, Method::GET, &format!("/v2/{repo}/referrers/{sd}"), &[], vec![]).await;
    let refs = r.json()["manifests"].as_array().unwrap().clone();
    let ix = refs.iter().find(|m| m["digest"] == id.to_string()).unwrap();
    assert!(ix.get("artifactType").is_none(), "{ix}");
}

/// Blob `Range` per RFC 9110: only one `bytes` range is served as `206`; other units and
/// several ranges are ignored, as is a `Range` whose `If-Range` is not the blob's ETag.
#[tokio::test]
async fn blob_range_requests_follow_rfc_9110() {
    let app = app(base_config()).await;
    let repo = "acme/ranges";
    let data = b"0123456789".to_vec();
    let d = push_blob(&app, repo, &data, None).await;
    let uri = format!("/v2/{repo}/blobs/{d}");
    let etag = format!("\"{d}\"");
    for ignored in ["bytes=0-1,4-5", "items=0-1", "bytes=garbage", "bytes=1-x"] {
        let r = send(&app, Method::GET, &uri, &[("range", ignored)], vec![]).await;
        assert_eq!((r.status, r.body.clone()), (StatusCode::OK, data.clone()), "{ignored}");
    }
    let r = send(&app, Method::GET, &uri, &[("range", "BYTES=2-5")], vec![]).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::PARTIAL_CONTENT, b"2345".to_vec()));
    let r = send(&app, Method::GET, &uri, &[("range", "bytes=-3")], vec![]).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::PARTIAL_CONTENT, b"789".to_vec()));
    assert_eq!(r.header("content-range"), "bytes 7-9/10");
    for bad in ["bytes=10-", "bytes=20-30", "bytes=-0", "bytes=5-2"] {
        let r = send(&app, Method::GET, &uri, &[("range", bad)], vec![]).await;
        assert_eq!(r.status, StatusCode::RANGE_NOT_SATISFIABLE, "{bad}");
        assert_eq!(r.header("content-range"), "bytes */10", "{bad}");
        assert_eq!(r.json()["errors"][0]["code"], "UNSUPPORTED", "{bad}");
    }
    // If-Range: a stale validator gets the whole blob, the current one the range.
    let other = format!("\"{}\"", Digest::sha256_of(b"other"));
    for stale in [other.as_str(), "W/\"x\"", "Wed, 21 Oct 2015 07:28:00 GMT"] {
        let r = send(&app, Method::GET, &uri, &[("range", "bytes=2-5"), ("if-range", stale)], vec![]).await;
        assert_eq!((r.status, r.body.clone()), (StatusCode::OK, data.clone()), "{stale}");
    }
    let r = send(&app, Method::GET, &uri, &[("range", "bytes=2-5"), ("if-range", &etag)], vec![]).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::PARTIAL_CONTENT, b"2345".to_vec()));
}

/// Upload start checks `?digest-algorithm=`; `204`s carry no `Content-Length`; error codes come
/// from the spec's table.
#[tokio::test]
async fn upload_and_reference_errors_follow_the_spec() {
    let app = app(base_config()).await;
    let repo = "acme/spec";
    for bad in ["md5", "sha384", ""] {
        let r = send(&app, Method::POST, &format!("/v2/{repo}/blobs/uploads/?digest-algorithm={bad}"), &[], vec![]).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(r.json()["errors"][0]["code"], "DIGEST_INVALID", "{bad}");
    }
    for ok in ["sha256", "sha512"] {
        let r = send(&app, Method::POST, &format!("/v2/{repo}/blobs/uploads/?digest-algorithm={ok}"), &[], vec![]).await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{ok}");
        assert_eq!(r.header("content-length"), "0");
    }
    let r = send(&app, Method::POST, &format!("/v2/{repo}/blobs/uploads/"), &[], vec![]).await;
    let loc = r.header("location");
    let r = send(&app, Method::GET, &loc, &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.headers.get("content-length").is_none(), "upload status 204");
    assert_eq!(r.header("range"), "0-0");
    let r = send(&app, Method::DELETE, &loc, &[], vec![]).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.headers.get("content-length").is_none(), "upload cancel 204");

    // A reference that is neither a tag nor a digest.
    for method in [Method::GET, Method::HEAD, Method::DELETE] {
        let r = send(&app, method.clone(), &format!("/v2/{repo}/manifests/sha256:nothex"), &[], vec![]).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{method}");
        if method != Method::HEAD {
            assert_eq!(r.json()["errors"][0]["code"], "DIGEST_INVALID", "{method}");
        }
        let r = send(&app, method.clone(), &format!("/v2/{repo}/manifests/-bad-tag"), &[], vec![]).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{method}");
        if method != Method::HEAD {
            assert_eq!(r.json()["errors"][0]["code"], "TAG_INVALID", "{method}");
        }
    }
    // A bad page size, on tags/list and _catalog.
    push_blob(&app, repo, b"x", None).await;
    for uri in [format!("/v2/{repo}/tags/list?n=-1"), "/v2/_catalog?n=many".to_string()] {
        let r = send(&app, Method::GET, &uri, &[], vec![]).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(r.json()["errors"][0]["code"], "UNSUPPORTED", "{uri}");
    }
}
