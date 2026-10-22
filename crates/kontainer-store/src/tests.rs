use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use object_store::ObjectStoreExt;
use kontainer_core::config::{StorageConfig, StorageDriver};
use kontainer_core::digest::Digest;

use crate::metadata::{PutManifest, StoredManifest};
use crate::Storage;

async fn memory_storage(dir: &tempfile::TempDir) -> Storage {
    let cfg = StorageConfig { driver: StorageDriver::Memory, upload_dir: dir.path().join("uploads"), ..Default::default() };
    Storage::from_config(&cfg).await.unwrap()
}

async fn put_blob(s: &Storage, repo: &str, data: &[u8]) -> Digest {
    let d = Digest::sha256_of(data);
    s.store_and_link_bytes(repo, &d, Bytes::copy_from_slice(data)).await.unwrap();
    d
}

/// Store manifest `body` in `repo` (tagged `tag`); its blobs need not be linked.
async fn put_manifest(s: &Storage, repo: &str, body: &[u8], tag: Option<&str>) -> Digest {
    let d = Digest::sha256_of(body);
    let m = StoredManifest::new(d.clone(), kontainer_core::manifest::OCI_MANIFEST, Bytes::copy_from_slice(body));
    assert_eq!(s.put_manifest(repo, &m, &[], &[], tag).await.unwrap(), PutManifest::Stored { previous_tag: None });
    d
}

fn image(config: &Digest, layer: &Digest) -> String {
    format!(
        r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config}","size":2}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer}","size":11}}]}}"#
    )
}

#[tokio::test]
async fn delete_repository_leaves_nested_repositories() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    for repo in ["org/app", "org/app/sub"] {
        put_blob(&s, repo, repo.as_bytes()).await;
        put_manifest(&s, repo, format!("{{\"schemaVersion\":2,\"r\":\"{repo}\"}}").as_bytes(), Some("latest")).await;
    }
    s.delete_repository("org/app").await.unwrap();
    assert_eq!(s.list_repositories().await.unwrap(), vec!["org/app/sub".to_string()]);
    assert!(s.resolve_tag("org/app/sub", "latest").await.unwrap().is_some());
    assert!(s.resolve_tag("org/app", "latest").await.unwrap().is_none());
}

#[tokio::test]
async fn a_repository_exists_from_its_first_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    put_blob(&s, "org/app", b"layer").await;
    assert!(!s.repository_exists("org/app").await.unwrap(), "layers alone don't make a repository");
    assert_eq!(s.list_repositories().await.unwrap(), vec!["org/app".to_string()], "but it is listed, so GC visits its links");
    put_manifest(&s, "org/app/sub", b"{}", None).await;
    assert!(!s.repository_exists("org/app").await.unwrap(), "nor does a nested repository");
    assert!(s.repository_exists("org/app/sub").await.unwrap());
    put_manifest(&s, "org/app", b"{}", None).await;
    assert!(s.repository_exists("org/app").await.unwrap());
    assert!(s.namespace_has_repositories("org").await.unwrap());
    assert!(!s.namespace_has_repositories("or").await.unwrap());
    s.delete_repository("org/app").await.unwrap();
    assert!(!s.repository_exists("org/app").await.unwrap());
    assert!(!s.repository_exists("org").await.unwrap());
}

#[tokio::test]
async fn gc_keeps_layers_of_manifests_without_media_type() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let repo = "acme/app";
    let config = put_blob(&s, repo, b"{}").await;
    let layer = put_blob(&s, repo, b"layer bytes").await;
    put_manifest(&s, repo, image(&config, &layer).as_bytes(), Some("v1")).await;

    let report = crate::gc::run(&s, true, false, Duration::ZERO, &HashMap::new()).await.unwrap();
    assert!(report.blobs_removed.is_empty(), "{report:?}");
    assert!(report.links_removed.is_empty(), "{report:?}");
    assert!(s.blob_size(&layer).await.unwrap().is_some());
    assert!(s.blob_size(&config).await.unwrap().is_some());
}

#[tokio::test]
async fn gc_collects_nothing_in_a_repository_with_an_unreadable_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let repo = "acme/app";
    let layer = put_blob(&s, repo, b"layer bytes").await;
    put_manifest(&s, repo, b"not a manifest", None).await;

    let report = crate::gc::run(&s, true, false, Duration::ZERO, &HashMap::new()).await.unwrap();
    assert!(report.manifests_removed.is_empty(), "{report:?}");
    assert!(report.blobs_removed.is_empty(), "{report:?}");
    assert!(s.blob_size(&layer).await.unwrap().is_some());
}

#[tokio::test]
async fn upload_is_sealed_by_assemble() {
    use crate::uploads::Assembled;
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let id = s.upload_start("acme/app").await.unwrap();
    let chunk = |b: &'static [u8]| futures::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from_static(b))]);
    s.upload_append(&id, chunk(b"hel"), None).await.unwrap();
    s.upload_append(&id, chunk(b"lo"), None).await.unwrap();
    let d = Digest::sha256_of(b"hello");
    let Assembled::Verified(file) = s.upload_assemble(&id, &d).await.unwrap() else { panic!("not verified") };
    // A chunk arriving after the final PUT sealed the session is refused...
    assert!(s.upload_append(&id, chunk(b" world"), None).await.is_err());
    assert_eq!(s.upload_chunk_objects(&id).await.unwrap(), 2, "the refused chunk's object is gone");
    // ...so what is stored is exactly what was verified.
    s.blob_put_file(&d, &file).await.unwrap();
    assert_eq!(s.blob_bytes(&d).await.unwrap().unwrap(), Bytes::from_static(b"hello"));
    // A retried PUT for the same digest may assemble again; another digest may not.
    assert!(matches!(s.upload_assemble(&id, &d).await.unwrap(), Assembled::Verified(_)));
    assert!(matches!(s.upload_assemble(&id, &Digest::sha256_of(b"x")).await.unwrap(), Assembled::Unknown));
    s.upload_remove(&id).await.unwrap();
    assert!(s.upload_session(&id).await.unwrap().is_none());
    assert_eq!(s.upload_chunk_objects(&id).await.unwrap(), 0);
}

#[tokio::test]
async fn upload_assemble_detects_a_digest_mismatch() {
    use crate::uploads::Assembled;
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let id = s.upload_start("acme/app").await.unwrap();
    s.upload_append(&id, futures::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from_static(b"abc"))]), None).await.unwrap();
    assert!(matches!(s.upload_assemble(&id, &Digest::sha256_of(b"abd")).await.unwrap(), Assembled::Mismatch));
}

#[tokio::test]
async fn upload_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let id = s.upload_start("acme/app").await.unwrap();
    let chunk = |b: &'static [u8]| futures::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from_static(b))]);
    assert_eq!(s.upload_append(&id, chunk(b"hello"), Some(8)).await.unwrap(), 5);
    // The limit counts what is already staged: 5 + 6 > 8, and the chunk is not recorded.
    assert!(matches!(s.upload_append(&id, chunk(b" world"), Some(8)).await, Err(crate::uploads::AppendError::TooLarge { limit: 8 })));
    assert_eq!(s.upload_session(&id).await.unwrap().unwrap().offset, 5);
    assert_eq!(s.upload_chunk_objects(&id).await.unwrap(), 1);
    assert_eq!(s.upload_append(&id, chunk(b"!!!"), Some(8)).await.unwrap(), 8, "exactly the limit is fine");
}

#[tokio::test]
async fn purge_removes_expired_sessions_and_orphan_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let chunk = |b: &'static [u8]| futures::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from_static(b))]);
    let id = s.upload_start("acme/app").await.unwrap();
    s.upload_append(&id, chunk(b"abc"), None).await.unwrap();
    // A chunk whose session is gone (an instance stopped between the two deletes).
    let orphan = uuid::Uuid::new_v4().to_string();
    let here = s.preferred();
    here.store.put(&here.key(format!("{}{orphan}/0", crate::uploads::CHUNK_PREFIX)), object_store::PutPayload::from_static(b"x")).await.unwrap();
    // Nothing is stale yet.
    assert_eq!(s.purge_stale_uploads(Duration::from_secs(3600)).await.unwrap().total(), 0);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let purged = s.purge_stale_uploads(Duration::ZERO).await.unwrap();
    assert_eq!((purged.sessions, purged.orphan_chunks), (1, 1), "{purged:?}");
    assert!(s.upload_session(&id).await.unwrap().is_none());
    assert_eq!(s.upload_chunk_objects(&id).await.unwrap() + s.upload_chunk_objects(&orphan).await.unwrap(), 0);
}

#[tokio::test]
async fn blob_put_file_refuses_content_that_does_not_match() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let path = dir.path().join("f");
    tokio::fs::write(&path, b"actual").await.unwrap();
    let claimed = Digest::sha256_of(b"claimed");
    assert!(s.blob_put_file(&claimed, &path).await.is_err());
    assert!(s.blob_size(&claimed).await.unwrap().is_none());
}

#[tokio::test]
async fn temp_file_is_removed_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let t = s.uploads.temp_file().await.unwrap();
    tokio::fs::write(&t, b"x").await.unwrap();
    let p = t.path().to_path_buf();
    drop(t);
    assert!(!p.exists());
}

#[tokio::test]
async fn namespace_cache_counts_recorded_pushes() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let a = Digest::sha256_of(b"a");
    let b = Digest::sha256_of(b"b");
    let (used, missing) = crate::usage::namespace_missing(&s, "acme", vec![a.clone(), b.clone(), a.clone()]).await.unwrap();
    assert_eq!(used, 0);
    assert_eq!(missing.len(), 2);
    crate::usage::record_namespace_blobs(&s, "acme", [(a.clone(), 10)]);
    let (used, missing) = crate::usage::namespace_missing(&s, "acme", vec![a, b.clone()]).await.unwrap();
    assert_eq!(used, 10);
    assert_eq!(missing, vec![b]);
}

#[test]
fn unpack_stops_at_the_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar");
    let mut b = tar::Builder::new(std::fs::File::create(&archive).unwrap());
    let data = vec![7u8; 4096];
    let mut h = tar::Header::new_ustar();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, "blobs/sha256/aa", &data[..]).unwrap();
    b.finish().unwrap();
    drop(b);
    let out = dir.path().join("out");
    assert!(crate::layout::unpack(&archive, &out, 1000).is_err());
    let out2 = dir.path().join("out2");
    crate::layout::unpack(&archive, &out2, 4096).unwrap();
    assert_eq!(std::fs::read(out2.join("blobs/sha256/aa")).unwrap().len(), 4096);
}

#[tokio::test]
async fn namespace_usage_includes_the_repository_named_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    for (repo, data) in [("acme", &b"top"[..]), ("acme/app", &b"nested"[..]), ("acmecorp/app", &b"other namespace"[..])] {
        let d = put_blob(&s, repo, data).await;
        let body = format!(r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"x","digest":"{d}","size":1}}]}}"#);
        put_manifest(&s, repo, body.as_bytes(), None).await;
    }
    let (blobs, bytes) = crate::usage::namespace_blobs(&s, "acme").await.unwrap();
    assert_eq!(blobs.len(), 4, "two manifests and the two blobs they reference");
    let manifests: u64 = futures::future::join_all(["acme", "acme/app"].map(|r| s.metadata().manifests(r))).await.into_iter().map(|m| m.unwrap()[0].size()).sum();
    assert_eq!(bytes, 3 + 6 + manifests);
}

#[tokio::test]
async fn append_range_checks_offset_and_length_with_compare_and_set() {
    use crate::uploads::{AppendError, Assembled};
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let id = s.upload_start("acme/app").await.unwrap();
    let chunk = |b: &'static [u8]| futures::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from_static(b))]);
    assert_eq!(s.upload_append_range(&id, chunk(b"hello"), None, Some((0, 4))).await.unwrap(), 5);
    // Same start again (a concurrent or replayed PATCH): refused, nothing appended.
    assert!(matches!(s.upload_append_range(&id, chunk(b"hello"), None, Some((0, 4))).await, Err(AppendError::RangeMismatch { offset: 5 })));
    // Body shorter or longer than the range says: refused, nothing recorded.
    assert!(matches!(s.upload_append_range(&id, chunk(b" wo"), None, Some((5, 10))).await, Err(AppendError::RangeMismatch { offset: 5 })));
    assert!(matches!(s.upload_append_range(&id, chunk(b" world!!"), None, Some((5, 10))).await, Err(AppendError::RangeMismatch { offset: 5 })));
    assert_eq!(s.upload_session(&id).await.unwrap().unwrap().offset, 5);
    // Another chunk for offset 5 is recorded (by another instance) while this one's body is
    // still arriving: the compare-and-set fails, and this chunk's object is deleted.
    let sessions = s.uploads.sessions().clone();
    let (sid, racing) = (id.clone(), Bytes::from_static(b" world"));
    let body = futures::stream::once(async move {
        assert!(sessions.advance(&sid, 5, 3, "00000000000000000005-other").await.unwrap());
        Ok::<_, std::io::Error>(racing)
    })
    .boxed();
    assert!(matches!(s.upload_append_range(&id, body, None, Some((5, 10))).await, Err(AppendError::RangeMismatch { offset: 8 })));
    assert_eq!(s.upload_chunk_objects(&id).await.unwrap(), 1, "only the first chunk is stored");
    s.upload_remove(&id).await.unwrap();

    let id = s.upload_start("acme/app").await.unwrap();
    assert_eq!(s.upload_append_range(&id, chunk(b"hello"), None, Some((0, 4))).await.unwrap(), 5);
    assert_eq!(s.upload_append_range(&id, chunk(b" world"), None, Some((5, 10))).await.unwrap(), 11);
    assert!(matches!(s.upload_assemble(&id, &Digest::sha256_of(b"hello world")).await.unwrap(), Assembled::Verified(_)));
}

#[tokio::test]
async fn put_manifest_needs_linked_blobs_and_children_and_refreshes_links() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let repo = "acme/app";
    let config = put_blob(&s, repo, b"{}").await;
    let layer = Digest::sha256_of(b"layer bytes");
    let child = Digest::sha256_of(b"child");
    let body = image(&config, &layer);
    let m = StoredManifest::new(Digest::sha256_of(body.as_bytes()), kontainer_core::manifest::OCI_MANIFEST, Bytes::from(body.clone()));
    let got = s.put_manifest(repo, &m, &[config.clone(), layer.clone()], std::slice::from_ref(&child), Some("v1")).await.unwrap();
    assert_eq!(got, PutManifest::Missing(vec![layer.clone(), child]));
    assert!(!s.has_manifest(repo, &m.digest).await.unwrap(), "nothing stored");
    assert!(s.resolve_tag(repo, "v1").await.unwrap().is_none());

    put_blob(&s, repo, b"layer bytes").await;
    let before = s.metadata().blob_link(repo, &config).await.unwrap().unwrap().linked_at;
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(s.put_manifest(repo, &m, &[config.clone(), layer], &[], Some("v1")).await.unwrap(), PutManifest::Stored { previous_tag: None });
    assert!(s.metadata().blob_link(repo, &config).await.unwrap().unwrap().linked_at > before, "a push refreshes the links it references");
    assert_eq!(s.manifest_bytes(repo, &m.digest).await.unwrap().unwrap(), Bytes::from(body));
    assert_eq!(s.put_tag(repo, "v1", &m.digest).await.unwrap(), Some(m.digest.clone()));
    assert!(s.put_tag(repo, "v2", &Digest::sha256_of(b"nope")).await.is_err(), "tags point at manifests of the repository");
    assert_eq!(s.delete_manifest(repo, &m.digest).await.unwrap(), Some(vec!["v1".to_string()]));
    assert_eq!(s.delete_manifest(repo, &m.digest).await.unwrap(), None);
}

/// Old, unreferenced blobs go; one linked again while the collection runs stays, even when the
/// link lands while its delete is in progress: the link waits, finds the blob gone, and the
/// linker stores it again.
#[tokio::test]
async fn gc_never_leaves_a_link_without_its_blob() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let relinked = Digest::sha256_of(b"relinked");
    let orphan = Digest::sha256_of(b"orphan");
    s.blob_put(&relinked, Bytes::from_static(b"relinked")).await.unwrap();
    s.blob_put(&orphan, Bytes::from_static(b"orphan")).await.unwrap();
    let grace = Duration::from_millis(200);
    tokio::time::sleep(grace + Duration::from_millis(50)).await;

    // Linked before the collection: kept, the orphan goes.
    assert!(s.link_blob("late/repo", &relinked, 8).await.unwrap());
    let report = crate::gc::run(&s, false, false, grace, &HashMap::new()).await.unwrap();
    assert_eq!(report.blobs_removed, vec![orphan.to_string()], "{report:?}");
    assert!(s.blob_size(&relinked).await.unwrap().is_some());

    // A sweep in progress (its delete is running) when a link comes in.
    assert!(s.unlink_blob("late/repo", &relinked).await.unwrap());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel::<()>();
    let sweeper = {
        let (s, d) = (s.clone(), relinked.clone());
        tokio::spawn(async move {
            let delete = Box::pin(async {
                started_tx.send(()).unwrap();
                finish_rx.await.unwrap();
                s.blob_delete(&d).await
            });
            s.metadata().sweep_blob(&d, delete).await.unwrap()
        })
    };
    started_rx.await.unwrap();
    let linker = {
        let (s, d) = (s.clone(), relinked.clone());
        tokio::spawn(async move { s.link_blob("late/repo", &d, 8).await.unwrap() })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!linker.is_finished(), "the link waits for the sweep");
    finish_tx.send(()).unwrap();
    assert!(sweeper.await.unwrap(), "nothing linked it when the sweep looked");
    assert!(!linker.await.unwrap(), "the blob is gone: the link is refused and removed");
    assert!(s.repo_blob_size("late/repo", &relinked).await.unwrap().is_none());
    // What a push does with the content in hand: store it again and link.
    s.store_and_link_bytes("late/repo", &relinked, Bytes::from_static(b"relinked")).await.unwrap();
    assert_eq!(s.repo_blob_size("late/repo", &relinked).await.unwrap(), Some(8));
    assert!(s.blob_size(&relinked).await.unwrap().is_some());

    // A sweep that finds the blob linked does not delete it.
    let ran = s.metadata().sweep_blob(&relinked, Box::pin(async { panic!("must not delete a linked blob") })).await.unwrap();
    assert!(!ran);
}

/// Hand-made keys of the layout before metadata moved into the database.
async fn put_legacy(s: &Storage, rel: String, data: &[u8]) {
    s.preferred().store.put(&s.key(rel), object_store::PutPayload::from(data.to_vec())).await.unwrap();
}

fn link_path(d: &Digest) -> String {
    format!("{}/{}/link", d.algorithm().as_str(), d.hex())
}

#[tokio::test]
async fn migrate_metadata_from_the_old_layout() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let repo = "acme/app";
    let (config, layer) = (Digest::sha256_of(b"{}"), Digest::sha256_of(b"layer bytes"));
    s.blob_put(&config, Bytes::from_static(b"{}")).await.unwrap();
    s.blob_put(&layer, Bytes::from_static(b"layer bytes")).await.unwrap();
    let body = image(&config, &layer);
    let md = Digest::sha256_of(body.as_bytes());
    s.blob_put(&md, Bytes::from(body.clone())).await.unwrap();
    let sbom = format!(r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/spdx+json","config":{{"mediaType":"application/vnd.oci.empty.v1+json","digest":"{config}","size":2}},"layers":[],"subject":{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{md}","size":1}}}}"#);
    let sd = Digest::sha256_of(sbom.as_bytes());
    s.blob_put(&sd, Bytes::from(sbom.clone())).await.unwrap();
    let dangling = Digest::sha256_of(b"never stored");
    for d in [&config, &layer] {
        put_legacy(&s, format!("repositories/{repo}/_layers/{}", link_path(d)), d.to_string().as_bytes()).await;
    }
    put_legacy(&s, format!("repositories/{repo}/_layers/{}", link_path(&dangling)), dangling.to_string().as_bytes()).await;
    for d in [&md, &sd] {
        put_legacy(&s, format!("repositories/{repo}/_manifests/revisions/{}", link_path(d)), d.to_string().as_bytes()).await;
    }
    // `body` has no mediaType: the push-time Content-Type was kept next to it.
    put_legacy(&s, format!("repositories/{repo}/_manifests/revisions/{}/{}/mediatype", md.algorithm().as_str(), md.hex()), b"application/vnd.docker.distribution.manifest.v2+json").await;
    put_legacy(&s, format!("repositories/{repo}/_manifests/tags/v1/current/link"), md.to_string().as_bytes()).await;
    put_legacy(&s, format!("repositories/{repo}/_manifests/tags/latest/current/link"), md.to_string().as_bytes()).await;
    put_legacy(&s, format!("repositories/{repo}/_manifests/tags/gone/current/link"), dangling.to_string().as_bytes()).await;
    put_legacy(&s, format!("repositories/{repo}/_referrers/{}/{}/{}", md.algorithm().as_str(), md.hex(), link_path(&sd)), sd.to_string().as_bytes()).await;
    put_legacy(&s, format!("repositories/{repo}/sub/_manifests/revisions/{}", link_path(&md)), md.to_string().as_bytes()).await;
    put_legacy(&s, format!("_touched/{}/{}", md.algorithm().as_str(), md.hex()), b"").await;

    assert!(s.has_legacy_metadata().await.unwrap());
    let err = crate::gc::run(&s, false, true, Duration::ZERO, &HashMap::new()).await.unwrap_err();
    assert!(err.to_string().contains("migrate-metadata"), "{err}");

    let counts = crate::legacy::migrate(&s).await.unwrap();
    assert_eq!(counts, crate::metadata::Counts { repositories: 2, manifests: 3, tags: 2, blob_links: 2, skipped: 2 }, "the dangling tag and link are skipped");
    assert_eq!(s.list_repositories().await.unwrap(), vec![repo.to_string(), format!("{repo}/sub")]);
    assert_eq!(s.list_tags(repo).await.unwrap(), vec!["latest".to_string(), "v1".to_string()]);
    assert_eq!(s.resolve_tag(repo, "v1").await.unwrap(), Some(md.clone()));
    let m = s.manifest(repo, &md).await.unwrap().unwrap();
    assert_eq!((m.media_type.as_str(), m.body.clone()), ("application/vnd.docker.distribution.manifest.v2+json", Bytes::from(body)));
    assert_eq!(s.manifest(repo, &sd).await.unwrap().unwrap().media_type, kontainer_core::manifest::OCI_MANIFEST);
    let refs = s.list_referrers(repo, &md, None).await.unwrap();
    assert_eq!(refs.iter().map(|r| r.digest.clone()).collect::<Vec<_>>(), vec![sd.clone()]);
    assert_eq!(refs[0].artifact_type.as_deref(), Some("application/spdx+json"));
    assert_eq!(s.repo_blob_size(repo, &layer).await.unwrap(), Some(11));
    assert!(s.repo_blob_size(repo, &dangling).await.unwrap().is_none());

    // Idempotent: a second run inserts nothing and changes nothing.
    let again = crate::legacy::migrate(&s).await.unwrap();
    assert_eq!((again.manifests, again.tags, again.blob_links), (0, 0, 0));
    assert_eq!(s.list_tags(repo).await.unwrap().len(), 2);
    // The old keys stay; collection now works and keeps everything referenced, only the old
    // manifest bodies under blobs/ go.
    assert!(s.has_legacy_metadata().await.unwrap());
    let report = crate::gc::run(&s, false, false, Duration::ZERO, &HashMap::new()).await.unwrap();
    let mut removed = report.blobs_removed.clone();
    removed.sort();
    let mut want = vec![md.to_string(), sd.to_string()];
    want.sort();
    assert_eq!(removed, want, "{report:?}");
    assert!(s.blob_size(&layer).await.unwrap().is_some());
}

#[tokio::test]
async fn metadata_export_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let s = memory_storage(&dir).await;
    let config = put_blob(&s, "acme/app", b"{}").await;
    let layer = put_blob(&s, "acme/app", b"layer bytes").await;
    let md = put_manifest(&s, "acme/app", image(&config, &layer).as_bytes(), Some("v1")).await;
    s.put_tag("acme/app", "latest", &md).await.unwrap();
    put_manifest(&s, "acme/other", b"\xff not utf-8", None).await;

    let mut out = vec![];
    let written = crate::metadata::export_jsonl(s.metadata().as_ref(), &mut out).await.unwrap();
    assert_eq!(written, crate::metadata::Counts { repositories: 2, manifests: 2, tags: 2, blob_links: 2, skipped: 0 });

    let other = memory_storage(&dir).await;
    let read = crate::metadata::import_jsonl(other.metadata().as_ref(), &out[..]).await.unwrap();
    assert_eq!(read, written);
    for repo in ["acme/app", "acme/other"] {
        let (a, b) = (s.metadata().snapshot(repo).await.unwrap(), other.metadata().snapshot(repo).await.unwrap());
        assert_eq!(a.manifests, b.manifests);
        assert_eq!(a.links, b.links);
        assert_eq!(a.tags.iter().map(|t| (&t.tag, &t.digest, t.pushed_at)).collect::<Vec<_>>(), b.tags.iter().map(|t| (&t.tag, &t.digest, t.pushed_at)).collect::<Vec<_>>());
    }
    let again = crate::metadata::import_jsonl(other.metadata().as_ref(), &out[..]).await.unwrap();
    assert_eq!((again.manifests, again.tags, again.blob_links, again.skipped), (0, 0, 0, 6));
}

/// Two peer locations: a write lands in the preferred one, is recorded there and queued for the
/// other; the copy is verified and recorded; reads prefer the client's region, then the
/// preferred location.
#[tokio::test]
async fn writes_are_placed_locally_and_copied_to_the_other_locations() {
    use crate::placement::{JobKind, MemoryPlacements, Placements};
    use crate::replication::Replicated;
    use kontainer_core::config::LocationConfig;
    let dir = tempfile::tempdir().unwrap();
    let loc = |name: &str, regions: &[&str]| LocationConfig { name: name.into(), driver: StorageDriver::Memory, regions: regions.iter().map(|r| r.to_string()).collect(), ..Default::default() };
    let cfg = StorageConfig { upload_dir: dir.path().join("uploads"), location: "eu".into(), locations: vec![loc("eu", &["eu-*"]), loc("us", &["us-*"])], ..Default::default() };
    let mut s = Storage::from_config(&cfg).await.unwrap();
    let places = std::sync::Arc::new(MemoryPlacements::default());
    s.set_placements(places.clone());

    let d = put_blob(&s, "acme/app", b"some layer").await;
    assert_eq!(places.placements(&d).await.unwrap(), [("eu".to_string(), 10)]);
    assert_eq!(places.queued(), [(JobKind::Blob, d.to_string(), "us".to_string())]);
    let names = |v: Vec<(&crate::Location, u64)>| v.into_iter().map(|(l, _)| l.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(s.blob_sources(&d, Some("us-west-2")).await.unwrap()), ["eu"], "not in us yet");

    let job = places.next_job().unwrap();
    assert_eq!(s.replicate(&job, "w").await.unwrap(), Replicated::Copied(10));
    assert!(places.queued().is_empty());
    assert_eq!(names(s.blob_sources(&d, Some("us-west-2")).await.unwrap()), ["us", "eu"]);
    assert_eq!(names(s.blob_sources(&d, None).await.unwrap()), ["eu", "us"]);
    let us = s.location("us").unwrap();
    assert_eq!(us.store.get(&us.key(crate::blob_rel(&d))).await.unwrap().bytes().await.unwrap().as_ref(), b"some layer");

    // A copy whose source does not match its digest is refused, and nothing is recorded.
    let bad = Digest::sha256_of(b"other bytes");
    let eu = s.preferred();
    eu.store.put(&eu.key(crate::blob_rel(&bad)), object_store::PutPayload::from_static(b"tampered!!!")).await.unwrap();
    places.place(&bad, "eu", 11).await.unwrap();
    places.enqueue_replication(JobKind::Blob, &[bad.to_string()], &["us".into()]).await.unwrap();
    let job = places.next_job().unwrap();
    let e = s.replicate(&job, "w").await.unwrap_err().to_string();
    assert!(e.contains("hashes to"), "{e}");
    assert!(!places.placements(&bad).await.unwrap().iter().any(|(l, _)| l == "us"));
    assert!(us.store.head(&us.key(crate::blob_rel(&bad))).await.is_err());

    // Garbage collection removes the blob from both locations, its placements and its copies.
    s.unlink_blob("acme/app", &d).await.unwrap();
    let report = crate::gc::run(&s, false, false, Duration::ZERO, &HashMap::new()).await.unwrap();
    assert!(report.blobs_removed.contains(&d.to_string()), "{report:?}");
    assert!(places.placements(&d).await.unwrap().is_empty());
    assert!(places.queued().iter().all(|(_, k, _)| *k != bad.to_string()), "queued copies of a deleted blob are dropped");
    assert!(us.store.head(&us.key(crate::blob_rel(&d))).await.is_err());
    assert!(s.blob_size(&d).await.unwrap().is_none());
}
