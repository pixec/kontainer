//! OCI image layout archives: export a tag as a tarball, and import one.
//!
//! The archive is a standard OCI image layout (`oci-layout`, `index.json`, `blobs/sha256/*`),
//! which `docker load` (Docker 25+), `skopeo copy oci-archive:`, `oras` and `crane` read. For a
//! single-platform image a Docker `manifest.json` is included too, for older `docker load`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::{SinkExt, TryStreamExt};

use kontainer_core::digest::Digest;
use kontainer_core::manifest::{Manifest, OCI_INDEX};
use crate::Storage;

const BLOCK: usize = 512;

fn tar_header(path: &str, size: u64) -> Result<Bytes> {
    let mut h = tar::Header::new_ustar();
    h.set_path(path)?;
    h.set_size(size);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    Ok(Bytes::copy_from_slice(h.as_bytes()))
}

fn padding(size: u64) -> Bytes {
    let rem = (size as usize) % BLOCK;
    Bytes::from(vec![0u8; if rem == 0 { 0 } else { BLOCK - rem }])
}

/// One file of an exported layout: a manifest body (from the metadata) or a blob (streamed
/// from storage).
enum Entry {
    Manifest(Digest, Bytes),
    Blob(Digest, u64),
}

impl Entry {
    fn size(&self) -> u64 {
        match self {
            Entry::Manifest(_, b) => b.len() as u64,
            Entry::Blob(_, n) => *n,
        }
    }
}

/// Everything a manifest needs: itself, children (for an index) and the configs and layers the
/// repository links, in dependency order.
async fn closure(storage: &Storage, repo: &str, root: &Digest) -> Result<(Vec<Entry>, Manifest, String)> {
    let mut out: Vec<Entry> = vec![];
    let mut seen = BTreeSet::new();
    let root_row = storage.manifest(repo, root).await?.ok_or_else(|| anyhow!("manifest {root} missing"))?;
    let root_manifest = crate::parse_stored_manifest(&root_row.body).map_err(|e| anyhow!(e))?;
    let root_media = match kontainer_core::manifest::body_media_type(&root_row.body) {
        Some(_) => crate::infer_media_type(&root_row.body),
        None => root_row.media_type.clone(),
    };
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        if !seen.insert(d.to_string()) {
            continue;
        }
        let Some(b) = storage.manifest_bytes(repo, &d).await? else { continue };
        let parsed = crate::parse_stored_manifest(&b);
        out.push(Entry::Manifest(d.clone(), b));
        match parsed {
            Ok(Manifest::Index(ix)) => {
                for c in &ix.manifests {
                    if storage.has_manifest(repo, &c.digest).await? {
                        stack.push(c.digest.clone());
                    }
                }
            }
            Ok(Manifest::Image(im)) => {
                for blob in std::iter::once(&im.config.digest).chain(im.layers.iter().map(|l| &l.digest)) {
                    if seen.insert(blob.to_string()) {
                        if let Some(size) = storage.repo_blob_size(repo, blob).await? {
                            out.push(Entry::Blob(blob.clone(), size));
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
    Ok((out, root_manifest, root_media))
}

/// A streaming tar of one tag (or digest). Returns the stream; errors after the first byte
/// end the stream early, which clients see as a truncated download.
pub async fn export(storage: Storage, repo: &str, digest: Digest, ref_name: &str, image_name: &str) -> Result<futures::channel::mpsc::Receiver<std::io::Result<Bytes>>> {
    let (blobs, root, root_media) = closure(&storage, repo, &digest).await?;
    let root_size = blobs.first().map(Entry::size).unwrap_or(0);
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [{
            "mediaType": root_media,
            "digest": digest.to_string(),
            "size": root_size,
            "annotations": { "org.opencontainers.image.ref.name": ref_name, "io.containerd.image.name": image_name },
        }],
    });
    let mut small: Vec<(String, Vec<u8>)> = vec![
        ("oci-layout".into(), br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec()),
        ("index.json".into(), serde_json::to_vec(&index)?),
    ];
    if let Manifest::Image(im) = &root {
        let blob_path = |d: &Digest| format!("blobs/{}/{}", d.algorithm().as_str(), d.hex());
        let docker = serde_json::json!([{
            "Config": blob_path(&im.config.digest),
            "RepoTags": [image_name],
            "Layers": im.layers.iter().map(|l| blob_path(&l.digest)).collect::<Vec<_>>(),
        }]);
        small.push(("manifest.json".into(), serde_json::to_vec(&docker)?));
    }
    let repo = repo.to_string();
    let (mut tx, rx) = futures::channel::mpsc::channel::<std::io::Result<Bytes>>(16);
    tokio::spawn(async move {
        let result = async {
            for (path, data) in &small {
                tx.send(Ok(tar_header(path, data.len() as u64)?)).await?;
                tx.send(Ok(Bytes::from(data.clone()))).await?;
                tx.send(Ok(padding(data.len() as u64))).await?;
            }
            for entry in &blobs {
                let (Entry::Manifest(d, _) | Entry::Blob(d, _)) = entry;
                let size = entry.size();
                tx.send(Ok(tar_header(&format!("blobs/{}/{}", d.algorithm().as_str(), d.hex()), size)?)).await?;
                match entry {
                    Entry::Manifest(_, body) => tx.send(Ok(body.clone())).await?,
                    Entry::Blob(d, _) => {
                        let stream = storage.blob_stream(d, None).await?.ok_or_else(|| anyhow!("blob {d} vanished during export of {repo}"))?;
                        let mut s = stream.stream;
                        while let Some(chunk) = s.try_next().await? {
                            tx.send(Ok(chunk)).await?;
                        }
                    }
                }
                tx.send(Ok(padding(size))).await?;
            }
            tx.send(Ok(Bytes::from(vec![0u8; BLOCK * 2]))).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, "image export aborted");
            let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
        }
    });
    Ok(rx)
}

/// Most bytes an archive may unpack to (guards against decompression bombs).
pub const MAX_UNPACKED_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Why an archive import failed: the archive's fault (tell the client) or ours (log it).
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The archive is not a usable OCI image layout. The message is for the client.
    #[error("{0}")]
    Invalid(String),
    /// The archive could not be unpacked: not a (gzipped) tar, or truncated.
    #[error("the archive could not be read: {0}")]
    Unreadable(#[source] std::io::Error),
    /// Storing what it contains failed (storage, local disk): not the archive's fault.
    #[error(transparent)]
    Storage(anyhow::Error),
}

impl ImportError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    fn storage(e: impl Into<anyhow::Error>) -> Self {
        Self::Storage(e.into())
    }
}

/// Unpack an OCI image layout tarball (optionally gzipped) into `dir`, writing at most `limit`
/// bytes. Blocking.
pub(crate) fn unpack(archive: &Path, dir: &Path, limit: u64) -> Result<(), ImportError> {
    let unreadable = ImportError::Unreadable;
    let mut file = std::fs::File::open(archive).map_err(ImportError::storage)?;
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic).ok();
    let file = std::fs::File::open(archive).map_err(ImportError::storage)?;
    let reader: Box<dyn Read> = if magic == [0x1f, 0x8b] { Box::new(flate2::read::GzDecoder::new(file)) } else { Box::new(file) };
    let mut tar = tar::Archive::new(reader);
    let mut total = 0u64;
    for entry in tar.entries().map_err(unreadable)? {
        let mut entry = entry.map_err(unreadable)?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path().map_err(unreadable)?.to_path_buf();
        let rel = path.strip_prefix("./").unwrap_or(&path).to_path_buf();
        // Only what a layout contains; never write outside `dir`.
        let s = rel.to_string_lossy().to_string();
        let ok = s == "index.json" || s == "oci-layout" || (s.starts_with("blobs/") && !s.contains(".."));
        if !ok {
            continue;
        }
        let dest = dir.join(&rel);
        std::fs::create_dir_all(dest.parent().unwrap_or(dir)).map_err(ImportError::storage)?;
        // Copy through a counting limit rather than trusting the header's size. `io::copy`
        // can't tell a bad archive (truncated, corrupt gzip) from a failed write; the former is
        // by far the likelier, so this counts as unreadable.
        let mut out = std::fs::File::create(&dest).map_err(ImportError::storage)?;
        let budget = limit.saturating_sub(total);
        let n = std::io::copy(&mut (&mut entry).take(budget.saturating_add(1)), &mut out).map_err(unreadable)?;
        if n > budget {
            return Err(ImportError::invalid(format!("archive unpacks to more than {limit} bytes")));
        }
        total += n;
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::Digest as _;
    let mut f = std::fs::File::open(path)?;
    let mut h = sha2::Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

#[derive(Debug, Default, serde::Serialize)]
pub struct Imported {
    pub tags: Vec<String>,
    /// Tag -> manifest, for the caller to apply (and record) once everything is stored.
    #[serde(skip)]
    pub roots: Vec<(String, Digest)>,
    pub manifests: usize,
    pub blobs: usize,
}

/// Import an OCI image layout archive into `repo`. `tag` overrides the tag names recorded in
/// the archive's `index.json` (`org.opencontainers.image.ref.name`).
pub async fn import(storage: &Storage, repo: &str, archive: &Path, work: &Path, tag: Option<&str>) -> Result<Imported, ImportError> {
    let (a, w) = (archive.to_path_buf(), work.to_path_buf());
    tokio::task::spawn_blocking(move || unpack(&a, &w, MAX_UNPACKED_BYTES)).await.map_err(ImportError::storage)??;
    let index_bytes = tokio::fs::read(work.join("index.json")).await.map_err(|_| ImportError::invalid("not an OCI image layout: index.json is missing (Docker archives need `docker save` from Docker 25 or newer)"))?;
    let index: serde_json::Value = serde_json::from_slice(&index_bytes).map_err(|_| ImportError::invalid("index.json is not valid JSON"))?;
    let blob_file = |d: &Digest| -> PathBuf { work.join("blobs").join(d.algorithm().as_str()).join(d.hex()) };
    let mut out = Imported::default();
    let mut stored: BTreeSet<String> = BTreeSet::new();

    // Store a blob after checking its digest.
    async fn put(storage: &Storage, repo: &str, d: &Digest, path: &Path, stored: &mut BTreeSet<String>) -> Result<(), ImportError> {
        if !stored.insert(d.to_string()) {
            return Ok(());
        }
        if d.algorithm().as_str() != "sha256" {
            return Err(ImportError::invalid(format!("unsupported digest algorithm in {d}")));
        }
        let p = path.to_path_buf();
        let got = tokio::task::spawn_blocking(move || sha256_file(&p)).await.map_err(ImportError::storage)?.map_err(ImportError::Storage)?;
        if got != d.hex() {
            return Err(ImportError::invalid(format!("blob {d} is corrupt (content hashes to sha256:{got})")));
        }
        storage.store_and_link_file(repo, d, path).await.map_err(ImportError::Storage)?;
        Ok(())
    }

    let mut roots: BTreeMap<String, Digest> = BTreeMap::new();
    for m in index["manifests"].as_array().into_iter().flatten() {
        let d: Digest = m["digest"].as_str().unwrap_or_default().parse().map_err(|_| ImportError::invalid("bad digest in index.json"))?;
        let name = tag.map(str::to_string).or_else(|| m["annotations"]["org.opencontainers.image.ref.name"].as_str().map(|r| r.rsplit(':').next().unwrap_or(r).to_string())).unwrap_or_else(|| "latest".into());
        roots.insert(name, d);
    }
    if roots.is_empty() {
        return Err(ImportError::invalid("index.json lists no images"));
    }
    for (name, root) in &roots {
        if !kontainer_core::names::is_valid_tag(name) {
            return Err(ImportError::invalid(format!("invalid tag {name:?}; pass ?tag=")));
        }
        let mut stack = vec![root.clone()];
        let mut manifests = vec![];
        while let Some(d) = stack.pop() {
            let path = blob_file(&d);
            let bytes = tokio::fs::read(&path).await.map_err(|_| ImportError::invalid(format!("manifest {d} is missing from the archive")))?;
            let m = crate::parse_stored_manifest(&bytes).map_err(|e| ImportError::invalid(format!("manifest {d}: {e}")))?;
            match &m {
                Manifest::Index(ix) => {
                    for c in &ix.manifests {
                        if tokio::fs::try_exists(blob_file(&c.digest)).await.map_err(ImportError::storage)? {
                            stack.push(c.digest.clone());
                        }
                    }
                }
                Manifest::Image(im) => {
                    for b in std::iter::once(&im.config.digest).chain(im.layers.iter().map(|l| &l.digest)) {
                        let p = blob_file(b);
                        if !tokio::fs::try_exists(&p).await.map_err(ImportError::storage)? {
                            return Err(ImportError::invalid(format!("blob {b} is missing from the archive")));
                        }
                        put(storage, repo, b, &p, &mut stored).await?;
                        out.blobs += 1;
                    }
                }
            }
            let blobs: Vec<Digest> = m.required_blobs().iter().map(|b| b.digest.clone()).collect();
            manifests.push((d, bytes, blobs));
        }
        // Children before parents.
        for (d, bytes, blobs) in manifests.into_iter().rev() {
            if stored.insert(d.to_string()) {
                let got = kontainer_core::digest::Digest::sha256_of(&bytes);
                if got != d {
                    return Err(ImportError::invalid(format!("manifest {d} is corrupt")));
                }
                let media_type = crate::infer_media_type(&bytes);
                let row = crate::metadata::StoredManifest::new(d.clone(), media_type, Bytes::from(bytes));
                match storage.put_manifest(repo, &row, &blobs, &[], None).await.map_err(ImportError::Storage)? {
                    crate::metadata::PutManifest::Stored { .. } => {}
                    crate::metadata::PutManifest::Missing(m) => return Err(ImportError::Storage(anyhow!("manifest {d}: blobs {m:?} were unlinked while importing"))),
                }
                out.manifests += 1;
            }
        }
        out.roots.push((name.clone(), root.clone()));
        out.tags.push(name.clone());
    }
    Ok(out)
}
