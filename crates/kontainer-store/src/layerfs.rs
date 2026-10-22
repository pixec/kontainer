//! Listing the files inside a layer tarball without materialising it on disk.
//!
//! The blob is streamed from storage, bridged into a blocking reader, decompressed according
//! to the layer media type and walked with the `tar` crate on a blocking thread.

use std::io::Read;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use serde::Serialize;
use tokio_util::io::{StreamReader, SyncIoBridge};

use kontainer_core::digest::Digest;
use crate::Storage;

#[derive(Debug, Serialize)]
pub struct LayerEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub size: u64,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    /// OCI is_whiteout: this entry deletes a path from lower layers.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_whiteout: bool,
}

#[derive(Debug, Serialize)]
pub struct LayerListing {
    pub digest: String,
    pub media_type: String,
    pub compression: &'static str,
    pub entries: Vec<LayerEntry>,
    pub is_truncated: bool,
    pub total_uncompressed: u64,
}

fn compression_for(media_type: &str) -> &'static str {
    if media_type.ends_with("+gzip") || media_type.ends_with(".gzip") || media_type.ends_with("tar.gzip") {
        "gzip"
    } else if media_type.ends_with("+zstd") || media_type.ends_with(".zstd") {
        "zstd"
    } else if media_type.ends_with(".tar") || media_type.ends_with("+tar") {
        "none"
    } else {
        "auto"
    }
}

pub async fn list_files(storage: &Storage, digest: &Digest, media_type: &str, limit: usize) -> Result<Option<LayerListing>> {
    let Some(blob) = storage.blob_stream(digest, None).await? else { return Ok(None) };
    let reader = StreamReader::new(blob.stream.map_err(std::io::Error::other));
    let bridge = SyncIoBridge::new(reader);
    let compression = compression_for(media_type);
    let digest_s = digest.to_string();
    let media_type_s = media_type.to_string();

    let listing = tokio::task::spawn_blocking(move || -> Result<LayerListing> {
        let mut peek = std::io::BufReader::with_capacity(64 * 1024, bridge);
        let compression = if compression == "auto" {
            use std::io::BufRead;
            let head = peek.fill_buf()?;
            if head.starts_with(&[0x1f, 0x8b]) {
                "gzip"
            } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
                "zstd"
            } else {
                "none"
            }
        } else {
            compression
        };
        let reader: Box<dyn Read> = match compression {
            "gzip" => Box::new(flate2::read::MultiGzDecoder::new(peek)),
            "zstd" => Box::new(zstd::stream::read::Decoder::new(peek).context("zstd decoder")?),
            _ => Box::new(peek),
        };
        let mut archive = tar::Archive::new(reader);
        let mut entries = vec![];
        let mut is_truncated = false;
        let mut total = 0u64;
        for entry in archive.entries().context("reading tar")? {
            let entry = entry.context("reading tar entry")?;
            let header = entry.header();
            let path = entry.path().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let path = path.strip_prefix("./").unwrap_or(&path).to_string();
            let size = header.size().unwrap_or(0);
            total += size;
            if entries.len() >= limit {
                is_truncated = true;
                continue; // keep draining to count total size
            }
            let kind = match header.entry_type() {
                tar::EntryType::Directory => "dir",
                tar::EntryType::Symlink => "symlink",
                tar::EntryType::Link => "hardlink",
                tar::EntryType::Char | tar::EntryType::Block => "device",
                tar::EntryType::Fifo => "fifo",
                _ => "file",
            };
            let file_name = path.rsplit('/').next().unwrap_or(&path);
            let is_whiteout = file_name.starts_with(".wh.");
            entries.push(LayerEntry {
                kind,
                size,
                mode: format!("{:o}", header.mode().unwrap_or(0) & 0o7777),
                link_target: entry.link_name().ok().flatten().map(|p| p.to_string_lossy().to_string()),
                mtime: header.mtime().ok().map(|m| m as i64),
                is_whiteout,
                path,
            });
        }
        Ok(LayerListing { digest: digest_s, media_type: media_type_s, compression, entries, is_truncated, total_uncompressed: total })
    })
    .await??;
    Ok(Some(listing))
}
