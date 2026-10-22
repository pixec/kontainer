//! Registry domain types with no I/O: digests, names, manifests, artifact classification,
//! glob matching, and what the registry and its build runners share.

pub mod artifact;
pub mod build;
pub mod config;
pub mod crypto;
pub mod digest;
pub mod glob;
pub mod manifest;
pub mod names;
pub mod perm;
pub mod secret;
pub mod upstream;

pub use secret::WireSecret;

/// The `User-Agent` for every request Kontainer makes, e.g. `kontainer/0.2.0`.
pub const USER_AGENT: &str = concat!("kontainer/", env!("CARGO_PKG_VERSION"));

/// `bytes` random bytes, hex-encoded.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::fill(&mut buf[..]);
    hex::encode(buf)
}
