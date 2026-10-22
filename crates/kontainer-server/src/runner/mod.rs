//! Build runners: `kontainer runner` claims queued builds from a registry and runs them. The
//! registry itself never builds; it only keeps the queue.
//!
//! A runner checks out the commit, builds it with BuildKit and hands back an OCI archive, which
//! the registry imports. Runners never get registry credentials, only their own token (to claim
//! builds) and a token per build.
//!
//! - [`worker`]: claiming builds and running them, here or through a launcher.
//! - [`steps`]: the build itself (git, BuildKit), independent of where it runs.
//! - [`launch`]: running a build in a pair of Docker containers or a Kubernetes Job.
//! - [`protocol`]: what runners and the registry send each other.

pub mod launch;
pub mod steps;
pub mod worker;

pub use kontainer_core::build::{and_list, protocol, render_tags, sentence, short_ref, valid_ref};

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// A path inside `root`, refusing `..` and absolute paths.
pub fn inside(root: &Path, rel: &str) -> Result<PathBuf> {
    let rel = rel.trim().trim_start_matches("./");
    if rel.starts_with('/') || rel.split('/').any(|p| p == "..") {
        bail!("{rel}: must be a path inside the repository");
    }
    Ok(if rel.is_empty() || rel == "." { root.to_path_buf() } else { root.join(rel) })
}

/// `path` with every symlink resolved, refusing anything that ends up outside `root` (a
/// repository can point `docker/Dockerfile` or the context at `/etc` with a symlink; [`inside`]
/// only looks at the text). `path` must exist. `what` names it in the error.
pub fn resolved_inside(root: &Path, path: &Path, what: &str) -> Result<PathBuf> {
    let root = std::fs::canonicalize(root).with_context(|| format!("resolving {}", root.display()))?;
    let real = std::fs::canonicalize(path).with_context(|| format!("Couldn't find {what} in the repository"))?;
    if !real.starts_with(&root) {
        bail!("{what} must be inside the repository (a symbolic link points outside it)");
    }
    Ok(real)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let root = Path::new("/w/src");
        assert_eq!(inside(root, "./docker/Dockerfile").unwrap(), root.join("docker/Dockerfile"));
        assert_eq!(inside(root, ".").unwrap(), root);
        assert!(inside(root, "../etc/passwd").is_err() && inside(root, "/etc").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_out_of_the_checkout_are_refused() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("Dockerfile"), "FROM scratch").unwrap();
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        std::fs::create_dir(root.join("docker")).unwrap();
        std::fs::write(root.join("docker/Dockerfile"), "FROM scratch").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("Dockerfile"), root.join("Dockerfile")).unwrap();
        std::os::unix::fs::symlink("docker/Dockerfile", root.join("Dockerfile.ok")).unwrap();

        let ok = resolved_inside(root, &inside(root, "docker/Dockerfile").unwrap(), "the Dockerfile").unwrap();
        assert!(ok.starts_with(std::fs::canonicalize(root).unwrap()));
        // A link that stays in the repository is fine.
        assert!(resolved_inside(root, &inside(root, "Dockerfile.ok").unwrap(), "the Dockerfile").is_ok());
        // Text-wise inside, actually outside.
        assert!(resolved_inside(root, &inside(root, "Dockerfile").unwrap(), "the Dockerfile").is_err());
        assert!(resolved_inside(root, &inside(root, "escape").unwrap(), "the build context").is_err());
        assert!(resolved_inside(root, &inside(root, "escape/Dockerfile").unwrap(), "the Dockerfile").is_err());
        assert!(resolved_inside(root, &inside(root, "missing").unwrap(), "the Dockerfile").is_err());
    }
}
