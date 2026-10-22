//! Ensure `web/dist` exists so `rust-embed` can compile even when the frontend has not been
//! built. Run `npm --prefix web run build` to embed the real UI.

use std::path::Path;

fn main() {
    let dist = Path::new("../../web/dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(dist).expect("creating web/dist");
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><title>OCI Registry</title><p>The web UI was not built. Run <code>npm --prefix web install && npm --prefix web run build</code> and rebuild the registry.</p>",
        )
        .expect("writing placeholder");
    }
    println!("cargo:rerun-if-changed=../../web/dist");
    // `sqlx::migrate!` embeds the migrations: rebuild when they change.
    println!("cargo:rerun-if-changed=migrations");

    // Build metadata for the About page.
    let run = |cmd: &str, args: &[&str]| {
        std::process::Command::new(cmd).args(args).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
    };
    let mut commit = run("git", &["rev-parse", "--short=10", "HEAD"]);
    if !commit.is_empty() && !run("git", &["status", "--porcelain", "--untracked-files=no"]).is_empty() {
        commit.push_str("-dirty");
    }
    let built = std::env::var("SOURCE_DATE_EPOCH").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
    let rustc = run(&std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()), &["--version"]);
    println!("cargo:rustc-env=KONTAINER_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=KONTAINER_BUILD_EPOCH={built}");
    println!("cargo:rustc-env=KONTAINER_RUSTC={rustc}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}
