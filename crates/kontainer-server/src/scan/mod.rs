//! Vulnerability scanning.
//!
//! A [`Scanner`] turns `repo@digest` into a normalized [`ScanReport`]. Scans run on a
//! background queue (see [`queue`]) so pushes return immediately; reports are persisted to
//! storage next to the image.

pub mod grype;
pub mod queue;
pub mod trivy;

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use kontainer_core::config::{ScannerConfig, ScannerKind, Severity};
use kontainer_core::digest::Digest;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    #[default]
    Pending,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: Severity,
    pub package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Layer the vulnerable package was introduced in, when the scanner reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanReport {
    pub status: ScanStatus,
    pub scanner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_version: Option<String>,
    pub digest: String,
    pub repository: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub summary: BTreeMap<Severity, usize>,
    pub total: usize,
    #[serde(default)]
    pub vulnerabilities: Vec<Vulnerability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

impl ScanReport {
    pub fn pending(scanner: &str, repository: &str, digest: &Digest) -> Self {
        Self {
            status: ScanStatus::Pending,
            scanner: scanner.to_string(),
            digest: digest.to_string(),
            repository: repository.to_string(),
            started_at: Some(chrono::Utc::now().to_rfc3339()),
            ..Default::default()
        }
    }

    pub fn finalize(&mut self) {
        self.summary.clear();
        for v in &self.vulnerabilities {
            *self.summary.entry(v.severity).or_default() += 1;
        }
        self.total = self.vulnerabilities.len();
        self.vulnerabilities.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        self.finished_at = Some(chrono::Utc::now().to_rfc3339());
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.vulnerabilities.iter().map(|v| v.severity).max()
    }

}

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub repository: String,
    pub digest: Digest,
}

#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    async fn scan(&self, target: &ScanTarget) -> Result<ScanReport>;
}

/// The only variables scanners inherit from the registry (whose environment holds its secrets):
/// what they need to find things and get through a proxy. `TRIVY_*`, `GRYPE_*` and `SYFT_*` pass
/// too, as does `scanner.env`.
const PASS_ENV: &[&str] = &[
    "PATH", "HOME", "TMPDIR", "USER", "LANG", "LC_ALL", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
];
const PASS_ENV_PREFIXES: &[&str] = &["TRIVY_", "GRYPE_", "SYFT_"];

fn passes(key: &str) -> bool {
    PASS_ENV.contains(&key) || PASS_ENV_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// Mints a short-lived, pull-only registry token for one target: what scanners pull with when
/// no `scanner.username` is configured. The registry provides it, since it signs its own tokens.
pub type TokenMinter = Arc<dyn Fn(&ScanTarget) -> Result<String> + Send + Sync>;

/// Shared bits for CLI-based scanners.
pub struct CliScanner {
    pub cfg: ScannerConfig,
    pub registry_host: String,
    pub token: Option<TokenMinter>,
}

impl CliScanner {
    pub fn image_ref(&self, t: &ScanTarget) -> String {
        format!("{}/{}@{}", self.registry_host, t.repository, t.digest)
    }

    /// Credentials for pulling `t`: the configured account when there is one, else a token
    /// minted for just this repository. `user`/`pass`/`token` name the scanner's variables.
    pub fn credentials(&self, t: &ScanTarget, user: &'static str, pass: &'static str, token: &'static str) -> Result<Vec<(&'static str, String)>> {
        let mut env = vec![];
        match (&self.cfg.username, &self.token) {
            (Some(u), _) => {
                env.push((user, u.clone()));
                if let Some(p) = &self.cfg.password {
                    env.push((pass, p.expose().to_string()));
                }
            }
            (None, Some(mint)) => env.push((token, mint(t).context("minting the scanner's pull token")?)),
            (None, None) => {}
        }
        Ok(env)
    }

    pub async fn run(&self, binary: &str, args: &[String], env: &[(&str, String)]) -> Result<Vec<u8>> {
        let mut cmd = tokio::process::Command::new(binary);
        cmd.args(args).args(&self.cfg.extra_args).env_clear();
        for (k, v) in std::env::vars_os() {
            if k.to_str().is_some_and(passes) {
                cmd.env(k, v);
            }
        }
        for (k, v) in &self.cfg.env {
            cmd.env(k, v);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        // Killed (and reaped by tokio) when the timeout drops it, instead of left running.
        cmd.stdin(std::process::Stdio::null()).kill_on_drop(true);
        tracing::info!(binary, ?args, "running scanner");
        let out = tokio::time::timeout(self.cfg.timeout, cmd.output())
            .await
            .map_err(|_| anyhow::anyhow!("{binary} didn't finish within {} seconds (scanner.timeout)", self.cfg.timeout.as_secs()))?
            .with_context(|| format!("spawning {binary}"))?;
        if !out.status.success() {
            anyhow::bail!("{binary} exited with {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(out.stdout)
    }
}

/// `token`: how to mint pull tokens when `cfg.username` is unset.
pub fn build(cfg: &ScannerConfig, bind: &str, token: Option<TokenMinter>) -> Option<Arc<dyn Scanner>> {
    let registry_host = cfg.registry_host.clone().unwrap_or_else(|| {
        let port = bind.rsplit(':').next().unwrap_or("5000");
        format!("127.0.0.1:{port}")
    });
    let cli = CliScanner { cfg: cfg.clone(), registry_host, token };
    match cfg.kind {
        ScannerKind::None => None,
        ScannerKind::Trivy => Some(Arc::new(trivy::Trivy(cli))),
        ScannerKind::Grype => Some(Arc::new(grype::Grype(cli))),
    }
}

pub fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "negligible" => Severity::Negligible,
        _ => Severity::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_harmless_variables_reach_scanners() {
        for k in ["PATH", "HOME", "https_proxy", "NO_PROXY", "SSL_CERT_FILE", "TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR"] {
            assert!(passes(k), "{k}");
        }
        for k in ["KONTAINER_ADMIN_PASSWORD", "KONTAINER_SCANNER_PASSWORD", "AWS_SECRET_ACCESS_KEY", "KONTAINER__AUTH__SECRET", "TRIVY"] {
            assert!(!passes(k), "{k}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_out_scanners_are_killed() {
        let dir = std::env::temp_dir().join(format!("kontainer-scan-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let cfg = ScannerConfig { timeout: std::time::Duration::from_millis(200), ..Default::default() };
        let cli = CliScanner { cfg, registry_host: "127.0.0.1:5000".into(), token: None };
        let script = format!("sleep 1; touch {}", dir.display());
        let err = cli.run("sh", &["-c".into(), script], &[]).await.unwrap_err();
        assert!(err.to_string().contains("didn't finish"), "{err}");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(!dir.exists(), "the scanner kept running after its timeout");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scanner_environment_is_clean() {
        let mut cfg = ScannerConfig::default();
        cfg.env.insert("FROM_CONFIG".into(), "yes".into());
        let cli = CliScanner { cfg, registry_host: "127.0.0.1:5000".into(), token: None };
        let out = cli.run("sh", &["-c".into(), "echo \"$PATH|$FROM_CONFIG|$GIVEN|$CARGO_PKG_NAME\"".into()], &[("GIVEN", "1".into())]).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        let parts: Vec<&str> = out.trim().split('|').collect();
        assert!(!parts[0].is_empty());
        assert_eq!(&parts[1..], &["yes", "1", ""], "cargo's variables must not leak through");
    }
}
