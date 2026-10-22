//! Trivy (<https://github.com/aquasecurity/trivy>) scanner: `trivy image --format json <ref>`.

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;

use super::{parse_severity, CliScanner, ScanReport, ScanTarget, Scanner, Vulnerability};

pub struct Trivy(pub CliScanner);

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyOutput {
    #[serde(default)]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyResult {
    target: String,
    #[serde(default)]
    vulnerabilities: Vec<TrivyVuln>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    pkg_name: String,
    #[serde(default)]
    installed_version: Option<String>,
    #[serde(default)]
    fixed_version: Option<String>,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default, rename = "PrimaryURL")]
    primary_url: Option<String>,
    #[serde(default)]
    layer: Option<TrivyLayer>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyLayer {
    #[serde(default)]
    digest: Option<String>,
}

#[async_trait]
impl Scanner for Trivy {
    fn name(&self) -> &'static str {
        "trivy"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanReport> {
        let cfg = &self.0.cfg;
        let binary = cfg.binary.clone().unwrap_or_else(|| "trivy".into());
        let args = vec![
            "image".to_string(),
            "--format".into(),
            "json".into(),
            "--quiet".into(),
            "--scanners".into(),
            "vuln".into(),
            self.0.image_ref(target),
        ];
        let mut env = vec![];
        if cfg.is_insecure {
            env.push(("TRIVY_INSECURE", "true".to_string()));
            env.push(("TRIVY_NON_SSL", "true".to_string()));
        }
        env.extend(self.0.credentials(target, "TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN")?);
        let out = self.0.run(&binary, &args, &env).await?;
        let parsed: TrivyOutput = serde_json::from_slice(&out)?;
        let mut report = ScanReport::pending(self.name(), &target.repository, &target.digest);
        for r in parsed.results {
            for v in r.vulnerabilities {
                report.vulnerabilities.push(Vulnerability {
                    id: v.vulnerability_id,
                    severity: parse_severity(&v.severity),
                    package: v.pkg_name,
                    installed_version: v.installed_version,
                    fixed_version: v.fixed_version.filter(|s| !s.is_empty()),
                    title: v.title,
                    url: v.primary_url,
                    layer: v.layer.and_then(|l| l.digest),
                    target: Some(r.target.clone()),
                });
            }
        }
        if cfg.is_store_raw {
            report.raw = serde_json::from_slice(&out).ok();
        }
        Ok(report)
    }
}
