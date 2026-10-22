//! Grype (<https://github.com/anchore/grype>) scanner: `grype registry:<ref> -o json`.

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;

use super::{parse_severity, CliScanner, ScanReport, ScanTarget, Scanner, Vulnerability};

pub struct Grype(pub CliScanner);

#[derive(Deserialize)]
struct GrypeOutput {
    #[serde(default)]
    matches: Vec<GrypeMatch>,
}

#[derive(Deserialize)]
struct GrypeMatch {
    vulnerability: GrypeVuln,
    artifact: GrypeArtifact,
}

#[derive(Deserialize)]
struct GrypeVuln {
    id: String,
    #[serde(default)]
    severity: String,
    #[serde(default, rename = "dataSource")]
    data_source: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    fix: Option<GrypeFix>,
}

#[derive(Deserialize)]
struct GrypeFix {
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct GrypeArtifact {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    locations: Vec<GrypeLocation>,
}

#[derive(Deserialize)]
struct GrypeLocation {
    #[serde(default, rename = "layerID")]
    layer_id: Option<String>,
}

#[async_trait]
impl Scanner for Grype {
    fn name(&self) -> &'static str {
        "grype"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanReport> {
        let cfg = &self.0.cfg;
        let binary = cfg.binary.clone().unwrap_or_else(|| "grype".into());
        let args = vec![format!("registry:{}", self.0.image_ref(target)), "-o".to_string(), "json".to_string(), "-q".to_string()];
        let mut env = vec![];
        if cfg.is_insecure {
            env.push(("GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY", "true".to_string()));
            env.push(("GRYPE_REGISTRY_INSECURE_USE_HTTP", "true".to_string()));
        }
        env.extend(self.0.credentials(target, "GRYPE_REGISTRY_AUTH_USERNAME", "GRYPE_REGISTRY_AUTH_PASSWORD", "GRYPE_REGISTRY_AUTH_TOKEN")?);
        let out = self.0.run(&binary, &args, &env).await?;
        let parsed: GrypeOutput = serde_json::from_slice(&out)?;
        let mut report = ScanReport::pending(self.name(), &target.repository, &target.digest);
        for m in parsed.matches {
            report.vulnerabilities.push(Vulnerability {
                id: m.vulnerability.id,
                severity: parse_severity(&m.vulnerability.severity),
                package: m.artifact.name,
                installed_version: m.artifact.version,
                fixed_version: m.vulnerability.fix.and_then(|f| f.versions.into_iter().next()),
                title: m.vulnerability.description.map(|d| d.chars().take(200).collect()),
                url: m.vulnerability.data_source,
                layer: m.artifact.locations.into_iter().find_map(|l| l.layer_id),
                target: None,
            });
        }
        if cfg.is_store_raw {
            report.raw = serde_json::from_slice(&out).ok();
        }
        Ok(report)
    }
}
