//! A build runner's configuration (`kontainer runner`): which registry it serves, and how it
//! runs builds. Loaded from `--config-file` and `KONTAINER_RUNNER__<SECTION>__<KEY>` variables,
//! with flags on top.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{humantime_serde, Secret};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RunnerConfig {
    /// The registry, e.g. `https://registry.example.com` (`KONTAINER_SERVER`).
    pub server: String,
    /// The runner's token, from registering it in the registry (`KONTAINER_RUNNER_TOKEN`).
    pub token: Option<Secret>,
    /// Shown on builds and in the UI. Defaults to the host name (`KONTAINER_RUNNER_NAME`).
    pub name: Option<String>,
    /// `local`: builds run in this process. `docker`: a fresh pair of containers per build on a
    /// Docker host (`[docker]`). `kubernetes`: one Job per build (`[kubernetes]`).
    pub executor: BuildExecutor,
    /// `local` builds: `docker` (the local daemon's BuildKit; Docker 25+ with the containerd image
    /// store) or `buildctl` (a BuildKit daemon at `buildkit_addr`, the stronger sandbox).
    pub backend: BuildBackend,
    /// For `buildctl`, e.g. `tcp://buildkitd:1234` (`BUILDKIT_HOST`).
    pub buildkit_addr: String,
    /// Builds at once; the registry keeps the rest queued.
    pub concurrency: usize,
    /// Scratch space for `local` builds.
    pub work_dir: PathBuf,
    /// How often to ask for work when there is none.
    #[serde(with = "humantime_serde")]
    pub poll: Duration,
    pub docker: DockerBuildConfig,
    pub kubernetes: KubernetesBuildConfig,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            token: None,
            name: None,
            executor: BuildExecutor::Local,
            backend: BuildBackend::Docker,
            buildkit_addr: String::new(),
            concurrency: 1,
            work_dir: PathBuf::from("./kontainer-builds"),
            poll: Duration::from_secs(5),
            docker: DockerBuildConfig::default(),
            kubernetes: KubernetesBuildConfig::default(),
        }
    }
}

impl RunnerConfig {
    /// `path` (if any), then `KONTAINER_RUNNER__*` overrides and the shorthands.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut table = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p).with_context(|| format!("reading runner config {}", p.display()))?;
                toml::from_str::<toml::Table>(&raw).with_context(|| format!("parsing runner config {}", p.display()))?
            }
            None => toml::Table::new(),
        };
        let defaults = toml::Table::try_from(RunnerConfig::default()).unwrap_or_default();
        crate::config::apply_overrides(&mut table, &defaults, "KONTAINER_RUNNER__", std::env::vars())?;
        let mut cfg: RunnerConfig = toml::Value::Table(table).try_into().context("parsing the runner configuration")?;
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if let Some(v) = env("KONTAINER_SERVER") {
            cfg.server = v;
        }
        if let Some(v) = env("KONTAINER_RUNNER_TOKEN") {
            cfg.token = Some(v.into());
        }
        if let Some(v) = env("KONTAINER_RUNNER_NAME") {
            cfg.name = Some(v);
        }
        if let Some(v) = env("BUILDKIT_HOST").filter(|_| cfg.buildkit_addr.is_empty()) {
            cfg.buildkit_addr = v;
        }
        Ok(cfg)
    }

    /// Can it run? Checked once flags are applied.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.server.is_empty(), "set the registry's URL (--server or KONTAINER_SERVER)");
        anyhow::ensure!(self.token.as_ref().is_some_and(|t| !t.is_empty()), "set the runner's token (--token or KONTAINER_RUNNER_TOKEN); register a runner in the registry to get one");
        match self.executor {
            BuildExecutor::Local => anyhow::ensure!(self.backend != BuildBackend::Buildctl || !self.buildkit_addr.is_empty(), "the buildctl backend needs buildkit_addr (--buildkit-addr or BUILDKIT_HOST)"),
            BuildExecutor::Docker => {
                anyhow::ensure!(!self.docker.image.is_empty(), "the docker executor needs docker.image: an image with kontainer, git and buildctl (this one)");
                // Docker reads an unset or zero limit as "unlimited": refuse anything that would get there.
                anyhow::ensure!(crate::config::parse_bytes(&self.docker.memory).is_some(), "docker.memory: `{}` is not a size, e.g. 4g or 4Gi", self.docker.memory);
                anyhow::ensure!(self.docker.cpus.is_finite() && self.docker.cpus > 0.0, "docker.cpus must be more than 0, e.g. 2 or 0.5 (got {})", self.docker.cpus);
            }
            BuildExecutor::Kubernetes => anyhow::ensure!(!self.kubernetes.image.is_empty(), "the kubernetes executor needs kubernetes.image: an image with kontainer, git and buildctl (this one)"),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BuildExecutor {
    Local,
    Docker,
    Kubernetes,
}

/// A pair of containers per build on a Docker host: the agent (this image, `kontainer
/// build-agent`) and a rootless BuildKit that does the build, sharing a volume for its socket.
/// They are removed when the build ends.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerBuildConfig {
    /// `unix:///var/run/docker.sock`, `tcp://host:2375`... Defaults to `DOCKER_HOST`, else the
    /// local socket.
    pub host: Option<String>,
    /// Image with the `kontainer` binary, `git` and `buildctl`: the registry's own image.
    pub image: String,
    pub buildkit_image: String,
    /// How build containers reach the registry. Defaults to `server.public_url`. On the same
    /// host, `http://host.docker.internal:5000` works with `build_network = "open"`.
    pub server_url: Option<String>,
    /// Docker network for the build containers. Defaults to `kontainer-builds` with the
    /// `isolated` build network (created if missing), `bridge` with `open`.
    pub network: Option<String>,
    /// What builds (whose `RUN` steps are anyone's code) can reach. `isolated` (the default):
    /// a dedicated bridge network without inter-container traffic, no `host.docker.internal`
    /// alias, and cloud metadata host names pointed at 127.0.0.1. `open`: what Docker gives
    /// any container, plus `host.docker.internal` for reaching a registry on the Docker host.
    pub build_network: DockerBuildNetwork,
    /// For BuildKit: CPUs (fractions allowed) and memory, e.g. `4g`, `512m`.
    pub cpus: f64,
    pub memory: String,
    /// Rootless BuildKit (the stronger sandbox) needs unprivileged user namespaces, which some
    /// hosts block (Ubuntu 23.10+: `kernel.apparmor_restrict_unprivileged_userns`). `false`
    /// runs `buildkit_image` without `-rootless` as a privileged container instead.
    pub rootless: bool,
}

impl Default for DockerBuildConfig {
    fn default() -> Self {
        Self {
            host: None,
            image: String::new(),
            buildkit_image: "moby/buildkit:v0.17.3-rootless".into(),
            server_url: None,
            network: None,
            build_network: DockerBuildNetwork::Isolated,
            cpus: 2.0,
            memory: "4g".into(),
            rootless: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DockerBuildNetwork {
    #[default]
    Isolated,
    Open,
}

/// One Job per build: the agent (this image, `kontainer build-agent`) next to a rootless
/// BuildKit sidecar that does the actual build. The server needs to create and delete Jobs in
/// `namespace` (see deploy/kubernetes/builds.yaml).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesBuildConfig {
    /// Defaults to the server's own namespace when it runs in the cluster, else `default`.
    pub namespace: Option<String>,
    /// Image with the `kontainer` binary, `git` and `buildctl`: the registry's own image.
    pub image: String,
    pub buildkit_image: String,
    /// How build pods reach the registry. Defaults to `server.public_url`.
    pub server_url: Option<String>,
    /// For the build containers: requests and limits, Kubernetes quantities.
    pub cpu: String,
    pub memory: String,
    /// Scratch disk for the checkout, BuildKit's layers and the archive.
    pub ephemeral_storage: String,
    pub node_selector: HashMap<String, String>,
    /// Kubernetes tolerations, e.g. `{ key = "builds", operator = "Exists", effect = "NoSchedule" }`.
    pub tolerations: Vec<HashMap<String, String>>,
    pub image_pull_secrets: Vec<String>,
    pub service_account: Option<String>,
    /// Finished Jobs are deleted after this long (their logs are kept on the build).
    #[serde(with = "humantime_serde")]
    pub job_ttl: Duration,
    /// Outside the cluster: the API server, a bearer token file and its CA. Inside, the pod's
    /// service account is used.
    pub api_url: Option<String>,
    pub token_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
    /// Create a NetworkPolicy with each build Job (owned by it), so `RUN` steps reach only DNS,
    /// the registry's pods and public addresses: not the cluster, private networks or cloud
    /// metadata. Needs a CNI that enforces NetworkPolicy, and `networkpolicies` (`create`) in
    /// the runner's Role.
    pub network_policy: bool,
    /// With `network_policy`: also allow private networks (`10/8`, `172.16/12`, `192.168/16`);
    /// link-local addresses (cloud metadata) stay blocked.
    pub allow_private_network: bool,
    /// With `network_policy`: more CIDRs builds may reach, e.g. an internal Git host.
    pub egress_cidrs: Vec<String>,
    /// With `network_policy`: how to find the registry's pods (labels, and their namespace;
    /// any namespace when unset), for build pods reaching it inside the cluster.
    pub registry_pod_labels: HashMap<String, String>,
    pub registry_namespace: Option<String>,
}

impl Default for KubernetesBuildConfig {
    fn default() -> Self {
        Self {
            namespace: None,
            image: String::new(),
            buildkit_image: "moby/buildkit:v0.17.3-rootless".into(),
            server_url: None,
            cpu: "2".into(),
            memory: "4Gi".into(),
            ephemeral_storage: "20Gi".into(),
            node_selector: HashMap::new(),
            tolerations: vec![],
            image_pull_secrets: vec![],
            service_account: None,
            job_ttl: Duration::from_secs(600),
            api_url: None,
            token_file: None,
            ca_file: None,
            network_policy: true,
            allow_private_network: false,
            egress_cidrs: vec![],
            registry_pod_labels: HashMap::from([("app.kubernetes.io/name".to_string(), "kontainer".to_string())]),
            registry_namespace: None,
        }
    }
}


#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BuildBackend {
    Docker,
    Buildctl,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docker(memory: &str, cpus: f64) -> RunnerConfig {
        RunnerConfig {
            server: "https://registry.example.com".into(),
            token: Some("t".repeat(20).into()),
            executor: BuildExecutor::Docker,
            docker: DockerBuildConfig { image: "kontainer:latest".into(), memory: memory.into(), cpus, ..Default::default() },
            ..Default::default()
        }
    }

    #[test]
    fn docker_limits_are_checked() {
        assert!(docker("4g", 2.0).validate().is_ok());
        assert!(docker("4Gi", 0.5).validate().is_ok());
        for (memory, cpus) in [("4 gigs", 2.0), ("", 2.0), ("0", 2.0), ("4g", 0.0), ("4g", -1.0), ("4g", f64::NAN)] {
            assert!(docker(memory, cpus).validate().is_err(), "{memory:?} {cpus}");
        }
        // Not used by the other executors.
        let mut local = docker("lots", 0.0);
        local.executor = BuildExecutor::Local;
        assert!(local.validate().is_ok());
    }
}
