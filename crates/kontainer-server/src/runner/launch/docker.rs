//! Builds in containers on a Docker host, started through the Docker API.
//!
//! `kontainer-build-<id>-buildkitd` is a rootless BuildKit with the CPU and memory limits;
//! `kontainer-build-<id>-agent` runs `kontainer runner --build-id <id>` with that build's
//! token. They share the volume `kontainer-build-<id>` for BuildKit's socket.
//!
//! The token is not in the agent's environment (where `docker inspect` and every process the
//! agent starts would see it): it is copied into the created container as a file readable only
//! by the agent's user, through the Docker API (so it works with a remote Docker host too), and
//! the agent deletes it once read.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bollard::errors::Error as DockerError;
use bollard::models::{ContainerCreateBody, ContainerSummaryStateEnum, HostConfig, NetworkCreateRequest, VolumeCreateRequest};
use bollard::query_parameters::{CreateContainerOptionsBuilder, CreateImageOptionsBuilder, ListContainersOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptionsBuilder, RemoveVolumeOptions, UploadToContainerOptionsBuilder};
use bollard::Docker;
use futures::TryStreamExt;

use kontainer_core::config::{parse_bytes, DockerBuildConfig, DockerBuildNetwork};

use super::{Launched, Launcher};

const MANAGED_BY: &str = "app.kubernetes.io/managed-by=kontainer";
const BUILD_LABEL: &str = "kontainer.dev/build-id";
/// Where BuildKit puts its socket. Rootless: the image's runtime directory, owned by its user, so
/// a fresh volume mounted there inherits that ownership.
const ROOTLESS_RUN: &str = "/run/user/1000";
const PRIVILEGED_RUN: &str = "/run/buildkit";
/// Where the agent sees the same volume.
const AGENT_RUN: &str = "/run/buildkit-shared";
/// The agent's user (BuildKit's, to use its socket).
const AGENT_UID: u64 = 1000;
/// Where the build token is put in the agent container (a directory every image has), and its name.
const TOKEN_DIR: &str = "/tmp";
const TOKEN_FILE: &str = "kontainer-build-token";
/// The `isolated` build network.
const ISOLATED_NETWORK: &str = "kontainer-builds";
/// Its Linux bridge (at most 15 characters), named so a host firewall rule can match it, e.g.
/// `iptables -I DOCKER-USER -i kontainer-bld -d 169.254.0.0/16 -j DROP`.
const ISOLATED_BRIDGE: &str = "kontainer-bld";
/// Cloud metadata host names, pointed at 127.0.0.1 in build containers with the `isolated`
/// build network. (The address itself is for a host firewall to block: see [`ISOLATED_BRIDGE`].)
const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.goog", "metadata", "instance-data", "instance-data.ec2.internal", "metadata.azure.com"];

/// `extra_hosts` for build containers.
fn extra_hosts(mode: DockerBuildNetwork) -> Vec<String> {
    match mode {
        // Lets `server_url` point at the Docker host (`host.docker.internal`) on Linux too.
        DockerBuildNetwork::Open => vec!["host.docker.internal:host-gateway".into()],
        DockerBuildNetwork::Isolated => METADATA_HOSTS.iter().map(|h| format!("{h}:127.0.0.1")).collect(),
    }
}

/// A tar archive holding just `token`, as a file only the agent's user can read.
fn token_archive(token: &str) -> Result<bytes::Bytes> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(token.len() as u64);
    h.set_mode(0o400);
    h.set_uid(AGENT_UID);
    h.set_gid(AGENT_UID);
    h.set_cksum();
    tar.append_data(&mut h, TOKEN_FILE, token.as_bytes())?;
    Ok(tar.into_inner()?.into())
}

pub struct DockerLauncher {
    docker: Docker,
    cfg: DockerBuildConfig,
    /// BuildKit's memory limit in bytes, from `cfg.memory`.
    memory: i64,
    /// How build containers reach the registry.
    server_url: String,
}

impl DockerLauncher {
    pub async fn new(cfg: &DockerBuildConfig, server_url: &str) -> Result<Self> {
        // Docker reads 0 as "no limit": never let a typo get there.
        let Some(memory) = parse_bytes(&cfg.memory) else { bail!("builds.docker.memory: `{}` is not a size, e.g. 4g or 4Gi", cfg.memory) };
        if !(cfg.cpus.is_finite() && cfg.cpus > 0.0) {
            bail!("builds.docker.cpus must be more than 0, e.g. 2 or 0.5");
        }
        let docker = match cfg.host.as_deref() {
            Some(h) if h.starts_with("unix://") => Docker::connect_with_socket(h, 120, bollard::API_DEFAULT_VERSION)?,
            Some(h) => Docker::connect_with_http(h, 120, bollard::API_DEFAULT_VERSION)?,
            None => Docker::connect_with_defaults()?,
        };
        // Talk the daemon's API version rather than assume ours.
        let docker = docker.negotiate_version().await.context("reaching the Docker daemon")?;
        if !cfg.rootless {
            tracing::warn!("docker.rootless = false: every build runs a privileged BuildKit, which is root on the Docker host. Only use it when everyone who can create build triggers is trusted");
        }
        if cfg.build_network == DockerBuildNetwork::Open {
            tracing::warn!("docker.build_network = \"open\": builds can reach the Docker host, its other containers and cloud metadata endpoints");
        }
        Ok(Self { docker, cfg: cfg.clone(), memory, server_url: server_url.to_string() })
    }

    /// Pull `image` unless it is already on the host.
    async fn ensure_image(&self, image: &str) -> Result<()> {
        if self.docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }
        tracing::info!(%image, "pulling build image");
        self.docker
            .create_image(Some(CreateImageOptionsBuilder::new().from_image(image).build()), None, None)
            .try_collect::<Vec<_>>()
            .await
            .with_context(|| format!("pulling {image}"))?;
        Ok(())
    }

    /// Create the `isolated` build network unless it exists: a bridge with outgoing NAT (builds
    /// fetch base images and packages) but no traffic between its containers.
    async fn ensure_network(&self, name: &str) -> Result<()> {
        if self.docker.inspect_network(name, None).await.is_ok() {
            return Ok(());
        }
        let options = HashMap::from([
            ("com.docker.network.bridge.name".to_string(), ISOLATED_BRIDGE.to_string()),
            ("com.docker.network.bridge.enable_ip_masquerade".to_string(), "true".to_string()),
            ("com.docker.network.bridge.enable_icc".to_string(), "false".to_string()),
        ]);
        let labels = HashMap::from([("app.kubernetes.io/managed-by".to_string(), "kontainer".to_string())]);
        let req = NetworkCreateRequest { name: name.to_string(), driver: Some("bridge".into()), options: Some(options), labels: Some(labels), ..Default::default() };
        match self.docker.create_network(req).await {
            // Another runner on this host got there first.
            Ok(_) | Err(DockerError::DockerResponseServerError { status_code: 409, .. }) => Ok(()),
            Err(e) => Err(anyhow::Error::new(e).context(format!("creating the build network {name}"))),
        }
    }

    /// The last lines a container printed.
    async fn log_tail(&self, container: &str) -> String {
        let out: Vec<String> = self
            .docker
            .logs(container, Some(LogsOptionsBuilder::new().stdout(true).stderr(true).tail("15").build()))
            .try_collect::<Vec<_>>()
            .await
            .unwrap_or_default()
            .iter()
            .map(|l| l.to_string())
            .collect();
        out.concat().trim().to_string()
    }

    /// Why build `id`'s containers stopped, with what the one that died printed last.
    async fn exit_reason(&self, id: i64) -> String {
        for suffix in ["buildkitd", "agent"] {
            let cname = format!("{}-{suffix}", self.name(id));
            let Ok(c) = self.docker.inspect_container(&cname, None).await else { continue };
            let s = c.state.unwrap_or_default();
            if s.running == Some(true) {
                continue;
            }
            if s.oom_killed == Some(true) {
                return if suffix == "agent" { "The build agent container ran out of memory".into() } else { "BuildKit ran out of memory. Raise builds.docker.memory".into() };
            }
            let tail = self.log_tail(&cname).await;
            let what = if suffix == "agent" { "The build agent container" } else { "BuildKit" };
            let mut why = format!("{what} exited with code {}", s.exit_code.unwrap_or(-1));
            if suffix == "buildkitd" && (tail.contains("apparmor_restrict_unprivileged_userns") || tail.contains("failed to start the child")) {
                why.push_str(". This host blocks the user namespaces rootless BuildKit needs: allow them (sysctl kernel.apparmor_restrict_unprivileged_userns=0) or set builds.docker.rootless = false");
            }
            if !tail.is_empty() {
                why.push_str(&format!("\n{tail}"));
            }
            return why;
        }
        "The build containers stopped".into()
    }
}

#[async_trait]
impl Launcher for DockerLauncher {
    fn prefix(&self) -> &'static str {
        "docker/"
    }

    async fn launch(&self, id: i64, token: &str) -> Result<()> {
        let d = &self.cfg;
        self.ensure_image(if d.rootless { &d.buildkit_image } else { d.buildkit_image.trim_end_matches("-rootless") }).await?;
        self.ensure_image(&d.image).await?;
        let volume = self.name(id);
        let labels = HashMap::from([
            ("app.kubernetes.io/managed-by".to_string(), "kontainer".to_string()),
            (BUILD_LABEL.to_string(), id.to_string()),
        ]);
        self.docker
            .create_volume(VolumeCreateRequest { name: Some(volume.clone()), labels: Some(labels.clone()), ..Default::default() })
            .await
            .context("creating the build volume")?;
        let network = match (d.build_network, &d.network) {
            (_, Some(n)) => n.clone(),
            (DockerBuildNetwork::Isolated, None) => {
                self.ensure_network(ISOLATED_NETWORK).await?;
                ISOLATED_NETWORK.to_string()
            }
            (DockerBuildNetwork::Open, None) => "bridge".into(),
        };

        let (run, image, mut cmd) = if d.rootless {
            (ROOTLESS_RUN, d.buildkit_image.clone(), vec!["--oci-worker-no-process-sandbox".to_string()])
        } else {
            // Root BuildKit: let the agent's group use the socket.
            (PRIVILEGED_RUN, d.buildkit_image.trim_end_matches("-rootless").to_string(), vec!["--group".to_string(), "1000".into()])
        };
        cmd.splice(0..0, ["--addr".to_string(), format!("unix://{run}/buildkit/buildkitd.sock")]);
        let buildkitd = ContainerCreateBody {
            image: Some(image.clone()),
            cmd: Some(cmd),
            labels: Some(labels.clone()),
            host_config: Some(HostConfig {
                binds: Some(vec![format!("{volume}:{run}")]),
                privileged: (!d.rootless).then_some(true),
                security_opt: d.rootless.then(|| vec!["seccomp=unconfined".into(), "apparmor=unconfined".into()]),
                nano_cpus: Some(((d.cpus * 1e9) as i64).max(1)),
                memory: Some(self.memory),
                network_mode: Some(network.clone()),
                // `RUN` steps share BuildKit's network (no process sandbox).
                extra_hosts: Some(extra_hosts(d.build_network)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let socket = format!("unix://{AGENT_RUN}/buildkit/buildkitd.sock");
        let agent = ContainerCreateBody {
            image: Some(d.image.clone()),
            entrypoint: Some(vec!["kontainer".into()]),
            cmd: Some(
                ["runner", "--server", &self.server_url, "--build-id", &id.to_string(), "--build-token-file", &format!("{TOKEN_DIR}/{TOKEN_FILE}"), "--backend", "buildctl", "--buildkit-addr", &socket, "--work-dir", "/tmp/work"]
                    .map(String::from)
                    .to_vec(),
            ),
            // BuildKit's user, to use its socket.
            user: Some(format!("{AGENT_UID}:{AGENT_UID}")),
            labels: Some(labels),
            host_config: Some(HostConfig {
                binds: Some(vec![format!("{volume}:{AGENT_RUN}")]),
                network_mode: Some(network),
                extra_hosts: Some(extra_hosts(d.build_network)),
                memory: Some(512 << 20),
                // An init as PID 1: forwards `docker stop`'s SIGTERM and reaps git's children.
                init: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        for (suffix, body) in [("buildkitd", buildkitd), ("agent", agent)] {
            let cname = format!("{volume}-{suffix}");
            self.docker.create_container(Some(CreateContainerOptionsBuilder::new().name(&cname).build()), body).await.with_context(|| format!("creating {cname}"))?;
            if suffix == "agent" {
                // Only good for this build's endpoints, and only while it runs.
                // `copyUIDGID`: owned by the container's user (the agent), whatever the daemon's
                // defaults for archive ownership.
                let options = UploadToContainerOptionsBuilder::new().path(TOKEN_DIR).copy_uidgid("true").build();
                self.docker.upload_to_container(&cname, Some(options), bollard::body_full(token_archive(token)?)).await.with_context(|| format!("handing the build token to {cname}"))?;
            }
            self.docker.start_container(&cname, None).await.with_context(|| format!("starting {cname}"))?;
        }
        Ok(())
    }

    async fn remove(&self, id: i64) -> Result<()> {
        for suffix in ["agent", "buildkitd"] {
            match self.docker.remove_container(&format!("{}-{suffix}", self.name(id)), Some(RemoveContainerOptionsBuilder::new().force(true).build())).await {
                Ok(()) | Err(DockerError::DockerResponseServerError { status_code: 404, .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        match self.docker.remove_volume(&self.name(id), None::<RemoveVolumeOptions>).await {
            Ok(()) | Err(DockerError::DockerResponseServerError { status_code: 404, .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn launched(&self) -> Result<HashMap<i64, Launched>> {
        let filters = HashMap::from([("label", vec![MANAGED_BY])]);
        let list = self.docker.list_containers(Some(ListContainersOptionsBuilder::new().all(true).filters(&filters).build())).await?;
        let mut stopped = vec![];
        let mut out = HashMap::new();
        for c in list {
            let Some(id) = c.labels.as_ref().and_then(|l| l.get(BUILD_LABEL)).and_then(|v| v.parse::<i64>().ok()) else { continue };
            let down = matches!(c.state, Some(ContainerSummaryStateEnum::EXITED | ContainerSummaryStateEnum::DEAD));
            // Either container going down takes the build with it.
            if down {
                stopped.push(id);
            }
            out.entry(id).or_insert(Launched::Running);
        }
        for id in stopped {
            out.insert(id, Launched::Stopped(self.exit_reason(id).await));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use kontainer_core::config::DockerBuildNetwork;

    #[test]
    fn isolated_builds_get_no_host_alias() {
        let isolated = super::extra_hosts(DockerBuildNetwork::Isolated);
        assert!(isolated.iter().all(|h| !h.contains("host-gateway")));
        assert!(isolated.contains(&"metadata.google.internal:127.0.0.1".to_string()));
        assert_eq!(super::extra_hosts(DockerBuildNetwork::Open), vec!["host.docker.internal:host-gateway".to_string()]);
    }

    #[test]
    fn token_archive_is_private_to_the_agent() {
        let bytes = super::token_archive("s3cret").unwrap();
        let mut tar = tar::Archive::new(&bytes[..]);
        let mut entries = tar.entries().unwrap();
        let mut e = entries.next().unwrap().unwrap();
        assert_eq!(e.path().unwrap().to_str(), Some(super::TOKEN_FILE));
        assert_eq!((e.header().mode().unwrap(), e.header().uid().unwrap()), (0o400, super::AGENT_UID));
        let mut body = String::new();
        std::io::Read::read_to_string(&mut e, &mut body).unwrap();
        assert_eq!(body, "s3cret");
        assert!(entries.next().is_none());
    }
}
