//! Builds as Kubernetes Jobs, one per build, created and deleted through the Kubernetes API.
//!
//! The pod runs `kontainer runner --build-id <id>` with that build's token, next to a
//! rootless BuildKit sidecar (a native sidecar: an init container with `restartPolicy: Always`,
//! Kubernetes 1.29+) that does the actual build. CPU, memory and disk limits apply to BuildKit.
//! Kubernetes enforces the time limit (`activeDeadlineSeconds`) and cleans up finished Jobs.
//!
//! The build token is not in the Job: it is in a Secret of the same name, owned by the Job so
//! Kubernetes deletes it with the Job. The runner's Role needs `secrets` (create, delete) besides
//! `jobs`.
//!
//! With `network_policy` (the default) each Job also gets a NetworkPolicy, owned by it, that
//! lets the pod reach DNS, the registry's pods and public addresses only: a Dockerfile's `RUN`
//! steps can't reach the cluster, private networks or cloud metadata. That needs
//! `networkpolicies` (create) in the Role too.

use std::path::PathBuf;
use std::time::Duration;

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use kontainer_core::config::KubernetesBuildConfig;

use super::{Launched, Launcher};

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
/// `app.kubernetes.io/managed-by=kontainer`, URL-encoded.
const MANAGED_BY: &str = "app.kubernetes.io%2Fmanaged-by%3Dkontainer";
/// Where the agent and BuildKit share BuildKit's socket.
const BUILDKIT_SOCKET: &str = "unix:///run/buildkit/buildkitd.sock";
/// Time to pull images and schedule the pod, on top of the build timeout.
const START_GRACE: Duration = Duration::from_secs(10 * 60);

fn job_name(id: i64) -> String {
    format!("kontainer-build-{id}")
}

pub struct KubernetesLauncher {
    client: Client,
    cfg: KubernetesBuildConfig,
    /// The build timeout; Kubernetes enforces it (plus time to start).
    timeout: Duration,
    /// How build pods reach the registry.
    server_url: String,
}

impl KubernetesLauncher {
    pub fn new(cfg: &KubernetesBuildConfig, timeout: Duration, server_url: &str) -> Result<Self> {
        Ok(Self { client: Client::new(cfg)?, cfg: cfg.clone(), timeout, server_url: server_url.to_string() })
    }
}

#[async_trait]
impl Launcher for KubernetesLauncher {
    fn prefix(&self) -> &'static str {
        "kubernetes/"
    }

    async fn launch(&self, id: i64, token: &str) -> Result<()> {
        // The Job first, to own the Secret; its pod waits for the Secret to appear.
        let created = self.client.create_job(&job(&self.cfg, self.timeout, &self.client.namespace, &self.server_url, id)).await?;
        let uid = created["metadata"]["uid"].as_str().unwrap_or_default().to_string();
        // The policy before the Secret: the agent container can't start (nor ask BuildKit to
        // run anything) until the Secret exists, so no `RUN` step runs without the policy.
        let secret = async {
            anyhow::ensure!(!uid.is_empty(), "the Kubernetes API didn't return the Job's uid");
            if self.cfg.network_policy {
                self.client.create_network_policy(&network_policy(&self.cfg, &self.client.namespace, id, &uid)).await?;
            }
            self.client.create_secret(&secret(&self.client.namespace, id, &uid, token)).await
        };
        if let Err(e) = secret.await {
            let _ = self.client.delete_job(&job_name(id)).await;
            return Err(e);
        }
        tracing::info!(build = id, job = %job_name(id), namespace = %self.client.namespace, "build Job created");
        Ok(())
    }

    async fn remove(&self, id: i64) -> Result<()> {
        self.client.delete_job(&job_name(id)).await?;
        // Garbage collection would get it too; don't leave the token lying around until then.
        self.client.delete_secret(&job_name(id)).await
    }

    async fn launched(&self) -> Result<HashMap<i64, Launched>> {
        Ok(self.client.jobs().await?.into_iter().map(|(id, s)| (id, match s {
            JobState::Running => Launched::Running,
            JobState::Failed(why) => Launched::Stopped(why),
            JobState::Done => Launched::Stopped("The build Job ended without reporting back".into()),
        })).collect())
    }

    /// Finished Jobs stay for `job_ttl`, so their pods' logs can still be read.
    fn keeps_finished(&self) -> bool {
        true
    }
}

/// A minimal Kubernetes API client: just Jobs, in one namespace.
struct Client {
    http: reqwest::Client,
    api: String,
    /// Re-read on every request: projected service account tokens rotate.
    token_file: Option<PathBuf>,
    pub namespace: String,
}

impl Client {
    fn new(cfg: &KubernetesBuildConfig) -> Result<Self> {
        let in_cluster = std::env::var("KUBERNETES_SERVICE_HOST").ok().zip(std::env::var("KUBERNETES_SERVICE_PORT").ok());
        let api = match (&cfg.api_url, &in_cluster) {
            (Some(url), _) => url.trim_end_matches('/').to_string(),
            (None, Some((host, port))) => format!("https://{}:{port}", if host.contains(':') { format!("[{host}]") } else { host.clone() }),
            (None, None) => bail!("not running in Kubernetes; set builds.kubernetes.api_url, token_file and ca_file"),
        };
        let sa = PathBuf::from(SA_DIR);
        let token_file = cfg.token_file.clone().or_else(|| in_cluster.is_some().then(|| sa.join("token")));
        let ca_file = cfg.ca_file.clone().or_else(|| in_cluster.is_some().then(|| sa.join("ca.crt")));
        let mut http = reqwest::Client::builder().user_agent(kontainer_core::USER_AGENT).timeout(Duration::from_secs(30));
        if let Some(ca) = &ca_file {
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            http = http.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        let namespace = cfg.namespace.clone().or_else(|| std::fs::read_to_string(sa.join("namespace")).ok().map(|s| s.trim().to_string())).unwrap_or_else(|| "default".into());
        Ok(Self { http: http.build()?, api, token_file, namespace })
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let req = match &self.token_file {
            Some(f) => req.bearer_auth(tokio::fs::read_to_string(f).await.with_context(|| format!("reading {}", f.display()))?.trim()),
            None => req,
        };
        req.send().await.with_context(|| format!("reaching the Kubernetes API at {}", self.api))
    }

    fn jobs_url(&self) -> String {
        format!("{}/apis/batch/v1/namespaces/{}/jobs", self.api, self.namespace)
    }

    fn network_policies_url(&self) -> String {
        format!("{}/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies", self.api, self.namespace)
    }

    /// Create a NetworkPolicy, replacing a left-over one of the same name. (Deleted with its Job
    /// by Kubernetes' garbage collection.)
    pub async fn create_network_policy(&self, policy: &Value) -> Result<()> {
        let name = policy["metadata"]["name"].as_str().unwrap_or_default();
        for retry in [true, false] {
            let r = self.send(self.http.post(self.network_policies_url()).json(policy)).await?;
            if r.status() == reqwest::StatusCode::CONFLICT && retry {
                let d = self.send(self.http.delete(format!("{}/{name}", self.network_policies_url()))).await?;
                if !d.status().is_success() && d.status() != reqwest::StatusCode::NOT_FOUND {
                    bail!("deleting NetworkPolicy {name}: {} {}", d.status(), api_message(d).await);
                }
                continue;
            }
            if r.status() == reqwest::StatusCode::FORBIDDEN {
                bail!("creating the build's NetworkPolicy: {} {} (grant the runner's Role `networkpolicies` create in group networking.k8s.io, or set kubernetes.network_policy = false)", r.status(), api_message(r).await);
            }
            if !r.status().is_success() {
                bail!("creating the build's NetworkPolicy: {} {}", r.status(), api_message(r).await);
            }
            break;
        }
        Ok(())
    }

    fn secrets_url(&self) -> String {
        format!("{}/api/v1/namespaces/{}/secrets", self.api, self.namespace)
    }

    /// The Job as created (with its `metadata.uid`).
    pub async fn create_job(&self, job: &Value) -> Result<Value> {
        let r = self.send(self.http.post(self.jobs_url()).json(job)).await?;
        if !r.status().is_success() {
            bail!("creating the Job: {} {}", r.status(), api_message(r).await);
        }
        Ok(r.json().await?)
    }

    /// Create a Secret, replacing a left-over one of the same name.
    pub async fn create_secret(&self, secret: &Value) -> Result<()> {
        let name = secret["metadata"]["name"].as_str().unwrap_or_default();
        for retry in [true, false] {
            let r = self.send(self.http.post(self.secrets_url()).json(secret)).await?;
            if r.status() == reqwest::StatusCode::CONFLICT && retry {
                self.delete_secret(name).await?;
                continue;
            }
            if !r.status().is_success() {
                bail!("creating the Secret for the build token: {} {}", r.status(), api_message(r).await);
            }
            break;
        }
        Ok(())
    }

    /// Delete a Secret. Already gone is fine.
    pub async fn delete_secret(&self, name: &str) -> Result<()> {
        let r = self.send(self.http.delete(format!("{}/{name}", self.secrets_url()))).await?;
        if !r.status().is_success() && r.status() != reqwest::StatusCode::NOT_FOUND {
            bail!("deleting Secret {name}: {} {}", r.status(), api_message(r).await);
        }
        Ok(())
    }

    /// Delete a Job and its pod. A Job that is already gone is fine.
    pub async fn delete_job(&self, name: &str) -> Result<()> {
        let r = self.send(self.http.delete(format!("{}/{name}?propagationPolicy=Background", self.jobs_url()))).await?;
        if !r.status().is_success() && r.status() != reqwest::StatusCode::NOT_FOUND {
            bail!("deleting Job {name}: {} {}", r.status(), api_message(r).await);
        }
        Ok(())
    }

    /// Our build Jobs, by build id.
    pub async fn jobs(&self) -> Result<std::collections::HashMap<i64, JobState>> {
        let r = self.send(self.http.get(format!("{}?labelSelector={MANAGED_BY}", self.jobs_url()))).await?;
        if !r.status().is_success() {
            bail!("listing Jobs: {} {}", r.status(), api_message(r).await);
        }
        let list: Value = r.json().await?;
        Ok(list["items"].as_array().into_iter().flatten().filter_map(|j| Some((j["metadata"]["labels"]["kontainer.dev/build-id"].as_str()?.parse().ok()?, JobState::of(j)))).collect())
    }
}

async fn api_message(r: reqwest::Response) -> String {
    r.json::<Value>().await.ok().and_then(|v| v["message"].as_str().map(str::to_string)).unwrap_or_default()
}

#[derive(Debug, PartialEq)]
enum JobState {
    Running,
    Failed(String),
    Done,
}

impl JobState {
    fn of(job: &Value) -> Self {
        for c in job["status"]["conditions"].as_array().into_iter().flatten() {
            if c["status"] != "True" {
                continue;
            }
            match c["type"].as_str() {
                Some("Failed") => {
                    let why = [c["reason"].as_str(), c["message"].as_str()].into_iter().flatten().collect::<Vec<_>>().join(": ");
                    return JobState::Failed(if why.is_empty() { "The build Job failed".into() } else { format!("The build Job failed ({why})") });
                }
                Some("Complete") => return JobState::Done,
                _ => {}
            }
        }
        JobState::Running
    }
}

fn labels(id: i64) -> Value {
    json!({
        "app.kubernetes.io/name": "kontainer-build",
        "app.kubernetes.io/managed-by": "kontainer",
        "kontainer.dev/build-id": id.to_string(),
    })
}

/// The Secret with build `id`'s token, owned by its Job (`job_uid`).
fn secret(namespace: &str, id: i64, job_uid: &str, token: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": job_name(id),
            "namespace": namespace,
            // Not the Job's selector label: the runner lists Jobs, not Secrets, by it.
            "labels": { "app.kubernetes.io/managed-by": "kontainer", "kontainer.dev/build-id": id.to_string() },
            "ownerReferences": [{ "apiVersion": "batch/v1", "kind": "Job", "name": job_name(id), "uid": job_uid }],
        },
        "type": "Opaque",
        "immutable": true,
        "stringData": { "token": token },
    })
}

/// The NetworkPolicy for build `id`'s pod, owned by its Job (`job_uid`): no ingress; egress to
/// DNS, the registry's pods, `egress_cidrs` and public addresses (private ones too with
/// `allow_private_network`), never link-local (cloud metadata).
fn network_policy(k: &KubernetesBuildConfig, namespace: &str, id: i64, job_uid: &str) -> Value {
    let except: &[&str] = if k.allow_private_network { &["169.254.0.0/16"] } else { &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8"] };
    let except6: &[&str] = if k.allow_private_network { &["fe80::/10"] } else { &["fc00::/7", "fe80::/10", "::1/128"] };
    let mut egress = vec![
        json!({ "ports": [{ "protocol": "UDP", "port": 53 }, { "protocol": "TCP", "port": 53 }] }),
        json!({ "to": [
            { "ipBlock": { "cidr": "0.0.0.0/0", "except": except } },
            { "ipBlock": { "cidr": "::/0", "except": except6 } },
        ] }),
    ];
    if !k.registry_pod_labels.is_empty() {
        let namespaces = match &k.registry_namespace {
            Some(ns) => json!({ "matchLabels": { "kubernetes.io/metadata.name": ns } }),
            None => json!({}),
        };
        egress.push(json!({ "to": [{ "namespaceSelector": namespaces, "podSelector": { "matchLabels": k.registry_pod_labels } }] }));
    }
    if !k.egress_cidrs.is_empty() {
        egress.push(json!({ "to": k.egress_cidrs.iter().map(|c| json!({ "ipBlock": { "cidr": c } })).collect::<Vec<_>>() }));
    }
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": job_name(id),
            "namespace": namespace,
            "labels": { "app.kubernetes.io/managed-by": "kontainer", "kontainer.dev/build-id": id.to_string() },
            "ownerReferences": [{ "apiVersion": "batch/v1", "kind": "Job", "name": job_name(id), "uid": job_uid }],
        },
        "spec": {
            "podSelector": { "matchLabels": { "kontainer.dev/build-id": id.to_string(), "app.kubernetes.io/managed-by": "kontainer" } },
            "policyTypes": ["Ingress", "Egress"],
            "egress": egress,
        },
    })
}

/// The Job for build `id`. Its token comes from the Secret of the same name ([`secret`]).
fn job(k: &KubernetesBuildConfig, timeout: Duration, namespace: &str, server_url: &str, id: i64) -> Value {
    let labels = labels(id);
    let resources = json!({
        "requests": { "cpu": k.cpu, "memory": k.memory, "ephemeral-storage": k.ephemeral_storage },
        "limits": { "cpu": k.cpu, "memory": k.memory, "ephemeral-storage": k.ephemeral_storage },
    });
    let mut pod = json!({
        "restartPolicy": "Never",
        "automountServiceAccountToken": false,
        // No environment variables describing every Service in the namespace.
        "enableServiceLinks": false,
        "securityContext": { "fsGroup": 1000 },
        "initContainers": [{
            "name": "buildkitd",
            "image": k.buildkit_image,
            "restartPolicy": "Always",
            "args": ["--addr", BUILDKIT_SOCKET, "--oci-worker-no-process-sandbox"],
            "securityContext": {
                "runAsUser": 1000, "runAsGroup": 1000,
                "seccompProfile": { "type": "Unconfined" },
                "appArmorProfile": { "type": "Unconfined" },
            },
            "startupProbe": {
                "exec": { "command": ["buildctl", "--addr", BUILDKIT_SOCKET, "debug", "workers"] },
                "periodSeconds": 2, "failureThreshold": 60,
            },
            "resources": resources,
            "volumeMounts": [
                { "name": "buildkit-run", "mountPath": "/run/buildkit" },
                { "name": "buildkit-state", "mountPath": "/home/user/.local/share/buildkit" },
            ],
        }],
        "containers": [{
            "name": "agent",
            "image": k.image,
            "command": ["kontainer", "runner", "--server", server_url, "--build-id", id.to_string(), "--backend", "buildctl", "--buildkit-addr", BUILDKIT_SOCKET, "--work-dir", "/work"],
            // Only good for this build's endpoints, and only while it runs.
            "env": [{ "name": "KONTAINER_BUILD_TOKEN", "valueFrom": { "secretKeyRef": { "name": job_name(id), "key": "token" } } }],
            // The agent only runs git and buildctl (BuildKit, next door, needs the relaxed
            // profiles rootless builds require).
            "securityContext": {
                "runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": true,
                "allowPrivilegeEscalation": false,
                "capabilities": { "drop": ["ALL"] },
                "seccompProfile": { "type": "RuntimeDefault" },
            },
            "resources": { "requests": { "cpu": "100m", "memory": "128Mi" }, "limits": { "memory": "512Mi" } },
            "volumeMounts": [
                { "name": "buildkit-run", "mountPath": "/run/buildkit" },
                { "name": "work", "mountPath": "/work" },
            ],
        }],
        "volumes": [
            { "name": "buildkit-run", "emptyDir": {} },
            { "name": "buildkit-state", "emptyDir": {} },
            { "name": "work", "emptyDir": {} },
        ],
    });
    if !k.node_selector.is_empty() {
        pod["nodeSelector"] = json!(k.node_selector);
    }
    if !k.tolerations.is_empty() {
        pod["tolerations"] = json!(k.tolerations);
    }
    if !k.image_pull_secrets.is_empty() {
        pod["imagePullSecrets"] = k.image_pull_secrets.iter().map(|s| json!({ "name": s })).collect();
    }
    if let Some(sa) = &k.service_account {
        pod["serviceAccountName"] = json!(sa);
    }
    json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": { "name": job_name(id), "namespace": namespace, "labels": labels },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": (timeout + START_GRACE).as_secs(),
            "ttlSecondsAfterFinished": k.job_ttl.as_secs(),
            "template": { "metadata": { "labels": labels }, "spec": pod },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_manifest() {
        let cfg = KubernetesBuildConfig {
            image: "registry.example.com/kontainer:0.2.0".into(),
            memory: "8Gi".into(),
            node_selector: [("pool".to_string(), "builds".to_string())].into(),
            ..Default::default()
        };
        let j = job(&cfg, Duration::from_secs(30 * 60), "ci", "https://registry.example.com", 42);
        assert_eq!(j["metadata"]["name"], "kontainer-build-42");
        assert_eq!(j["metadata"]["labels"]["kontainer.dev/build-id"], "42");
        assert_eq!(j["spec"]["backoffLimit"], 0);
        assert_eq!(j["spec"]["activeDeadlineSeconds"], (30 * 60 + 10 * 60) as u64);
        let pod = &j["spec"]["template"]["spec"];
        let bk = &pod["initContainers"][0];
        assert_eq!(bk["restartPolicy"], "Always");
        assert_eq!(bk["resources"]["limits"]["memory"], "8Gi");
        assert_eq!(bk["resources"]["limits"]["ephemeral-storage"], "20Gi");
        let agent = &pod["containers"][0];
        let cmd: Vec<&str> = agent["command"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(&cmd[..6], &["kontainer", "runner", "--server", "https://registry.example.com", "--build-id", "42"]);
        // The token is never in the Job itself.
        assert!(!j.to_string().contains("tok\""));
        assert_eq!(agent["env"][0]["valueFrom"]["secretKeyRef"]["name"], "kontainer-build-42");
        assert_eq!(agent["securityContext"]["capabilities"]["drop"][0], "ALL");
        assert_eq!(agent["securityContext"]["seccompProfile"]["type"], "RuntimeDefault");
        assert_eq!(pod["enableServiceLinks"], false);
        assert_eq!(pod["nodeSelector"]["pool"], "builds");
        assert_eq!(pod["automountServiceAccountToken"], false);

        let s = secret("ci", 42, "uid-1", "tok");
        assert_eq!(s["metadata"]["name"], "kontainer-build-42");
        assert_eq!(s["metadata"]["ownerReferences"][0]["uid"], "uid-1");
        assert_eq!(s["metadata"]["ownerReferences"][0]["kind"], "Job");
        assert_eq!(s["stringData"]["token"], "tok");
    }

    #[test]
    fn network_policy_blocks_private_and_metadata() {
        let cfg = KubernetesBuildConfig::default();
        let p = network_policy(&cfg, "ci", 7, "uid-7");
        assert_eq!(p["metadata"]["ownerReferences"][0]["uid"], "uid-7");
        assert_eq!(p["spec"]["podSelector"]["matchLabels"]["kontainer.dev/build-id"], "7");
        let text = p["spec"]["egress"].to_string();
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"] {
            assert!(text.contains(cidr), "{cidr}");
        }
        assert!(text.contains("\"app.kubernetes.io/name\":\"kontainer\""));
        let open = network_policy(&KubernetesBuildConfig { allow_private_network: true, egress_cidrs: vec!["10.1.0.0/16".into()], ..Default::default() }, "ci", 7, "u");
        let text = open["spec"]["egress"].to_string();
        assert!(!text.contains("10.0.0.0/8") && text.contains("169.254.0.0/16") && text.contains("10.1.0.0/16"));
    }

    #[test]
    fn job_states() {
        assert_eq!(JobState::of(&json!({ "status": { "active": 1 } })), JobState::Running);
        assert_eq!(JobState::of(&json!({ "status": { "conditions": [{ "type": "Complete", "status": "True" }] } })), JobState::Done);
        let failed = json!({ "status": { "conditions": [{ "type": "Failed", "status": "True", "reason": "DeadlineExceeded", "message": "Job was active longer than specified deadline" }] } });
        assert_eq!(JobState::of(&failed), JobState::Failed("The build Job failed (DeadlineExceeded: Job was active longer than specified deadline)".into()));
    }
}
