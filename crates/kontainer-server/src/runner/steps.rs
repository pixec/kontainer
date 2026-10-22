//! The build itself: check out the commit, build it with BuildKit and write an OCI archive.
//! Where it runs and where the log and archive go is up to the caller.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

use crate::runner::protocol::BuildSpec;
use kontainer_core::WireSecret;
use crate::runner::{and_list, inside, resolved_inside, short_ref, valid_ref};

/// The most log a runner holds that the registry hasn't acknowledged (it has been unreachable
/// for a long while): more output is dropped, with a note.
const MAX_PENDING: usize = 64 << 20;
/// Short helper commands (`git rev-parse`, `docker rmi`, a BuildKit probe) get this long.
const QUICK: Duration = Duration::from_secs(30);

/// The only variables build commands inherit from the runner (whose own environment holds its
/// token): what git, docker and buildctl need to find things and get through a proxy.
const PASS_ENV: &[&str] = &[
    "PATH", "HOME", "TMPDIR", "USER", "LANG", "LC_ALL", "XDG_RUNTIME_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
    "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_CONTEXT", "BUILDKIT_HOST",
];

/// `program` with a clean environment: [`PASS_ENV`] only, and never a Git prompt.
fn command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear().env("GIT_TERMINAL_PROMPT", "0");
    for k in PASS_ENV {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    cmd
}

/// How the image is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// `docker build` + `docker save` through the local daemon's BuildKit (Docker 25+ with the
    /// containerd image store).
    Docker,
    /// A BuildKit daemon, e.g. `tcp://buildkitd:1234` or `unix:///run/buildkit/buildkitd.sock`.
    Buildctl { addr: String },
}

impl Backend {
    /// For the log: "Building docker/Dockerfile with BuildKit".
    fn label(&self) -> &'static str {
        match self {
            Backend::Docker => "Docker",
            Backend::Buildctl { .. } => "BuildKit",
        }
    }
}

/// Build output, with secrets masked. Cheap to clone; whoever runs the build decides where it
/// goes and how often. Offsets count bytes from the start of the log; what the registry has
/// acknowledged can be forgotten ([`Log::forget_before`]), keeping memory bounded however much a
/// build prints.
#[derive(Clone, Default)]
pub struct Log {
    inner: Arc<Mutex<LogInner>>,
}

#[derive(Default)]
struct LogInner {
    /// The log from byte `start` on.
    text: String,
    start: usize,
    secrets: Vec<String>,
}

impl Log {
    /// Never write `secret` (a Git token) to the log, as is or percent-encoded (as in a URL).
    pub fn redact(&self, secret: &str) {
        if secret.len() >= 4 {
            let mut g = self.lock();
            let encoded = percent_encode(secret);
            if encoded != secret {
                g.secrets.push(encoded);
            }
            g.secrets.push(secret.to_string());
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LogInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn line(&self, text: &str) {
        let mut g = self.lock();
        let mut text = text.to_string();
        for s in &g.secrets {
            text = text.replace(s.as_str(), "***");
        }
        if g.text.len() < MAX_PENDING {
            g.text.push_str(&text);
            g.text.push('\n');
            if g.text.len() >= MAX_PENDING {
                g.text.push_str("[log truncated]\n");
            }
        }
    }

    /// The log as held: all of it, unless some was forgotten.
    pub fn text(&self) -> String {
        self.lock().text.clone()
    }

    /// Bytes logged so far.
    pub fn len(&self) -> u64 {
        let g = self.lock();
        (g.start + g.text.len()) as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The log from byte `offset` on; `None` when that was forgotten, isn't logged yet, or falls
    /// inside a character.
    pub fn since(&self, offset: u64) -> Option<String> {
        let g = self.lock();
        let at = usize::try_from(offset).ok()?.checked_sub(g.start)?;
        g.text.get(at..).map(str::to_string)
    }

    /// The last `max` bytes or so (whole characters) and where they start.
    pub fn tail(&self, max: usize) -> (u64, String) {
        let g = self.lock();
        let from = g.text.ceil_char_boundary(g.text.len().saturating_sub(max));
        ((g.start + from) as u64, g.text[from..].to_string())
    }

    /// The registry has the log up to `offset`: drop it, except for the last `keep` bytes (the
    /// tail of a log the registry truncates).
    pub fn forget_before(&self, offset: u64, keep: usize) {
        let mut g = self.lock();
        let upto = usize::try_from(offset).unwrap_or(usize::MAX).saturating_sub(g.start);
        let cut = g.text.floor_char_boundary(upto.min(g.text.len().saturating_sub(keep)));
        if cut > 0 {
            g.text.drain(..cut);
            g.start += cut;
        }
    }
}

/// The server's side of a build, as seen from the steps.
#[async_trait]
pub trait Server: Send + Sync {
    /// The checkout is at `sha`; the server picks the tags (and can refuse, failing the build).
    async fn commit(&self, sha: &str) -> Result<Vec<String>>;
}

/// Build `spec` in `work` (created, and left for the caller to remove). Returns the OCI archive.
/// Stops when `cancel` turns true or the spec's timeout passes.
pub async fn run(spec: &BuildSpec, backend: &Backend, work: &Path, log: &Log, server: &dyn Server, mut cancel: watch::Receiver<bool>) -> Result<PathBuf> {
    let deadline = Instant::now() + Duration::from_secs(spec.timeout_secs.max(1));
    if !valid_ref(&spec.git_ref) || !valid_ref(&spec.target) {
        bail!("Invalid branch, tag or commit: {:?}", spec.git_ref);
    }
    let _ = tokio::fs::remove_dir_all(work).await;
    tokio::fs::create_dir_all(work).await.with_context(|| format!("creating {}", work.display()))?;
    let src = work.join("src");
    let auth = GitAuth::new(&spec.git_url, spec.git_username.as_deref(), spec.git_token.as_ref().map(WireSecret::expose))?;
    if let Some(t) = &spec.git_token {
        log.redact(t.expose());
    }
    auth.redact(log);
    let c = &mut cancel;
    let what = short_ref(&spec.target);
    log.line(&format!("==> Fetching the Git repository ({what})"));
    log.line(&format!("From {}", spec.git_url));
    exec(command("git").args(["init", "-q"]).arg(&src), log, c, deadline).await.context("Couldn't prepare a Git checkout")?;
    exec(auth.apply(command("git").arg("-C").arg(&src).args(["fetch", "--depth", "1", "--no-tags", "--", &auth.url, &spec.target])), log, c, deadline)
        .await
        .with_context(|| format!("Couldn't fetch {what} from the Git repository. Check the URL, that the branch or tag exists, and the trigger's credentials"))?;
    exec(command("git").arg("-C").arg(&src).args(["checkout", "-q", "FETCH_HEAD"]), log, c, deadline).await.context("Couldn't check out the fetched commit")?;
    let sha = capture(command("git").arg("-C").arg(&src).args(["rev-parse", "HEAD"])).await?;
    let subject = capture(command("git").arg("-C").arg(&src).args(["log", "-1", "--format=%s"])).await.unwrap_or_default();
    log.line(&format!("==> Fetched commit {}{}", &sha[..sha.len().min(7)], if subject.is_empty() { String::new() } else { format!(": {subject}") }));
    log.line(&sha);
    let tags = server.commit(&sha).await?;
    log.line(&if tags.is_empty() { "==> The image won't be tagged: it is pushed by digest only".to_string() } else { format!("==> The image will be tagged {}", and_list(&tags)) });

    // The paths are checked as text before the checkout and resolved after it: the repository
    // decides what its symbolic links point at.
    let context = inside(&src, &spec.context)?;
    let dockerfile = inside(&src, &spec.dockerfile)?;
    if !tokio::fs::try_exists(&dockerfile).await.unwrap_or(false) {
        bail!("Couldn't find {} in the repository. Check the Dockerfile path in the build trigger", spec.dockerfile);
    }
    let context = resolved_inside(&src, &context, &format!("The build context ({})", spec.context))?;
    let dockerfile = resolved_inside(&src, &dockerfile, &format!("The Dockerfile ({})", spec.dockerfile))?;
    let archive = work.join("image.tar");
    log.line(&format!("==> Building {} with {}", spec.dockerfile, backend.label()));
    match backend {
        Backend::Docker => {
            let image = format!("kontainer-build-{}:latest", spec.id);
            let r = async {
                exec(command("docker").args(["build", "-f"]).arg(&dockerfile).args(["-t", &image]).arg(&context), log, c, deadline).await.context("The image build failed; the step that broke is shown above")?;
                exec(command("docker").args(["save", "-o"]).arg(&archive).arg(&image), log, c, deadline).await.context("Couldn't export the built image")
            }
            .await;
            let mut rmi = command("docker");
            rmi.args(["rmi", "-f", &image]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
            if !matches!(tokio::time::timeout(QUICK, rmi.status()).await, Ok(Ok(_))) {
                tracing::warn!(%image, "couldn't remove the built image");
            }
            r?;
        }
        Backend::Buildctl { addr } => {
            if addr.is_empty() {
                bail!("No BuildKit address is configured (builds.buildkit_addr)");
            }
            wait_for_buildkit(addr, log, c, deadline).await?;
            let df_dir = dockerfile.parent().unwrap_or(&src).to_path_buf();
            let df_name = dockerfile.file_name().and_then(|n| n.to_str()).unwrap_or("Dockerfile").to_string();
            exec(
                command("buildctl")
                    .args(["--addr", addr, "build", "--progress", "plain", "--frontend", "dockerfile.v0"])
                    .arg("--local")
                    .arg(format!("context={}", context.display()))
                    .arg("--local")
                    .arg(format!("dockerfile={}", df_dir.display()))
                    .args(["--opt", &format!("filename={df_name}")])
                    .args(["--output", &format!("type=oci,dest={}", archive.display())]),
                log,
                c,
                deadline,
            )
            .await
            .context("The image build failed; the step that broke is shown above")?;
        }
    }
    Ok(archive)
}

/// A BuildKit sidecar may still be starting when the build begins.
async fn wait_for_buildkit(addr: &str, log: &Log, cancel: &mut watch::Receiver<bool>, deadline: Instant) -> Result<()> {
    let give_up = Instant::now() + Duration::from_secs(90);
    let mut said = false;
    loop {
        let mut probe = command("buildctl");
        probe.args(["--addr", addr, "debug", "workers"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
        let ok = matches!(tokio::time::timeout(Duration::from_secs(10), probe.status()).await, Ok(Ok(s)) if s.success());
        if ok {
            return Ok(());
        }
        if Instant::now() > give_up.min(deadline) {
            bail!("BuildKit at {addr} didn't start answering within 90 seconds");
        }
        if !said {
            log.line(&format!("==> Waiting for BuildKit to start ({addr})"));
            said = true;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = cancel.changed() => bail!("Cancelled"),
        }
    }
}

/// Run a command, streaming its output into the log; killed on cancel or timeout.
async fn exec(cmd: &mut Command, log: &Log, cancel: &mut watch::Receiver<bool>, deadline: Instant) -> Result<()> {
    if *cancel.borrow() {
        bail!("Cancelled");
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null()).kill_on_drop(true);
    let mut child = cmd.spawn().with_context(|| format!("starting {:?}", cmd.as_std().get_program()))?;
    let (out, err) = (child.stdout.take().expect("piped"), child.stderr.take().expect("piped"));
    let pump = |r: Box<dyn tokio::io::AsyncRead + Unpin + Send>| {
        let log = log.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(r).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                log.line(&l);
            }
        })
    };
    let (a, b) = (pump(Box::new(out)), pump(Box::new(err)));
    let status = tokio::select! {
        s = child.wait() => s?,
        _ = cancel.changed() => { let _ = child.kill().await; bail!("Cancelled") }
        _ = tokio::time::sleep_until(deadline.into()) => { let _ = child.kill().await; bail!("Stopped: the build ran longer than its time limit (builds.timeout)") }
    };
    let _ = tokio::join!(a, b);
    if !status.success() {
        bail!("{} exited with {status}", cmd.as_std().get_program().to_string_lossy());
    }
    Ok(())
}

async fn capture(cmd: &mut Command) -> Result<String> {
    let program = cmd.as_std().get_program().to_string_lossy().into_owned();
    let out = tokio::time::timeout(QUICK, cmd.stdin(Stdio::null()).kill_on_drop(true).output()).await.map_err(|_| anyhow!("{program} didn't finish within {} seconds", QUICK.as_secs()))??;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// How `git` reaches a repository with a token: the URL without credentials, and the token as
/// an `Authorization` header handed to git through its environment, so it shows up in neither
/// the process list (argv) nor git's own messages.
struct GitAuth {
    /// What to pass to git.
    url: String,
    /// `http.<origin>/.extraHeader` and its value.
    header: Option<(String, String)>,
}

impl GitAuth {
    /// A token alone uses the username `x-access-token` (GitHub's convention, which GitLab and
    /// Gitea accept too).
    fn new(url: &str, username: Option<&str>, token: Option<&str>) -> Result<Self> {
        let Some(token) = token.filter(|s| !s.is_empty()) else { return Ok(Self { url: url.to_string(), header: None }) };
        let mut u = url::Url::parse(url).context("git URL")?;
        if !matches!(u.scheme(), "http" | "https") {
            bail!("A Git token only works with an http:// or https:// repository URL");
        }
        let _ = u.set_username("");
        let _ = u.set_password(None);
        let user = username.filter(|s| !s.is_empty()).unwrap_or("x-access-token");
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{user}:{token}"));
        // Scoped to the repository's origin: never sent to another host.
        let key = format!("http.{}/.extraHeader", u.origin().ascii_serialization());
        Ok(Self { url: u.to_string(), header: Some((key, format!("Authorization: Basic {basic}"))) })
    }

    fn apply<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        if let Some((key, value)) = &self.header {
            cmd.env("GIT_CONFIG_COUNT", "1").env("GIT_CONFIG_KEY_0", key).env("GIT_CONFIG_VALUE_0", value);
        }
        cmd
    }

    /// The encoded credentials are as secret as the token.
    fn redact(&self, log: &Log) {
        if let Some((_, value)) = &self.header {
            log.redact(value.trim_start_matches("Authorization: Basic "));
        }
    }
}

/// `s` as it would appear in a URL: everything but unreserved characters percent-encoded.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The branches and tags of the repository at `url` and the commit each points at (annotated
/// tags resolved to their commit). For watching a repository without webhooks.
pub async fn ls_remote(url: &str, username: Option<&str>, token: Option<&str>) -> Result<Vec<(String, String)>> {
    let auth = GitAuth::new(url, username, token)?;
    let mut cmd = command("git");
    auth.apply(cmd.args(["ls-remote", "--heads", "--tags", "--", &auth.url]).stdin(Stdio::null()).kill_on_drop(true));
    let out = tokio::time::timeout(Duration::from_secs(30), cmd.output())
    .await
    .map_err(|_| anyhow!("The Git repository didn't answer within 30 seconds"))?
    .context("Couldn't run git")?;
    if !out.status.success() {
        let mut why = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let log = Log::default();
        if let Some(t) = token {
            log.redact(t);
        }
        auth.redact(&log);
        for s in &log.inner.lock().unwrap_or_else(|e| e.into_inner()).secrets {
            why = why.replace(s.as_str(), "***");
        }
        let why = why.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("git ls-remote failed").trim_start_matches("fatal: ").to_string();
        bail!("{}", crate::runner::sentence(&why));
    }
    let mut refs: Vec<(String, String)> = vec![];
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some((sha, name)) = line.split_once('\t') else { continue };
        match name.strip_suffix("^{}") {
            // The commit an annotated tag points at, listed right after the tag itself.
            Some(tag) => match refs.iter_mut().find(|(n, _)| n == tag) {
                Some(r) => r.1 = sha.to_string(),
                None => refs.push((tag.to_string(), sha.to_string())),
            },
            None => refs.push((name.to_string(), sha.to_string())),
        }
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use std::process::Command as Std;

    use super::{GitAuth, Log};

    #[test]
    fn git_token_goes_in_a_header_not_the_url() {
        let a = GitAuth::new("https://old:creds@git.example.com:8443/acme/app.git", None, Some("s3cr/t+tok")).unwrap();
        assert_eq!(a.url, "https://git.example.com:8443/acme/app.git");
        let (key, value) = a.header.clone().unwrap();
        assert_eq!(key, "http.https://git.example.com:8443/.extraHeader");
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "x-access-token:s3cr/t+tok");
        assert_eq!(value, format!("Authorization: Basic {b64}"));
        let named = GitAuth::new("https://git.example.com/a.git", Some("bot"), Some("tok123")).unwrap();
        assert!(named.header.unwrap().1.ends_with(&base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "bot:tok123")));
        // No token: the URL as given, nothing added.
        assert!(GitAuth::new("https://git.example.com/a.git", None, None).unwrap().header.is_none());
        assert!(GitAuth::new("ssh://git@git.example.com/a.git", None, Some("tok123")).is_err());

        let log = Log::default();
        log.redact("s3cr/t+tok");
        a.redact(&log);
        log.line(&format!("plain s3cr/t+tok encoded s3cr%2Ft%2Btok basic {b64}"));
        assert_eq!(log.text(), "plain *** encoded *** basic ***\n");
    }

    #[test]
    fn logs_are_addressed_by_offset_and_forgotten_once_sent() {
        let log = Log::default();
        log.line("héllo");
        log.line("world");
        assert_eq!(log.len(), 13);
        assert_eq!(log.since(7).as_deref(), Some("world\n"));
        assert_eq!(log.since(2), None, "inside the é");
        assert_eq!(log.since(14), None);
        assert_eq!(log.tail(6), (7, "world\n".to_string()));
        log.forget_before(13, 4);
        assert_eq!((log.len(), log.text().as_str()), (13, "rld\n"), "only the tail kept");
        assert_eq!(log.since(10).as_deref(), Some("ld\n"));
        assert_eq!(log.since(3), None, "forgotten");
        log.line("more");
        assert_eq!(log.since(13).as_deref(), Some("more\n"));
    }

    #[tokio::test]
    async fn ls_remote_lists_branches_and_tags() {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| assert!(Std::new("git").arg("-C").arg(dir.path()).args(args).env("GIT_CONFIG_GLOBAL", "/dev/null").status().unwrap().success());
        git(&["init", "-q", "-b", "main"]);
        git(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "first"]);
        git(&["-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "v1", "-m", "v1"]);
        let head = String::from_utf8(Std::new("git").arg("-C").arg(dir.path()).args(["rev-parse", "HEAD"]).output().unwrap().stdout).unwrap().trim().to_string();
        let refs = super::ls_remote(&format!("file://{}", dir.path().display()), None, None).await.unwrap();
        // The annotated tag is listed at its commit, not the tag object.
        assert_eq!(refs, vec![("refs/heads/main".to_string(), head.clone()), ("refs/tags/v1".to_string(), head)]);
        let err = super::ls_remote("file:///nonexistent/repo", None, None).await.unwrap_err();
        assert!(err.to_string().starts_with(char::is_uppercase), "{err}");
    }
}
