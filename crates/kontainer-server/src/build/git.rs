//! Listing a Git repository's branches and tags over the smart HTTP protocol (what
//! `git ls-remote` does), so the registry can watch repositories without a `git` binary.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use futures::TryStreamExt;

use kontainer_core::upstream::netguard;

/// Largest ref advertisement read (a repository with tens of thousands of refs is well under).
const MAX_ADVERTISEMENT_BYTES: usize = 4 * 1024 * 1024;
/// What the guard's errors point at.
const PRIVATE_HINT: &str = "policy.webhooks_allow_private_targets";

/// The branches and tags of the repository at `url` (https) and the commit each points at,
/// annotated tags resolved to their commit. Unless `allow_private`, the Git host must be a
/// public address (the URL is chosen by namespace users, and the registry's own network is not
/// theirs to probe); redirects are not followed either way, so credentials stay on that host.
pub async fn ls_remote(url: &str, username: Option<&str>, token: Option<&str>, allow_private: bool) -> Result<Vec<(String, String)>> {
    let base = url.trim_end_matches('/');
    if !base.starts_with("https://") && !base.starts_with("http://") {
        bail!("Watching for new commits needs an https:// Git URL");
    }
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("git/2.0 (kontainer/", env!("CARGO_PKG_VERSION"), ")"))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());
    if !allow_private {
        netguard::check_target(base, PRIVATE_HINT).await?;
        builder = builder.dns_resolver(netguard::PublicOnly { hint: PRIVATE_HINT });
    }
    let http = builder.build()?;
    let mut req = http.get(format!("{base}/info/refs?service=git-upload-pack"));
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        req = req.basic_auth(username.filter(|u| !u.is_empty()).unwrap_or("x-access-token"), Some(t));
    }
    let r = req.send().await.with_context(|| format!("Couldn't reach {base}"))?;
    match r.status() {
        s if s.is_success() => {}
        s if s.is_redirection() => bail!("The Git host answered a redirect ({s}): use the repository's final URL"),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => bail!("The Git host refused access ({}): check the trigger's credentials", r.status()),
        reqwest::StatusCode::NOT_FOUND => bail!("The Git repository wasn't found (404): check the URL, or its credentials if it is private"),
        s => bail!("The Git host answered {s}"),
    }
    if r.content_length().is_some_and(|n| n > MAX_ADVERTISEMENT_BYTES as u64) {
        bail!("The Git host's ref list is larger than {MAX_ADVERTISEMENT_BYTES} bytes");
    }
    let mut body = Vec::new();
    let mut stream = r.bytes_stream();
    while let Some(chunk) = stream.try_next().await? {
        if body.len() + chunk.len() > MAX_ADVERTISEMENT_BYTES {
            bail!("The Git host's ref list is larger than {MAX_ADVERTISEMENT_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    parse_advertisement(&body)
}

/// Parse a `git-upload-pack` ref advertisement: pkt-lines of `<sha> <ref>[\0capabilities]`.
fn parse_advertisement(body: &[u8]) -> Result<Vec<(String, String)>> {
    let mut refs: Vec<(String, String)> = vec![];
    let mut at = 0;
    while at + 4 <= body.len() {
        let len = usize::from_str_radix(std::str::from_utf8(&body[at..at + 4])?, 16).map_err(|_| anyhow!("Not a Git smart HTTP response"))?;
        if len == 0 {
            at += 4; // flush
            continue;
        }
        if len < 4 || at + len > body.len() {
            bail!("Truncated Git response");
        }
        let line = String::from_utf8_lossy(&body[at + 4..at + len]);
        at += len;
        let line = line.trim_end_matches('\n');
        let line = line.split('\0').next().unwrap_or_default();
        if line.starts_with('#') {
            continue; // `# service=git-upload-pack`
        }
        let Some((sha, name)) = line.split_once(' ') else { continue };
        if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) || name == "capabilities^{}" {
            continue;
        }
        match name.strip_suffix("^{}") {
            // The commit an annotated tag points at, listed right after the tag itself.
            Some(tag) => match refs.iter_mut().find(|(n, _)| n == tag) {
                Some(r) => r.1 = sha.to_string(),
                None => refs.push((tag.to_string(), sha.to_string())),
            },
            None => refs.push((name.to_string(), sha.to_string())),
        }
    }
    if refs.is_empty() && !body.starts_with(b"001e# service=git-upload-pack") {
        bail!("Not a Git smart HTTP response: is the URL a Git repository?");
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    fn pkt(s: &str) -> String {
        format!("{:04x}{s}", s.len() + 4)
    }

    #[test]
    fn advertisement() {
        let (a, b, c) = ("a".repeat(40), "b".repeat(40), "c".repeat(40));
        let body = format!(
            "{}0000{}{}{}{}0000",
            pkt("# service=git-upload-pack\n"),
            pkt(&format!("{a} HEAD\0multi_ack thin-pack side-band symref=HEAD:refs/heads/main\n")),
            pkt(&format!("{a} refs/heads/main\n")),
            pkt(&format!("{b} refs/tags/v1\n")),
            pkt(&format!("{c} refs/tags/v1^{{}}\n")),
        );
        let refs = super::parse_advertisement(body.as_bytes()).unwrap();
        assert_eq!(refs, vec![("HEAD".to_string(), a.clone()), ("refs/heads/main".to_string(), a), ("refs/tags/v1".to_string(), c)]);
        assert!(super::parse_advertisement(b"<html>login</html>").is_err());
        // An empty repository advertises no refs.
        let empty = format!("{}0000{}0000", pkt("# service=git-upload-pack\n"), pkt(&format!("{} capabilities^{{}}\0agent=git\n", "0".repeat(40))));
        assert!(super::parse_advertisement(empty.as_bytes()).unwrap().is_empty());
    }
}
