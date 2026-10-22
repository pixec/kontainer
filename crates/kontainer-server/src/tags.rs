//! Every tag change goes through here: it moves the tag (in the registry tables) and records the change, so
//! the repository has a history and a deleted or moved tag can be restored (Time Machine), and
//! push replication sees it.

use anyhow::Result;

use kontainer_core::digest::Digest;
use crate::state::AppState;

/// Point `tag` at `digest`. `action` names what did it (`push`, `sync`, `import`, `restore`, ...).
/// No history when the tag already pointed there.
pub async fn set(state: &AppState, repo: &str, tag: &str, digest: &Digest, action: &str, actor: &str) -> Result<()> {
    let previous = state.storage.put_tag(repo, tag, digest).await?;
    record_set(state, repo, tag, digest, previous, action, actor).await
}

/// Record that `tag` was pointed at `digest` (from `previous`), when storage already did it
/// (a manifest push stores the manifest and its tag in one transaction).
pub async fn record_set(state: &AppState, repo: &str, tag: &str, digest: &Digest, previous: Option<Digest>, action: &str, actor: &str) -> Result<()> {
    if previous.as_ref() == Some(digest) {
        return Ok(());
    }
    let action = if previous.is_some() && action == "push" { "move" } else { action };
    let prev = previous.map(|d| d.to_string());
    state.auth.db.record_tag_event(repo, tag, action, Some(&digest.to_string()), prev.as_deref(), actor).await?;
    crate::replicate::on_push(state, repo, tag);
    Ok(())
}

/// Delete `tag`, recording where it pointed. Returns that digest, if the tag existed.
pub async fn remove(state: &AppState, repo: &str, tag: &str, action: &str, actor: &str) -> Result<Option<Digest>> {
    let Some(previous) = state.storage.delete_tag(repo, tag).await? else { return Ok(None) };
    record_removal(state, repo, tag, &previous, action, actor).await?;
    Ok(Some(previous))
}

/// Record that `tag` (which pointed at `previous`) is gone, when storage already removed it.
pub async fn record_removal(state: &AppState, repo: &str, tag: &str, previous: &Digest, action: &str, actor: &str) -> Result<()> {
    state.auth.db.set_tag_expiration(repo, tag, None, actor).await?;
    state.auth.db.record_tag_event(repo, tag, action, None, Some(&previous.to_string()), actor).await?;
    crate::replicate::on_delete(state, repo, tag);
    Ok(())
}

/// The Time Machine window for a repository: its organization's setting, else the instance's.
pub async fn time_machine(state: &AppState, repo: &str) -> Result<chrono::Duration> {
    let ns = kontainer_core::names::namespace(repo);
    let secs = match state.auth.db.time_machine_secs(ns).await? {
        Some(s) => s,
        None => state.config.policy.time_machine.as_secs() as i64,
    };
    Ok(chrono::Duration::seconds(secs.max(0)))
}

/// The longest window any repository can have, for garbage collection and history pruning.
pub async fn longest_time_machine(db: &crate::database::Db, instance: std::time::Duration) -> Result<chrono::Duration> {
    let org_max = db.longest_org_time_machine().await?;
    Ok(chrono::Duration::seconds(org_max.unwrap_or(0).max(instance.as_secs() as i64)))
}

/// Manifests that deleted or moved tags pointed at within the longest Time Machine window, by
/// repository. Garbage collection keeps them so they can still be restored.
pub async fn restorable(db: &crate::database::Db, window: chrono::Duration) -> Result<std::collections::HashMap<String, Vec<Digest>>> {
    let since = chrono::Utc::now() - window;
    let mut out: std::collections::HashMap<String, Vec<Digest>> = std::collections::HashMap::new();
    for (repo, d) in db.restorable_digests(since).await? {
        if let Ok(d) = d.parse() {
            out.entry(repo).or_default().push(d);
        }
    }
    Ok(out)
}

/// Parse `quay.expires-after` style durations: `30m`, `12h`, `3d`, `2w`.
pub fn parse_expires_after(v: &str) -> Option<chrono::Duration> {
    let v = v.trim();
    let (n, unit) = v.split_at(v.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = n.parse().ok()?;
    let secs = match unit.trim() {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 7 * 86400,
        _ => return None,
    };
    (n > 0).then(|| chrono::Duration::seconds(n * secs))
}

/// Delete tags whose expiration has passed. Returns how many.
pub async fn expire_due(state: &AppState) -> Result<usize> {
    let mut n = 0;
    for e in state.auth.db.due_tag_expirations(chrono::Utc::now()).await? {
        if state.tag_is_immutable(&e.repository, &e.tag) || state.auth.db.repo_state(&e.repository).await?.is_some_and(|s| s.state == "read_only") {
            continue;
        }
        if remove(state, &e.repository, &e.tag, "expire", "system").await?.is_some() {
            n += 1;
            state.reindex(&e.repository).await;
        } else {
            state.auth.db.set_tag_expiration(&e.repository, &e.tag, None, "system").await?;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_after() {
        assert_eq!(parse_expires_after("2w"), Some(chrono::Duration::days(14)));
        assert_eq!(parse_expires_after("12h"), Some(chrono::Duration::hours(12)));
        assert_eq!(parse_expires_after("30m"), Some(chrono::Duration::minutes(30)));
        assert_eq!(parse_expires_after("1y"), None);
        assert_eq!(parse_expires_after("h"), None);
        assert_eq!(parse_expires_after("0d"), None);
    }
}
