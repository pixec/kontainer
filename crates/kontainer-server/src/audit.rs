//! Usage log: who did what, when, to which repository.
//!
//! Each entry is a small JSON object stored under `logs/<unix-micros>-<seq>-<instance>.json`
//! so that lexical listing yields chronological order and any backend works without append
//! support.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

/// Monotonic sequence so entries written in the same microsecond still sort in order.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Random per process: with several instances writing to one store, two entries with the same
/// time and sequence number still get different ids (and neither overwrites the other).
static INSTANCE: LazyLock<String> = LazyLock::new(|| kontainer_core::random_token(4));

/// A new entry id: time, then this process's sequence, then its instance suffix.
fn entry_id(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("{:016}-{:08}-{}", now.timestamp_micros(), SEQ.fetch_add(1, Ordering::Relaxed), *INSTANCE)
}

use crate::auth::Principal;
use kontainer_store::Storage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub actor: String,
    pub is_robot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Organization an org-management event (teams, robots, settings) belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// Which entries to return from [`Audit::list`].
#[derive(Debug, Default)]
pub struct LogFilter<'a> {
    /// Exact repository name.
    pub repository: Option<&'a str>,
    /// Case-insensitive substring of the repository name.
    pub search: Option<&'a str>,
    /// A workspace: repositories under `<namespace>/`, plus that org's own events, or for the
    /// caller's personal namespace their own account events.
    pub namespace: Option<&'a str>,
    /// RFC 3339 bounds (inclusive since, exclusive until).
    pub since: Option<&'a str>,
    pub until: Option<&'a str>,
}

#[derive(Clone)]
pub struct Audit {
    enabled: bool,
    pub log_pulls: bool,
    storage: Storage,
}

impl Audit {
    pub fn new(cfg: &kontainer_core::config::AuditConfig, storage: Storage) -> Self {
        Self { enabled: cfg.is_enabled, log_pulls: cfg.is_log_pulls, storage }
    }

    pub fn record(&self, principal: &Principal, action: &str, repository: Option<&str>, reference: Option<&str>, digest: Option<&str>, detail: Option<String>) {
        self.write(principal, action, repository, reference, digest, detail, None)
    }

    /// An organization-management event, visible to that org's admins.
    pub fn record_org(&self, principal: &Principal, action: &str, org: &str, detail: Option<String>) {
        self.write(principal, action, None, None, None, detail, Some(org))
    }

    #[allow(clippy::too_many_arguments)]
    fn write(&self, principal: &Principal, action: &str, repository: Option<&str>, reference: Option<&str>, digest: Option<&str>, detail: Option<String>, org: Option<&str>) {
        if !self.enabled {
            return;
        }
        let now = chrono::Utc::now();
        let entry = AuditEntry {
            id: entry_id(now),
            timestamp: now.to_rfc3339(),
            action: action.to_string(),
            actor: principal.name().to_string(),
            is_robot: principal.is_robot,
            repository: repository.map(str::to_string),
            reference: reference.map(str::to_string),
            digest: digest.map(str::to_string),
            org: org.map(str::to_string),
            detail,
        };
        let storage = self.storage.clone();
        tokio::spawn(async move {
            if let Err(e) = storage.put_log(&entry.id, serde_json::to_vec(&entry).unwrap_or_default()).await {
                tracing::warn!(error = %e, "writing audit log");
            }
        });
    }

    /// Newest-first entries matching `filter` that are visible to `principal`.
    pub async fn list(&self, principal: &Principal, filter: &LogFilter<'_>, limit: usize) -> anyhow::Result<Vec<AuditEntry>> {
        use kontainer_core::perm::{Action, Global};
        let mut ids = self.storage.list_log_ids().await?;
        ids.sort_unstable_by(|a, b| b.cmp(a));
        let search = filter.search.map(str::to_lowercase).filter(|s| !s.is_empty());
        let all = principal.has_global(Global::LogsAll);
        let mut out = vec![];
        for id in ids {
            if out.len() >= limit {
                break;
            }
            let Some(raw) = self.storage.get_log(&id).await? else { continue };
            let Ok(e) = serde_json::from_slice::<AuditEntry>(&raw) else { continue };
            let at = chrono::DateTime::parse_from_rfc3339(&e.timestamp).ok();
            let bound = |b: Option<&str>| b.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
            if let (Some(at), Some(s)) = (at, bound(filter.since)) {
                if at < s {
                    // Newest first: everything after this is older still.
                    break;
                }
            }
            if let (Some(at), Some(u)) = (at, bound(filter.until)) {
                if at >= u {
                    continue;
                }
            }
            if filter.repository.is_some_and(|r| e.repository.as_deref() != Some(r)) {
                continue;
            }
            if let Some(q) = &search {
                if !e.repository.as_deref().is_some_and(|r| r.to_lowercase().contains(q.as_str())) {
                    continue;
                }
            }
            if let Some(ns) = filter.namespace {
                let in_ns = match (&e.repository, &e.org) {
                    (Some(r), _) => r.strip_prefix(ns).is_some_and(|rest| rest.starts_with('/')),
                    (None, Some(o)) => o == ns,
                    // Account events (logins, tokens) belong to the actor's personal workspace.
                    (None, None) => ns == principal.name() && e.actor == ns,
                };
                if !in_ns {
                    continue;
                }
            }
            let visible = all
                || match (&e.repository, &e.org) {
                    (Some(r), _) => principal.allowed(Action::Logs, r),
                    // Org admins hold `admin` on every repository under the org.
                    (None, Some(o)) => principal.allowed(Action::Admin, &format!("{o}/*")),
                    (None, None) => principal.user_id.is_some() && e.actor == principal.name(),
                };
            if visible {
                out.push(e);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_sort_by_time_and_carry_the_instance() {
        let t = chrono::Utc::now();
        let (a, b) = (super::entry_id(t), super::entry_id(t + chrono::Duration::microseconds(1)));
        assert!(a < b);
        assert!(a.ends_with(&format!("-{}", *super::INSTANCE)));
        assert_eq!(a.split('-').count(), 3);
    }
}
