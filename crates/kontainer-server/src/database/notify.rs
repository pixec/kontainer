//! Cross-instance cache invalidation with PostgreSQL `LISTEN`/`NOTIFY`.
//!
//! Several registry instances share one database, but each keeps a few things in memory: role
//! definitions, public repositories, pull-through cache namespaces and the set of repositories
//! with content (see [`crate::auth::Authenticator`]), and its own search index. Every write that
//! changes one of them ends with [`Db::notify`], a `pg_notify` on [`CHANNEL`] naming a
//! [`Topic`]. Each process holds one [`Listener`]: a dedicated connection `LISTEN`ing on that
//! channel, which hands the topics to its subscribers (the authenticator's caches, the search
//! index) over a broadcast channel.
//!
//! Build logs use the same connection on a second channel, [`BUILD_LOG_CHANNEL`]: every chunk
//! appended to a build's log (and the build's end) is announced as `<build id>:<seq>`, and the
//! listener hands these to [`Listener::subscribe_build_logs`] as [`LogNote`]s, kept apart from the
//! cache topics so a busy build never makes the caches lag.
//!
//! Notifications are transient: those sent while a listener is disconnected are lost. So after
//! reconnecting (with backoff, logged at warn) the listener sends [`Topic::Resync`], telling
//! subscribers to reload everything; and the caches are reloaded on a timer anyway.

use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;

use super::Db;

/// The channel every instance listens on.
pub const CHANNEL: &str = "kontainer_cache";

/// The channel announcing build log chunks, as `<build id>:<seq>`.
pub const BUILD_LOG_CHANNEL: &str = "kontainer_build_log";

/// Backoff between attempts to reconnect a lost listener.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// What changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Topic {
    /// Role definitions.
    Roles,
    /// Repository visibility in general.
    PublicRepos,
    /// Pull-through cache namespaces.
    Proxies,
    /// One repository was created, deleted, or its catalogue entry (visibility) changed.
    Repo(String),
    /// Many repositories at once (a namespace rename).
    Repos,
    /// Notifications may have been missed (the listener reconnected): reload everything. Never
    /// sent through the database.
    Resync,
}

impl Topic {
    pub fn payload(&self) -> String {
        match self {
            Self::Roles => "roles".into(),
            Self::PublicRepos => "public_repos".into(),
            Self::Proxies => "proxies".into(),
            Self::Repo(name) => format!("repo:{name}"),
            Self::Repos => "repos".into(),
            Self::Resync => "resync".into(),
        }
    }

    /// The topic named by a notification's payload; unknown payloads (from a newer version
    /// during a rolling upgrade) mean "reload everything".
    pub fn parse(payload: &str) -> Self {
        match payload {
            "roles" => Self::Roles,
            "public_repos" => Self::PublicRepos,
            "proxies" => Self::Proxies,
            "repos" => Self::Repos,
            other => match other.strip_prefix("repo:") {
                Some(name) if !name.is_empty() => Self::Repo(name.to_string()),
                _ => Self::Resync,
            },
        }
    }
}

/// A build log changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogNote {
    /// Build `build` has chunks up to `seq`, or ended.
    Chunk { build: i64, seq: i64 },
    /// Notifications may have been missed: every follower should look again.
    Resync,
}

impl LogNote {
    pub fn parse(payload: &str) -> Self {
        payload.split_once(':').and_then(|(b, s)| Some(Self::Chunk { build: b.parse().ok()?, seq: s.parse().ok()? })).unwrap_or(Self::Resync)
    }
}

impl Db {
    /// Tell every instance (this one included) that `topic` changed. Best effort: a failure is
    /// logged, and the periodic reload catches up.
    pub async fn notify(&self, topic: &Topic) {
        if let Err(e) = sqlx::query("SELECT pg_notify($1, $2)").bind(CHANNEL).bind(topic.payload()).execute(self.pool()).await {
            tracing::warn!(topic = %topic.payload(), error = %e, "notifying other instances of a change");
        }
    }
}

/// This process's subscription to [`CHANNEL`]. Dropping it stops the listener and closes its
/// connection.
pub struct Listener {
    tx: broadcast::Sender<Topic>,
    logs: broadcast::Sender<LogNote>,
    task: tokio::task::JoinHandle<()>,
}

impl Listener {
    /// Connect to the database at `url` and start listening. Returns once `LISTEN` is in place,
    /// so a cache loaded afterwards misses no change.
    pub async fn start(url: &str) -> Result<Self> {
        let first = connect(url).await.context("listening for changes from other instances")?;
        let (tx, _) = broadcast::channel(256);
        let (logs, _) = broadcast::channel(1024);
        let task = tokio::spawn(run(url.to_string(), first, tx.clone(), logs.clone()));
        Ok(Self { tx, logs, task })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Topic> {
        self.tx.subscribe()
    }

    /// Build log notifications.
    pub fn subscribe_build_logs(&self) -> broadcast::Receiver<LogNote> {
        self.logs.subscribe()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn connect(url: &str) -> Result<PgListener, sqlx::Error> {
    let mut l = PgListener::connect(url).await?;
    l.listen_all([CHANNEL, BUILD_LOG_CHANNEL]).await?;
    Ok(l)
}

async fn run(url: String, first: PgListener, tx: broadcast::Sender<Topic>, logs: broadcast::Sender<LogNote>) {
    let mut listener = Some(first);
    let mut backoff = BACKOFF_MIN;
    loop {
        let Some(l) = listener.as_mut() else {
            match connect(&url).await {
                Ok(l) => {
                    tracing::warn!("listening for changes from other instances again; reloading caches");
                    listener = Some(l);
                    backoff = BACKOFF_MIN;
                    let _ = tx.send(Topic::Resync);
                    let _ = logs.send(LogNote::Resync);
                }
                Err(e) => {
                    tracing::warn!(error = %e, retry_in = ?backoff, "reconnecting the change listener");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
            }
            continue;
        };
        match l.try_recv().await {
            Ok(Some(n)) => {
                backoff = BACKOFF_MIN;
                // No subscribers is fine: nothing to invalidate, nobody following.
                if n.channel() == BUILD_LOG_CHANNEL {
                    let _ = logs.send(LogNote::parse(n.payload()));
                } else {
                    let _ = tx.send(Topic::parse(n.payload()));
                }
            }
            // The connection dropped and was re-established: changes in between are lost.
            Ok(None) => {
                tracing::warn!("the change listener's connection dropped and was re-established; reloading caches");
                let _ = tx.send(Topic::Resync);
                let _ = logs.send(LogNote::Resync);
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_in = ?backoff, "the change listener lost its connection");
                listener = None;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::test_support::fresh_database_url;

    #[test]
    fn topics_round_trip() {
        for t in [Topic::Roles, Topic::PublicRepos, Topic::Proxies, Topic::Repo("acme/app".into()), Topic::Repos] {
            assert_eq!(Topic::parse(&t.payload()), t);
        }
        assert_eq!(Topic::parse("something-new"), Topic::Resync);
        assert_eq!(Topic::parse("repo:"), Topic::Resync);
        assert_eq!(LogNote::parse("12:3"), LogNote::Chunk { build: 12, seq: 3 });
        assert_eq!(LogNote::parse("12"), LogNote::Resync);
    }

    #[tokio::test]
    async fn a_notification_reaches_another_instance() {
        let url = fresh_database_url();
        let (a, b) = (Db::open(&url, 2).await.unwrap(), Db::open(&url, 2).await.unwrap());
        let listener = Listener::start(&url).await.unwrap();
        let mut rx = listener.subscribe();
        drop(b);
        a.notify(&Topic::Repo("acme/app".into())).await;
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("delivered in time").unwrap();
        assert_eq!(got, Topic::Repo("acme/app".into()));
    }
}
