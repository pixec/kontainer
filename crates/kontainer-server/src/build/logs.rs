//! Following build logs live. Every chunk appended to a build's log, on any instance, is
//! announced on [`BUILD_LOG_CHANNEL`](crate::database::notify::BUILD_LOG_CHANNEL); each
//! instance's listener hands the announcements to its [`BuildLogHub`], which wakes the
//! followers of that build here (the log streams, `api::builds`). A woken follower reads the
//! chunks after the last one it sent, so a lost notification only delays it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::broadcast;

use crate::database::notify::LogNote;

/// Per-build wake-up channels for this instance's log followers. An entry exists while someone
/// follows that build.
#[derive(Default)]
pub struct BuildLogHub {
    channels: Mutex<HashMap<i64, broadcast::Sender<()>>>,
}

/// One follower's wake-ups for one build; leaving drops the build's channel once nobody else
/// follows it.
pub struct LogFollower {
    hub: Arc<BuildLogHub>,
    build: i64,
    rx: Option<broadcast::Receiver<()>>,
}

impl BuildLogHub {
    /// Wake-ups for `build`'s log.
    pub fn follow(self: &Arc<Self>, build: i64) -> LogFollower {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        // Several notes may come in a burst; one wake-up is enough for any number of them.
        let rx = channels.entry(build).or_insert_with(|| broadcast::channel(1).0).subscribe();
        LogFollower { hub: self.clone(), build, rx: Some(rx) }
    }

    /// Builds followed here.
    pub fn followed(&self) -> usize {
        self.channels.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn wake(&self, note: LogNote) {
        let channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        match note {
            LogNote::Chunk { build, .. } => {
                if let Some(tx) = channels.get(&build) {
                    let _ = tx.send(());
                }
            }
            LogNote::Resync => {
                for tx in channels.values() {
                    let _ = tx.send(());
                }
            }
        }
    }
}

impl LogFollower {
    /// Wait for news of the build: a chunk, its end, or possibly missed notifications.
    pub async fn changed(&mut self) {
        match self.rx.as_mut() {
            // Lagged: something happened all the same.
            Some(rx) => match rx.recv().await {
                Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                // The hub dropped the channel (it can't while we hold it): nothing more to wait for.
                Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
            },
            None => std::future::pending().await,
        }
    }
}

impl Drop for LogFollower {
    fn drop(&mut self) {
        let mut channels = self.hub.channels.lock().unwrap_or_else(|e| e.into_inner());
        drop(self.rx.take());
        if channels.get(&self.build).is_some_and(|tx| tx.receiver_count() == 0) {
            channels.remove(&self.build);
        }
    }
}

/// Hand `notes` (this instance's listener) to `hub` until either goes away.
pub fn dispatch(hub: &Arc<BuildLogHub>, mut notes: broadcast::Receiver<LogNote>) {
    let hub: Weak<BuildLogHub> = Arc::downgrade(hub);
    tokio::spawn(async move {
        loop {
            let note = match notes.recv().await {
                Ok(n) => n,
                Err(broadcast::error::RecvError::Lagged(_)) => LogNote::Resync,
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let Some(hub) = hub.upgrade() else { return };
            hub.wake(note);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn followers_are_woken_and_cleaned_up() {
        let hub = Arc::new(BuildLogHub::default());
        let (mut a, mut b, mut other) = (hub.follow(1), hub.follow(1), hub.follow(2));
        assert_eq!(hub.followed(), 2);
        hub.wake(LogNote::Chunk { build: 1, seq: 4 });
        tokio::time::timeout(Duration::from_secs(1), a.changed()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), b.changed()).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), other.changed()).await.is_err(), "another build's chunk");
        hub.wake(LogNote::Resync);
        tokio::time::timeout(Duration::from_secs(1), other.changed()).await.unwrap();
        drop(a);
        assert_eq!(hub.followed(), 2, "b still follows build 1");
        drop(b);
        drop(other);
        assert_eq!(hub.followed(), 0);
    }
}
