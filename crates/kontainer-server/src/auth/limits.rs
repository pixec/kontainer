//! Brute-force protection for password and one-time-code checks, and a short-lived cache of
//! successful password sign-ins, so clients that send Basic credentials on every request
//! (`docker pull` in `basic` mode) don't cost an Argon2 verification each time.
//!
//! The failure counters are in PostgreSQL (`login_failures`), so a lockout holds on every
//! instance behind the load balancer and attempts spread over them add up. The sign-in cache
//! is per process and bounded in size: a miss only costs a password verification.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::database::Db;

/// Failed attempts allowed per account, and per client address, within [`WINDOW`].
const MAX_FAILURES_PER_USER: u32 = 10;
const MAX_FAILURES_PER_IP: u32 = 50;
pub(crate) const WINDOW: Duration = Duration::from_secs(300);

const BASIC_TTL: Duration = Duration::from_secs(60);
const MAX_BASIC_ENTRIES: usize = 10_000;

/// Counts failed sign-in attempts per account and per client address; once either reaches its
/// limit, attempts are refused until the window that started with the first failure ends.
pub struct LoginLimiter {
    db: Db,
}

fn user_key(username: &str) -> String {
    format!("u:{}", username.to_lowercase())
}

fn ip_key(ip: &str) -> String {
    format!("ip:{ip}")
}

impl LoginLimiter {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    #[cfg(test)]
    pub async fn check(&self, username: &str, ip: Option<&str>) -> Result<Result<(), Duration>> {
        self.check_any(Some(username), ip).await
    }

    /// `Err(retry_after)` while `username` or `ip` is locked out. Without a username (a passkey
    /// sign-in that names no account yet) only the address counts.
    pub async fn check_any(&self, username: Option<&str>, ip: Option<&str>) -> Result<Result<(), Duration>> {
        let keys: Vec<String> = username.map(user_key).into_iter().chain(ip.map(ip_key)).collect();
        // In the database's clock, like the lockouts themselves.
        let wait: Option<f64> = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM max(locked_until) - now())::float8 FROM login_failures WHERE key = ANY($1) AND locked_until > now()")
            .bind(&keys)
            .fetch_one(self.db.pool())
            .await?;
        Ok(match wait {
            Some(secs) => Err(Duration::from_secs_f64(secs.max(0.0)).min(WINDOW)),
            None => Ok(()),
        })
    }

    pub async fn fail(&self, username: &str, ip: Option<&str>) -> Result<()> {
        self.fail_any(Some(username), ip).await
    }

    /// [`Self::fail`] when the account may not be known: only the address counts then.
    pub async fn fail_any(&self, username: Option<&str>, ip: Option<&str>) -> Result<()> {
        let keys = username.map(|u| (user_key(u), MAX_FAILURES_PER_USER)).into_iter().chain(ip.map(|ip| (ip_key(ip), MAX_FAILURES_PER_IP)));
        for (key, limit) in keys {
            // One statement, so attempts on several instances at once all count. A window that
            // is over starts again with this failure; reaching the limit locks the key out until
            // the window ends.
            sqlx::query(
                "INSERT INTO login_failures (key, failures, window_started_at, locked_until)
                 VALUES ($1, 1, now(), CASE WHEN 1 >= $2 THEN now() + make_interval(secs => $3) END)
                 ON CONFLICT (key) DO UPDATE SET
                   failures = CASE WHEN login_failures.window_started_at + make_interval(secs => $3) <= now() THEN 1 ELSE login_failures.failures + 1 END,
                   window_started_at = CASE WHEN login_failures.window_started_at + make_interval(secs => $3) <= now() THEN now() ELSE login_failures.window_started_at END,
                   locked_until = CASE
                     WHEN login_failures.window_started_at + make_interval(secs => $3) <= now() THEN CASE WHEN 1 >= $2 THEN now() + make_interval(secs => $3) END
                     WHEN login_failures.failures + 1 >= $2 THEN login_failures.window_started_at + make_interval(secs => $3)
                   END
                 RETURNING failures",
            )
            .bind(&key)
            .bind(i64::from(limit))
            .bind(WINDOW.as_secs_f64())
            .execute(self.db.pool())
            .await?;
        }
        Ok(())
    }

    /// A correct password or code clears the account's failures (not the address's).
    pub async fn succeed(&self, username: &str) -> Result<()> {
        sqlx::query("DELETE FROM login_failures WHERE key = $1").bind(user_key(username)).execute(self.db.pool()).await?;
        Ok(())
    }
}

/// Recently verified `(username, password)` pairs, stored as a salted hash, with the account and
/// password hash they matched. A hit counts only while the account still has that password hash.
pub struct BasicCache {
    salt: String,
    entries: Mutex<HashMap<[u8; 32], (i64, String, Instant)>>,
}

impl Default for BasicCache {
    fn default() -> Self {
        Self { salt: kontainer_core::random_token(32), entries: Mutex::default() }
    }
}

impl BasicCache {
    fn key(&self, username: &str, secret: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.salt.as_bytes());
        h.update((username.len() as u64).to_le_bytes());
        h.update(username.as_bytes());
        h.update(secret.as_bytes());
        h.finalize().into()
    }

    /// The account id and password hash `username`/`secret` were verified against, if that
    /// happened within the last minute.
    pub fn get(&self, username: &str, secret: &str) -> Option<(i64, String)> {
        let key = self.key(username, secret);
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&key).filter(|(_, _, at)| at.elapsed() < BASIC_TTL).map(|(id, hash, _)| (*id, hash.clone()))
    }

    pub fn insert(&self, username: &str, secret: &str, user_id: i64, password_hash: &str) {
        let key = self.key(username, secret);
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_BASIC_ENTRIES {
            map.retain(|_, (_, _, at)| at.elapsed() < BASIC_TTL);
            if map.len() >= MAX_BASIC_ENTRIES {
                map.clear();
            }
        }
        map.insert(key, (user_id, password_hash.to_string(), Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::test_support::{fresh_database_url, fresh_db};

    #[tokio::test]
    async fn locks_out_an_account_after_repeated_failures() {
        let l = LoginLimiter::new(fresh_db().await);
        for _ in 0..MAX_FAILURES_PER_USER {
            assert!(l.check("alice", Some("10.0.0.1")).await.unwrap().is_ok());
            l.fail("alice", Some("10.0.0.1")).await.unwrap();
        }
        let wait = l.check("Alice", Some("10.0.0.2")).await.unwrap().unwrap_err();
        assert!(wait > Duration::ZERO && wait <= WINDOW);
        assert!(l.check("bob", Some("10.0.0.2")).await.unwrap().is_ok(), "other accounts are unaffected");
        l.succeed("alice").await.unwrap();
        assert!(l.check("alice", None).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn locks_out_an_address_trying_many_accounts() {
        let l = LoginLimiter::new(fresh_db().await);
        for i in 0..MAX_FAILURES_PER_IP {
            l.fail(&format!("user{i}"), Some("10.0.0.9")).await.unwrap();
        }
        assert!(l.check("someone-else", Some("10.0.0.9")).await.unwrap().is_err());
        assert!(l.check("someone-else", Some("10.0.0.10")).await.unwrap().is_ok());
        assert!(l.check("someone-else", None).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn failures_on_two_instances_add_up() {
        let url = fresh_database_url();
        let a = LoginLimiter::new(Db::open(&url, 4).await.unwrap());
        let b = LoginLimiter::new(Db::open(&url, 4).await.unwrap());
        // Attempts alternate between the instances behind a load balancer, some at once.
        for _ in 0..MAX_FAILURES_PER_USER / 2 - 1 {
            a.fail("carol", Some("10.0.0.1")).await.unwrap();
            b.fail("carol", Some("10.0.0.2")).await.unwrap();
        }
        let (x, y) = tokio::join!(a.fail("carol", Some("10.0.0.1")), b.fail("carol", Some("10.0.0.2")));
        x.unwrap();
        y.unwrap();
        assert!(a.check("carol", None).await.unwrap().is_err(), "locked out on the instance that saw half the attempts");
        assert!(b.check("carol", None).await.unwrap().is_err(), "and on the other");
        // A correct password on one instance clears the account everywhere.
        b.succeed("carol").await.unwrap();
        assert!(a.check("carol", None).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn a_window_that_is_over_starts_again() {
        let db = fresh_db().await;
        let l = LoginLimiter::new(db.clone());
        for _ in 0..MAX_FAILURES_PER_USER {
            l.fail("dave", None).await.unwrap();
        }
        assert!(l.check("dave", None).await.unwrap().is_err());
        // Six minutes later: the lockout is over, and the next failure counts from one.
        sqlx::query("UPDATE login_failures SET window_started_at = window_started_at - interval '6 minutes', locked_until = locked_until - interval '6 minutes'").execute(db.pool()).await.unwrap();
        assert!(l.check("dave", None).await.unwrap().is_ok());
        l.fail("dave", None).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT failures FROM login_failures WHERE key = 'u:dave'").fetch_one(db.pool()).await.unwrap();
        assert_eq!(n, 1);
        assert!(l.check("dave", None).await.unwrap().is_ok());
        // The periodic purge drops rows whose window is over.
        sqlx::query("UPDATE login_failures SET window_started_at = window_started_at - interval '6 minutes'").execute(db.pool()).await.unwrap();
        db.purge_expired().await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM login_failures").fetch_one(db.pool()).await.unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn basic_cache_matches_exact_credentials() {
        let c = BasicCache::default();
        c.insert("alice", "pw", 7, "$argon2id$x");
        assert_eq!(c.get("alice", "pw"), Some((7, "$argon2id$x".to_string())));
        assert_eq!(c.get("alice", "pw2"), None);
        assert_eq!(c.get("alic", "epw"), None, "username and secret are not just concatenated");
    }
}
