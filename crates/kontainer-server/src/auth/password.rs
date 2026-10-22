//! Password hashing: Argon2id for everything we create; bcrypt hashes (htpasswd-style, older
//! configs) are still verified.

use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

/// Why `password` is not acceptable for a new or changed password, if it isn't.
pub fn check_strength(password: &str) -> Result<(), &'static str> {
    kontainer_core::config::check_password_strength(password)
}

pub fn hash(password: &str) -> Result<String> {
    let h: PasswordHash = Argon2::default().hash_password(password.as_bytes()).map_err(|e| anyhow!("hashing password: {e}"))?;
    Ok(h.to_string())
}

pub fn verify(password: &str, hash: &str) -> bool {
    if hash.starts_with("$argon2") {
        match PasswordHash::new(hash) {
            Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
            Err(_) => false,
        }
    } else if hash.starts_with("$2") {
        bcrypt::verify(password, hash).unwrap_or(false)
    } else {
        false
    }
}

/// Argon2 is deliberately expensive (memory and CPU): at most one hash or verification per
/// CPU runs at a time, so a burst of sign-ins queues instead of exhausting the server.
fn hashing_slots() -> &'static tokio::sync::Semaphore {
    use std::sync::OnceLock;
    static SLOTS: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(std::thread::available_parallelism().map_or(4, |n| n.get())))
}

/// [`hash`] on the blocking thread pool, within the hashing limit. For async code.
pub async fn hash_async(password: &str) -> Result<String> {
    let _slot = hashing_slots().acquire().await?;
    let password = password.to_string();
    tokio::task::spawn_blocking(move || hash(&password)).await?
}

/// [`verify`] on the blocking thread pool, within the hashing limit. `hash: None` verifies
/// against [`dummy_hash`] (and fails), so unknown accounts take as long as known ones.
pub async fn verify_async(password: &str, hash: Option<String>) -> Result<bool> {
    let _slot = hashing_slots().acquire().await?;
    let password = password.to_string();
    Ok(tokio::task::spawn_blocking(move || match hash {
        Some(h) => verify(&password, &h),
        None => {
            verify(&password, dummy_hash());
            false
        }
    })
    .await?)
}

/// A valid hash of an unguessable value, verified against on unknown usernames so timing does
/// not reveal whether an account exists.
pub fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash(&kontainer_core::random_token(16)).expect("argon2"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip_and_bcrypt_compat() {
        let h = super::hash("hunter2").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(super::verify("hunter2", &h));
        assert!(!super::verify("hunter3", &h));
        let b = bcrypt::hash("legacy", 4).unwrap();
        assert!(super::verify("legacy", &b));
        assert!(!super::verify("x", "garbage"));
    }

    #[tokio::test]
    async fn async_helpers() {
        let h = super::hash_async("hunter2").await.unwrap();
        assert!(super::verify_async("hunter2", Some(h.clone())).await.unwrap());
        assert!(!super::verify_async("hunter3", Some(h)).await.unwrap());
        assert!(!super::verify_async("hunter2", None).await.unwrap());
    }
}
