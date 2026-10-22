//! Time-based one-time passwords (RFC 6238) and recovery codes.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use totp_rs::{Algorithm, Builder, Secret, Totp};

use kontainer_core::random_token;
use crate::database::{sha256_hex, Db};

/// How long a secret from [`enroll`] waits for its first code before the setup is dropped.
pub const SETUP_TTL: chrono::Duration = chrono::Duration::minutes(15);

pub struct Enrollment {
    pub secret: String,
    pub otpauth_url: String,
    pub qr_svg: String,
}

fn totp(secret_b32: &str, issuer: &str, account: &str) -> Result<Totp> {
    let secret = Secret::try_from_base32(secret_b32).map_err(|e| anyhow::anyhow!("bad totp secret: {e:?}"))?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(issuer))
        .with_account_name(account)
        .build()
        .map_err(|e| anyhow::anyhow!("building totp: {e:?}"))
}

pub fn enroll(issuer: &str, account: &str) -> Result<Enrollment> {
    let secret = Secret::generate().to_base32();
    let t = totp(&secret, issuer, account)?;
    let otpauth_url = t.to_url().map_err(|e| anyhow::anyhow!("totp url: {e:?}"))?;
    let qr = qrcode::QrCode::new(otpauth_url.as_bytes()).context("building qr code")?;
    let qr_svg = qr.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).quiet_zone(true).build();
    Ok(Enrollment { secret, otpauth_url, qr_svg })
}

/// The time step `code` belongs to, if it is valid now (one step of clock skew either way).
/// Callers must accept each step only once: see [`verify_once`].
pub fn verify(secret_b32: &str, issuer: &str, account: &str, code: &str) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    totp(secret_b32, issuer, account).ok()?.check_current(&code)
}

/// [`verify`], then consume the code's time step for `user_id`: a code is accepted once, and
/// never after a code from a later step.
pub async fn verify_once(db: &Db, user_id: i64, secret_b32: &str, issuer: &str, account: &str, code: &str) -> Result<bool> {
    match verify(secret_b32, issuer, account, code) {
        Some(step) => db.claim_totp_step(user_id, step).await,
        None => Ok(false),
    }
}

/// Key for hashing recovery codes, derived from the instance secret (`auth.secret` or the
/// generated one), so a copy of the database alone does not allow brute-forcing them.
/// Changing the secret invalidates existing recovery codes.
#[derive(Clone)]
pub struct RecoveryKey([u8; 32]);

impl RecoveryKey {
    pub fn derive(instance_secret: &[u8]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(instance_secret).expect("HMAC accepts keys of any length");
        mac.update(b"kontainer mfa recovery codes v1");
        Self(mac.finalize().into_bytes().into())
    }

    /// The stored form of `code`; dashes, spaces and case do not matter.
    pub fn hash(&self, code: &str) -> String {
        let normalized: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts keys of any length");
        mac.update(normalized.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Hashes `code` may be stored under: the current form, and for `xxxxx-xxxxx` codes issued
    /// before keyed hashing, the old unkeyed one.
    pub fn candidates(&self, code: &str) -> Vec<String> {
        let mut out = vec![self.hash(code)];
        let legacy = code.trim().to_ascii_lowercase();
        if legacy.len() == 11 && legacy.as_bytes()[5] == b'-' && legacy.bytes().enumerate().all(|(i, b)| i == 5 || b.is_ascii_hexdigit()) {
            out.push(sha256_hex(&legacy));
        }
        out
    }
}

/// Eight single-use codes of 80 random bits, as `xxxxx-xxxxx-xxxxx-xxxxx`. Returns (plain, hashed).
pub fn recovery_codes(key: &RecoveryKey) -> (Vec<String>, Vec<String>) {
    let plain: Vec<String> = (0..8)
        .map(|_| {
            let t = random_token(10);
            format!("{}-{}-{}-{}", &t[..5], &t[5..10], &t[10..15], &t[15..])
        })
        .collect();
    let hashed = plain.iter().map(|c| key.hash(c)).collect();
    (plain, hashed)
}

/// Consume one of `user_id`'s recovery codes. Returns true if `code` was valid and unused.
pub async fn use_recovery_code(db: &Db, key: &RecoveryKey, user_id: i64, code: &str) -> Result<bool> {
    for hash in key.candidates(code) {
        if db.use_recovery_code(user_id, &hash).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> String {
        Secret::from(*b"12345678901234567890").to_base32()
    }

    #[test]
    fn verify_returns_the_step() {
        let s = secret();
        let t = totp(&s, "kontainer", "alice").unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let code = t.generate(now).to_string();
        assert_eq!(verify(&s, "kontainer", "alice", &code), Some(now / 30));
        assert_eq!(verify(&s, "kontainer", "alice", "000000x"), None);
        assert_eq!(verify("not base32!", "kontainer", "alice", &code), None);
    }

    #[tokio::test]
    async fn codes_cannot_be_replayed() {
        let db = crate::database::test_support::fresh_db().await;
        let s = secret();
        let user = db.create_user("alice", None, None, None, false, None, false).await.unwrap();
        let t = totp(&s, "kontainer", "alice").unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let code = t.generate(now).to_string();
        assert!(verify_once(&db, user.id, &s, "kontainer", "alice", &code).await.unwrap());
        assert!(!verify_once(&db, user.id, &s, "kontainer", "alice", &code).await.unwrap(), "same code twice");
        // A code from the previous step (still inside the skew window) is older than the one used.
        let earlier = t.generate(now - 30).to_string();
        assert!(!verify_once(&db, user.id, &s, "kontainer", "alice", &earlier).await.unwrap(), "older step");
        assert!(!db.claim_totp_step(user.id, now / 30).await.unwrap());
        assert!(db.claim_totp_step(user.id, now / 30 + 1).await.unwrap());
    }

    #[test]
    fn recovery_codes_are_long_and_keyed() {
        let key = RecoveryKey::derive(b"instance secret");
        let (plain, hashed) = recovery_codes(&key);
        assert_eq!(plain.len(), 8);
        assert_eq!(plain[0].len(), 23);
        assert_eq!(plain[0].chars().filter(char::is_ascii_hexdigit).count(), 20, "80 bits");
        assert_eq!(key.hash(&plain[0]), hashed[0]);
        assert_eq!(key.hash(&format!("  {}  ", plain[0].to_uppercase().replace('-', ""))), hashed[0]);
        assert_ne!(RecoveryKey::derive(b"another secret").hash(&plain[0]), hashed[0]);
        assert_ne!(hashed[0], sha256_hex(&plain[0]));
        assert_eq!(key.candidates(&plain[0]).len(), 1);
        assert_eq!(key.candidates("abcde-12345"), vec![key.hash("abcde-12345"), sha256_hex("abcde-12345")]);
    }

    #[tokio::test]
    async fn recovery_codes_are_single_use() {
        let db = crate::database::test_support::fresh_db().await;
        let user = db.create_user("bob", None, None, None, false, None, false).await.unwrap();
        let key = RecoveryKey::derive(b"instance secret");
        let (plain, hashed) = recovery_codes(&key);
        let mut stored = hashed.clone();
        stored.push(sha256_hex("abcde-12345"));
        db.replace_recovery_codes(user.id, &stored).await.unwrap();
        assert!(use_recovery_code(&db, &key, user.id, &plain[3]).await.unwrap());
        assert!(!use_recovery_code(&db, &key, user.id, &plain[3]).await.unwrap());
        assert!(use_recovery_code(&db, &key, user.id, "ABCDE-12345").await.unwrap(), "legacy code still works once");
        assert!(!use_recovery_code(&db, &key, user.id, "abcde-12345").await.unwrap());
    }
}
