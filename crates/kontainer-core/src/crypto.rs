//! Secrets at rest: AES-256-GCM envelopes for the credentials the registry keeps in its
//! database (upstream passwords, webhook secrets, Git tokens, client secrets, ...).
//!
//! A stored value is one of:
//!
//! - `enc:v1:<key_id>:<base64(nonce || ciphertext)>`: sealed with the data key whose id is
//!   `key_id` (the first 8 hex characters of the SHA-256 of the key), a random 96-bit nonce;
//! - `enc:v0:<base64(plaintext)>`: not encrypted (no key configured), written only for a value
//!   that itself starts with `enc:`, so it can't be mistaken for an envelope;
//! - anything else: plaintext (written before encryption existed, or with no key configured).
//!
//! A [`Keyring`] holds the current key, which seals, and previous keys, which only open, so a
//! key can be rotated without downtime (see `kontainer rotate-encryption-key`).

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::config::AuthConfig;

/// What every envelope starts with.
pub const PREFIX: &str = "enc:";
const V1: &str = "enc:v1:";
const V0: &str = "enc:v0:";
const NONCE_LEN: usize = 12;

/// HKDF `info` for a key from `auth.encryption_key` (or `auth.previous_encryption_keys`).
const INFO_ENCRYPTION_KEY: &[u8] = b"kontainer secrets at rest v1: auth.encryption_key";
/// HKDF `info` for the key derived from `auth.secret` when no encryption key is set. Distinct
/// from the above, so the derived key is never the token-signing secret itself.
const INFO_AUTH_SECRET: &[u8] = b"kontainer secrets at rest v1: derived from auth.secret";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Why a stored value could not be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("encrypted with key {key_id}, but no encryption key is configured: set auth.encryption_key (KONTAINER_ENCRYPTION_KEY) or auth.secret to the key it was encrypted with")]
    NoKey { key_id: String },
    #[error("encrypted with key {key_id}, which is neither the current key ({current}) nor one of auth.previous_encryption_keys{known}: configure the key it was encrypted with")]
    UnknownKey { key_id: String, current: String, known: String },
    #[error("decrypting with key {key_id} failed: the value was altered, or another key has the same id")]
    Decrypt { key_id: String },
    #[error("not a valid envelope ({0})")]
    Malformed(&'static str),
}

/// One 256-bit data key and its id.
#[derive(Clone)]
pub struct DataKey {
    id: String,
    cipher: Aes256Gcm,
}

impl DataKey {
    /// The key for `auth.encryption_key` (or one of `auth.previous_encryption_keys`): HKDF-SHA256
    /// of the configured string, so any 32+ byte string (hex, base64, a passphrase) works.
    pub fn from_material(material: &str) -> Self {
        Self::derive(material.as_bytes(), INFO_ENCRYPTION_KEY)
    }

    /// The key derived from `auth.secret`, for deployments that set only that.
    pub fn from_auth_secret(secret: &str) -> Self {
        Self::derive(secret.as_bytes(), INFO_AUTH_SECRET)
    }

    fn derive(ikm: &[u8], info: &[u8]) -> Self {
        let mut key = [0u8; 32];
        hkdf::Hkdf::<Sha256>::new(None, ikm).expand(info, &mut key).expect("32 bytes is a valid HKDF-SHA256 output length");
        let id = hex::encode(Sha256::digest(key))[..8].to_string();
        let cipher = Aes256Gcm::new_from_slice(&key).expect("a 32-byte key");
        key.fill(0);
        Self { id, cipher }
    }

    /// The first 8 hex characters of the key's SHA-256: what envelopes name it by.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DataKey({})", self.id)
    }
}

/// A stored value, classified without decrypting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope<'a> {
    /// Plaintext: no `enc:` prefix.
    Plain(&'a str),
    /// `enc:v0:<base64>`: plaintext that starts with `enc:`.
    Encoded(&'a str),
    /// `enc:v1:<key_id>:<base64>`.
    Sealed { key_id: &'a str, payload: &'a str },
}

impl<'a> Envelope<'a> {
    pub fn parse(stored: &'a str) -> Result<Self, CryptoError> {
        if let Some(rest) = stored.strip_prefix(V1) {
            let (key_id, payload) = rest.split_once(':').ok_or(CryptoError::Malformed("no key id"))?;
            if key_id.is_empty() || !key_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CryptoError::Malformed("bad key id"));
            }
            Ok(Self::Sealed { key_id, payload })
        } else if let Some(rest) = stored.strip_prefix(V0) {
            Ok(Self::Encoded(rest))
        } else if stored.starts_with(PREFIX) {
            Err(CryptoError::Malformed("unknown version"))
        } else {
            Ok(Self::Plain(stored))
        }
    }

    /// The id of the key that sealed it, if it is sealed.
    pub fn key_id(&self) -> Option<&'a str> {
        match self {
            Self::Sealed { key_id, .. } => Some(key_id),
            _ => None,
        }
    }
}

/// Which key a stored value needs, relative to a [`Keyring`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyUse {
    Plaintext,
    Current,
    Previous(String),
    Unknown(String),
}

/// The current data key (sealing and opening) and previous ones (opening only). Without a
/// current key, values are stored as plaintext.
#[derive(Clone, Default)]
pub struct Keyring {
    current: Option<DataKey>,
    previous: Vec<DataKey>,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring").field("current", &self.current_id()).field("previous", &self.previous_ids()).finish()
    }
}

impl Keyring {
    /// `previous` keys with the current key's id (or an id seen before) are dropped.
    pub fn new(current: Option<DataKey>, previous: impl IntoIterator<Item = DataKey>) -> Self {
        let mut seen: Vec<String> = current.iter().map(|k| k.id.clone()).collect();
        let previous = previous
            .into_iter()
            .filter(|k| {
                let new = !seen.contains(&k.id);
                seen.push(k.id.clone());
                new
            })
            .collect();
        Self { current, previous }
    }

    /// No keys: values are stored as plaintext.
    pub fn unencrypted() -> Self {
        Self::default()
    }

    /// From the configuration: the current key is `auth.encryption_key`, else derived from
    /// `auth.secret`, else none (plaintext). Previous keys are `auth.previous_encryption_keys`
    /// and, when `auth.encryption_key` is set, the key derived from `auth.secret` (so moving from
    /// the derived key to an explicit one only takes a rotation).
    pub fn from_config(auth: &AuthConfig) -> Self {
        let secret = auth.secret.as_ref().filter(|s| !s.is_empty()).map(|s| DataKey::from_auth_secret(s.expose()));
        let explicit = auth.encryption_key.as_ref().filter(|s| !s.is_empty()).map(|s| DataKey::from_material(s.expose()));
        let mut previous: Vec<DataKey> = auth.previous_encryption_keys.iter().filter(|s| !s.is_empty()).map(|s| DataKey::from_material(s.expose())).collect();
        let current = match explicit {
            Some(k) => {
                previous.extend(secret);
                Some(k)
            }
            None => secret,
        };
        Self::new(current, previous)
    }

    /// Whether new values are encrypted.
    pub fn is_encrypting(&self) -> bool {
        self.current.is_some()
    }

    pub fn current_id(&self) -> Option<&str> {
        self.current.as_ref().map(DataKey::id)
    }

    pub fn previous_ids(&self) -> Vec<&str> {
        self.previous.iter().map(DataKey::id).collect()
    }

    fn key(&self, id: &str) -> Option<&DataKey> {
        self.current.iter().chain(&self.previous).find(|k| k.id == id)
    }

    /// `plain`, ready to store: sealed under the current key, or plaintext without one.
    pub fn seal(&self, plain: &str) -> String {
        match &self.current {
            Some(key) => {
                let mut nonce = [0u8; NONCE_LEN];
                rand::fill(&mut nonce[..]);
                let ct = key.cipher.encrypt(Nonce::from_slice(&nonce), plain.as_bytes()).expect("AES-GCM encrypts any value the database can hold");
                let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
                blob.extend_from_slice(&nonce);
                blob.extend_from_slice(&ct);
                format!("{V1}{}:{}", key.id, B64.encode(blob))
            }
            None if plain.starts_with(PREFIX) => format!("{V0}{}", B64.encode(plain)),
            None => plain.to_string(),
        }
    }

    /// The plaintext of a stored value: plaintext passes through; envelopes open with the
    /// current key or a previous one.
    pub fn open(&self, stored: &str) -> Result<String, CryptoError> {
        match Envelope::parse(stored)? {
            Envelope::Plain(p) => Ok(p.to_string()),
            Envelope::Encoded(b) => String::from_utf8(B64.decode(b).map_err(|_| CryptoError::Malformed("bad base64"))?).map_err(|_| CryptoError::Malformed("not UTF-8")),
            Envelope::Sealed { key_id, payload } => {
                let key = self.key(key_id).ok_or_else(|| self.missing(key_id))?;
                let blob = B64.decode(payload).map_err(|_| CryptoError::Malformed("bad base64"))?;
                if blob.len() < NONCE_LEN + 16 {
                    return Err(CryptoError::Malformed("too short"));
                }
                let (nonce, ct) = blob.split_at(NONCE_LEN);
                let plain = key.cipher.decrypt(Nonce::from_slice(nonce), ct).map_err(|_| CryptoError::Decrypt { key_id: key_id.to_string() })?;
                String::from_utf8(plain).map_err(|_| CryptoError::Malformed("not UTF-8"))
            }
        }
    }

    fn missing(&self, key_id: &str) -> CryptoError {
        match self.current_id() {
            None if self.previous.is_empty() => CryptoError::NoKey { key_id: key_id.to_string() },
            current => {
                let ids = self.previous_ids();
                CryptoError::UnknownKey {
                    key_id: key_id.to_string(),
                    current: current.unwrap_or("none").to_string(),
                    known: if ids.is_empty() { String::new() } else { format!(" ({})", ids.join(", ")) },
                }
            }
        }
    }

    /// Which key `stored` needs. Malformed envelopes count as [`KeyUse::Unknown`].
    pub fn classify(&self, stored: &str) -> KeyUse {
        match Envelope::parse(stored) {
            Ok(Envelope::Plain(_) | Envelope::Encoded(_)) => KeyUse::Plaintext,
            Ok(Envelope::Sealed { key_id, .. }) => self.classify_id(Some(key_id)),
            Err(_) => KeyUse::Unknown("malformed".into()),
        }
    }

    /// [`Keyring::classify`] by key id (`None`: plaintext).
    pub fn classify_id(&self, key_id: Option<&str>) -> KeyUse {
        match key_id {
            None => KeyUse::Plaintext,
            Some(id) if self.current_id() == Some(id) => KeyUse::Current,
            Some(id) if self.previous.iter().any(|k| k.id == id) => KeyUse::Previous(id.to_string()),
            Some(id) => KeyUse::Unknown(id.to_string()),
        }
    }

    /// Whether `stored` is already as [`Keyring::seal`] would write it now: under the current
    /// key, or plaintext when there is none.
    pub fn is_current(&self, stored: &str) -> bool {
        match self.classify(stored) {
            KeyUse::Current => true,
            KeyUse::Plaintext => !self.is_encrypting(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;

    const K1: &str = "0123456789abcdef0123456789abcdef-one";
    const K2: &str = "0123456789abcdef0123456789abcdef-two";

    fn ring(current: &str, previous: &[&str]) -> Keyring {
        Keyring::new(Some(DataKey::from_material(current)), previous.iter().map(|p| DataKey::from_material(p)))
    }

    #[test]
    fn round_trip() {
        let k = ring(K1, &[]);
        let sealed = k.seal("hunter2");
        let id = k.current_id().unwrap();
        assert_eq!(id.len(), 8);
        assert!(sealed.starts_with(&format!("enc:v1:{id}:")), "{sealed}");
        assert!(!sealed.contains("hunter2"));
        assert_ne!(k.seal("hunter2"), sealed, "a fresh nonce every time");
        assert_eq!(k.open(&sealed).unwrap(), "hunter2");
        assert_eq!(k.open(&k.seal("")).unwrap(), "");
        assert_eq!(k.classify(&sealed), KeyUse::Current);
        assert!(k.is_current(&sealed));
    }

    #[test]
    fn opens_with_a_previous_key() {
        let old = ring(K1, &[]);
        let sealed = old.seal("token");
        let rotated = ring(K2, &[K1]);
        assert_eq!(rotated.open(&sealed).unwrap(), "token");
        assert_eq!(rotated.classify(&sealed), KeyUse::Previous(old.current_id().unwrap().into()));
        assert!(!rotated.is_current(&sealed));
        assert!(rotated.seal("token").starts_with(&format!("enc:v1:{}:", rotated.current_id().unwrap())));
    }

    #[test]
    fn unknown_key_is_named() {
        let sealed = ring(K1, &[]).seal("token");
        let id = ring(K1, &[]).current_id().unwrap().to_string();
        let err = ring(K2, &[]).open(&sealed).unwrap_err();
        assert!(matches!(&err, CryptoError::UnknownKey { key_id, .. } if *key_id == id), "{err:?}");
        assert!(err.to_string().contains(&id), "{err}");
        let err = Keyring::unencrypted().open(&sealed).unwrap_err();
        assert!(matches!(err, CryptoError::NoKey { .. }) && err.to_string().contains(&id), "{err}");
        assert_eq!(ring(K2, &[]).classify(&sealed), KeyUse::Unknown(id));
    }

    #[test]
    fn tampering_is_detected() {
        let k = ring(K1, &[]);
        let sealed = k.seal("token");
        let (head, payload) = sealed.rsplit_once(':').unwrap();
        let mut blob = B64.decode(payload).unwrap();
        *blob.last_mut().unwrap() ^= 1;
        assert!(matches!(k.open(&format!("{head}:{}", B64.encode(blob))), Err(CryptoError::Decrypt { .. })));
        assert!(matches!(k.open("enc:v9:x"), Err(CryptoError::Malformed(_))));
        assert!(matches!(k.open("enc:v1:zz:AAAA"), Err(CryptoError::Malformed(_))));
    }

    #[test]
    fn plaintext_passes_through() {
        let none = Keyring::unencrypted();
        assert!(!none.is_encrypting());
        assert_eq!(none.seal("hunter2"), "hunter2");
        assert_eq!(none.open("hunter2").unwrap(), "hunter2");
        assert!(none.is_current("hunter2"));
        // A plaintext value that looks like an envelope is written as one (v0) and survives.
        let odd = none.seal("enc:v1:abcd:not-really");
        assert!(odd.starts_with("enc:v0:"), "{odd}");
        assert_eq!(none.open(&odd).unwrap(), "enc:v1:abcd:not-really");
        assert_eq!(none.classify(&odd), KeyUse::Plaintext);
        // Legacy plaintext opens under any keyring, and is not current once a key is set.
        let k = ring(K1, &[]);
        assert_eq!(k.open("legacy").unwrap(), "legacy");
        assert_eq!(k.open(&odd).unwrap(), "enc:v1:abcd:not-really");
        assert!(!k.is_current("legacy"));
    }

    #[test]
    fn from_config() {
        let mut auth = AuthConfig::default();
        assert!(!Keyring::from_config(&auth).is_encrypting());
        auth.secret = Some(Secret::from(K1));
        let derived = Keyring::from_config(&auth);
        assert_eq!(derived.current_id(), Some(DataKey::from_auth_secret(K1).id()));
        assert_ne!(derived.current_id(), Some(DataKey::from_material(K1).id()), "the derived key is not the secret's own key");
        auth.encryption_key = Some(Secret::from(K2));
        auth.previous_encryption_keys = vec![Secret::from(K1), Secret::from(K2)];
        let explicit = Keyring::from_config(&auth);
        assert_eq!(explicit.current_id(), Some(DataKey::from_material(K2).id()));
        assert_eq!(explicit.previous_ids(), [DataKey::from_material(K1).id(), DataKey::from_auth_secret(K1).id()]);
        assert_eq!(explicit.open(&derived.seal("x")).unwrap(), "x", "values sealed under the derived key still open");
        assert_eq!(format!("{explicit:?}").matches("0123").count(), 0, "no key material in Debug");
    }
}
