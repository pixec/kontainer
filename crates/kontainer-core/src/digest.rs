//! Content digests as defined by the OCI image spec: `<algorithm>:<hex>`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
        }
    }
    fn hex_len(&self) -> usize {
        match self {
            Algorithm::Sha256 => 64,
            Algorithm::Sha512 => 128,
        }
    }
}

/// A validated digest: the hex part always has the algorithm's length and is lowercase. Build
/// one by parsing, with [`Digest::new`], or by hashing.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    algorithm: Algorithm,
    hex: String,
}

impl Digest {
    /// `hex` must be the algorithm's length in lowercase hex.
    pub fn new(algorithm: Algorithm, hex: &str) -> Result<Self, InvalidDigest> {
        if hex.len() != algorithm.hex_len() || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(InvalidDigest(format!("{}:{hex}", algorithm.as_str())));
        }
        Ok(Digest { algorithm, hex: hex.to_string() })
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The hex-encoded hash, without the `<algorithm>:` prefix.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    pub fn sha256_of(data: &[u8]) -> Self {
        Digest { algorithm: Algorithm::Sha256, hex: hex::encode(Sha256::digest(data)) }
    }

    pub fn hasher(algorithm: Algorithm) -> Hasher {
        match algorithm {
            Algorithm::Sha256 => Hasher::Sha256(Sha256::new()),
            Algorithm::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
}

pub enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }
    pub fn finalize(self) -> Digest {
        match self {
            Hasher::Sha256(h) => Digest { algorithm: Algorithm::Sha256, hex: hex::encode(h.finalize()) },
            Hasher::Sha512(h) => Digest { algorithm: Algorithm::Sha512, hex: hex::encode(h.finalize()) },
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid digest: {0}")]
pub struct InvalidDigest(pub String);

impl FromStr for Digest {
    type Err = InvalidDigest;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (alg, hex) = s.split_once(':').ok_or_else(|| InvalidDigest(s.to_string()))?;
        let algorithm = match alg {
            "sha256" => Algorithm::Sha256,
            "sha512" => Algorithm::Sha512,
            _ => return Err(InvalidDigest(s.to_string())),
        };
        Digest::new(algorithm, hex).map_err(|_| InvalidDigest(s.to_string()))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm.as_str(), self.hex)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        let d = Digest::sha256_of(b"hello");
        assert_eq!(d.to_string(), "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(d.to_string().parse::<Digest>().unwrap(), d);
        assert!("sha256:abc".parse::<Digest>().is_err());
        assert!("md5:abc".parse::<Digest>().is_err());
        assert_eq!(Digest::new(Algorithm::Sha256, d.hex()).unwrap(), d);
        assert!(Digest::new(Algorithm::Sha512, d.hex()).is_err());
        assert!(Digest::new(Algorithm::Sha256, "../../etc").is_err());
        assert!("sha256:2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824".parse::<Digest>().is_err());
    }
}
