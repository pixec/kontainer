//! Credentials in the configuration.

use std::fmt;

use serde::{Deserialize, Serialize};

pub use crate::secret::REDACTED;

/// A credential from the configuration (passwords, tokens, keys). Read from the config as a
/// plain string; `Debug`, `Display` and `Serialize` never show it (serialized, a set secret is
/// `"[redacted]"` and an empty one stays `""`), so a printed or dumped config can't leak it. Read
/// it with [`Secret::expose`].
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The secret itself. Only pass it to what needs it (a client, a comparison); never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

// No `Display`: APIs such as reqwest's `basic_auth` accept any `Display`, and a redacted
// placeholder would be sent instead of the secret. Use `expose()` to send it, and `Debug` or
// `redacted()` to show it.

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(if self.0.is_empty() { "" } else { REDACTED })
    }
}

/// The database's `postgres://` URL. Read from the config as a plain string; `Debug`, `Display`
/// and `Serialize` show it with its password replaced by `***`. Read it with
/// [`DatabaseUrl::expose`].
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct DatabaseUrl(String);

impl DatabaseUrl {
    pub const DEFAULT: &'static str = "postgres://kontainer:kontainer@127.0.0.1:5432/kontainer";

    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The URL with its password, for connecting. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The URL with its password (if any) replaced by `***`.
    pub fn redacted(&self) -> String {
        redact_url_password(&self.0)
    }

    /// A URL that parses, with the `postgres` (or `postgresql`) scheme.
    pub fn validate(&self) -> Result<(), String> {
        let url = url::Url::parse(self.0.trim()).map_err(|e| format!("not a URL ({e})"))?;
        match url.scheme() {
            "postgres" | "postgresql" => Ok(()),
            other => Err(format!("unsupported scheme `{other}`; expected postgres://user:password@host:5432/database")),
        }
    }
}

impl Default for DatabaseUrl {
    fn default() -> Self {
        Self(Self::DEFAULT.into())
    }
}

impl From<String> for DatabaseUrl {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for DatabaseUrl {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.redacted())
    }
}

impl fmt::Display for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl Serialize for DatabaseUrl {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.redacted())
    }
}

/// `scheme://user:password@host/...` with the password replaced by `***`. Also handles URLs
/// that don't parse: everything between the user's `:` and the last `@` of the authority goes.
pub fn redact_url_password(raw: &str) -> String {
    if let Ok(mut url) = url::Url::parse(raw) {
        if url.password().is_some() && url.set_password(Some("***")).is_ok() {
            return url.to_string();
        }
        if url.password().is_none() {
            return raw.to_string();
        }
    }
    let Some((scheme, rest)) = raw.split_once("://") else { return raw.to_string() };
    // The authority ends at the first `/`, `?` or `#` after its last `@`.
    let Some(at) = rest.rfind('@').filter(|&at| !rest[..at].contains(['?', '#'])) else { return raw.to_string() };
    match rest[..at].split_once(':') {
        Some((user, _)) => format!("{scheme}://{user}:***{}", &rest[at..]),
        None => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_shown() {
        let s: Secret = toml::from_str::<toml::Table>("v = \"hunter2\"").unwrap()["v"].clone().try_into().unwrap();
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(format!("{s:?}"), "[redacted]");
        assert_eq!(toml::Value::try_from(&s).unwrap().as_str(), Some(REDACTED));
        assert_eq!(toml::Value::try_from(Secret::default()).unwrap().as_str(), Some(""));
    }

    #[test]
    fn database_url_password_is_never_shown() {
        let u = DatabaseUrl::from("postgres://kontainer:hunter2@db:5432/kontainer?sslmode=require");
        assert_eq!(u.expose(), "postgres://kontainer:hunter2@db:5432/kontainer?sslmode=require");
        let shown = "postgres://kontainer:***@db:5432/kontainer?sslmode=require";
        assert_eq!(format!("{u}"), shown);
        assert_eq!(format!("{u:?}"), format!("{shown:?}"));
        assert_eq!(toml::Value::try_from(&u).unwrap().as_str(), Some(shown));
        assert!(u.validate().is_ok());
        assert_eq!(DatabaseUrl::from("postgres://db/kontainer").redacted(), "postgres://db/kontainer");
        assert!(DatabaseUrl::from("mysql://u:p@db/k").validate().is_err());
        assert!(DatabaseUrl::from("./data/auth.db").validate().is_err());
        assert!(DatabaseUrl::default().validate().is_ok());
    }
}
