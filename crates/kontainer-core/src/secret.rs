//! A credential that must not end up in logs.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A credential that crosses the wire (the build protocol's tokens): (de)serialized as the plain
/// string so the other side can use it, but `Debug` and `Display` print `[redacted]`. Read it
/// with [`WireSecret::expose`]. Configuration secrets use `crate::config::Secret`, which also
/// redacts when serialized.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WireSecret(String);

impl WireSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The secret itself. Only pass it to what needs it (a header, a comparison); never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for WireSecret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for WireSecret {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for WireSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// What a secret prints as.
pub const REDACTED: &str = "[redacted]";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_in_logs_but_sent_on_the_wire() {
        let s = WireSecret::from("hunter2");
        assert_eq!(format!("{s:?} {s}"), "[redacted] [redacted]");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"hunter2\"");
        let back: WireSecret = serde_json::from_str("\"hunter2\"").unwrap();
        assert_eq!(back.expose(), "hunter2");
    }
}
