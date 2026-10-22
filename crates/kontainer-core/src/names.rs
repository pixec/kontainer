//! Validation of repository names and tags per the distribution spec.

use regex::Regex;
use std::sync::LazyLock;

static NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$").unwrap()
});
static TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$").unwrap());

pub fn is_valid_repository(name: &str) -> bool {
    name.len() <= 255 && NAME_RE.is_match(name)
}

pub fn is_valid_tag(tag: &str) -> bool {
    TAG_RE.is_match(tag)
}

/// A manifest reference is either a tag or a digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    Tag(String),
    Digest(crate::digest::Digest),
}

impl Reference {
    pub fn parse(s: &str) -> Option<Reference> {
        if let Ok(d) = s.parse() {
            return Some(Reference::Digest(d));
        }
        if is_valid_tag(s) {
            return Some(Reference::Tag(s.to_string()));
        }
        None
    }
}

/// The namespace (user or organization) a repository belongs to: `acme` for `acme/api/web`.
pub fn namespace(repo: &str) -> &str {
    repo.split('/').next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_valid_repository("library/ubuntu"));
        assert!(is_valid_repository("a/b/c-d_e.f"));
        assert!(!is_valid_repository("Library/Ubuntu"));
        assert!(!is_valid_repository("a//b"));
        assert!(!is_valid_repository("a/"));
        assert!(!is_valid_repository(""));
    }

    #[test]
    fn tags() {
        assert!(is_valid_tag("latest"));
        assert!(is_valid_tag("v1.2.3-rc.1"));
        assert!(!is_valid_tag("-bad"));
        assert!(!is_valid_tag("has space"));
    }
}
