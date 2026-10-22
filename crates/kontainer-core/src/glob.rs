//! Tiny glob matcher for repository names and tags.
//!
//! - `*` matches any run of characters except `/`.
//! - `**/` (at the start of the pattern or right after a `/`) matches zero or more whole path
//!   segments: `acme/**/prod` matches `acme/prod` and `acme/x/prod`, not `acme/nonprod`.
//! - Any other `**` (e.g. a trailing `acme/**`) matches anything, including `/`.
//!
//! All other characters match literally. Matching simulates the pattern as an automaton over
//! the input bytes, so it takes O(pattern × input) time whatever the pattern looks like.

/// Patterns up to this many bytes are matched without allocating.
const INLINE: usize = 64;

pub fn matches(pattern: &str, input: &str) -> bool {
    let (p, s) = (pattern.as_bytes(), input.as_bytes());
    let states = p.len() + 1;
    if states <= INLINE {
        let mut buf = [false; 4 * INLINE];
        run(p, s, &mut buf[..4 * states])
    } else {
        run(p, s, &mut vec![false; 4 * states])
    }
}

pub fn any_matches<'a>(patterns: impl IntoIterator<Item = &'a String>, input: &str) -> bool {
    patterns.into_iter().any(|p| matches(p, input))
}

#[derive(Clone, Copy)]
enum Tok {
    Lit(u8),
    /// `*`
    Star,
    /// `**/` at a segment start.
    Segments,
    /// Any other `**`.
    Any,
}

/// The token starting at byte `k` of the pattern, and its length.
fn token(p: &[u8], k: usize) -> (Tok, usize) {
    match &p[k..] {
        [b'*', b'*', b'/', ..] if k == 0 || p[k - 1] == b'/' => (Tok::Segments, 3),
        [b'*', b'*', ..] => (Tok::Any, 2),
        [b'*', ..] => (Tok::Star, 1),
        [c, ..] => (Tok::Lit(*c), 1),
        [] => unreachable!("token past the end of the pattern"),
    }
}

/// `buf` holds four state sets of `p.len() + 1` flags: positions in the pattern that are active
/// now and next, and (for `**/`) whether we are inside a segment it is consuming.
fn run(p: &[u8], s: &[u8], buf: &mut [bool]) -> bool {
    let n = p.len();
    let (cur, next) = buf.split_at_mut(2 * (n + 1));
    let (mut at, mut inside) = cur.split_at_mut(n + 1);
    let (mut next_at, mut next_inside) = next.split_at_mut(n + 1);
    at[0] = true;
    close(p, at);
    for &c in s {
        next_at.fill(false);
        next_inside.fill(false);
        let mut alive = false;
        for k in 0..n {
            if at[k] {
                let (tok, len) = token(p, k);
                let target = match tok {
                    Tok::Lit(b) if b == c => Some(&mut next_at[k + len]),
                    Tok::Lit(_) => None,
                    Tok::Star if c == b'/' => None,
                    Tok::Star | Tok::Any => Some(&mut next_at[k]),
                    Tok::Segments if c == b'/' => Some(&mut next_at[k]),
                    Tok::Segments => Some(&mut next_inside[k]),
                };
                if let Some(t) = target {
                    *t = true;
                    alive = true;
                }
            }
            if inside[k] {
                if c == b'/' { next_at[k] = true } else { next_inside[k] = true }
                alive = true;
            }
        }
        if !alive {
            return false;
        }
        close(p, next_at);
        std::mem::swap(&mut at, &mut next_at);
        std::mem::swap(&mut inside, &mut next_inside);
    }
    at[n]
}

/// Wildcards may match nothing: activate whatever follows an active one. Tokens only point
/// forward, so one ascending pass reaches the fixpoint.
fn close(p: &[u8], at: &mut [bool]) {
    for k in 0..p.len() {
        if at[k] {
            if let (Tok::Star | Tok::Segments | Tok::Any, len) = token(p, k) {
                at[k + len] = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn globs() {
        assert!(matches("**", "a/b/c"));
        assert!(matches("**", ""));
        assert!(matches("*", "abc"));
        assert!(!matches("*", "a/b"));
        assert!(matches("team-a/*", "team-a/app"));
        assert!(!matches("team-a/*", "team-a/app/sub"));
        assert!(matches("team-a/**", "team-a/app/sub"));
        assert!(matches("team-a/**", "team-a/app"));
        assert!(!matches("team-a/**", "team-b/app"));
        assert!(!matches("team-a/**", "team-a"));
        assert!(matches("v*", "v1.2"));
        assert!(matches("release-*", "release-2024"));
        assert!(!matches("release-*", "dev"));
        assert!(matches("exact", "exact"));
        assert!(!matches("exact", "exactly"));
        assert!(!matches("", "x"));
        assert!(matches("", ""));
    }

    #[test]
    fn double_star_slash_is_whole_segments() {
        assert!(matches("acme/**/prod", "acme/prod"));
        assert!(matches("acme/**/prod", "acme/x/prod"));
        assert!(matches("acme/**/prod", "acme/x/y/prod"));
        assert!(!matches("acme/**/prod", "acme/nonprod"));
        assert!(!matches("acme/**/prod", "acme/x/notprod"));
        assert!(!matches("acme/**/prod", "acme/prod/x"));
        assert!(matches("**/public", "public"));
        assert!(matches("**/public", "a/b/public"));
        assert!(!matches("**/public", "team/notpublic"));
        assert!(!matches("**/public", "notpublic"));
        assert!(matches("acme/**", "acme/x/y"));
        assert!(matches("acme/**/*-svc", "acme/a/b/api-svc"));
        assert!(!matches("acme/**/*-svc", "acme/a/b/api-svc/x"));
    }

    #[test]
    fn bare_double_star_mid_segment_matches_anything() {
        assert!(matches("a**/b", "a/b"));
        assert!(matches("a**/b", "axy/z/b"));
        assert!(matches("a**", "a/b/c"));
    }

    #[test]
    fn pathological_patterns_are_fast() {
        let input = "a".repeat(10_000);
        let start = std::time::Instant::now();
        assert!(!matches("*a*a*a*a*a*a*a*a*a*a*a*b", &input));
        assert!(!matches("**a**a**a**a**a**a**a**b", &input));
        let long_pattern = format!("{}b", "*a".repeat(200));
        assert!(!matches(&long_pattern, &input));
        assert!(matches(&"**/".repeat(50), &"x/".repeat(500)));
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "took {:?}", start.elapsed());
    }
}
