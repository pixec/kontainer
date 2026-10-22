//! Builds from Git, the parts the registry and its runners share: the runner protocol and the
//! rules for refs, tags and build messages.

pub mod protocol;

/// A Git ref or commit safe to put on a command line.
pub fn valid_ref(r: &str) -> bool {
    !r.is_empty() && r.len() <= 200 && !r.starts_with('-') && !r.contains("..") && r.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// `refs/heads/main` -> `main`; `refs/tags/v1` -> `v1`.
pub fn short_ref(r: &str) -> &str {
    r.strip_prefix("refs/heads/").or_else(|| r.strip_prefix("refs/tags/")).unwrap_or(r)
}

/// Tag templates: `{branch}`, `{tag}` (for a Git tag push), `{sha}`, `{sha7}`, and literals.
/// Templates that resolve to nothing or an invalid tag are skipped.
pub fn render_tags(templates: &[String], git_ref: &str, sha: &str) -> Vec<String> {
    let is_tag = git_ref.starts_with("refs/tags/");
    let name = short_ref(git_ref).replace('/', "-");
    let mut out: Vec<String> = vec![];
    for t in templates {
        if (t.contains("{tag}") && !is_tag) || (t.contains("{branch}") && is_tag) {
            continue;
        }
        let v = t.replace("{branch}", &name).replace("{tag}", &name).replace("{sha7}", &sha[..sha.len().min(7)]).replace("{sha}", sha);
        if crate::names::is_valid_tag(&v) && !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// `main`, `0fe1385 and latest`, `a, b and c`: a list for a sentence.
pub fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// A message as a sentence: capitalised (errors from git, Docker and the like often aren't).
pub fn sentence(message: &str) -> String {
    let mut c = message.trim().chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_templates() {
        let t = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(render_tags(&t(&["{branch}", "{sha7}", "latest"]), "refs/heads/feature/x", sha), vec!["feature-x", "0123456", "latest"]);
        assert_eq!(render_tags(&t(&["{branch}", "{tag}"]), "refs/tags/v1.2.0", sha), vec!["v1.2.0"]);
        assert_eq!(render_tags(&t(&["bad tag!", "{sha}"]), "main", sha), vec![sha.to_string()]);
    }

    #[test]
    fn wording() {
        let t = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(and_list(&t(&["main"])), "main");
        assert_eq!(and_list(&t(&["main", "0fe1385", "latest"])), "main, 0fe1385 and latest");
        assert_eq!(sentence("couldn't fetch"), "Couldn't fetch");
        assert_eq!(sentence(""), "");
    }

    #[test]
    fn refs() {
        assert!(valid_ref("refs/heads/main") && valid_ref("0123abc") && !valid_ref("--upload-pack=x") && !valid_ref("a..b") && !valid_ref("a b"));
        assert_eq!(short_ref("refs/heads/main"), "main");
        assert_eq!(short_ref("refs/tags/v1"), "v1");
    }
}
