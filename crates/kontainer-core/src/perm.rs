//! The permission model.
//!
//! A [`Role`] is a named bundle of repository [`Rule`]s plus [`Global`] permissions. Rules
//! grant [`Action`]s on repositories matching glob patterns. Roles are stored in the database
//! (and may be seeded from the config file); users and robot accounts reference them by name.

use serde::{Deserialize, Serialize};

use crate::glob;

/// Repository-scoped permissions.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Read manifests, blobs, tags, referrers and scan reports.
    Pull,
    /// Upload blobs and manifests, create and move tags, mount blobs from repositories you can pull.
    Push,
    /// Delete tags, manifests and blobs.
    Delete,
    /// Delete the whole repository.
    DeleteRepository,
    /// Trigger vulnerability scans.
    Scan,
    /// Read the usage log for the repository.
    Logs,
    /// Edit the description, README and topics.
    Metadata,
    /// Make the repository public or private.
    Visibility,
    /// See and change who has access to the repository.
    Permissions,
    /// Make the repository read-only or a mirror target, and back.
    State,
    /// Create, edit and delete build triggers (running one needs `push`).
    Builds,
    /// Set up mirrors that sync into the repository.
    Mirror,
    /// Every repository action, including ones added later.
    Admin,
}

impl Action {
    pub const ALL: [Action; 13] = [
        Action::Pull,
        Action::Push,
        Action::Delete,
        Action::DeleteRepository,
        Action::Scan,
        Action::Logs,
        Action::Metadata,
        Action::Visibility,
        Action::Permissions,
        Action::State,
        Action::Builds,
        Action::Mirror,
        Action::Admin,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Pull => "pull",
            Action::Push => "push",
            Action::Delete => "delete",
            Action::DeleteRepository => "delete_repository",
            Action::Scan => "scan",
            Action::Logs => "logs",
            Action::Metadata => "metadata",
            Action::Visibility => "visibility",
            Action::Permissions => "permissions",
            Action::State => "state",
            Action::Builds => "builds",
            Action::Mirror => "mirror",
            Action::Admin => "admin",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Action::Pull => "Pull images: read manifests, blobs, tags, referrers and scan reports",
            Action::Push => "Push images: upload blobs and manifests, create and move tags",
            Action::Delete => "Delete tags, manifests and blobs",
            Action::DeleteRepository => "Delete the entire repository",
            Action::Scan => "Trigger vulnerability scans",
            Action::Logs => "Read the repository's usage log",
            Action::Metadata => "Edit the description, README and topics",
            Action::Visibility => "Make the repository public or private",
            Action::Permissions => "See and change who has access",
            Action::State => "Make the repository read-only or a mirror target",
            Action::Builds => "Manage build triggers (running a build needs push)",
            Action::Mirror => "Set up mirrors into the repository",
            Action::Admin => "Every repository action",
        }
    }

    pub fn parse(s: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.as_str() == s)
    }

    fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

/// Registry-wide permissions, not tied to a repository.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Global {
    #[serde(rename = "users:read")]
    UsersRead,
    #[serde(rename = "users:write")]
    UsersWrite,
    #[serde(rename = "roles:write")]
    RolesWrite,
    #[serde(rename = "gc")]
    Gc,
    #[serde(rename = "logs:all")]
    LogsAll,
    #[serde(rename = "catalog")]
    Catalog,
    #[serde(rename = "orgs:create")]
    OrgsCreate,
    #[serde(rename = "system")]
    System,
}

impl Global {
    pub const ALL: [Global; 8] =
        [Global::UsersRead, Global::UsersWrite, Global::RolesWrite, Global::Gc, Global::LogsAll, Global::Catalog, Global::OrgsCreate, Global::System];

    pub fn as_str(&self) -> &'static str {
        match self {
            Global::UsersRead => "users:read",
            Global::UsersWrite => "users:write",
            Global::RolesWrite => "roles:write",
            Global::Gc => "gc",
            Global::LogsAll => "logs:all",
            Global::Catalog => "catalog",
            Global::OrgsCreate => "orgs:create",
            Global::System => "system",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Global::UsersRead => "List users and robot accounts",
            Global::UsersWrite => "Create, edit and delete users; reset passwords and MFA",
            Global::RolesWrite => "Create, edit and delete roles",
            Global::Gc => "Run garbage collection",
            Global::LogsAll => "Read the usage log of every repository",
            Global::Catalog => "List every repository, regardless of pull access",
            Global::OrgsCreate => "Create organizations (the creator becomes its first admin)",
            Global::System => "Superuser: every permission on everything",
        }
    }
}

/// Grants `actions` on repositories matching any of the `repositories` globs.
///
/// Glob syntax: `*` matches within one path segment, `**` across segments.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub repositories: Vec<String>,
    pub actions: Vec<Action>,
}

impl Rule {
    pub fn grants(&self, action: Action, repository: &str) -> bool {
        (self.actions.contains(&action) || self.actions.contains(&Action::Admin))
            && glob::any_matches(&self.repositories, repository)
    }
}

pub fn rules_grant(rules: &[Rule], action: Action, repository: &str) -> bool {
    rules.iter().any(|r| r.grants(action, repository))
}

impl Rule {
    /// Grants `action` on every repository the pattern `want` could match.
    pub fn covers(&self, action: Action, want: &str) -> bool {
        (self.actions.contains(&action) || self.actions.contains(&Action::Admin)) && self.repositories.iter().any(|g| covers(g, want))
    }
}

/// Some rule grants `action` on every repository the pattern `want` could match.
pub fn rules_cover(rules: &[Rule], action: Action, want: &str) -> bool {
    rules.iter().any(|r| r.covers(action, want))
}

/// A pattern token, as [`crate::glob`] reads them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    Lit(u8),
    /// `*`: any run without `/`.
    Star,
    /// `**/` at a segment start: empty, or anything ending in `/`.
    Segments,
    /// Any other `**`: anything.
    Any,
}

fn tokens(p: &str) -> Vec<Tok> {
    let p = p.as_bytes();
    let mut out = vec![];
    let mut k = 0;
    while k < p.len() {
        let (t, len) = match &p[k..] {
            [b'*', b'*', b'/', ..] if k == 0 || p[k - 1] == b'/' => (Tok::Segments, 3),
            [b'*', b'*', ..] => (Tok::Any, 2),
            [b'*', ..] => (Tok::Star, 1),
            [c, ..] => (Tok::Lit(*c), 1),
            [] => unreachable!(),
        };
        out.push(t);
        k += len;
    }
    out
}

/// Whether the glob `grant` matches every name the glob `want` could match (pattern covers
/// pattern), so holding `grant` justifies handing out `want`. Conservative: it may answer no for
/// some patterns that are in fact covered, never yes for one that is not.
///
/// Each token of `grant` takes a run of `want`'s tokens whose strings it surely matches: a
/// literal takes the same literal; `*` takes literals other than `/` and `*`s; `**` takes
/// anything; `**/` takes `**/`s and runs that end in a literal `/`.
pub fn covers(grant: &str, want: &str) -> bool {
    let (g, w) = (tokens(grant), tokens(want));
    // reach[i][j]: grant[..i] covers want[..j].
    let mut reach = vec![vec![false; w.len() + 1]; g.len() + 1];
    reach[0][0] = true;
    for i in 0..=g.len() {
        for j in 0..=w.len() {
            if !reach[i][j] {
                continue;
            }
            let Some(&gt) = g.get(i) else { continue };
            match gt {
                Tok::Lit(c) => {
                    if w.get(j) == Some(&Tok::Lit(c)) {
                        reach[i + 1][j + 1] = true;
                    }
                }
                Tok::Star => {
                    reach[i + 1][j] = true;
                    if matches!(w.get(j), Some(Tok::Star)) || matches!(w.get(j), Some(Tok::Lit(c)) if *c != b'/') {
                        reach[i][j + 1] = true;
                    }
                }
                Tok::Any => {
                    reach[i + 1][j] = true;
                    if j < w.len() {
                        reach[i][j + 1] = true;
                    }
                }
                Tok::Segments => {
                    reach[i + 1][j] = true;
                    if w.get(j) == Some(&Tok::Segments) {
                        reach[i][j + 1] = true;
                    }
                    for k in j..w.len() {
                        if w[k] == Tok::Lit(b'/') {
                            reach[i][k + 1] = true;
                        }
                    }
                }
            }
        }
    }
    reach[g.len()][w.len()]
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub global: Vec<Global>,
    /// Defined in the configuration file; cannot be edited through the API.
    #[serde(default, skip_deserializing)]
    pub is_managed: bool,
}

impl Role {
    pub fn allows(&self, action: Action, repository: &str) -> bool {
        self.global.contains(&Global::System) || rules_grant(&self.rules, action, repository)
    }

    pub fn has_global(&self, g: Global) -> bool {
        self.global.contains(&Global::System) || self.global.contains(&g)
    }
}

pub fn valid_role_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

pub fn valid_username(name: &str) -> bool {
    // `owner+robot` is the robot account convention.
    let (base, robot) = name.split_once('+').map(|(a, b)| (a, Some(b))).unwrap_or((name, None));
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    ok(base) && robot.is_none_or(ok)
}

/// Access to one repository: a set of [`Action`]s. `read`, `write` and `admin` are the named
/// presets; any other mix is a custom grant. Stored and serialized as the preset
/// name, or as a comma list such as `pull,push,metadata`; also deserializes from a JSON array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Level(u32);

impl Level {
    /// Pull.
    pub const READ: Level = Level(1 << Action::Pull as u32);
    /// Pull, push, delete tags and manifests, run scans.
    pub const WRITE: Level = Level((1 << Action::Pull as u32) | (1 << Action::Push as u32) | (1 << Action::Delete as u32) | (1 << Action::Scan as u32));
    /// Everything, including settings, permissions and deleting the repository.
    pub const ADMIN: Level = Level(1 << Action::Admin as u32);

    pub fn of(actions: impl IntoIterator<Item = Action>) -> Self {
        Level(actions.into_iter().fold(0, |acc, a| acc | a.bit()))
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn grants(self, action: Action) -> bool {
        self.0 & (action.bit() | Action::Admin.bit()) != 0
    }

    /// Everything either grants.
    pub fn union(self, other: Level) -> Level {
        Level(self.0 | other.0)
    }

    /// The actions in the set, as stored (`admin` is not expanded).
    pub fn actions(self) -> Vec<Action> {
        Action::ALL.into_iter().filter(|a| self.0 & a.bit() != 0).collect()
    }

    /// `read`, `write` or `admin` when the set is exactly a preset.
    pub fn preset(self) -> Option<&'static str> {
        match self {
            Level::READ => Some("read"),
            Level::WRITE => Some("write"),
            _ if self.0 & Action::Admin.bit() != 0 => Some("admin"),
            _ => None,
        }
    }

    pub fn as_string(self) -> String {
        match self.preset() {
            Some(p) => p.to_string(),
            None => self.actions().iter().map(|a| a.as_str()).collect::<Vec<_>>().join(","),
        }
    }

    /// A preset name or a comma list of actions. Unknown names make the whole value invalid.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "read" => Some(Level::READ),
            "write" => Some(Level::WRITE),
            "admin" => Some(Level::ADMIN),
            list => {
                let mut out = Level::default();
                for a in list.split(',').map(str::trim).filter(|a| !a.is_empty()) {
                    out = out.union(Level::of([Action::parse(a)?]));
                }
                (!out.is_empty()).then_some(out)
            }
        }
    }

    /// The weakest preset that covers every action in a legacy rule.
    pub fn covering(actions: &[Action]) -> Self {
        if actions.iter().any(|a| !matches!(a, Action::Pull | Action::Push | Action::Delete | Action::Scan)) {
            Level::ADMIN
        } else if actions.iter().any(|a| matches!(a, Action::Push | Action::Delete | Action::Scan)) {
            Level::WRITE
        } else {
            Level::READ
        }
    }
}

impl Serialize for Level {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for Level {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Name(String),
            List(Vec<Action>),
        }
        let level = match Raw::deserialize(d)? {
            Raw::Name(s) => Level::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown level or action in `{s}`")))?,
            Raw::List(v) => Level::of(v),
        };
        if level.is_empty() {
            return Err(serde::de::Error::custom("a grant needs at least one action"));
        }
        Ok(level)
    }
}

/// What a team may do in its organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TeamRole {
    /// Access only through repository grants and the team's base permission.
    Member,
    /// Member, plus may create new repositories in the org (and becomes their admin).
    Creator,
    /// Full access to every repository; manages teams, members and robots.
    Admin,
}

impl TeamRole {
    pub fn as_str(self) -> &'static str {
        match self {
            TeamRole::Member => "member",
            TeamRole::Creator => "creator",
            TeamRole::Admin => "admin",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "admin" => TeamRole::Admin,
            "creator" => TeamRole::Creator,
            _ => TeamRole::Member,
        }
    }
}

/// Membership of one team, as seen by the permission check.
#[derive(Debug, Clone, Serialize)]
pub struct TeamGrant {
    pub org: String,
    pub team: String,
    pub role: TeamRole,
    /// Access to every repository in the org.
    pub base: Option<Level>,
}

impl TeamGrant {
    pub fn covers(&self, repository: &str) -> bool {
        repository.strip_prefix(&self.org).is_some_and(|r| r.starts_with('/'))
    }
    pub fn allows(&self, action: Action, repository: &str) -> bool {
        self.covers(repository) && (self.role == TeamRole::Admin || self.base.is_some_and(|l| l.grants(action)))
    }
}

pub fn valid_org_name(name: &str) -> bool {
    valid_username(name) && !name.contains('+')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_covers_pattern() {
        // A user named `x` owns `x/**`, which must not cover patterns reaching beyond it.
        assert!(!covers("x/**", "**"));
        assert!(!covers("x/**", "*"));
        assert!(!covers("x/**", "*/**"));
        assert!(!covers("x/**", "x*/**"));
        assert!(!covers("x", "*"));
        assert!(covers("x/**", "x/**"));
        assert!(covers("x/**", "x/*"));
        assert!(covers("x/**", "x/app"));
        assert!(covers("x/**", "x/**/prod"));

        assert!(covers("**", "**"));
        assert!(covers("**", "anything/*/at-all"));
        assert!(covers("team-a/**", "team-a/*"));
        assert!(!covers("team-a/*", "team-a/**"));
        assert!(!covers("team-a/**", "team-*/**"));
        assert!(covers("team-*/**", "team-a/**"));
        assert!(covers("*", "app"));
        assert!(!covers("*", "a/b"));
        assert!(covers("*-svc", "api-svc"));
        assert!(!covers("*-svc", "*"));
        assert!(covers("acme/**/prod", "acme/prod"));
        assert!(covers("acme/**/prod", "acme/x/y/prod"));
        assert!(covers("acme/**/prod", "acme/*/prod"));
        assert!(covers("acme/**/prod", "acme/**/prod"));
        assert!(!covers("acme/**/prod", "acme/**"));
        assert!(!covers("acme/**/prod", "acme/*prod"));
        assert!(covers("exact", "exact"));
        assert!(!covers("exact", "exactly"));
    }

    /// Never says yes when some name matched by `want` escapes `grant` (checked by brute force
    /// over short names).
    #[test]
    fn covers_is_sound() {
        let patterns = ["**", "*", "x", "x/**", "x/*", "*/**", "**/x", "x*", "*x", "x/**/y", "**/", "*/", "x/", "y/**", "x**", "**x", "*/*", "x/*/y"];
        let mut names = vec![String::new()];
        for _ in 0..4 {
            let more: Vec<String> = names.iter().flat_map(|n| ["x", "y", "/"].map(|c| format!("{n}{c}"))).collect();
            names.extend(more);
        }
        names.sort();
        names.dedup();
        for g in patterns {
            for w in patterns {
                if covers(g, w) {
                    for n in &names {
                        assert!(!glob::matches(w, n) || glob::matches(g, n), "covers({g:?}, {w:?}) but {n:?} matches only the latter");
                    }
                }
            }
        }
    }

    #[test]
    fn rules_cover_needs_the_action() {
        let rules = vec![Rule { repositories: vec!["team-a/**".into()], actions: vec![Action::Pull] }];
        assert!(rules_cover(&rules, Action::Pull, "team-a/*"));
        assert!(!rules_cover(&rules, Action::Push, "team-a/*"));
        let admin = vec![Rule { repositories: vec!["team-a/**".into()], actions: vec![Action::Admin] }];
        assert!(rules_cover(&admin, Action::Push, "team-a/app"));
    }
}
