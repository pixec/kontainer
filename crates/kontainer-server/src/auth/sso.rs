//! What every external sign-in (LDAP, OIDC, an organization's OIDC) has in common: find or
//! create the account, map directory groups to roles, and set the membership of synced teams.

use std::collections::HashMap;

use anyhow::Result;

use crate::database::{Db, User};

/// How an unknown identity may be matched to an existing account.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Matching {
    /// Instance-configured providers are trusted to assert usernames: an existing account whose
    /// username is exactly the asserted one is linked, unless it could sign in some other way
    /// (it has a local password) or holds instance-wide permissions. Those must be linked
    /// explicitly by their owner.
    ByUsername,
    /// An organization's own provider is not: unknown identities always get a new account,
    /// unless a signed-in user is linking it to theirs.
    NewAccountOnly,
}

pub struct Identity<'a> {
    /// `ldap`, an OIDC issuer, or `org:<org>:<issuer>`.
    pub provider: &'a str,
    pub subject: &'a str,
    pub username: &'a str,
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
}

/// A valid username derived from what a provider asserts, for new accounts only: it is lossy
/// (`Alice@corp` and `alice` both give `alice`), so it is never used to find existing accounts.
pub fn sanitize_username(s: &str) -> String {
    let base: String = s.split('@').next().unwrap_or(s).chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c.to_ascii_lowercase() } else { '-' }).collect();
    let base = base.trim_matches(|c: char| !c.is_ascii_alphanumeric()).to_string();
    if base.is_empty() { "user".into() } else { base.chars().take(64).collect() }
}

/// The existing account `id` may be linked to without its owner's involvement: same username,
/// byte for byte, and nothing to take over. Accounts with a local password or any instance-wide
/// permission are never claimed this way.
async fn auto_link_target(db: &Db, id: &Identity<'_>) -> Result<Option<User>> {
    let Some(u) = db.user_by_name(id.username).await? else { return Ok(None) };
    if u.username != id.username || u.is_robot || u.password_hash.is_some() {
        return Ok(None);
    }
    for name in db.user_roles(u.id).await? {
        if db.get_role(&name).await?.is_none_or(|r| !r.global.is_empty()) {
            return Ok(None);
        }
    }
    Ok(Some(u))
}

/// The account for `id`, creating it when allowed. `link_to`: a signed-in user claiming it.
pub async fn provision(db: &Db, id: &Identity<'_>, matching: Matching, may_create: bool, default_roles: &[String], link_to: Option<i64>) -> Result<Option<User>> {
    if let Some(link) = db.identity(id.provider, id.subject).await? {
        return db.user_by_id(link.user_id).await;
    }
    if let Some(uid) = link_to {
        let user = db.user_by_id(uid).await?.filter(|u| !u.is_robot);
        if let Some(u) = &user {
            db.link_identity(id.provider, id.subject, u.id, id.email).await?;
        }
        return Ok(user);
    }
    if matching == Matching::ByUsername {
        if let Some(u) = auto_link_target(db, id).await? {
            db.link_identity(id.provider, id.subject, u.id, id.email).await?;
            return Ok(Some(u));
        }
    }
    if !may_create {
        return Ok(None);
    }
    let wanted = sanitize_username(id.username);
    let mut name = wanted.clone();
    let mut n = 1;
    while db.name_taken(&name).await? {
        n += 1;
        name = format!("{wanted}{n}");
    }
    let u = db.create_user(&name, None, id.email, id.name, false, None, false).await?;
    db.set_user_roles(u.id, default_roles).await?;
    db.link_identity(id.provider, id.subject, u.id, id.email).await?;
    Ok(Some(u))
}

/// Replace the roles that `mapping` controls with those the user's groups grant; roles given
/// by hand (not in the mapping) are left alone.
pub async fn sync_roles(db: &Db, user_id: i64, mapping: &HashMap<String, Vec<String>>, groups: &[String]) -> Result<()> {
    if mapping.is_empty() {
        return Ok(());
    }
    let managed: Vec<&String> = mapping.values().flatten().collect();
    let mut roles: Vec<String> = db.user_roles(user_id).await?.into_iter().filter(|r| !managed.contains(&r)).collect();
    for g in groups {
        if let Some(rs) = mapping.get(g) {
            roles.extend(rs.iter().cloned());
        }
    }
    roles.sort();
    roles.dedup();
    db.set_user_roles(user_id, &roles).await
}

/// Teams synced from `source` (only `org_id`'s, when given) gain or lose the user to match
/// their groups. Group names compare case-insensitively.
pub async fn sync_teams(db: &Db, user_id: i64, source: &str, org_id: Option<i64>, groups: &[String]) -> Result<()> {
    let have: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();
    for (sync, _) in db.team_syncs_for(source, org_id).await? {
        if have.contains(&sync.group_name.to_lowercase()) {
            db.add_team_member(sync.team_id, user_id).await?;
        } else {
            db.remove_team_member(sync.team_id, user_id).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kontainer_core::config::{Global, Role};

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_username("Alice@corp.example"), "alice");
        assert_eq!(sanitize_username("  -bob smith- "), "bob-smith");
        assert_eq!(sanitize_username("@@@"), "user");
        assert_eq!(sanitize_username(&"x".repeat(100)).len(), 64);
    }

    async fn db() -> Db {
        crate::database::test_support::fresh_db().await
    }

    fn ident<'a>(subject: &'a str, username: &'a str) -> Identity<'a> {
        Identity { provider: "https://idp.example", subject, username, email: None, name: None }
    }

    async fn sign_in(db: &Db, subject: &str, username: &str) -> Option<User> {
        provision(db, &ident(subject, username), Matching::ByUsername, true, &[], None).await.unwrap()
    }

    #[tokio::test]
    async fn links_only_exact_passwordless_unprivileged_accounts() {
        let db = db().await;
        let carol = db.create_user("carol", None, None, None, false, None, false).await.unwrap();
        assert_eq!(sign_in(&db, "s-carol", "carol").await.unwrap().id, carol.id, "exact match is linked");
        assert_eq!(sign_in(&db, "s-carol", "whatever").await.unwrap().id, carol.id, "then found by subject");

        let dave = db.create_user("dave", None, None, None, false, None, false).await.unwrap();
        for (sub, claimed) in [("s1", "Dave"), ("s2", "dave@evil.example"), ("s3", " dave ")] {
            let u = sign_in(&db, sub, claimed).await.unwrap();
            assert_ne!(u.id, dave.id, "{claimed:?} must not take over dave");
            assert_ne!(u.username, "dave");
        }
    }

    #[tokio::test]
    async fn never_links_accounts_with_passwords_or_global_permissions() {
        let db = db().await;
        let alice = db.create_user("alice", Some("$argon2id$hash"), None, None, false, None, false).await.unwrap();
        let u = sign_in(&db, "s-alice", "alice").await.unwrap();
        assert_ne!(u.id, alice.id);
        assert_eq!(u.username, "alice2");

        db.upsert_role(&Role { name: "admins".into(), description: String::new(), rules: vec![], global: vec![Global::UsersWrite], is_managed: false }).await.unwrap();
        let root = db.create_user("root", None, None, None, false, None, false).await.unwrap();
        db.set_user_roles(root.id, &["admins".to_string()]).await.unwrap();
        let u = sign_in(&db, "s-root", "root").await.unwrap();
        assert_ne!(u.id, root.id);

        let id = ident("s-none", "root");
        assert!(provision(&db, &id, Matching::ByUsername, false, &[], None).await.unwrap().is_none(), "no account when creation is off");

        // The owner may still link explicitly.
        let linked = provision(&db, &id, Matching::ByUsername, false, &[], Some(root.id)).await.unwrap().unwrap();
        assert_eq!(linked.id, root.id);
    }

    #[tokio::test]
    async fn org_providers_never_match_by_username() {
        let db = db().await;
        let erin = db.create_user("erin", None, None, None, false, None, false).await.unwrap();
        let u = provision(&db, &ident("s-erin", "erin"), Matching::NewAccountOnly, true, &[], None).await.unwrap().unwrap();
        assert_ne!(u.id, erin.id);
    }
}
