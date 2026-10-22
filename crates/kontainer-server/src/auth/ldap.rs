//! LDAP / Active Directory sign-in: find the user with a service bind, check the password by
//! binding as them, then read their groups (a group search, or `memberOf`).

use std::time::Duration;

use anyhow::{Context, Result};
use ldap3::{ldap_escape, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use kontainer_core::config::LdapConfig;

#[derive(Debug, Clone)]
pub struct LdapUser {
    pub dn: String,
    pub username: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

fn first(e: &SearchEntry, attr: &str) -> Option<String> {
    e.attrs.get(attr).and_then(|v| v.first()).cloned().filter(|v| !v.is_empty())
}

/// `CN=Developers,OU=Groups,DC=corp` -> `Developers`.
fn cn_of(dn: &str) -> String {
    dn.split(',').next().and_then(|rdn| rdn.split_once('=')).map(|(_, v)| v.to_string()).unwrap_or_else(|| dn.to_string())
}

/// `Ok(None)` when the user is unknown or the password is wrong.
pub async fn authenticate(cfg: &LdapConfig, username: &str, password: &str) -> Result<Option<LdapUser>> {
    // An empty password is an "unauthenticated bind", which many servers accept.
    if password.is_empty() || username.is_empty() {
        return Ok(None);
    }
    let settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(10)).set_starttls(cfg.is_start_tls);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &cfg.url).await.with_context(|| format!("connecting to {}", cfg.url))?;
    ldap3::drive!(conn);
    ldap.with_timeout(Duration::from_secs(10));

    let service_bind = |ldap: &mut ldap3::Ldap| {
        let (dn, pw) = (cfg.bind_dn.clone(), cfg.bind_password.clone());
        let mut ldap = ldap.clone();
        async move {
            if !dn.is_empty() {
                ldap.simple_bind(&dn, pw.expose()).await?.success().context("service bind failed")?;
            }
            anyhow::Ok(())
        }
    };
    service_bind(&mut ldap).await?;

    let filter = cfg.user_filter.replace("{username}", &ldap_escape(username));
    let attrs = vec![cfg.username_attr.as_str(), cfg.email_attr.as_str(), cfg.name_attr.as_str(), "memberOf"];
    let (entries, _) = ldap.search(&cfg.user_base_dn, Scope::Subtree, &filter, attrs).await?.success().context("searching for the user")?;
    if entries.len() != 1 {
        let _ = ldap.unbind().await;
        return Ok(None);
    }
    let entry = SearchEntry::construct(entries.into_iter().next().expect("one entry"));

    // The password check: bind as the user.
    let ok = ldap.simple_bind(&entry.dn, password).await?.rc == 0;
    if !ok {
        let _ = ldap.unbind().await;
        return Ok(None);
    }

    let mut groups: Vec<String> = vec![];
    if cfg.group_base_dn.is_empty() {
        groups.extend(entry.attrs.get("memberOf").into_iter().flatten().map(|dn| cn_of(dn)));
    } else {
        service_bind(&mut ldap).await?;
        let gf = cfg.group_filter.replace("{dn}", &ldap_escape(&entry.dn)).replace("{username}", &ldap_escape(username));
        let (gs, _) = ldap.search(&cfg.group_base_dn, Scope::Subtree, &gf, vec![cfg.group_name_attr.as_str()]).await?.success().context("searching for groups")?;
        groups.extend(gs.into_iter().filter_map(|g| first(&SearchEntry::construct(g), &cfg.group_name_attr)));
    }
    groups.sort();
    groups.dedup();
    let _ = ldap.unbind().await;
    Ok(Some(LdapUser {
        username: first(&entry, &cfg.username_attr).unwrap_or_else(|| username.to_string()),
        email: first(&entry, &cfg.email_attr),
        name: first(&entry, &cfg.name_attr),
        dn: entry.dn,
        groups,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn group_cn() {
        assert_eq!(super::cn_of("CN=Developers,OU=Groups,DC=corp,DC=example"), "Developers");
        assert_eq!(super::cn_of("plain"), "plain");
    }
}
