//! Organizations, teams and memberships.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{now, Db, User};
use std::collections::HashMap;

use kontainer_core::glob;
use kontainer_core::perm::{Level, Rule, TeamGrant, TeamRole};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Organization {
    pub id: i64,
    pub name: String,
    pub display_name: Option<String>,
    pub description: String,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TeamRow {
    pub id: i64,
    pub org_id: i64,
    pub name: String,
    pub description: String,
    pub rules: String,
    pub is_org_admin: bool,
    pub created_at: DateTime<Utc>,
    pub role: String,
    pub base_permission: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Team {
    pub id: i64,
    pub org_id: i64,
    pub name: String,
    pub description: String,
    pub role: TeamRole,
    /// Access to every repository in the org.
    pub base_permission: Option<Level>,
    #[serde(with = "super::rfc3339")]
    pub created_at: DateTime<Utc>,
}

impl Team {
    pub fn is_admin(&self) -> bool {
        self.role == TeamRole::Admin
    }
}

/// One repository grant, joined to its subject for display.
#[derive(Debug, Clone, Serialize)]
pub struct RepoGrant {
    pub kind: &'static str,
    pub name: String,
    pub display_name: Option<String>,
    pub is_robot: bool,
    pub level: Level,
}

impl TeamRow {
    pub fn into_team(self) -> Team {
        Team {
            id: self.id,
            org_id: self.org_id,
            name: self.name,
            description: self.description,
            role: TeamRole::parse(&self.role),
            base_permission: self.base_permission.as_deref().and_then(Level::parse),
            created_at: self.created_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TeamGrantRow {
    pub org: String,
    pub team: String,
    pub role: String,
    pub base_permission: Option<String>,
}

impl Db {
    /// Usernames and organization names share one namespace.
    pub async fn name_taken(&self, name: &str) -> Result<bool> {
        let u: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1").bind(name).fetch_one(&self.pool).await?;
        let o: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organizations WHERE name = $1").bind(name).fetch_one(&self.pool).await?;
        let p: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proxy_caches WHERE namespace = $1").bind(name).fetch_one(&self.pool).await?;
        Ok(u + o + p > 0)
    }

    pub async fn create_org(&self, name: &str, display_name: Option<&str>, description: &str) -> Result<Organization> {
        let id: i64 = sqlx::query_scalar("INSERT INTO organizations(name, display_name, description, created_at) VALUES ($1, $2, $3, $4) RETURNING id")
            .bind(name)
            .bind(display_name)
            .bind(description)
            .bind(now())
            .fetch_one(&self.pool)
            .await?;
        Ok(self.org_by_id(id).await?.expect("just inserted"))
    }

    pub async fn org_by_id(&self, id: i64) -> Result<Option<Organization>> {
        Ok(sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = $1").bind(id).fetch_optional(&self.pool).await?)
    }

    pub async fn org_by_name(&self, name: &str) -> Result<Option<Organization>> {
        Ok(sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE name = $1").bind(name).fetch_optional(&self.pool).await?)
    }

    pub async fn list_orgs(&self) -> Result<Vec<Organization>> {
        Ok(sqlx::query_as::<_, Organization>("SELECT * FROM organizations ORDER BY name").fetch_all(&self.pool).await?)
    }

    /// Organizations the user belongs to through any team.
    /// The longest Time Machine window any organization sets, if any does.
    pub async fn longest_org_time_machine(&self) -> Result<Option<i64>> {
        Ok(sqlx::query_scalar("SELECT MAX(time_machine_secs) FROM organizations").fetch_one(&self.pool).await?)
    }

    pub async fn orgs_for_user(&self, user_id: i64) -> Result<Vec<Organization>> {
        Ok(sqlx::query_as::<_, Organization>(
            "SELECT DISTINCT o.* FROM organizations o JOIN teams t ON t.org_id = o.id JOIN team_members m ON m.team_id = t.id WHERE m.user_id = $1 ORDER BY o.name",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn update_org(&self, id: i64, display_name: Option<&str>, description: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE organizations SET display_name = COALESCE($1, display_name), description = COALESCE($2, description) WHERE id = $3")
            .bind(display_name)
            .bind(description)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_org(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM organizations WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn org_robots(&self, org_id: i64) -> Result<Vec<User>> {
        Ok(sqlx::query_as::<_, User>("SELECT * FROM users WHERE org_id = $1 ORDER BY username").bind(org_id).fetch_all(&self.pool).await?)
    }

    pub async fn create_org_robot(&self, org_id: i64, username: &str, description: Option<&str>) -> Result<User> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO users(username, display_name, is_robot, org_id, created_at) VALUES ($1, $2, true, $3, $4) RETURNING id",
        )
        .bind(username)
        .bind(description)
        .bind(org_id)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        Ok(self.user_by_id(id).await?.expect("just inserted"))
    }

    pub async fn create_team(&self, org_id: i64, name: &str, description: &str, role: TeamRole, base: Option<Level>) -> Result<Team> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO teams(org_id, name, description, role, base_permission, is_org_admin, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(org_id)
        .bind(name)
        .bind(description)
        .bind(role.as_str())
        .bind(base.map(Level::as_string))
        .bind(role == TeamRole::Admin)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        Ok(self.team_by_id(id).await?.expect("just inserted"))
    }

    pub async fn team_by_id(&self, id: i64) -> Result<Option<Team>> {
        Ok(sqlx::query_as::<_, TeamRow>("SELECT * FROM teams WHERE id = $1").bind(id).fetch_optional(&self.pool).await?.map(TeamRow::into_team))
    }

    pub async fn team_by_name(&self, org_id: i64, name: &str) -> Result<Option<Team>> {
        Ok(sqlx::query_as::<_, TeamRow>("SELECT * FROM teams WHERE org_id = $1 AND name = $2")
            .bind(org_id)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .map(TeamRow::into_team))
    }

    pub async fn list_teams(&self, org_id: i64) -> Result<Vec<Team>> {
        Ok(sqlx::query_as::<_, TeamRow>("SELECT * FROM teams WHERE org_id = $1 ORDER BY name")
            .bind(org_id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(TeamRow::into_team)
            .collect())
    }

    pub async fn update_team(&self, id: i64, description: &str, role: TeamRole, base: Option<Level>) -> Result<()> {
        sqlx::query("UPDATE teams SET description = $1, role = $2, base_permission = $3, is_org_admin = $4 WHERE id = $5")
            .bind(description)
            .bind(role.as_str())
            .bind(base.map(Level::as_string))
            .bind(role == TeamRole::Admin)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_team(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM teams WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn team_members(&self, team_id: i64) -> Result<Vec<User>> {
        Ok(sqlx::query_as::<_, User>("SELECT u.* FROM users u JOIN team_members m ON m.user_id = u.id WHERE m.team_id = $1 ORDER BY u.username")
            .bind(team_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn add_team_member(&self, team_id: i64, user_id: i64) -> Result<()> {
        sqlx::query("INSERT INTO team_members(team_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(team_id).bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn remove_team_member(&self, team_id: i64, user_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2").bind(team_id).bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    /// Number of org-admin members across the org, used to keep at least one.
    pub async fn org_admin_count(&self, org_id: i64) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(DISTINCT m.user_id) FROM team_members m JOIN teams t ON t.id = m.team_id JOIN users u ON u.id = m.user_id WHERE t.org_id = $1 AND t.role = 'admin' AND u.is_robot = false AND u.is_disabled = false",
        )
        .bind(org_id)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Every team grant a user holds, resolved to org names.
    pub async fn team_grants(&self, user_id: i64) -> Result<Vec<TeamGrant>> {
        let rows = sqlx::query_as::<_, TeamGrantRow>(
            "SELECT o.name AS org, t.name AS team, t.role, t.base_permission FROM team_members m JOIN teams t ON t.id = m.team_id JOIN organizations o ON o.id = t.org_id WHERE m.user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| TeamGrant { org: r.org, team: r.team, role: TeamRole::parse(&r.role), base: r.base_permission.as_deref().and_then(Level::parse) })
            .collect())
    }

    /// Repository grants that apply to a user directly or through any of their teams,
    /// reduced to the strongest level per repository.
    pub async fn effective_repo_grants(&self, user_id: i64) -> Result<HashMap<String, Level>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT repository, level FROM repo_user_permissions WHERE user_id = $1
             UNION ALL
             SELECT p.repository, p.level FROM repo_team_permissions p JOIN team_members m ON m.team_id = p.team_id WHERE m.user_id = $2",
        )
        .bind(user_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out: HashMap<String, Level> = HashMap::new();
        for (repo, level) in rows {
            if let Some(l) = Level::parse(&level) {
                out.entry(repo).and_modify(|e| *e = e.union(l)).or_insert(l);
            }
        }
        Ok(out)
    }

    pub async fn repo_grants(&self, repository: &str) -> Result<Vec<RepoGrant>> {
        let users: Vec<(String, Option<String>, bool, String)> = sqlx::query_as(
            "SELECT u.username, u.display_name, u.is_robot, p.level FROM repo_user_permissions p JOIN users u ON u.id = p.user_id WHERE p.repository = $1 ORDER BY u.is_robot, u.username",
        )
        .bind(repository)
        .fetch_all(&self.pool)
        .await?;
        let teams: Vec<(String, String)> = sqlx::query_as(
            "SELECT t.name, p.level FROM repo_team_permissions p JOIN teams t ON t.id = p.team_id WHERE p.repository = $1 ORDER BY t.name",
        )
        .bind(repository)
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<RepoGrant> = teams
            .into_iter()
            .filter_map(|(name, l)| Some(RepoGrant { kind: "team", name, display_name: None, is_robot: false, level: Level::parse(&l)? }))
            .collect();
        out.extend(users.into_iter().filter_map(|(name, display_name, is_robot, l)| {
            Some(RepoGrant { kind: if is_robot { "robot" } else { "user" }, name, display_name, is_robot, level: Level::parse(&l)? })
        }));
        Ok(out)
    }

    pub async fn set_user_grant(&self, repository: &str, user_id: i64, level: Option<Level>) -> Result<()> {
        match level {
            Some(l) => sqlx::query(
                "INSERT INTO repo_user_permissions(repository, user_id, level, created_at) VALUES ($1, $2, $3, $4)
                 ON CONFLICT(repository, user_id) DO UPDATE SET level = excluded.level",
            )
            .bind(repository)
            .bind(user_id)
            .bind(l.as_string())
            .bind(now())
            .execute(&self.pool)
            .await?,
            None => sqlx::query("DELETE FROM repo_user_permissions WHERE repository = $1 AND user_id = $2").bind(repository).bind(user_id).execute(&self.pool).await?,
        };
        Ok(())
    }

    pub async fn set_team_grant(&self, repository: &str, team_id: i64, level: Option<Level>) -> Result<()> {
        match level {
            Some(l) => sqlx::query(
                "INSERT INTO repo_team_permissions(repository, team_id, level, created_at) VALUES ($1, $2, $3, $4)
                 ON CONFLICT(repository, team_id) DO UPDATE SET level = excluded.level",
            )
            .bind(repository)
            .bind(team_id)
            .bind(l.as_string())
            .bind(now())
            .execute(&self.pool)
            .await?,
            None => sqlx::query("DELETE FROM repo_team_permissions WHERE repository = $1 AND team_id = $2").bind(repository).bind(team_id).execute(&self.pool).await?,
        };
        Ok(())
    }

    /// Repositories a team has an explicit grant on.
    pub async fn team_repo_grants(&self, team_id: i64) -> Result<Vec<(String, Level)>> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT repository, level FROM repo_team_permissions WHERE team_id = $1 ORDER BY repository")
            .bind(team_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().filter_map(|(r, l)| Some((r, Level::parse(&l)?))).collect())
    }

    /// Repositories a user or robot has an explicit grant on.
    pub async fn user_repo_grants(&self, user_id: i64) -> Result<Vec<(String, Level)>> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT repository, level FROM repo_user_permissions WHERE user_id = $1 ORDER BY repository")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().filter_map(|(r, l)| Some((r, Level::parse(&l)?))).collect())
    }

    pub async fn delete_repo_grants(&self, repository: &str) -> Result<()> {
        sqlx::query("DELETE FROM repo_user_permissions WHERE repository = $1").bind(repository).execute(&self.pool).await?;
        sqlx::query("DELETE FROM repo_team_permissions WHERE repository = $1").bind(repository).execute(&self.pool).await?;
        Ok(())
    }

    /// Rename a namespace (an organization or a user) and everything that stores its name:
    /// robots (`old+x`), repository metadata, stars and repository grants. One transaction.
    pub async fn rename_namespace(&self, old: &str, new: &str, org_id: Option<i64>, user_id: Option<i64>) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        match (org_id, user_id) {
            (Some(id), _) => {
                sqlx::query("UPDATE organizations SET name = $1 WHERE id = $2").bind(new).bind(id).execute(&mut *tx).await?;
                sqlx::query("UPDATE users SET username = $1 || substr(username, $2::int) WHERE org_id = $3 AND substr(username, 1, $4::int) = $5")
                    .bind(format!("{new}+"))
                    .bind(old.len() as i64 + 2)
                    .bind(id)
                    .bind(old.len() as i64 + 1)
                    .bind(format!("{old}+"))
                    .execute(&mut *tx)
                    .await?;
            }
            (None, Some(id)) => {
                sqlx::query("UPDATE users SET username = $1 WHERE id = $2").bind(new).bind(id).execute(&mut *tx).await?;
                sqlx::query("UPDATE users SET username = $1 || substr(username, $2::int) WHERE owner_id = $3 AND substr(username, 1, $4::int) = $5")
                    .bind(format!("{new}+"))
                    .bind(old.len() as i64 + 2)
                    .bind(id)
                    .bind(old.len() as i64 + 1)
                    .bind(format!("{old}+"))
                    .execute(&mut *tx)
                    .await?;
            }
            (None, None) => anyhow::bail!("rename_namespace needs an organization or a user"),
        }
        // `substr` rather than LIKE: names may contain `_`, a LIKE wildcard.
        const UPDATES: [&str; 11] = [
            "UPDATE repositories SET name = $1 || substr(name, $2::int) WHERE substr(name, 1, $3::int) = $4",
            "UPDATE stars SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
            "UPDATE repo_user_permissions SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
            "UPDATE repo_team_permissions SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
            "UPDATE repo_imports SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
            "UPDATE mirrors SET target = $1 || substr(target, $2::int) WHERE substr(target, 1, $3::int) = $4",
            "UPDATE tag_events SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
            "UPDATE tag_expirations SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
            "UPDATE repo_states SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
            "UPDATE build_triggers SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
            "UPDATE builds SET repository = $1 || substr(repository, $2::int) WHERE substr(repository, 1, $3::int) = $4",
        ];
        for sql in UPDATES {
            sqlx::query(sql)
                .bind(format!("{new}/"))
                .bind(old.len() as i64 + 2)
                .bind(old.len() as i64 + 1)
                .bind(format!("{old}/"))
                .execute(&mut *tx)
                .await?;
        }
        // Quotas, retention policies, webhooks and security policies are keyed by namespace too.
        sqlx::query("UPDATE retention_policies SET namespace = $1 WHERE namespace = $2").bind(new).bind(old).execute(&mut *tx).await?;
        sqlx::query("UPDATE quotas SET namespace = $1 WHERE namespace = $2").bind(new).bind(old).execute(&mut *tx).await?;
        sqlx::query("UPDATE webhooks SET namespace = $1 WHERE namespace = $2").bind(new).bind(old).execute(&mut *tx).await?;
        sqlx::query("UPDATE security_policies SET namespace = $1 WHERE namespace = $2").bind(new).bind(old).execute(&mut *tx).await?;
        sqlx::query("UPDATE cve_allowlist SET namespace = $1 WHERE namespace = $2").bind(new).bind(old).execute(&mut *tx).await?;
        // The registry content: manifests (and their tags) and blob links.
        Self::rename_registry_namespace(&mut tx, old, new).await?;
        tx.commit().await?;
        self.notify(&super::notify::Topic::Repos).await;
        Ok(())
    }

    /// One-time conversion of legacy glob team rules: `**` becomes the team's base permission,
    /// other patterns become grants on the repositories they match today. Rules are then cleared.
    pub async fn migrate_team_rules(&self, repositories: &[String]) -> Result<usize> {
        let rows: Vec<(i64, String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT t.id, o.name, t.rules, t.base_permission, t.role FROM teams t JOIN organizations o ON o.id = t.org_id WHERE t.rules != '[]'",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut n = 0;
        for (team_id, org, rules, base, role) in rows {
            // Admin teams already reach everything in the org; their rules carry no information.
            let rules: Vec<Rule> = if role == "admin" {
                vec![]
            } else {
                match serde_json::from_str(&rules) {
                    Ok(r) => r,
                    // Left as they are (not emptied): an operator can fix them and restart.
                    Err(e) => {
                        tracing::error!(team_id, %org, error = %e, "team has unreadable legacy rules; not converting them");
                        continue;
                    }
                }
            };
            let mut base = base.as_deref().and_then(Level::parse);
            let prefix = format!("{org}/");
            // A team's grants and the clearing of its rules land together, or not at all.
            let mut tx = self.pool.begin().await?;
            for rule in &rules {
                let level = Level::covering(&rule.actions);
                if rule.repositories.iter().any(|g| g == "**") {
                    base = Some(base.map_or(level, |b| b.union(level)));
                    continue;
                }
                for repo in repositories.iter().filter_map(|r| r.strip_prefix(&prefix).map(|rest| (r, rest))) {
                    if glob::any_matches(rule.repositories.iter(), repo.1) {
                        sqlx::query(
                            "INSERT INTO repo_team_permissions(repository, team_id, level, created_at) VALUES ($1, $2, $3, $4)
                             ON CONFLICT(repository, team_id) DO UPDATE SET level = excluded.level",
                        )
                        .bind(repo.0)
                        .bind(team_id)
                        .bind(level.as_string())
                        .bind(now())
                        .execute(&mut *tx)
                        .await?;
                    }
                }
            }
            sqlx::query("UPDATE teams SET rules = '[]', base_permission = $1 WHERE id = $2").bind(base.map(Level::as_string)).bind(team_id).execute(&mut *tx).await?;
            tx.commit().await?;
            n += 1;
        }
        Ok(n)
    }

}
