//! Secrets at rest: which columns hold secrets, how many are sealed under which key, and
//! re-sealing them under the current key (`kontainer encryption-status`,
//! `kontainer rotate-encryption-key`). Sealing and opening happen in each module's queries
//! through [`Db::seal_secret`] and [`Db::open_secret`]; see [`kontainer_core::crypto`].

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Serialize;
use sqlx::AssertSqlSafe;

use kontainer_core::crypto::KeyUse;

use super::Db;

/// A column holding secrets.
#[derive(Debug, Clone, Copy)]
pub struct SecretColumn {
    pub table: &'static str,
    pub column: &'static str,
    /// The primary key (one column), and its SQL type.
    pub id: &'static str,
    pub id_type: &'static str,
    /// Narrows the rows, for tables where only some rows hold secrets.
    pub filter: &'static str,
}

impl SecretColumn {
    pub fn name(&self) -> String {
        format!("{}.{}", self.table, self.column)
    }
}

const fn col(table: &'static str, column: &'static str) -> SecretColumn {
    SecretColumn { table, column, id: "id", id_type: "BIGINT", filter: "true" }
}

/// Every secret column, sealed when written and opened when read. Password, token and
/// recovery-code hashes are not here: they are hashes, not secrets to recover.
pub const SECRET_COLUMNS: &[SecretColumn] = &[
    col("registries", "password"),
    col("webhooks", "secret"),
    col("webhooks", "auth_header"),
    col("build_triggers", "git_token"),
    col("build_triggers", "secret"),
    SecretColumn { table: "org_sso", column: "client_secret", id: "org_id", id_type: "BIGINT", filter: "true" },
    // TOTP secrets: the account's, and one being set up.
    col("users", "mfa_secret"),
    SecretColumn { table: "mfa_setups", column: "secret", id: "user_id", id_type: "BIGINT", filter: "true" },
    // `SECRET_META_KEYS`.
    SecretColumn { table: "meta", column: "value", id: "key", id_type: "TEXT", filter: "key IN ('jwt_secret')" },
];

/// What a secret column holds, by key.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ColumnStatus {
    pub column: String,
    pub plaintext: i64,
    pub current: i64,
    /// Rows per previous key id.
    pub previous: BTreeMap<String, i64>,
    /// Rows per key id the keyring doesn't have (`malformed` for unreadable envelopes).
    pub unknown: BTreeMap<String, i64>,
}

impl ColumnStatus {
    pub fn total(&self) -> i64 {
        self.plaintext + self.current + self.previous.values().sum::<i64>() + self.unknown.values().sum::<i64>()
    }
}

/// Rows of a secret column re-sealed by a rotation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Resealed {
    pub column: String,
    pub resealed: u64,
}

impl Db {
    /// How the stored secrets are sealed, column by column.
    pub async fn encryption_status(&self) -> Result<Vec<ColumnStatus>> {
        let mut out = vec![];
        for c in SECRET_COLUMNS {
            let sql = format!(
                "SELECT CASE WHEN {col} LIKE 'enc:v1:%' THEN split_part({col}, ':', 3) WHEN {col} LIKE 'enc:v0:%' OR {col} NOT LIKE 'enc:%' THEN NULL ELSE 'malformed' END AS k, count(*)::BIGINT
                 FROM {table} WHERE {col} IS NOT NULL AND {filter} GROUP BY k",
                col = c.column,
                table = c.table,
                filter = c.filter
            );
            let rows: Vec<(Option<String>, i64)> = sqlx::query_as(AssertSqlSafe(sql)).fetch_all(self.pool()).await.with_context(|| format!("counting {}", c.name()))?;
            let mut s = ColumnStatus { column: c.name(), ..Default::default() };
            for (key, n) in rows {
                let used = if key.as_deref() == Some("malformed") { KeyUse::Unknown("malformed".into()) } else { self.keyring().classify_id(key.as_deref()) };
                match used {
                    KeyUse::Plaintext => s.plaintext += n,
                    KeyUse::Current => s.current += n,
                    KeyUse::Previous(id) => *s.previous.entry(id).or_default() += n,
                    KeyUse::Unknown(id) => *s.unknown.entry(id).or_default() += n,
                }
            }
            out.push(s);
        }
        Ok(out)
    }

    /// Re-seal every stored secret that isn't under the current key (or, with no current key,
    /// every sealed one, which decrypts them), `batch` rows per transaction. Rows already
    /// current are left alone, so it can run again; a value no configured key opens stops it,
    /// naming the column and row.
    pub async fn reseal_secrets(&self, batch: i64) -> Result<Vec<Resealed>> {
        let keyring = self.keyring();
        // Rows that need work: anything but the current key's envelopes, or (no key) envelopes.
        let (op, pattern) = match keyring.current_id() {
            Some(id) => ("NOT LIKE", format!("enc:v1:{id}:%")),
            None => ("LIKE", "enc:v1:%".to_string()),
        };
        let mut out = vec![];
        for c in SECRET_COLUMNS {
            let select = format!(
                "SELECT {id}::TEXT, {col} FROM {table} WHERE {col} IS NOT NULL AND {filter} AND {col} {op} $1 AND ($2::TEXT IS NULL OR {id} > CAST($2::TEXT AS {ty}))
                 ORDER BY {id} LIMIT $3 FOR UPDATE",
                id = c.id,
                ty = c.id_type,
                col = c.column,
                table = c.table,
                filter = c.filter
            );
            let update = format!("UPDATE {table} SET {col} = $1 WHERE {id} = CAST($2::TEXT AS {ty})", table = c.table, col = c.column, id = c.id, ty = c.id_type);
            let (mut done, mut after) = (0u64, None::<String>);
            loop {
                let mut tx = self.pool().begin().await?;
                let rows: Vec<(String, String)> = sqlx::query_as(AssertSqlSafe(select.clone())).bind(&pattern).bind(&after).bind(batch.max(1)).fetch_all(&mut *tx).await.with_context(|| format!("reading {}", c.name()))?;
                for (id, stored) in &rows {
                    // A plaintext value under no key is already as it should be.
                    if keyring.is_current(stored) {
                        continue;
                    }
                    let plain = self.open_secret(&c.name(), id, stored)?;
                    sqlx::query(AssertSqlSafe(update.clone())).bind(keyring.seal(&plain)).bind(id).execute(&mut *tx).await?;
                    done += 1;
                }
                tx.commit().await?;
                if (rows.len() as i64) < batch.max(1) {
                    break;
                }
                after = rows.last().map(|(id, _)| id.clone());
            }
            out.push(Resealed { column: c.name(), resealed: done });
        }
        Ok(out)
    }

    /// At startup: fail when stored secrets need a key that isn't configured, and warn about
    /// secrets stored unencrypted.
    pub async fn check_secrets_at_rest(&self) -> Result<()> {
        let status = self.encryption_status().await?;
        let unknown: Vec<String> = status.iter().filter(|s| !s.unknown.is_empty()).map(|s| format!("{} (key {})", s.column, s.unknown.keys().cloned().collect::<Vec<_>>().join(", "))).collect();
        if !unknown.is_empty() {
            let have = match self.keyring().current_id() {
                None => "no encryption key is configured (auth.encryption_key, auth.secret)".to_string(),
                Some(id) => format!("the configured keys are {id} (current) and [{}] (auth.previous_encryption_keys)", self.keyring().previous_ids().join(", ")),
            };
            anyhow::bail!("the database holds secrets encrypted with keys this instance doesn't have: {}; {have}. Configure the key they were encrypted with (a restore needs the key the backup was made with)", unknown.join("; "));
        }
        let plaintext: i64 = status.iter().map(|s| s.plaintext).sum();
        match self.keyring().current_id() {
            None => tracing::warn!("auth.encryption_key and auth.secret are not set: secrets stored in the database (upstream passwords, webhook secrets, Git tokens, ...) are not encrypted"),
            Some(_) if plaintext > 0 => tracing::warn!(rows = plaintext, "secrets stored in the database before encryption was enabled are still plaintext: run `kontainer rotate-encryption-key` to encrypt them"),
            Some(id) => tracing::debug!(key = id, "secrets at rest are encrypted"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use kontainer_core::crypto::{DataKey, Keyring};

    use super::*;
    use crate::database::remote::RegistryInput;
    use crate::database::test_support::fresh_database_url;

    const K1: &str = "first-key-0123456789abcdef0123456789";
    const K2: &str = "second-key-0123456789abcdef012345678";

    fn ring(current: Option<&str>, previous: &[&str]) -> Keyring {
        Keyring::new(current.map(DataKey::from_material), previous.iter().map(|p| DataKey::from_material(p)))
    }

    fn input(name: &str, password: &str) -> RegistryInput {
        RegistryInput { name: name.into(), url: "https://up.example".into(), username: Some("u".into()), password: Some(password.into()), is_insecure: false }
    }

    async fn raw(db: &Db, sql: &str) -> Vec<String> {
        sqlx::query_scalar(AssertSqlSafe(sql.to_string())).fetch_all(db.pool()).await.unwrap()
    }

    fn of<'a>(status: &'a [ColumnStatus], column: &str) -> &'a ColumnStatus {
        status.iter().find(|s| s.column == column).unwrap()
    }

    #[tokio::test]
    async fn secrets_are_sealed_rotated_and_counted() {
        let url = fresh_database_url();
        // Before encryption: plaintext, as older versions wrote it.
        let plain = Db::open(&url, 2).await.unwrap();
        let a = plain.create_registry(&input("a", "pw-a")).await.unwrap();
        assert_eq!(raw(&plain, "SELECT password FROM registries").await, ["pw-a"]);
        plain.meta_init("jwt_secret", "signing-secret").await.unwrap();

        // Key 1: new values are sealed; old ones still read; reads hand back plaintext.
        let k1 = Db::open(&url, 2).await.unwrap().with_keyring(ring(Some(K1), &[]));
        let id1 = k1.keyring().current_id().unwrap().to_string();
        let b = k1.create_registry(&input("b", "pw-b")).await.unwrap();
        assert_eq!(b.password.as_deref(), Some("pw-b"));
        let stored = raw(&k1, &format!("SELECT password FROM registries WHERE id = {}", b.id)).await;
        assert!(stored[0].starts_with(&format!("enc:v1:{id1}:")) && !stored[0].contains("pw-b"), "{stored:?}");
        assert_eq!(k1.registry(a.id).await.unwrap().unwrap().password.as_deref(), Some("pw-a"));
        let s = k1.encryption_status().await.unwrap();
        assert_eq!((of(&s, "registries.password").plaintext, of(&s, "registries.password").current), (1, 1));
        assert_eq!(of(&s, "meta.value").plaintext, 1);
        // Encrypting what was plaintext.
        let r = k1.reseal_secrets(1).await.unwrap();
        assert_eq!(r.iter().find(|r| r.column == "registries.password").unwrap().resealed, 1);
        assert_eq!(r.iter().find(|r| r.column == "meta.value").unwrap().resealed, 1);
        let s = k1.encryption_status().await.unwrap();
        assert!(s.iter().all(|c| c.plaintext == 0), "{s:?}");
        assert_eq!(of(&s, "registries.password").current, 2);
        assert!(raw(&k1, "SELECT value FROM meta WHERE key = 'jwt_secret'").await[0].starts_with("enc:v1:"));
        assert_eq!(k1.meta_get("jwt_secret").await.unwrap().as_deref(), Some("signing-secret"));

        // Without the key, sealed values are refused with the column, the row and the key.
        let err = plain.registry(b.id).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("registries.password") && msg.contains(&format!("row {}", b.id)) && msg.contains(&id1), "{msg}");
        assert!(format!("{:#}", plain.check_secrets_at_rest().await.unwrap_err()).contains(&id1));
        k1.check_secrets_at_rest().await.unwrap();

        // Rotation to key 2, key 1 kept as previous.
        let k2 = Db::open(&url, 2).await.unwrap().with_keyring(ring(Some(K2), &[K1]));
        let id2 = k2.keyring().current_id().unwrap().to_string();
        let s = k2.encryption_status().await.unwrap();
        assert_eq!(of(&s, "registries.password").previous.get(&id1), Some(&2));
        assert_eq!(k2.registry(a.id).await.unwrap().unwrap().password.as_deref(), Some("pw-a"));
        let r = k2.reseal_secrets(500).await.unwrap();
        assert_eq!(r.iter().map(|r| r.resealed).sum::<u64>(), 3);
        let again = k2.reseal_secrets(500).await.unwrap();
        assert_eq!(again.iter().map(|r| r.resealed).sum::<u64>(), 0, "idempotent");
        let s = k2.encryption_status().await.unwrap();
        assert!(s.iter().all(|c| c.previous.is_empty() && c.unknown.is_empty() && c.plaintext == 0), "{s:?}");
        assert_eq!(of(&s, "registries.password").current, 2);
        // Key 1 can go now.
        let only2 = Db::open(&url, 2).await.unwrap().with_keyring(ring(Some(K2), &[]));
        assert_eq!(only2.registry(b.id).await.unwrap().unwrap().password.as_deref(), Some("pw-b"));
        assert_eq!(only2.meta_get("jwt_secret").await.unwrap().as_deref(), Some("signing-secret"));
        assert!(raw(&only2, "SELECT password FROM registries").await.iter().all(|p| p.starts_with(&format!("enc:v1:{id2}:"))));
        // An unknown key shows up as such.
        let s = Db::open(&url, 2).await.unwrap().with_keyring(ring(Some(K1), &[])).encryption_status().await.unwrap();
        assert_eq!(of(&s, "registries.password").unknown.get(&id2), Some(&2));

        // Rotating with no current key decrypts.
        let off = Db::open(&url, 2).await.unwrap().with_keyring(ring(None, &[K2]));
        off.reseal_secrets(500).await.unwrap();
        assert_eq!(raw(&off, "SELECT password FROM registries ORDER BY id").await, ["pw-a", "pw-b"]);
    }

    #[tokio::test]
    async fn every_secret_column_is_sealed() {
        use crate::database::builds::TriggerInput;
        use crate::database::sso::OrgSsoInput;
        use crate::database::webhooks::WebhookInput;

        let db = Db::open(&fresh_database_url(), 2).await.unwrap().with_keyring(ring(Some(K1), &[]));
        let hook = WebhookInput { name: "h".into(), url: "https://hooks.example/x".into(), format: "default".into(), events: vec![], repositories: vec![], secret: Some("hmac-key".into()), auth_header: Some("Bearer t".into()), is_verify_tls: true, is_enabled: true };
        let h = db.create_webhook("ns", &hook, "admin").await.unwrap();
        assert_eq!((h.secret.as_deref(), h.auth_header.as_deref()), (Some("hmac-key"), Some("Bearer t")));
        db.update_webhook(h.id, &WebhookInput { secret: None, auth_header: Some("Bearer u".into()), ..hook.clone() }).await.unwrap();
        let h = db.webhook(h.id).await.unwrap().unwrap();
        assert_eq!((h.secret.as_deref(), h.auth_header.as_deref()), (Some("hmac-key"), Some("Bearer u")));
        assert_eq!(db.all_webhooks().await.unwrap()[0].auth_header.as_deref(), Some("Bearer u"));

        let t = TriggerInput { name: "t".into(), git_url: "https://git.example/r.git".into(), git_username: None, git_token: Some("ghp_x".into()), branches: vec![], dockerfile: None, context: None, tags: vec![], is_enabled: true, poll_secs: Some(60) };
        let tr = db.create_build_trigger("ns/app", &t, "whsec", "admin").await.unwrap();
        assert_eq!((tr.git_token.as_deref(), tr.secret.as_str()), (Some("ghp_x"), "whsec"));
        db.update_build_trigger(tr.id, &TriggerInput { git_token: None, ..t.clone() }).await.unwrap();
        db.set_build_trigger_secret(tr.id, "whsec2").await.unwrap();
        let tr = db.polling_build_triggers().await.unwrap().remove(0);
        assert_eq!((tr.git_token.as_deref(), tr.secret.as_str()), (Some("ghp_x"), "whsec2"));

        let org: i64 = sqlx::query_scalar("INSERT INTO organizations (name, created_at) VALUES ('o', now()) RETURNING id").fetch_one(db.pool()).await.unwrap();
        let sso = OrgSsoInput { issuer: "https://idp.example".into(), client_id: "c".into(), client_secret: Some("cs".into()), display_name: None, groups_claim: None };
        db.set_org_sso(org, &sso).await.unwrap();
        db.set_org_sso(org, &OrgSsoInput { client_secret: None, ..sso }).await.unwrap();
        assert_eq!(db.org_sso(org).await.unwrap().unwrap().client_secret, "cs");

        // TOTP: one account with it on, another setting it up.
        let on = db.create_user("totp-on", None, None, None, false, None, false).await.unwrap();
        db.start_mfa_setup(on.id, "TOTPSECRET", chrono::Duration::minutes(15)).await.unwrap();
        assert!(db.complete_mfa_setup(on.id, "TOTPSECRET", &[]).await.unwrap(), "the sealed pending secret compares by plaintext");
        let on = db.user_by_id(on.id).await.unwrap().unwrap();
        assert_eq!(db.user_mfa_secret(&on).unwrap().as_deref(), Some("TOTPSECRET"));
        let pending = db.create_user("totp-pending", None, None, None, false, None, false).await.unwrap();
        db.start_mfa_setup(pending.id, "PENDINGSECRET", chrono::Duration::minutes(15)).await.unwrap();
        assert_eq!(db.pending_mfa_secret(pending.id).await.unwrap().as_deref(), Some("PENDINGSECRET"));
        let n: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM users WHERE mfa_secret = 'TOTPSECRET') + (SELECT count(*) FROM mfa_setups WHERE secret = 'PENDINGSECRET')").fetch_one(db.pool()).await.unwrap();
        assert_eq!(n, 0, "TOTP secrets stored in plaintext");

        db.meta_init("jwt_secret", "s").await.unwrap();
        let s = db.encryption_status().await.unwrap();
        for c in SECRET_COLUMNS.iter().filter(|c| c.table != "registries") {
            let st = of(&s, &c.name());
            assert!(st.current >= 1 && st.plaintext == 0, "{st:?}");
        }
        for leaked in ["hmac-key", "Bearer u", "ghp_x", "whsec2", "cs"] {
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM webhooks, build_triggers, org_sso WHERE webhooks.secret = $1 OR webhooks.auth_header = $1 OR build_triggers.git_token = $1 OR build_triggers.secret = $1 OR org_sso.client_secret = $1")
                .bind(leaked)
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_eq!(n, 0, "{leaked} stored in plaintext");
        }
    }
}
