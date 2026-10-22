//! Registry configuration, loaded from a TOML file with environment overrides.
//!
//! Any setting can be overridden as `KONTAINER__<SECTION>__<KEY>`, e.g.
//! `KONTAINER__BUILDS__ENABLED=true` or `KONTAINER__STORAGE__S3__BUCKET=registry` (keys inside
//! maps keep their case: `KONTAINER__SCANNER__ENV__TRIVY_CACHE_DIR`). Values are
//! read as TOML (`true`, `3`, `["a", "b"]`, `"quoted"`), falling back to a plain string. The older
//! `KONTAINER_*` shorthands (see [`Config::apply_env`]) still work and win over both.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

mod auth;
mod builds;
mod observability;
mod policy;
mod runner;
mod scanner;
mod secret;
mod server;
mod storage;

pub use auth::*;
pub use builds::*;
pub use observability::*;
pub use policy::*;
pub use runner::*;
pub use scanner::*;
pub use secret::{redact_url_password, DatabaseUrl, Secret};
pub use server::*;
pub use storage::*;

pub use crate::perm::{Action, Global, Role, Rule};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub auth: AuthConfig,
    pub scanner: ScannerConfig,
    pub features: FeatureConfig,
    pub ui: UiConfig,
    pub webhooks: Vec<WebhookConfig>,
    pub policy: PolicyConfig,
    pub audit: AuditConfig,
    pub metrics: MetricsConfig,
    pub retention: RetentionConfig,
    pub builds: BuildsConfig,
    pub gc: GcConfig,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let (mut table, source) = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                (toml::from_str::<toml::Table>(&raw).with_context(|| format!("parsing config {}", p.display()))?, p.display().to_string())
            }
            None => (toml::Table::new(), "the defaults".to_string()),
        };
        let defaults = toml::Table::try_from(Config::default()).unwrap_or_default();
        check_storage_form(&table)?;
        let overridden = apply_overrides(&mut table, &defaults, OVERRIDE, std::env::vars())?;
        if !overridden.is_empty() {
            check_storage_form(&table).with_context(|| format!("with {}", overridden.join(", ")))?;
        }
        let mut cfg: Config = toml::Value::Table(table).try_into().with_context(|| {
            if overridden.is_empty() { format!("parsing config {source}") } else { format!("parsing config {source} with {}", overridden.join(", ")) }
        })?;
        cfg.apply_env()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Shorthand environment overrides for the most common knobs.
    fn apply_env(&mut self) -> Result<()> {
        if let Ok(v) = std::env::var("KONTAINER_BIND") {
            self.server.bind = v;
        }
        if let Ok(v) = std::env::var("KONTAINER_PUBLIC_URL") {
            self.server.public_url = Some(v);
        }
        if let Ok(v) = std::env::var("KONTAINER_STORAGE_LOCATION") {
            self.storage.location = v;
        }
        if !self.storage.locations.is_empty() {
            for var in ["KONTAINER_STORAGE_DRIVER", "KONTAINER_STORAGE_ROOT", "KONTAINER_S3_BUCKET", "KONTAINER_S3_ENDPOINT"] {
                anyhow::ensure!(std::env::var_os(var).is_none(), "{var} configures the flat storage driver, which [[storage.locations]] replaces: set it on the location instead");
            }
        }
        if let Ok(v) = std::env::var("KONTAINER_STORAGE_DRIVER") {
            self.storage.driver = parse_storage_driver(&v).with_context(|| format!("KONTAINER_STORAGE_DRIVER={v:?}"))?;
        }
        if let Ok(v) = std::env::var("KONTAINER_STORAGE_ROOT") {
            self.storage.filesystem.root = v.into();
        }
        if let Ok(v) = std::env::var("KONTAINER_UPLOAD_DIR") {
            self.storage.upload_dir = v.into();
        }
        if let Ok(v) = std::env::var("KONTAINER_S3_BUCKET") {
            self.storage.s3.bucket = v;
        }
        if let Ok(v) = std::env::var("KONTAINER_S3_ENDPOINT") {
            self.storage.s3.endpoint = Some(v);
        }
        if let Ok(v) = std::env::var("KONTAINER_LOG") {
            self.server.log = v;
        }
        if let Ok(v) = std::env::var("KONTAINER_DATABASE_URL") {
            self.auth.database_url = v.into();
        }
        if let Ok(v) = std::env::var("KONTAINER_METRICS_TOKEN") {
            self.metrics.token = Some(v).filter(|t| !t.is_empty()).map(Secret::from);
        }
        // A shared runner deployed with the registry (Helm, Compose) uses the same variable.
        if let Ok(token) = std::env::var("KONTAINER_RUNNER_TOKEN") {
            if !token.is_empty() && !self.builds.runners.iter().any(|r| r.name == "default") {
                self.builds.runners.push(ConfigRunner { name: "default".into(), token: token.into(), namespaces: vec![] });
            }
        }
        if let Ok(v) = std::env::var("KONTAINER_AUTH_SECRET") {
            self.auth.secret = Some(v.into());
        }
        if let Ok(v) = std::env::var("KONTAINER_ENCRYPTION_KEY") {
            self.auth.encryption_key = Some(v).filter(|k| !k.is_empty()).map(Secret::from);
        }
        if let Ok(v) = std::env::var("KONTAINER_PREVIOUS_ENCRYPTION_KEYS") {
            self.auth.previous_encryption_keys = v.split(',').map(str::trim).filter(|k| !k.is_empty()).map(Secret::from).collect();
        }
        // Credentials, always text (a digits-only password stays a password): for Kubernetes
        // secrets and Compose `.env` files.
        if let (Ok(username), Ok(password)) = (std::env::var("KONTAINER_ADMIN_USERNAME"), std::env::var("KONTAINER_ADMIN_PASSWORD")) {
            if !username.is_empty() && !password.is_empty() {
                self.auth.bootstrap_admin = Some(BootstrapAdmin { username, password: password.into() });
            }
        }
        if let Ok(v) = std::env::var("KONTAINER_OIDC_CLIENT_SECRET") {
            self.auth.oidc.client_secret = v.into();
        }
        if let Ok(v) = std::env::var("KONTAINER_LDAP_BIND_PASSWORD") {
            self.auth.ldap.bind_password = v.into();
        }
        if let Ok(v) = std::env::var("KONTAINER_SCANNER_PASSWORD") {
            self.scanner.password = Some(v).filter(|p| !p.is_empty()).map(Secret::from);
        }
        // An empty username (`KONTAINER__SCANNER__USERNAME=`) means "none": the scanner then
        // pulls with the token the registry mints per scan.
        self.scanner.username = self.scanner.username.take().filter(|u| !u.trim().is_empty());
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        let role_names: Vec<&str> = self.auth.roles.iter().map(|r| r.name.as_str()).collect();
        for r in &self.auth.roles {
            anyhow::ensure!(crate::perm::valid_role_name(&r.name), "invalid role name `{}`", r.name);
        }
        for u in &self.auth.users {
            anyhow::ensure!(crate::perm::valid_username(&u.username), "invalid username `{}`", u.username);
            anyhow::ensure!(
                u.password.is_some() || u.password_hash.is_some(),
                "user `{}` needs a password or password_hash",
                u.username
            );
            if let (None, Some(p)) = (&u.password_hash, &u.password) {
                auth::check_password_strength(p.expose()).map_err(|e| anyhow::anyhow!("auth.users `{}`: {e}", u.username))?;
            }
            for r in &u.roles {
                anyhow::ensure!(role_names.contains(&r.as_str()), "user `{}` references undefined role `{r}` (roles created in the UI cannot be referenced from the config)", u.username);
            }
        }
        if let Some(b) = &self.auth.bootstrap_admin {
            auth::check_password_strength(b.password.expose()).map_err(|e| anyhow::anyhow!("auth.bootstrap_admin (or KONTAINER_ADMIN_PASSWORD): {e}"))?;
        }
        if self.auth.mode == AuthMode::None {
            anyhow::ensure!(
                self.auth.allow_insecure_none || is_loopback_bind(&self.server.bind),
                "auth.mode = \"none\" makes every caller a superuser; with server.bind = \"{}\" anyone who can reach the server could. Use mode \"basic\" or \"token\", bind to 127.0.0.1, or set auth.allow_insecure_none = true",
                self.server.bind
            );
        }
        self.auth.database_url.validate().map_err(|e| anyhow::anyhow!("auth.database_url (or KONTAINER_DATABASE_URL) {}: {e}", self.auth.database_url))?;
        anyhow::ensure!(self.auth.database_pool >= 1, "auth.database_pool must be >= 1");
        if let Some(secret) = &self.auth.secret {
            anyhow::ensure!(secret.expose().len() >= 32, "auth.secret must be at least 32 bytes (or unset, to generate one)");
        }
        if let Some(key) = self.auth.encryption_key.as_ref().filter(|k| !k.is_empty()) {
            anyhow::ensure!(key.expose().len() >= 32, "auth.encryption_key (or KONTAINER_ENCRYPTION_KEY) must be at least 32 bytes, e.g. `openssl rand -hex 32`");
        }
        for key in &self.auth.previous_encryption_keys {
            anyhow::ensure!(key.expose().len() >= 32, "auth.previous_encryption_keys: every key must be at least 32 bytes");
        }
        let ldap = &self.auth.ldap;
        if ldap.is_enabled {
            anyhow::ensure!(!ldap.url.trim().is_empty(), "auth.ldap.url is required");
            anyhow::ensure!(!ldap.user_base_dn.trim().is_empty(), "auth.ldap.user_base_dn is required");
            let plain = ldap.url.trim().get(..7).is_some_and(|s| s.eq_ignore_ascii_case("ldap://"));
            anyhow::ensure!(
                !plain || ldap.is_start_tls || ldap.allow_insecure,
                "auth.ldap.url is plain ldap://: set start_tls = true, use ldaps://, or set allow_insecure = true to send passwords in clear text"
            );
        }
        if self.auth.oidc.is_enabled {
            anyhow::ensure!(!self.auth.oidc.issuer.is_empty(), "auth.oidc.issuer is required");
            anyhow::ensure!(!self.auth.oidc.client_id.is_empty(), "auth.oidc.client_id is required");
        }
        let check_driver = |what: &str, d: StorageDriver, s3: &S3Config, gcs: &GcsConfig, azure: &AzureConfig| -> Result<()> {
            match d {
                StorageDriver::S3 => anyhow::ensure!(!s3.bucket.is_empty(), "{what}.s3.bucket is required"),
                StorageDriver::Gcs => anyhow::ensure!(!gcs.bucket.is_empty(), "{what}.gcs.bucket is required"),
                StorageDriver::Azure => anyhow::ensure!(!azure.container.is_empty(), "{what}.azure.container is required"),
                _ => {}
            }
            Ok(())
        };
        let st = &self.storage;
        let locations = st.resolved_locations()?;
        let mut names: Vec<&str> = vec![];
        for l in &locations {
            anyhow::ensure!(!l.name.is_empty() && l.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "storage location name `{}` must be letters, digits, - or _", l.name);
            anyhow::ensure!(!names.contains(&l.name.as_str()), "storage location name `{}` is used twice", l.name);
            names.push(&l.name);
            check_driver(&format!("storage location `{}`", l.name), l.driver, &l.s3, &l.gcs, &l.azure)?;
        }
        anyhow::ensure!(names.contains(&st.location.as_str()), "storage.location (or KONTAINER_STORAGE_LOCATION) `{}` must name one of the storage locations: {}", st.location, names.join(", "));
        anyhow::ensure!(st.replication_concurrency >= 1, "storage.replication_concurrency must be >= 1");
        anyhow::ensure!(self.scanner.workers >= 1, "scanner.workers must be >= 1");
        for (key, v) in [("gc.interval", self.gc.interval), ("scanner.rescan_interval", self.scanner.rescan_interval)] {
            anyhow::ensure!(v.is_none_or(|d| d >= Duration::from_secs(600)), "{key}: at least 10m");
        }
        if let Some(v) = &self.server.max_blob_size {
            anyhow::ensure!(parse_bytes(v).is_some(), "server.max_blob_size: invalid size `{v}` (e.g. 10g)");
        }
        for p in &self.server.trusted_proxies {
            anyhow::ensure!(server::parse_net(p).is_some(), "server.trusted_proxies: `{p}` is not an IP address or CIDR range (e.g. 10.0.0.0/8)");
        }
        for (key, v) in [("default_user_quota", &self.policy.default_user_quota), ("default_org_quota", &self.policy.default_org_quota)] {
            if let Some(v) = v {
                anyhow::ensure!(parse_bytes(v).is_some(), "policy.{key}: invalid size `{v}` (e.g. 10g)");
            }
        }
        if self.builds.is_enabled {
            let b = &self.builds;
            anyhow::ensure!(b.heartbeat_timeout >= Duration::from_secs(10), "builds.heartbeat_timeout must be at least 10s");
            anyhow::ensure!(b.max_log_bytes >= 64 << 10, "builds.max_log_bytes must be at least 65536 (64 KiB)");
            let mut names = std::collections::HashSet::new();
            for r in &b.runners {
                anyhow::ensure!(!r.name.trim().is_empty() && names.insert(r.name.as_str()), "builds.runners: every runner needs a unique name");
                anyhow::ensure!(r.token.expose().len() >= 16, "builds.runners `{}`: the token needs 16+ characters", r.name);
            }
        }
        Ok(())
    }

    pub fn public_url(&self) -> String {
        self.server
            .public_url
            .clone()
            .unwrap_or_else(|| format!("http://{}", self.server.bind))
            .trim_end_matches('/')
            .to_string()
    }

    /// Token audience: explicit `auth.service`, else the host part of the public URL.
    pub fn service_name(&self) -> String {
        self.auth.service.clone().unwrap_or_else(|| {
            let url = self.public_url();
            url.split("://").nth(1).unwrap_or(&url).trim_end_matches('/').to_string()
        })
    }
}

/// `4g`, `512m`, `1024k` or plain bytes; Kubernetes-style `4Gi`, `512Mi` too (all binary units).
pub fn parse_bytes(raw: &str) -> Option<i64> {
    let raw = raw.trim().to_ascii_lowercase();
    let raw = raw.strip_suffix('b').unwrap_or(&raw);
    let raw = raw.strip_suffix('i').filter(|r| r.ends_with(['k', 'm', 'g', 't'])).unwrap_or(raw);
    let (num, mult) = match raw.chars().last()? {
        'k' => (&raw[..raw.len() - 1], 1i64 << 10),
        'm' => (&raw[..raw.len() - 1], 1 << 20),
        'g' => (&raw[..raw.len() - 1], 1 << 30),
        't' => (&raw[..raw.len() - 1], 1 << 40),
        _ => (raw, 1),
    };
    let n: f64 = num.trim().parse().ok()?;
    let bytes = n * mult as f64;
    // Also rejects NaN, infinities and sizes beyond i64.
    (n > 0.0 && bytes.is_finite() && bytes < i64::MAX as f64).then_some(bytes as i64)
}

/// `[[storage.locations]]` replaces the flat driver settings: refuse a config with both.
fn check_storage_form(table: &toml::Table) -> Result<()> {
    let Some(st) = table.get("storage").and_then(toml::Value::as_table) else { return Ok(()) };
    if st.contains_key("locations") {
        let flat: Vec<&str> = FLAT_STORAGE_KEYS.iter().copied().filter(|k| st.contains_key(*k)).collect();
        anyhow::ensure!(flat.is_empty(), "storage.locations cannot be combined with the flat storage settings ({}): move them into a [[storage.locations]] entry", flat.iter().map(|k| format!("storage.{k}")).collect::<Vec<_>>().join(", "));
    }
    Ok(())
}

/// A storage driver by name, as in `storage.driver`.
fn parse_storage_driver(v: &str) -> Result<StorageDriver> {
    StorageDriver::deserialize(toml::Value::String(v.to_string())).map_err(|_| anyhow::anyhow!("unknown storage driver `{v}`; expected one of: filesystem, s3, gcs, azure, memory"))
}

/// `127.0.0.1:5000`, `[::1]:5000`, `localhost:5000`: only this machine can connect.
pub fn is_loopback_bind(bind: &str) -> bool {
    if let Ok(addr) = bind.parse::<std::net::SocketAddr>() {
        return addr.ip().is_loopback();
    }
    let host = bind.rsplit_once(':').map_or(bind, |(h, _)| h);
    host.eq_ignore_ascii_case("localhost")
}

/// `24h`, `7d`, `90s`: the largest unit that divides the duration exactly (days from two up,
/// so a day reads `24h`).
pub fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0 => "0s".into(),
        _ if s.is_multiple_of(86400) && s >= 2 * 86400 => format!("{}d", s / 86400),
        _ if s.is_multiple_of(3600) => format!("{}h", s / 3600),
        _ if s.is_multiple_of(60) => format!("{}m", s / 60),
        _ => format!("{s}s"),
    }
}

/// Parse `"30m"`, `"24h"`, `"90s"`.
pub fn parse_duration(raw: &str) -> Option<Duration> {
    humantime_serde::parse(raw)
}

/// Minimal `humantime`-style (de)serialization for durations: `"30m"`, `"24h"`, `"90s"`.
pub(crate) mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::format_duration(*d))
    }

    /// For `Option<Duration>` fields: `#[serde(with = "humantime_serde::option")]`.
    pub mod option {
        use serde::{Deserialize, Deserializer, Serializer};
        use std::time::Duration;

        pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
            match d {
                Some(d) => s.serialize_str(&super::super::format_duration(*d)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(raw) => super::parse(&raw).map(Some).ok_or_else(|| serde::de::Error::custom(format!("invalid duration `{raw}`"))),
                None => Ok(None),
            }
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let raw = String::deserialize(d)?;
        parse(&raw).ok_or_else(|| serde::de::Error::custom(format!("invalid duration `{raw}`")))
    }

    pub fn parse(raw: &str) -> Option<Duration> {
        let raw = raw.trim();
        let idx = raw.find(|c: char| !c.is_ascii_digit())?;
        let (num, unit) = raw.split_at(idx);
        let n: u64 = num.parse().ok()?;
        let mult = match unit.trim() {
            "s" | "sec" | "secs" => 1,
            "m" | "min" | "mins" => 60,
            "h" | "hr" | "hours" => 3600,
            "d" | "days" => 86400,
            _ => return None,
        };
        n.checked_mul(mult).map(Duration::from_secs)
    }
}

/// The value at `path` in `table`, if any.
fn lookup<'a>(table: &'a toml::Table, path: &[String]) -> Option<&'a toml::Value> {
    let (last, parents) = path.split_last()?;
    let mut at = table;
    for p in parents {
        at = at.get(p)?.as_table()?;
    }
    at.get(last)
}

/// Prefix of `KONTAINER__SECTION__KEY` overrides.
const OVERRIDE: &str = "KONTAINER__";

/// Apply `KONTAINER__A__B=value` variables to `table` as `a.b = value`. Returns their names.
/// A setting that is text by default stays text (a bucket named `2024`); others are read as TOML.
fn apply_overrides(table: &mut toml::Table, defaults: &toml::Table, prefix: &str, vars: impl Iterator<Item = (String, String)>) -> Result<Vec<String>> {
    let mut vars: Vec<(String, String)> = vars.filter(|(k, _)| k.starts_with(prefix) && k.len() > prefix.len()).collect();
    vars.sort();
    for (name, raw) in &vars {
        let raw_path: Vec<&str> = name[prefix.len()..].split("__").collect();
        anyhow::ensure!(raw_path.iter().all(|s| !s.is_empty()), "{name}: empty key (use single `_` within a key and `__` between levels)");
        // Settings are lowercase; keys inside a map (`scanner.env`, `node_selector`: empty
        // tables by default) keep their case, e.g. KONTAINER__SCANNER__ENV__TRIVY_CACHE_DIR.
        let mut path: Vec<String> = vec![];
        for seg in raw_path {
            let in_map = !path.is_empty() && lookup(defaults, &path).and_then(toml::Value::as_table).is_some_and(toml::Table::is_empty);
            path.push(if in_map { seg.to_string() } else { seg.to_ascii_lowercase() });
        }
        let is_text = lookup(defaults, &path).is_some_and(toml::Value::is_str);
        let value = if is_text { None } else { toml::from_str::<toml::Table>(&format!("v = {raw}")).ok().and_then(|mut t| t.remove("v")) };
        let value = value.unwrap_or_else(|| toml::Value::String(raw.clone()));
        let (key, parents) = path.split_last().expect("not empty");
        let mut at = &mut *table;
        for p in parents {
            let entry = at.entry(p.clone()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
            at = entry.as_table_mut().with_context(|| format!("{name}: `{p}` is not a section"))?;
        }
        at.insert(key.clone(), value);
    }
    Ok(vars.into_iter().map(|(k, _)| k).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn bytes() {
        assert_eq!(super::parse_bytes("4g"), Some(4 << 30));
        assert_eq!(super::parse_bytes("512MB"), Some(512 << 20));
        assert_eq!(super::parse_bytes("1.5g"), Some(3 << 29));
        assert_eq!(super::parse_bytes("1000"), Some(1000));
        assert_eq!(super::parse_bytes("lots"), None);
        assert_eq!(super::parse_bytes("0"), None);
        assert_eq!(super::parse_bytes("-1g"), None);
        assert_eq!(super::parse_bytes("NaN"), None);
        assert_eq!(super::parse_bytes("inf"), None);
        assert_eq!(super::parse_bytes("1e30t"), None);
        assert_eq!(super::parse_bytes("4Gi"), Some(4 << 30));
        assert_eq!(super::parse_bytes("512Mi"), Some(512 << 20));
        assert_eq!(super::parse_bytes("64KiB"), Some(64 << 10));
        assert_eq!(super::parse_bytes("4i"), None);
    }

    #[test]
    fn durations() {
        assert_eq!(super::parse_duration("90s"), Some(std::time::Duration::from_secs(90)));
        assert_eq!(super::parse_duration("7d"), Some(std::time::Duration::from_secs(7 * 86400)));
        assert_eq!(super::parse_duration(&format!("{}d", u64::MAX / 86400 + 1)), None, "overflow");
        assert_eq!(super::parse_duration(&format!("{}s", u64::MAX)), Some(std::time::Duration::from_secs(u64::MAX)));
        assert_eq!(super::parse_duration("5 weeks"), None);
    }

    fn valid() -> super::Config {
        let mut cfg = super::Config::default();
        cfg.server.bind = "0.0.0.0:5000".into();
        cfg
    }

    #[test]
    fn auth_mode_none_needs_loopback_or_opt_in() {
        let mut cfg = valid();
        assert_eq!(cfg.auth.mode, super::AuthMode::Token, "authentication is on by default");
        cfg.validate().unwrap();
        cfg.auth.mode = super::AuthMode::None;
        assert!(cfg.validate().is_err());
        for bind in ["127.0.0.1:5000", "[::1]:5000", "localhost:5000"] {
            cfg.server.bind = bind.into();
            cfg.validate().unwrap();
        }
        cfg.server.bind = "[::]:5000".into();
        assert!(cfg.validate().is_err());
        cfg.auth.allow_insecure_none = true;
        cfg.validate().unwrap();
    }

    #[test]
    fn config_passwords_must_be_strong() {
        let mut cfg = valid();
        cfg.auth.bootstrap_admin = Some(super::BootstrapAdmin { username: "admin".into(), password: "short".into() });
        let e = cfg.validate().unwrap_err().to_string();
        assert!(e.contains("bootstrap_admin") && e.contains("8 characters"), "{e}");
        cfg.auth.bootstrap_admin = Some(super::BootstrapAdmin { username: "admin".into(), password: "long enough".into() });
        cfg.validate().unwrap();
        let user = |password: Option<&str>, password_hash: Option<&str>| super::User { username: "ci".into(), password_hash: password_hash.map(Into::into), password: password.map(Into::into), roles: vec![], is_robot: false, email: None };
        cfg.auth.users = vec![user(Some("pw"), None)];
        assert!(cfg.validate().unwrap_err().to_string().contains("auth.users `ci`"));
        cfg.auth.users = vec![user(None, Some("$argon2id$hash"))];
        cfg.validate().unwrap();
        cfg.auth.users = vec![user(Some("a strong one"), None)];
        cfg.validate().unwrap();
    }

    #[test]
    fn storage_driver_names() {
        assert_eq!(super::parse_storage_driver("s3").unwrap(), super::StorageDriver::S3);
        assert_eq!(super::parse_storage_driver("filesystem").unwrap(), super::StorageDriver::Filesystem);
        let e = super::parse_storage_driver("s4").unwrap_err().to_string();
        assert!(e.contains("filesystem, s3, gcs, azure, memory"), "{e}");
    }

    #[test]
    fn storage_flat_form_converts_to_locations() {
        let cfg = valid();
        let locs = cfg.storage.resolved_locations().unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!((locs[0].name.as_str(), locs[0].driver), ("primary", super::StorageDriver::Filesystem));
        assert!(locs[0].regions.is_empty());
        cfg.validate().unwrap();

        let raw = r#"
            [storage]
            driver = "s3"
            location = "us"
            redirect = true
            [storage.s3]
            bucket = "registry-us"
            [[storage.replicas]]
            name = "eu"
            regions = ["eu-*", "DE"]
            [storage.replicas.s3]
            bucket = "registry-eu"
            [[storage.replicas]]
            name = "dr"
            driver = "filesystem"
            redirect = false
            [storage.replicas.filesystem]
            root = "/mnt/dr"
        "#;
        let mut table: toml::Table = toml::from_str(raw).unwrap();
        table.insert("server".into(), toml::Value::Table(toml::from_str("bind = \"0.0.0.0:5000\"").unwrap()));
        super::check_storage_form(&table).unwrap();
        let cfg: super::Config = toml::Value::Table(table).try_into().unwrap();
        cfg.validate().unwrap();
        let locs = cfg.storage.resolved_locations().unwrap();
        let names: Vec<&str> = locs.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["us", "eu", "dr"]);
        assert_eq!((locs[0].s3.bucket.as_str(), locs[0].is_redirect), ("registry-us", true));
        assert_eq!((locs[1].s3.bucket.as_str(), locs[1].regions.len(), locs[1].driver), ("registry-eu", 2, super::StorageDriver::S3));
        assert_eq!((locs[2].driver, locs[2].is_redirect), (super::StorageDriver::Filesystem, false), "a standby replica stays a location");
        assert_eq!(cfg.storage.preferred_location().unwrap().name, "us");

        // In the flat form, `location` names the flat driver's location...
        let mut renamed = cfg.clone();
        renamed.storage.location = "mars".into();
        renamed.validate().unwrap();
        assert_eq!(renamed.storage.resolved_locations().unwrap()[0].name, "mars");
        // ...so it cannot also be a replica's name.
        let mut bad = cfg.clone();
        bad.storage.location = "eu".into();
        let e = bad.validate().unwrap_err().to_string();
        assert!(e.contains("`eu` is used twice"), "{e}");
    }

    #[test]
    fn storage_locations_form() {
        let raw = r#"
            [server]
            bind = "0.0.0.0:5000"
            [storage]
            location = "eu"
            region_header = "X-Client-Region"
            replication_concurrency = 8
            [[storage.locations]]
            name = "eu"
            regions = ["eu-*", "DE", "FR"]
            driver = "s3"
            redirect = true
            prefix = ""
            [storage.locations.s3]
            bucket = "registry-eu"
            region = "eu-central-1"
            [[storage.locations]]
            name = "us"
            regions = ["us-*"]
            driver = "s3"
            redirect = true
            [storage.locations.s3]
            bucket = "registry-us"
        "#;
        let table: toml::Table = toml::from_str(raw).unwrap();
        super::check_storage_form(&table).unwrap();
        let cfg: super::Config = toml::Value::Table(table).try_into().unwrap();
        cfg.validate().unwrap();
        let locs = cfg.storage.resolved_locations().unwrap();
        assert_eq!(locs.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["eu", "us"]);
        assert_eq!(cfg.storage.replication_concurrency, 8);

        // The flat settings and the list exclude each other.
        let mut mixed: toml::Table = toml::from_str(raw).unwrap();
        mixed["storage"].as_table_mut().unwrap().insert("driver".into(), "s3".into());
        let e = super::check_storage_form(&mixed).unwrap_err().to_string();
        assert!(e.contains("storage.locations cannot be combined"), "{e}");
        let mut both = cfg.clone();
        both.storage.replicas.push(both.storage.locations[1].clone());
        assert!(both.validate().is_err(), "locations and replicas together");
        let mut dup = cfg.clone();
        dup.storage.locations[1].name = "eu".into();
        assert!(dup.validate().unwrap_err().to_string().contains("used twice"));
        let mut missing = cfg;
        missing.storage.location = "primary".into();
        assert!(missing.validate().is_err(), "the preferred location must be one of the list");
    }

    #[test]
    fn auth_secret_and_ldap() {
        let mut cfg = valid();
        cfg.auth.secret = Some("short".into());
        assert!(cfg.validate().is_err());
        cfg.auth.secret = Some("x".repeat(32).into());
        cfg.validate().unwrap();
        cfg.auth.ldap.is_enabled = true;
        assert!(cfg.validate().is_err(), "url and user_base_dn are required");
        cfg.auth.ldap.url = "ldap://ldap.example.com".into();
        cfg.auth.ldap.user_base_dn = "ou=people,dc=example,dc=com".into();
        assert!(cfg.validate().is_err(), "plain ldap:// without StartTLS");
        cfg.auth.ldap.is_start_tls = true;
        cfg.validate().unwrap();
        cfg.auth.ldap.is_start_tls = false;
        cfg.auth.ldap.allow_insecure = true;
        cfg.validate().unwrap();
        cfg.auth.ldap.allow_insecure = false;
        cfg.auth.ldap.url = "ldaps://ldap.example.com".into();
        cfg.validate().unwrap();
    }

    #[test]
    fn blob_size_and_trusted_proxies() {
        let mut cfg = valid();
        assert_eq!(cfg.server.max_blob_bytes(), None);
        cfg.server.max_blob_size = Some("2g".into());
        cfg.validate().unwrap();
        assert_eq!(cfg.server.max_blob_bytes(), Some(2 << 30));
        cfg.server.max_blob_size = Some("big".into());
        assert!(cfg.validate().is_err());
        cfg.server.max_blob_size = None;
        cfg.server.trusted_proxies = vec!["10.0.0.0/8".into(), "192.168.1.5".into(), "::1".into()];
        cfg.validate().unwrap();
        let nets = cfg.server.trusted_proxy_nets();
        assert!(nets[0].contains(&"10.1.2.3".parse::<std::net::IpAddr>().unwrap()));
        assert!(nets[1].contains(&"192.168.1.5".parse::<std::net::IpAddr>().unwrap()));
        assert!(!nets[1].contains(&"192.168.1.6".parse::<std::net::IpAddr>().unwrap()));
        cfg.server.trusted_proxies = vec!["10.0.0.0/33".into()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn env_overrides() {
        let mut table: toml::Table = toml::from_str("[server]\nbind = \"0.0.0.0:5000\"\n[builds]\nmax_per_namespace = 1").unwrap();
        let vars = [
            ("KONTAINER__BUILDS__ENABLED", "true"),
            ("KONTAINER__BUILDS__MAX_PER_NAMESPACE", "4"),
            ("KONTAINER__BUILDS__TIMEOUT", "10m"),
            ("KONTAINER__STORAGE__S3__BUCKET", "2024"),
            ("KONTAINER__AUTH__ANONYMOUS_ROLES", "[\"readers\"]"),
            ("KONTAINER__SERVER__PUBLIC_URL", "https://r.example.com"),
            ("KONTAINER__SCANNER__ENV__TRIVY_CACHE_DIR", "/cache"),
            ("KONTAINER_LOG", "ignored here"),
        ];
        let defaults = toml::Table::try_from(super::Config::default()).unwrap();
        let names = super::apply_overrides(&mut table, &defaults, super::OVERRIDE, vars.iter().map(|(k, v)| (k.to_string(), v.to_string()))).unwrap();
        assert_eq!(names.len(), 7);
        let cfg: super::Config = toml::Value::Table(table).try_into().unwrap();
        assert!(cfg.builds.is_enabled);
        assert_eq!(cfg.builds.max_per_namespace, 4);
        assert_eq!(cfg.builds.timeout, std::time::Duration::from_secs(600));
        assert_eq!(cfg.storage.s3.bucket, "2024", "text settings stay text");
        assert_eq!(cfg.auth.anonymous_roles, vec!["readers"]);
        assert_eq!(cfg.server.public_url.as_deref(), Some("https://r.example.com"));
        assert_eq!(cfg.server.bind, "0.0.0.0:5000");
        assert_eq!(cfg.scanner.env.get("TRIVY_CACHE_DIR").map(String::as_str), Some("/cache"), "map keys keep their case");
        let mut t = toml::Table::new();
        assert!(super::apply_overrides(&mut t, &defaults, super::OVERRIDE, [("KONTAINER__A____B".to_string(), "1".to_string())].into_iter()).is_err());
    }

    #[test]
    fn runner_config() {
        let mut table: toml::Table = toml::from_str("server = \"https://r.example.com\"\nexecutor = \"kubernetes\"\n[kubernetes]\nimage = \"kontainer:1\"").unwrap();
        let defaults = toml::Table::try_from(super::RunnerConfig::default()).unwrap();
        let vars = [("KONTAINER_RUNNER__CONCURRENCY", "4"), ("KONTAINER_RUNNER__KUBERNETES__NODE_SELECTOR", "{ pool = \"builds\" }"), ("KONTAINER__BUILDS__ENABLED", "false")];
        super::apply_overrides(&mut table, &defaults, "KONTAINER_RUNNER__", vars.iter().map(|(k, v)| (k.to_string(), v.to_string()))).unwrap();
        let mut cfg: super::RunnerConfig = toml::Value::Table(table).try_into().unwrap();
        assert_eq!((cfg.executor, cfg.concurrency), (super::BuildExecutor::Kubernetes, 4));
        assert_eq!(cfg.kubernetes.node_selector.get("pool").map(String::as_str), Some("builds"));
        assert!(cfg.validate().is_err(), "no token");
        cfg.token = Some("t".into());
        cfg.validate().unwrap();
    }
}
