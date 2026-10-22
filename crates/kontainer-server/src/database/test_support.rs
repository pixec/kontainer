//! Throwaway PostgreSQL databases for tests (unit tests, and integration tests through the
//! `test-support` feature).
//!
//! Every call to [`fresh_database_url`] creates a new, empty database named
//! `kontainer_test_<unix seconds>_<random>` on the server in `KONTAINER_TEST_DATABASE_URL`
//! (default [`DEFAULT_URL`]; the role needs `CREATEDB`), so tests run in parallel without seeing
//! each other's rows. Databases are not dropped when a test ends (the server may still hold its
//! connections); instead, the first call in each test process drops test databases older than
//! [`KEEP`]. To remove them all by hand:
//!
//! ```sh
//! psql "$KONTAINER_TEST_DATABASE_URL" -Atc "SELECT format('DROP DATABASE %I WITH (FORCE);', datname) FROM pg_database WHERE datname LIKE 'kontainer\_test\_%'" | psql "$KONTAINER_TEST_DATABASE_URL"
//! ```

use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Names are generated here (or checked to be `[A-Za-z0-9_]`), so quoting them is enough.
use sqlx::{AssertSqlSafe, Connection, PgConnection};

use super::Db;

/// The server tests use unless `KONTAINER_TEST_DATABASE_URL` says otherwise.
pub const DEFAULT_URL: &str = "postgres://kontainer:kontainer@127.0.0.1:55432/kontainer";

/// Test databases older than this are dropped by the next test run.
pub const KEEP: Duration = Duration::from_secs(600);

const PREFIX: &str = "kontainer_test_";

static SWEEP: Once = Once::new();

/// The server to create test databases on (an existing database there to connect to).
pub fn server_url() -> String {
    std::env::var("KONTAINER_TEST_DATABASE_URL").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| DEFAULT_URL.into())
}

/// Create a new, empty database and return its URL. Blocking (it runs on a thread of its own),
/// so it also works from synchronous config builders inside async tests.
pub fn fresh_database_url() -> String {
    let server = server_url();
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let name = format!("{PREFIX}{secs}_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let mut url = url::Url::parse(&server).expect("KONTAINER_TEST_DATABASE_URL is not a URL");
    url.set_path(&name);
    let created = name.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("test runtime");
        rt.block_on(async move {
            let mut conn = PgConnection::connect(&server).await.unwrap_or_else(|e| {
                panic!("tests need PostgreSQL: set KONTAINER_TEST_DATABASE_URL (default {DEFAULT_URL}) to a server where this role may CREATE DATABASE: {e}")
            });
            let mut sweep = false;
            SWEEP.call_once(|| sweep = true);
            if sweep {
                drop_stale(&mut conn, secs).await;
            }
            sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{created}\""))).execute(&mut conn).await.expect("creating a test database");
            let _ = conn.close().await;
        })
    })
    .join()
    .expect("creating a test database");
    url.to_string()
}

/// A [`Db`] on a new, empty database.
pub async fn fresh_db() -> Db {
    Db::open(&fresh_database_url(), 4).await.expect("opening the test database")
}

/// Best effort: drop test databases created more than [`KEEP`] before `now`.
async fn drop_stale(conn: &mut PgConnection, now: u64) {
    let names: Vec<String> = sqlx::query_scalar("SELECT datname::text FROM pg_database WHERE starts_with(datname::text, $1)").bind(PREFIX).fetch_all(&mut *conn).await.unwrap_or_default();
    for name in names {
        let created = name.strip_prefix(PREFIX).and_then(|rest| rest.split('_').next()).and_then(|s| s.parse::<u64>().ok());
        if created.is_some_and(|t| t + KEEP.as_secs() < now) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            let _ = sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))).execute(&mut *conn).await;
        }
    }
}
