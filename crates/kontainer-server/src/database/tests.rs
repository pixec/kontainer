use chrono::Utc;

use crate::database::{now, AccessToken, Db};

async fn open() -> Db {
    crate::database::test_support::fresh_db().await
}

fn token(scopes: Option<&str>) -> AccessToken {
    AccessToken { id: 1, user_id: 1, name: "t".into(), hint: "p".into(), token_hash: String::new(), scopes: scopes.map(str::to_string), created_at: now(), expires_at: None, last_used_at: None }
}

#[test]
fn unreadable_token_scopes_are_an_error_not_unrestricted() {
    assert!(token(None).scope_rules().unwrap().is_none());
    let rules = token(Some(r#"[{"repositories":["a/*"],"actions":["pull"]}]"#)).scope_rules().unwrap().unwrap();
    assert_eq!(rules.len(), 1);
    assert!(token(Some("")).scope_rules().is_err());
    assert!(token(Some("not json")).scope_rules().is_err());
    assert!(token(Some(r#"[{"repositories":["a"],"actions":["fly"]}]"#)).scope_rules().is_err());
}

#[tokio::test]
async fn mfa_setups_expire_and_complete_once() {
    let db = open().await;
    let u = db.create_user("bob", None, None, None, false, None, false).await.unwrap();
    assert!(!u.is_mfa_enabled);
    assert_eq!(db.pending_mfa_secret(u.id).await.unwrap(), None);
    // An expired setup is neither pending nor completable, and the purge drops it.
    db.start_mfa_setup(u.id, "OLD", chrono::Duration::seconds(-1)).await.unwrap();
    assert_eq!(db.pending_mfa_secret(u.id).await.unwrap(), None);
    assert!(!db.complete_mfa_setup(u.id, "OLD", &[]).await.unwrap());
    db.purge_expired().await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM mfa_setups").fetch_one(db.pool()).await.unwrap();
    assert_eq!(left, 0);
    // A new setup replaces the old one; only the pending secret completes, once.
    db.start_mfa_setup(u.id, "A", chrono::Duration::minutes(15)).await.unwrap();
    db.start_mfa_setup(u.id, "B", chrono::Duration::minutes(15)).await.unwrap();
    assert_eq!(db.pending_mfa_secret(u.id).await.unwrap().as_deref(), Some("B"));
    assert!(!db.complete_mfa_setup(u.id, "A", &[]).await.unwrap());
    assert!(db.complete_mfa_setup(u.id, "B", &["h1".into(), "h2".into()]).await.unwrap());
    assert!(!db.complete_mfa_setup(u.id, "B", &[]).await.unwrap());
    let u = db.user_by_id(u.id).await.unwrap().unwrap();
    assert!(u.is_mfa_enabled);
    assert_eq!(db.user_mfa_secret(&u).unwrap().as_deref(), Some("B"));
    assert_eq!(db.pending_mfa_secret(u.id).await.unwrap(), None);
    assert!(db.use_recovery_code(u.id, "h2").await.unwrap());
    // Disabling clears the secret, any setup and the recovery codes.
    db.start_mfa_setup(u.id, "C", chrono::Duration::minutes(15)).await.unwrap();
    db.disable_mfa(u.id).await.unwrap();
    let u = db.user_by_id(u.id).await.unwrap().unwrap();
    assert!(!u.is_mfa_enabled && u.mfa_secret.is_none());
    assert_eq!(db.pending_mfa_secret(u.id).await.unwrap(), None);
    assert!(!db.use_recovery_code(u.id, "h1").await.unwrap());
}

#[tokio::test]
async fn timestamps_round_trip_and_compare_as_times() {
    let db = open().await;
    let u = db.create_user("ann", None, None, None, false, None, false).await.unwrap();
    // Microseconds, as TIMESTAMPTZ keeps them.
    assert!((Utc::now() - u.created_at).num_seconds().abs() < 60);
    assert_eq!(u.last_login_at, None);
    db.touch_login(u.id).await.unwrap();
    assert!(db.user_by_id(u.id).await.unwrap().unwrap().last_login_at.is_some_and(|t| t >= u.created_at));
    // Sessions: expired ones are neither returned nor listed.
    let live = db.create_session(u.id, chrono::Duration::hours(1), None, None).await.unwrap();
    sqlx::query("INSERT INTO sessions(id, user_id, created_at, expires_at) VALUES ('dead', $1, $2, $3)").bind(u.id).bind(now()).bind(now() - chrono::Duration::seconds(1)).execute(db.pool()).await.unwrap();
    assert!(db.session(&live.id).await.unwrap().is_some());
    assert!(db.session("dead").await.unwrap().is_none());
    assert_eq!(db.list_sessions(u.id).await.unwrap().len(), 1);
    // Tag history and expirations bound by DateTime.
    db.record_tag_event("r", "v1", "move", Some("sha256:01"), Some("sha256:00"), "me").await.unwrap();
    assert_eq!(db.restorable_digests(Utc::now() - chrono::Duration::minutes(1)).await.unwrap().len(), 1);
    assert!(db.restorable_digests(Utc::now() + chrono::Duration::minutes(1)).await.unwrap().is_empty());
    db.set_tag_expiration("r", "v1", Some(Utc::now() + chrono::Duration::hours(1)), "me").await.unwrap();
    assert!(db.due_tag_expirations(Utc::now()).await.unwrap().is_empty());
    assert_eq!(db.due_tag_expirations(Utc::now() + chrono::Duration::hours(2)).await.unwrap().len(), 1);
    assert_eq!(db.prune_tag_events(Utc::now() + chrono::Duration::minutes(1)).await.unwrap(), 1);
}

#[tokio::test]
async fn delete_repo_meta_removes_every_repository_row() {
    let db = open().await;
    let pool = db.pool();
    let org: i64 = sqlx::query_scalar("INSERT INTO organizations(name, created_at) VALUES ('acme', $1) RETURNING id").bind(now()).fetch_one(pool).await.unwrap();
    let team: i64 = sqlx::query_scalar("INSERT INTO teams(org_id, name, created_at) VALUES ($1, 'devs', $2) RETURNING id").bind(org).bind(now()).fetch_one(pool).await.unwrap();
    for repo in ["acme/app", "acme/app/sub"] {
        db.record_tag_event(repo, "v1", "push", Some("sha256:00"), None, "me").await.unwrap();
        sqlx::query("INSERT INTO repo_team_permissions(repository, team_id, level, created_at) VALUES ($1, $2, 'read', $3)").bind(repo).bind(team).bind(now()).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO build_triggers(repository, name, git_url, secret, created_by, created_at) VALUES ($1, 'b', 'https://git.example/x', 's', 'me', $2)").bind(repo).bind(now()).execute(pool).await.unwrap();
    }
    db.delete_repo_meta("acme/app").await.unwrap();
    for sql in ["SELECT repository FROM tag_events", "SELECT repository FROM repo_team_permissions", "SELECT repository FROM build_triggers"] {
        let left: Vec<String> = sqlx::query_scalar(sql).fetch_all(pool).await.unwrap();
        assert_eq!(left, vec!["acme/app/sub".to_string()], "{sql}");
    }
}

#[tokio::test]
async fn migrate_team_rules_skips_unreadable_rules() {
    let db = open().await;
    let pool = db.pool();
    let org: i64 = sqlx::query_scalar("INSERT INTO organizations(name, created_at) VALUES ('acme', $1) RETURNING id").bind(now()).fetch_one(pool).await.unwrap();
    let insert = |name: &'static str, rules: &'static str| async move {
        sqlx::query_scalar::<_, i64>("INSERT INTO teams(org_id, name, rules, created_at) VALUES ($1, $2, $3, $4) RETURNING id").bind(org).bind(name).bind(rules).bind(now()).fetch_one(pool).await.unwrap()
    };
    let good = insert("good", r#"[{"repositories":["app"],"actions":["pull"]}]"#).await;
    let bad = insert("bad", "{broken").await;
    let n = db.migrate_team_rules(&["acme/app".to_string()]).await.unwrap();
    assert_eq!(n, 1);
    let rules = |id: i64| async move { sqlx::query_scalar::<_, String>("SELECT rules FROM teams WHERE id = $1").bind(id).fetch_one(pool).await.unwrap() };
    assert_eq!(rules(good).await, "[]");
    assert_eq!(rules(bad).await, "{broken");
    assert_eq!(db.team_repo_grants(good).await.unwrap().len(), 1);
}

/// The queries rewritten by hand for PostgreSQL (JSON, string functions, ILIKE, NULL params).
#[tokio::test]
async fn postgres_specific_queries() {
    let db = open().await;
    // search_people: case-insensitive like SQLite's LIKE; exact and prefix matches first.
    for name in ["alice", "malice", "alicia"] {
        db.create_user(name, None, None, None, false, None, false).await.unwrap();
    }
    db.create_user("alice+bot", None, None, None, true, None, false).await.unwrap();
    let hits: Vec<String> = db.search_people("ALIC", 10).await.unwrap().into_iter().map(|h| h.0).collect();
    assert_eq!(hits, ["alice", "alicia", "malice"]);
    assert_eq!(db.search_people("alice", 10).await.unwrap()[0].0, "alice");
    assert!(db.search_people("a_i", 10).await.unwrap().is_empty(), "`_` is literal");

    // see_build_ref merges into the JSON map; tag events filter by an optional tag.
    let input: crate::database::builds::TriggerInput = serde_json::from_value(serde_json::json!({ "name": "t", "git_url": "https://git.example/x" })).unwrap();
    let t = db.create_build_trigger("acme/app", &input, "s", "me").await.unwrap();
    db.see_build_ref(t.id, "refs/heads/main", "aaa").await.unwrap();
    db.see_build_ref(t.id, "refs/tags/v\"1", "bbb").await.unwrap();
    db.see_build_ref(t.id, "refs/heads/main", "ccc").await.unwrap();
    let seen = db.build_trigger(t.id).await.unwrap().unwrap().seen();
    assert_eq!(seen.get("refs/heads/main").map(String::as_str), Some("ccc"));
    assert_eq!(seen.get("refs/tags/v\"1").map(String::as_str), Some("bbb"));
    db.update_build_trigger(t.id, &input).await.unwrap();
    db.record_tag_event("acme/app", "v1", "push", Some("sha256:01"), None, "me").await.unwrap();
    db.record_tag_event("acme/app", "v2", "push", Some("sha256:02"), None, "me").await.unwrap();
    assert_eq!(db.tag_events("acme/app", None, 10).await.unwrap().len(), 2);
    assert_eq!(db.tag_events("acme/app", Some("v2"), 10).await.unwrap().len(), 1);

    // claim_build: namespace scope (JSON list), fairness limit, oldest first.
    let a1 = db.create_build(None, "acme/app", "u", "main", "me").await.unwrap();
    let a2 = db.create_build(None, "acme/web", "u", "main", "me").await.unwrap();
    let b1 = db.create_build(None, "beta/app", "u", "main", "me").await.unwrap();
    let only_beta = ["beta".to_string()];
    assert_eq!(db.claim_build(None, "r", "h", Some(&only_beta), 0).await.unwrap(), Some(b1));
    assert_eq!(db.claim_build(None, "r", "h", None, 1).await.unwrap(), Some(a1));
    assert_eq!(db.claim_build(None, "r", "h", None, 1).await.unwrap(), None, "acme is at its limit");
    assert_eq!(db.build_queue_position(a2, "acme/web").await.unwrap(), (0, 1));
    assert_eq!(db.claim_build(None, "r", "h", None, 0).await.unwrap(), Some(a2));
    assert!(db.cancel_build(a2).await.map(|queued| !queued).unwrap());
    let at = |offset: u64, data: &'static str| crate::database::builds::LogInput::At { offset, data, tail: false };
    assert!(db.append_build_log(a2, at(0, "log\n"), 1 << 20).await.unwrap().stop, "cancel requested");

    // A namespace-scoped team sync lookup with and without an organization.
    assert!(db.team_syncs_for("ldap", None).await.unwrap().is_empty());
    assert!(db.team_syncs_for("org-oidc", Some(1)).await.unwrap().is_empty());
    db.ping().await.unwrap();
}

/// A running build, claimed.
async fn running_build(db: &Db) -> i64 {
    let id = db.create_build(None, "acme/app", "u", "main", "me").await.unwrap();
    assert_eq!(db.claim_build(None, "r", "h", None, 0).await.unwrap(), Some(id));
    id
}

fn at(offset: u64, data: &str) -> crate::database::builds::LogInput<'_> {
    crate::database::builds::LogInput::At { offset, data, tail: false }
}

#[tokio::test]
async fn build_log_chunks_append_at_the_stored_length_and_resync() {
    let db = open().await;
    let id = running_build(&db).await;
    let max = 1 << 20;
    let r = db.append_build_log(id, at(0, "one\n"), max).await.unwrap();
    assert_eq!((r.stop, r.length, r.truncated), (false, 4, false));
    // The reply to the next one is lost: the runner still thinks 4, and sends it again.
    assert_eq!(db.append_build_log(id, at(4, "two\n"), max).await.unwrap().length, 8);
    let r = db.append_build_log(id, at(4, "two\nthree\n"), max).await.unwrap();
    assert_eq!(r.length, 8, "a mismatched offset stores nothing and says where the log stands");
    assert_eq!(db.append_build_log(id, at(8, "three\n"), max).await.unwrap().length, 14);
    // An offset past the end (a runner with another idea of the log) is refused too.
    assert_eq!(db.append_build_log(id, at(99, "x"), max).await.unwrap().length, 14);
    // A heartbeat alone adds no chunk.
    assert_eq!(db.append_build_log(id, at(14, ""), max).await.unwrap().length, 14);
    let chunks = db.build_log_chunks(id, 0, 100).await.unwrap();
    assert_eq!(chunks.iter().map(|c| (c.seq, c.data.as_str())).collect::<Vec<_>>(), vec![(1, "one\n"), (2, "two\n"), (3, "three\n")]);
    assert_eq!(db.build_log_chunks(id, 2, 100).await.unwrap().len(), 1);
    assert_eq!(db.build_log_text(id).await.unwrap(), "one\ntwo\nthree\n");
    // A runner from before chunked logs sends all of it; the server takes what it lacks.
    let r = db.append_build_log(id, crate::database::builds::LogInput::Whole("one\ntwo\nthree\nfour\n"), max).await.unwrap();
    assert_eq!(r.length, 19);
    // Finishing adds the outcome on a line of its own and caches the whole log.
    db.append_build_log(id, at(19, "no newline"), max).await.unwrap();
    assert!(db.finish_build(id, "failed", "Boom", Some("==> Boom")).await.unwrap());
    assert!(!db.finish_build(id, "failed", "Again", None).await.unwrap(), "already over");
    let b = db.build(id).await.unwrap().unwrap();
    assert_eq!(b.log, "one\ntwo\nthree\nfour\nno newline\n==> Boom\n");
    let r = db.append_build_log(id, at(29, "late\n"), max).await.unwrap();
    assert!(r.stop, "over: stop");
    assert_eq!(db.build_log_text(id).await.unwrap(), b.log, "and nothing more is stored");
}

#[tokio::test]
async fn build_logs_past_the_limit_keep_head_tail_and_a_marker() {
    use kontainer_core::build::protocol::LOG_TAIL_BYTES;
    let db = open().await;
    let id = running_build(&db).await;
    let max = 100;
    let line = |i: usize| format!("line {i:04}\n"); // 10 bytes
    let all: String = (0..30_000).map(line).collect();
    // 80 bytes fit; the next 50 don't: the head ends at the last whole line within the limit.
    assert!(!db.append_build_log(id, at(0, &all[..80]), max).await.unwrap().truncated);
    let r = db.append_build_log(id, at(80, &all[80..130]), max).await.unwrap();
    assert_eq!((r.length, r.truncated), (130, true));
    // A runner that keeps sending is counted, not stored.
    assert_eq!(db.append_build_log(id, at(130, &all[130..1000]), max).await.unwrap().length, 1000);
    // At the end, the tail: the last 64 KiB of a much longer log.
    let tail_from = (all.len() - 70_000) as u64;
    let r = db.append_build_log(id, crate::database::builds::LogInput::At { offset: tail_from, data: &all[tail_from as usize..], tail: true }, max).await.unwrap();
    assert_eq!(r.length, all.len() as u64);
    // Sent again (its reply was lost): nothing changes.
    let again = db.append_build_log(id, crate::database::builds::LogInput::At { offset: tail_from, data: &all[tail_from as usize..], tail: true }, max).await.unwrap();
    assert_eq!(again.length, all.len() as u64);
    assert!(db.finish_build(id, "succeeded", "Pushed", Some("==> Pushed")).await.unwrap());
    let log = db.build(id).await.unwrap().unwrap().log;
    let kept_tail = &all[all.len() - LOG_TAIL_BYTES..];
    let omitted = all.len() - 100 - LOG_TAIL_BYTES;
    assert_eq!(log, format!("{}==> log truncated: {omitted} bytes omitted\n{kept_tail}==> Pushed\n", &all[..100]));
    assert_eq!(log.matches("log truncated").count(), 1);
}

#[tokio::test]
async fn a_truncated_log_without_its_tail_still_says_so() {
    let db = open().await;
    let id = running_build(&db).await;
    let r = db.append_build_log(id, at(0, "abcdefghij"), 4).await.unwrap();
    assert!(r.truncated);
    assert!(db.finish_build(id, "failed", "Lost", None).await.unwrap());
    assert_eq!(db.build(id).await.unwrap().unwrap().log, "abcd\n==> log truncated: 6 bytes omitted\n");
}
