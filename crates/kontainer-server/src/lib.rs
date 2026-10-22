//! OCI Distribution Spec registry with pluggable storage, RBAC, vulnerability scanning,
//! webhooks and a layer-inspection UI.

pub mod api;
pub mod audit;
pub mod auth;
pub mod background;
pub mod build;
pub mod database;
pub mod error;
pub mod locations;
pub mod maintenance;
pub mod metrics;
pub mod policy;
pub mod replicate;
pub mod retention;
pub mod runner;
pub mod scan;
pub mod search;
pub mod state;
pub mod sync;
pub mod tags;
pub mod ui;
pub mod webhook;
pub mod workqueue;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use tower_http::trace::TraceLayer;

use kontainer_core::config::Config;
use crate::scan::queue::{OnReport, ScanQueue};
use crate::state::AppState;

pub async fn build_state(cfg: Config) -> Result<AppState> {
    for l in cfg.storage.resolved_locations()?.iter().filter(|l| l.driver == kontainer_core::config::StorageDriver::Filesystem) {
        tracing::warn!(location = %l.name, root = %l.filesystem.root.display(), "a filesystem storage location: every instance must mount the same shared volume at this path");
    }
    let mut storage = kontainer_store::Storage::from_config(&cfg.storage).await.context("initialising storage")?;
    // Secrets at rest: every `Db` of this database seals and opens with the configured keys.
    // Refuse to start when stored secrets need a key that isn't configured.
    database::install_keyring(&cfg);
    database::Db::open(cfg.auth.database_url.expose(), 1).await?.check_secrets_at_rest().await.context("checking secrets at rest")?;
    let auth = Arc::new(auth::Authenticator::new(&cfg).await.context("initialising auth")?);
    // Upload sessions in the database, so any instance can continue any upload, and the
    // registry metadata (manifests, tags, links), so every instance sees every push at once.
    storage.uploads.set_sessions(Arc::new(auth.db.clone()));
    storage.set_metadata(Arc::new(auth.db.clone()));
    // Which locations hold which blobs, and the copies queued between them.
    storage.set_placements(Arc::new(auth.db.clone()));
    if storage.metadata().is_empty().await? && storage.has_legacy_metadata().await.unwrap_or(false) {
        tracing::warn!("storage holds registry metadata in the old layout (repositories/...) and the database has none: run `kontainer migrate-metadata`; until then the registry looks empty and garbage collection refuses to run");
    }
    let webhooks = webhook::Webhooks::new(cfg.webhooks.clone(), auth.db.clone(), cfg.policy.is_webhooks_allow_private_targets, &cfg.public_url()).await.context("loading webhooks")?;
    let minter: crate::scan::TokenMinter = { let auth = auth.clone(); Arc::new(move |t: &crate::scan::ScanTarget| auth.issue_scanner_token(&t.repository)) };
    let scans = crate::scan::build(&cfg.scanner, &cfg.server.bind, Some(minter))
        .map(|s| {
            let hooks = webhooks.clone();
            let on_report: OnReport = Arc::new(move |t, r| hooks.fire(webhook::Event::scan(&t.repository, &t.digest, r)));
            ScanQueue::start(s, storage.clone(), auth.db.clone(), on_report, cfg.scanner.workers).with_budget(crate::scan::queue::Budget::from_config(&cfg.scanner))
        });
    let audit = audit::Audit::new(&cfg.audit, storage.clone());
    let repos = storage.list_repositories().await.context("listing repositories")?;
    let migrated = auth.db.migrate_team_rules(&repos).await.context("converting team rules")?;
    if migrated > 0 {
        tracing::info!(teams = migrated, "converted legacy team rules into base permissions and repository grants");
    }
    // Repositories created empty exist too.
    auth.set_known_repos(repos.into_iter().chain(auth.db.catalogue_names().await.context("listing the catalogue")?)).await;
    auth.set_storage(storage.clone());
    let search = Arc::new(crate::search::SearchIndex::new().context("creating the search index")?);
    let state = AppState { auth, config: Arc::new(cfg), storage, scans, webhooks, audit, search, usage: Arc::default(), usage_running: Arc::default(), jobs: Arc::default(), signed: Default::default(), running: Default::default(), proxy: Default::default(), build_logs: Arc::default() };
    build::logs::dispatch(&state.build_logs, state.auth.subscribe_build_logs());
    build::sync_config_runners(&state).await.context("registering the configured runners")?;
    let indexed = state.rebuild_search().await.context("building the search index")?;
    tracing::info!(repositories = indexed, "search index ready");
    follow_repository_changes(&state);
    Ok(state)
}

/// Keep this instance's search index in step with repository changes made on any instance
/// (their notifications, see [`database::notify`]). Holds no strong reference to the state, so
/// it ends when the state is dropped (the authenticator's listener closes the channel).
fn follow_repository_changes(state: &AppState) {
    use crate::database::notify::Topic;
    use tokio::sync::broadcast::error::RecvError;
    let mut rx = state.auth.subscribe();
    let search = Arc::downgrade(&state.search);
    let (storage, db, public) = (state.storage.clone(), state.auth.db.clone(), state.config.auth.public_repositories.clone());
    tokio::spawn(async move {
        loop {
            let topic = match rx.recv().await {
                Ok(t) => t,
                Err(RecvError::Lagged(_)) => Topic::Resync,
                Err(RecvError::Closed) => return,
            };
            let Some(search) = search.upgrade() else { return };
            match topic {
                Topic::Repo(name) => search::reindex(&storage, &db, &public, &search, &name).await,
                Topic::Repos | Topic::Resync => {
                    if let Err(e) = search::rebuild(&storage, &db, &public, &search).await {
                        tracing::warn!(error = %format!("{e:#}"), "rebuilding the search index after changes on another instance");
                    }
                }
                Topic::Roles | Topic::PublicRepos | Topic::Proxies => {}
            }
        }
    });
}

pub use background::start as start_background;

pub fn build_router(state: AppState) -> Router {
    let mut app = api::v2::router().merge(api::auth::router());
    if state.config.ui.is_enabled {
        app = app.merge(api::ext::router()).merge(api::admin::router()).merge(api::orgs::router()).merge(api::repos::router()).merge(api::namespaces::router()).merge(api::webhooks::router()).merge(api::security::router()).merge(api::replication::router()).merge(api::remote::router()).merge(api::federation::router()).merge(api::builds::router()).merge(api::runners::router()).merge(api::storage::router()).merge(ui::router());
    }
    let app = app.layer(axum::middleware::from_fn_with_state(state.clone(), auth::middleware));
    // Probes are unauthenticated; the detailed report checks its caller itself.
    let mut app = app.merge(api::health::router().layer(axum::middleware::from_fn_with_state(state.clone(), auth::middleware)));
    // Outside the auth layer: runners use their own tokens, not registry credentials.
    app = app.merge(api::runner::router());
    // Outside the auth layer: scrapers use their own `metrics.token`, not registry credentials.
    if state.config.metrics.is_enabled {
        if state.config.metrics.token.as_ref().is_none_or(|t| t.is_empty()) {
            tracing::warn!("/metrics is enabled but metrics.token is not set; it will refuse every request");
        }
        app = app.route("/metrics", axum::routing::get(metrics::endpoint));
    }
    // Outermost, so every route (and the auth middleware) sees the client's address.
    let trusted = Arc::new(state.config.server.trusted_proxy_nets());
    app.layer(axum::middleware::from_fn(error::api_errors))
        .layer(axum::middleware::from_fn(metrics::track))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(move |req, next| auth::client_ip::middleware(trusted.clone(), req, next)))
        .with_state(state)
}
