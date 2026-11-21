//! kanbot backend: configuration, application state and the HTTP API.
#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod authz;
pub mod base64;
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod http;
pub mod names;
pub mod openshell;
pub mod organizations;
pub mod sessions;
pub mod state;
pub mod teams;
pub mod telemetry;
pub mod telemetry_relay;
pub mod users;

use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpListener;

use crate::{
    auth::{discovery::IdpClient, keys::KeyCache},
    config::Config,
    error::StartupError,
    state::AppState,
};

/// Connects to the database, binds the listener and serves until Ctrl+C or
/// SIGTERM.
///
/// # Errors
///
/// Returns [`StartupError`] if the database options are invalid, the listener
/// cannot bind, or the server fails.
pub async fn run(config: Config) -> Result<(), StartupError> {
    let db = db::pool(&config.database_url, config.database_max_connections)?;
    db::observe_pool(&opentelemetry::global::meter(telemetry::SCOPE), db.clone());
    let client =
        IdpClient::new(&config.oidc.extra_root_certificates).map_err(StartupError::IdpClient)?;
    let keys = Arc::new(KeyCache::new(Arc::new(config.oidc), client));
    // The server starts even if the identity provider is unreachable: it
    // reports not ready until the keys load.
    keys.spawn_refresh();
    sessions::service::spawn_cleanup(db.clone());
    tracing::info!(
        deployer_policies = ?config.authz.deployer_policy_ids(),
        "authorization policies loaded"
    );
    let relay = config
        .telemetry_relay_upstream
        .map(|upstream| telemetry_relay::routes(upstream, config.rate_limits.telemetry))
        .transpose()?;
    let app = http::router(
        AppState {
            db,
            migrator: &db::MIGRATOR,
            keys,
            sessions: Arc::new(config.sessions),
            authz: Arc::new(config.authz),
        },
        http::HttpSettings::configured(
            config.cors_allowed_origins,
            config.trusted_proxies,
            config.rate_limits,
            config.max_in_flight_requests,
            config.web_dir,
        ),
        relay,
    )?;

    let listener = TcpListener::bind(config.listen_addr)
        .await
        .map_err(StartupError::Bind)?;
    tracing::info!(addr = %config.listen_addr, "listening");
    // Connect info: the per-client rate limit needs the peer address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(StartupError::Serve)
}

/// Applies pending migrations from `migrations/`, then returns. Run it
/// before starting a new version: instances report not ready until it has.
///
/// # Errors
///
/// Returns [`StartupError::Migrate`] if the database is unreachable or a
/// migration fails.
pub async fn migrate(config: Config) -> Result<(), StartupError> {
    db::migrate(&config.database_url, &db::MIGRATOR).await?;
    tracing::info!("migrations are up to date");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to listen for Ctrl+C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
