//! kanbot backend: configuration, application state and the HTTP API.
#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod http;
pub mod state;
pub mod telemetry;
pub mod telemetry_relay;

use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpListener;

use crate::{config::Config, error::StartupError, state::AppState};

/// Connects to the database, binds the listener and serves until Ctrl+C or
/// SIGTERM.
///
/// # Errors
///
/// Returns [`StartupError`] if the database options are invalid, the listener
/// cannot bind, or the server fails.
pub async fn run(config: Config) -> Result<(), StartupError> {
    let db = db::pool(&config.database_url)?;
    db::observe_pool(&opentelemetry::global::meter(telemetry::SCOPE), db.clone());
    let relay = config
        .telemetry_relay_upstream
        .map(|upstream| telemetry_relay::routes(upstream, Arc::new(config.trusted_proxies)))
        .transpose()?;
    let app = http::router(
        AppState {
            db,
            migrator: &db::MIGRATOR,
        },
        &config.cors_allowed_origins,
        relay,
    );

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
