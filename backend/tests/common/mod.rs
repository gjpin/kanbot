//! Shared setup for integration tests.
//!
//! Tests that need the database use `#[sqlx::test]`, which creates a fresh
//! database per test (with `migrations/` applied) on the server at
//! `DATABASE_URL`, and drops it afterwards. They fail, rather than skip, when
//! `DATABASE_URL` is not set. `docker compose up -d` in `backend/` starts a
//! server; CI always sets it.

pub mod api;
pub mod authelia;
pub mod base64url;
pub mod idp;
pub mod keycloak;

use std::{net::SocketAddr, sync::Arc};

use axum::{Extension, Router, extract::ConnectInfo};
use kanbot_backend::{
    auth::keys::KeyCache,
    authz::policies::Policies,
    db,
    http::{self, HttpSettings},
    sessions::config::SessionConfig,
    state::AppState,
};
use sqlx::{PgPool, migrate::Migrator, postgres::PgConnectOptions};

/// The login flow's settings for tests: client `kanbot`, `PUBLIC_URL`
/// `http://localhost:3000` (registered at the local Authelia), and a fixed
/// test-only session key.
///
/// # Panics
///
/// Never: the values are valid.
#[must_use]
pub fn session_config() -> Arc<SessionConfig> {
    let vars: std::collections::HashMap<&str, &str> = [
        ("OIDC_CLIENT_ID", "kanbot"),
        ("OIDC_CLIENT_SECRET", "kanbot-dev-client-secret"),
        ("OIDC_SCOPES", "openid profile email groups offline_access"),
        ("PUBLIC_URL", "http://localhost:3000"),
        (
            "SESSION_ENCRYPTION_KEYS",
            "test1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        ),
    ]
    .into_iter()
    .collect();
    Arc::new(
        SessionConfig::from_lookup(&|name| {
            vars.get(name)
                .map(|value| (*value).to_owned())
                .ok_or(std::env::VarError::NotPresent)
        })
        .unwrap(),
    )
}

/// [`session_config`] with other `OIDC_SCOPES` (Keycloak refuses scopes it
/// does not know, such as `groups`).
///
/// # Panics
///
/// If `scopes` is invalid.
#[must_use]
pub fn session_config_with_scopes(scopes: &str) -> Arc<SessionConfig> {
    let scopes = scopes.to_owned();
    let vars: std::collections::HashMap<&str, String> = [
        ("OIDC_CLIENT_ID", "kanbot".to_owned()),
        ("OIDC_CLIENT_SECRET", "kanbot-dev-client-secret".to_owned()),
        ("OIDC_SCOPES", scopes),
        ("PUBLIC_URL", "http://localhost:3000".to_owned()),
        (
            "SESSION_ENCRYPTION_KEYS",
            "test1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_owned(),
        ),
    ]
    .into_iter()
    .collect();
    Arc::new(
        SessionConfig::from_lookup(&|name| {
            vars.get(name)
                .cloned()
                .ok_or(std::env::VarError::NotPresent)
        })
        .unwrap(),
    )
}

/// [`session_config`] with other `SESSION_ENCRYPTION_KEYS`.
///
/// # Panics
///
/// If `keys` is invalid.
#[must_use]
pub fn session_config_with_keys(keys: &str) -> Arc<SessionConfig> {
    let keys = keys.to_owned();
    let vars: std::collections::HashMap<&str, String> = [
        ("OIDC_CLIENT_ID", "kanbot".to_owned()),
        ("OIDC_CLIENT_SECRET", "kanbot-dev-client-secret".to_owned()),
        (
            "OIDC_SCOPES",
            "openid profile email groups offline_access".to_owned(),
        ),
        ("PUBLIC_URL", "http://localhost:3000".to_owned()),
        ("SESSION_ENCRYPTION_KEYS", keys),
    ]
    .into_iter()
    .collect();
    Arc::new(
        SessionConfig::from_lookup(&|name| {
            vars.get(name)
                .cloned()
                .ok_or(std::env::VarError::NotPresent)
        })
        .unwrap(),
    )
}

/// The built-in authorization policies.
///
/// # Panics
///
/// Never: the built-in policies are valid.
#[must_use]
pub fn policies() -> Arc<Policies> {
    Arc::new(Policies::builtin().unwrap())
}

/// The client address requests come from, unless a test chooses another.
pub const PEER: &str = "203.0.113.9:50000";

/// The full router as the real server serves it, with requests coming from
/// `peer` (what `into_make_service_with_connect_info` provides).
///
/// # Panics
///
/// If a rate limit is invalid.
pub fn serve_from(
    peer: SocketAddr,
    state: AppState,
    settings: HttpSettings,
    relay: Option<Router>,
) -> Router {
    http::router(state, settings, relay)
        .unwrap()
        .layer(Extension(ConnectInfo(peer)))
}

/// [`serve_from`] [`PEER`].
///
/// # Panics
///
/// If a rate limit is invalid.
pub fn serve(state: AppState, settings: HttpSettings, relay: Option<Router>) -> Router {
    serve_from(PEER.parse().unwrap(), state, settings, relay)
}

/// The full router, backed by a lazy pool that points at a closed port. Fine
/// for routes that never touch the database.
pub fn app_without_db() -> Router {
    let options = PgConnectOptions::new_without_pgpass()
        .host("127.0.0.1")
        .port(1);
    app_with(db::pool_with(options), &db::MIGRATOR)
}

/// The full router, backed by `pool` (from `#[sqlx::test]`).
pub fn app_with_pool(pool: PgPool) -> Router {
    app_with(pool, &db::MIGRATOR)
}

/// The full router, backed by `pool`, expecting `migrator`'s migrations,
/// with the test identity provider's default keys loaded (see [`idp::static_key_cache`]).
pub fn app_with(pool: PgPool, migrator: &'static Migrator) -> Router {
    app_with_keys(pool, migrator, idp::static_key_cache())
}

/// The full router, backed by `pool`, deciding with `policies`.
pub fn app_with_policies(pool: PgPool, policies: Arc<Policies>) -> Router {
    serve(
        AppState {
            db: pool,
            migrator: &db::MIGRATOR,
            keys: idp::static_key_cache(),
            sessions: session_config(),
            authz: policies,
        },
        HttpSettings::new(),
        None,
    )
}

/// The full router, backed by `pool`, expecting `migrator`'s migrations,
/// with `keys`.
pub fn app_with_keys(pool: PgPool, migrator: &'static Migrator, keys: Arc<KeyCache>) -> Router {
    serve(
        AppState {
            db: pool,
            migrator,
            keys,
            sessions: session_config(),
            authz: policies(),
        },
        HttpSettings::new(),
        None,
    )
}
