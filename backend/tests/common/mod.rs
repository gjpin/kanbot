//! Shared setup for integration tests.
//!
//! Tests that need the database use `#[sqlx::test]`, which creates a fresh
//! database per test (with `migrations/` applied) on the server at
//! `DATABASE_URL`, and drops it afterwards. They fail, rather than skip, when
//! `DATABASE_URL` is not set. `docker compose up -d` in `backend/` starts a
//! server; CI always sets it.

pub mod authelia;
pub mod base64url;
pub mod idp;

use std::{net::SocketAddr, sync::Arc};

use axum::{Extension, Router, extract::ConnectInfo};
use kanbot_backend::{
    auth::keys::KeyCache,
    db,
    http::{self, HttpSettings},
    state::AppState,
};
use sqlx::{PgPool, migrate::Migrator, postgres::PgConnectOptions};

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

/// The full router, backed by `pool`, expecting `migrator`'s migrations,
/// with `keys`.
pub fn app_with_keys(pool: PgPool, migrator: &'static Migrator, keys: Arc<KeyCache>) -> Router {
    serve(
        AppState {
            db: pool,
            migrator,
            keys,
        },
        HttpSettings::new(),
        None,
    )
}
