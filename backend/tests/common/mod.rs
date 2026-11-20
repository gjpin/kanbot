//! Shared setup for integration tests.
//!
//! Tests that need the database use `#[sqlx::test]`, which creates a fresh
//! database per test (with `migrations/` applied) on the server at
//! `DATABASE_URL`, and drops it afterwards. They fail, rather than skip, when
//! `DATABASE_URL` is not set. `docker compose up -d` in `backend/` starts a
//! server; CI always sets it.

use axum::Router;
use kanbot_backend::{db, http, state::AppState};
use sqlx::{PgPool, migrate::Migrator, postgres::PgConnectOptions};

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

/// The full router, backed by `pool`, expecting `migrator`'s migrations.
pub fn app_with(pool: PgPool, migrator: &'static Migrator) -> Router {
    http::router(AppState { db: pool, migrator }, &[], None)
}
