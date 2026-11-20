//! Shared application state, cloned into every handler.

use sqlx::{PgPool, migrate::Migrator};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// The migrations the app expects to have been applied: `db::MIGRATOR`,
    /// or a fixture in tests. `/ready` checks them.
    pub migrator: &'static Migrator,
}
