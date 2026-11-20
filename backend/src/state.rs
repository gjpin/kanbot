//! Shared application state, cloned into every handler.

use std::sync::Arc;

use sqlx::{PgPool, migrate::Migrator};

use crate::{auth::keys::KeyCache, sessions::config::SessionConfig};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// The migrations the app expects to have been applied: `db::MIGRATOR`,
    /// or a fixture in tests. `/ready` checks them.
    pub migrator: &'static Migrator,
    /// The identity provider's signing keys and the OIDC configuration.
    /// `/ready` checks that keys have been loaded.
    pub keys: Arc<KeyCache>,
    /// The login flow's settings: the confidential client, `PUBLIC_URL`,
    /// session keys and lifetimes.
    pub sessions: Arc<SessionConfig>,
}
