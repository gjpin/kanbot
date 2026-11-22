//! Kanbot sessions: the login flow through the backend, and the sessions
//! it creates for kanbot's own apps (`docs/oidc.md`).

pub mod config;
pub mod crypto;
mod dto;
mod handlers;
pub mod model;
mod repo;
pub mod secrets;
pub mod service;

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::state::AppState;

pub use handlers::{
    LOGIN_COOKIE, SESSION_COOKIE, TelemetryAvailable, clear_session_cookie, cookie,
};

/// The routes that start or finish a sign-in, which get their own per-IP
/// rate limit (`RATE_LIMIT_LOGIN_*`).
pub fn login_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(handlers::login))
        .routes(routes!(handlers::callback))
        .routes(routes!(handlers::token))
}

/// `/auth/config`: public, it never looks at credentials.
pub fn public_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(handlers::config))
}

/// `/auth/logout`, behind the authentication middleware's sign-out variant
/// ([`crate::auth::middleware::identify`]), which finds a session from its
/// token alone.
pub fn logout_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(handlers::logout))
}
