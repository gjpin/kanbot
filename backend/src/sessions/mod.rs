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

pub use handlers::{LOGIN_COOKIE, SESSION_COOKIE, cookie};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(handlers::login))
        .routes(routes!(handlers::callback))
        .routes(routes!(handlers::token))
}
