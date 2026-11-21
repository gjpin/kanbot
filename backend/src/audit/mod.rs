//! The audit log of changes to organizations and teams (`GET /audit`).

mod dto;
mod handlers;
pub mod model;
mod repo;
pub mod service;

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::state::AppState;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(handlers::list))
}
