//! Users: everyone who has signed in at the identity provider, recorded on
//! each authenticated request.

pub(crate) mod dto;
mod handlers;
pub mod model;
mod repo;
pub mod service;

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::state::AppState;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(handlers::me))
        .routes(routes!(handlers::update_preferences))
        .routes(routes!(handlers::search))
}
