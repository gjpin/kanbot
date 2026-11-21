//! Organizations: what kanbot's features belong to, their admins, and the
//! teams linked to them.

mod dto;
mod handlers;
pub mod model;
mod repo;
pub mod service;

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::state::AppState;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(handlers::list, handlers::create))
        .routes(routes!(handlers::get, handlers::update, handlers::delete))
        .routes(routes!(handlers::admins))
        .routes(routes!(handlers::add_admin, handlers::remove_admin))
        .routes(routes!(handlers::team_links))
        .routes(routes!(handlers::set_team_link, handlers::remove_team_link))
        .routes(routes!(
            handlers::link_openshell,
            handlers::unlink_openshell
        ))
}
