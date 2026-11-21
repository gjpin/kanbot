//! Teams: instance-wide groups of users, linked to organizations. A team
//! with an identity provider group (`idp_group`) gets its members from the
//! groups claim.

pub mod dto;
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
        .routes(routes!(handlers::members))
        .routes(routes!(handlers::set_member, handlers::remove_member))
}
