//! Handlers of the users routes.

use axum::{Json, extract::State};

use crate::{
    error::AppError,
    http::{extract::AuthUser, problem::Problem},
    state::AppState,
    users::{
        dto::{Me, Preferences},
        service,
    },
};

/// The signed-in user.
#[utoipa::path(
    get,
    path = "/me",
    tag = "users",
    security(("bearer" = [])),
    responses(
        (status = OK, description = "The signed-in user.", body = Me),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn me(AuthUser(user): AuthUser) -> Json<Me> {
    Json(user.into())
}

/// Updates the signed-in user's preferences.
#[utoipa::path(
    put,
    path = "/me/preferences",
    tag = "users",
    security(("bearer" = [])),
    request_body = Preferences,
    responses(
        (status = OK, description = "The user, with the new preferences.", body = Me),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "The body is not valid preferences.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn update_preferences(
    State(state): State<AppState>,
    AuthUser(mut user): AuthUser,
    Json(preferences): Json<Preferences>,
) -> Result<Json<Me>, AppError> {
    service::set_telemetry_opt_in(&state.db, user.id, preferences.telemetry_opt_in).await?;
    user.telemetry_opt_in = preferences.telemetry_opt_in;
    Ok(Json(user.into()))
}
