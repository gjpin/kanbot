//! Handlers of the users routes.

use axum::{
    Json,
    extract::{Query, State},
};

use crate::{
    error::{AppError, FieldError},
    http::{extract::Caller, problem::Problem},
    state::AppState,
    users::{
        dto::{Me, Preferences, UserSearch, UserSummaryDto},
        model::UserQuery,
        service,
    },
};

/// The signed-in user.
#[utoipa::path(
    get,
    path = "/me",
    tag = "users",
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The signed-in user.", body = Me),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn me(
    State(state): State<AppState>,
    Caller(actor): Caller,
) -> Result<Json<Me>, AppError> {
    let permissions = service::platform_permissions(&state.db, &state.authz, &actor).await?;
    Ok(Json(Me::new(actor.user, &permissions)))
}

/// Updates the signed-in user's preferences.
#[utoipa::path(
    put,
    path = "/me/preferences",
    tag = "users",
    security(("bearer" = []), ("session" = [])),
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
    Caller(mut actor): Caller,
    Json(preferences): Json<Preferences>,
) -> Result<Json<Me>, AppError> {
    service::set_telemetry_opt_in(&state.db, actor.user.id, preferences.telemetry_opt_in).await?;
    actor.user.telemetry_opt_in = preferences.telemetry_opt_in;
    let permissions = service::platform_permissions(&state.db, &state.authz, &actor).await?;
    Ok(Json(Me::new(actor.user, &permissions)))
}

/// Users who have signed in, by display name (at most 20), to add as
/// organization admins or team members. Disabled users are left out.
#[utoipa::path(
    get,
    path = "/users",
    operation_id = "search_users",
    tag = "users",
    params(UserSearch),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The matching users.", body = Vec<UserSummaryDto>),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Only platform admins, organization admins and team maintainers may search users.",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "`query` is longer than 100 characters.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn search(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Query(search): Query<UserSearch>,
) -> Result<Json<Vec<UserSummaryDto>>, AppError> {
    let query = UserQuery::parse(search.query.as_deref().unwrap_or_default())
        .ok_or_else(|| AppError::Validation(vec![FieldError::new("/query", "too_long")]))?;
    let users = service::search(&state.db, &state.authz, &actor, &query).await?;
    Ok(Json(users.into_iter().map(UserSummaryDto::from).collect()))
}
