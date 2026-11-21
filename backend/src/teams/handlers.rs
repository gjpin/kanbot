//! Handlers of the `/teams` routes.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    error::AppError,
    http::{extract::Caller, problem::Problem},
    state::AppState,
    teams::{
        dto::{MemberChangeDto, MemberDto, NewTeamDto, TeamChangesDto, TeamDto, TeamSummaryDto},
        model::{IdpGroupChange, Team, TeamChanges, TeamId},
        service,
    },
    users::model::UserId,
};

/// The teams the caller may see, by slug: their own, or all of them for
/// platform and organization admins.
#[utoipa::path(
    get,
    path = "/teams",
    operation_id = "list_teams",
    tag = "teams",
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The teams.", body = Vec<TeamSummaryDto>),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn list(
    State(state): State<AppState>,
    Caller(actor): Caller,
) -> Result<Json<Vec<TeamSummaryDto>>, AppError> {
    let teams = service::list(&state.db, &state.authz, &actor).await?;
    Ok(Json(teams.into_iter().map(TeamSummaryDto::from).collect()))
}

/// Creates a team, with the caller as its maintainer. Platform admins and
/// organization admins only.
#[utoipa::path(
    post,
    path = "/teams",
    operation_id = "create_team",
    tag = "teams",
    request_body = NewTeamDto,
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = CREATED, description = "The new team.", body = TeamDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to create teams.",
         body = Problem, content_type = "application/problem+json"),
        (status = CONFLICT, description = "The slug is taken.",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "The slug or name is invalid.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn create(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Json(new): Json<NewTeamDto>,
) -> Result<(StatusCode, Json<TeamDto>), AppError> {
    let new = Team::try_from(new)?;
    let created = service::create(&state.db, &state.authz, &actor, new).await?;
    let (team, permissions) = service::get(&state.db, &state.authz, &actor, created.id).await?;
    Ok((StatusCode::CREATED, Json(TeamDto::new(team, &permissions))))
}

/// A team, and what the caller may do to it.
#[utoipa::path(
    get,
    path = "/teams/{id}",
    operation_id = "get_team",
    tag = "teams",
    params(("id" = String, Path, description = "The team's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The team.", body = TeamDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such team, or not allowed to see it.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn get(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<TeamDto>, AppError> {
    let (team, permissions) =
        service::get(&state.db, &state.authz, &actor, TeamId::from_uuid(id)).await?;
    Ok(Json(TeamDto::new(team, &permissions)))
}

/// Renames a team, changes its slug, or sets or clears its identity
/// provider group (platform admins only).
#[utoipa::path(
    patch,
    path = "/teams/{id}",
    operation_id = "update_team",
    tag = "teams",
    params(("id" = String, Path, description = "The team's ID (a UUID).")),
    request_body = TeamChangesDto,
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The team, changed.", body = TeamDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to make this change.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such team, or not allowed to see it.",
         body = Problem, content_type = "application/problem+json"),
        (status = CONFLICT, description = "The slug or the identity provider group is taken.",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "A field is invalid.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn update(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
    Json(changes): Json<TeamChangesDto>,
) -> Result<Json<TeamDto>, AppError> {
    let id = TeamId::from_uuid(id);
    let changes = TeamChanges::try_from(changes)?;
    service::update(&state.db, &state.authz, &actor, id, &changes).await?;
    let (team, permissions) = service::get(&state.db, &state.authz, &actor, id).await?;
    Ok(Json(TeamDto::new(team, &permissions)))
}

/// Deletes a team, its memberships and its links.
#[utoipa::path(
    delete,
    path = "/teams/{id}",
    operation_id = "delete_team",
    tag = "teams",
    params(("id" = String, Path, description = "The team's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = NO_CONTENT, description = "Deleted."),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to delete the team.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such team, or not allowed to see it.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn delete(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    service::delete(&state.db, &state.authz, &actor, TeamId::from_uuid(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The team's members: maintainers first, then by display name.
#[utoipa::path(
    get,
    path = "/teams/{id}/members",
    operation_id = "list_team_members",
    tag = "teams",
    params(("id" = String, Path, description = "The team's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The members.", body = Vec<MemberDto>),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such team, or not allowed to see it.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn members(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<MemberDto>>, AppError> {
    let members = service::members(&state.db, &state.authz, &actor, TeamId::from_uuid(id)).await?;
    Ok(Json(members.into_iter().map(MemberDto::from).collect()))
}

/// Adds a user to the team with a role, or changes their role.
#[utoipa::path(
    put,
    path = "/teams/{id}/members/{user_id}",
    operation_id = "set_team_member",
    tag = "teams",
    params(
        ("id" = String, Path, description = "The team's ID (a UUID)."),
        ("user_id" = String, Path, description = "The user's ID (a UUID)."),
    ),
    request_body = MemberChangeDto,
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = NO_CONTENT, description = "The user is a member with this role."),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to manage the team's members.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such team or user, or not allowed to see the team.",
         body = Problem, content_type = "application/problem+json"),
        (status = CONFLICT, description = "The membership comes from the identity provider.",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "The body is not a member change.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn set_member(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path((id, user)): Path<(Uuid, Uuid)>,
    Json(change): Json<MemberChangeDto>,
) -> Result<StatusCode, AppError> {
    service::set_member(
        &state.db,
        &state.authz,
        &actor,
        TeamId::from_uuid(id),
        UserId::from_uuid(user),
        change.role.into(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a user from the team.
#[utoipa::path(
    delete,
    path = "/teams/{id}/members/{user_id}",
    operation_id = "remove_team_member",
    tag = "teams",
    params(
        ("id" = String, Path, description = "The team's ID (a UUID)."),
        ("user_id" = String, Path, description = "The user's ID (a UUID)."),
    ),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = NO_CONTENT, description = "The user is no longer a member."),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to manage the team's members.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such team, the user is not a member, or not allowed to see the team.",
         body = Problem, content_type = "application/problem+json"),
        (status = CONFLICT, description = "The membership comes from the identity provider.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn remove_member(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path((id, user)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    service::remove_member(
        &state.db,
        &state.authz,
        &actor,
        TeamId::from_uuid(id),
        UserId::from_uuid(user),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Stops syncing the team with its identity provider group: the synced
/// members are removed and the team is managed by hand again. Platform
/// admins only. The same as `PATCH` with `"idp_group": null`, for clients
/// that cannot send a null.
#[utoipa::path(
    delete,
    path = "/teams/{id}/idp_group",
    operation_id = "clear_team_idp_group",
    tag = "teams",
    params(("id" = String, Path, description = "The team's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The team, no longer synced.", body = TeamDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to change the team's identity provider group.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such team, or not allowed to see it.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn clear_idp_group(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<TeamDto>, AppError> {
    let id = TeamId::from_uuid(id);
    let changes = TeamChanges {
        idp_group: Some(IdpGroupChange::Clear),
        ..TeamChanges::default()
    };
    service::update(&state.db, &state.authz, &actor, id, &changes).await?;
    let (team, permissions) = service::get(&state.db, &state.authz, &actor, id).await?;
    Ok(Json(TeamDto::new(team, &permissions)))
}
