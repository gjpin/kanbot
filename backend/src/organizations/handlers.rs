//! Handlers of the `/organizations` routes.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    authz::model::Action,
    error::{AppError, FieldError},
    http::{
        extract::{Caller, UserAccessToken},
        problem::Problem,
    },
    openshell::model::WorkspaceName,
    organizations::{
        dto::{
            NewOrganizationDto, OpenShellLinkDto, OrganizationChangesDto, OrganizationDto,
            OrganizationSummaryDto, TeamLinkChangeDto, TeamLinkDto,
        },
        model::{Organization, OrganizationChanges, OrganizationId},
        service,
    },
    state::AppState,
    teams::model::TeamId,
    users::{dto::UserSummaryDto, model::UserId},
};

/// `permissions` without what this server cannot do: linking an
/// `OpenShell` workspace needs the integration.
fn without_unavailable(state: &AppState, mut permissions: Vec<Action>) -> Vec<Action> {
    if state.openshell.is_none() {
        permissions.retain(|action| *action != Action::LinkOpenShellWorkspace);
    }
    permissions
}

/// The organizations the caller may read, by slug.
#[utoipa::path(
    get,
    path = "/organizations",
    operation_id = "list_organizations",
    tag = "organizations",
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The organizations.", body = Vec<OrganizationSummaryDto>),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn list(
    State(state): State<AppState>,
    Caller(actor): Caller,
) -> Result<Json<Vec<OrganizationSummaryDto>>, AppError> {
    let organizations = service::list(&state.db, &state.authz, &actor).await?;
    Ok(Json(
        organizations
            .into_iter()
            .map(OrganizationSummaryDto::from)
            .collect(),
    ))
}

/// Creates an organization. Platform admins only.
#[utoipa::path(
    post,
    path = "/organizations",
    operation_id = "create_organization",
    tag = "organizations",
    request_body = NewOrganizationDto,
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = CREATED, description = "The new organization.", body = OrganizationDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to create organizations.",
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
    Json(new): Json<NewOrganizationDto>,
) -> Result<(StatusCode, Json<OrganizationDto>), AppError> {
    let new = Organization::try_from(new)?;
    let created = service::create(&state.db, &state.authz, &actor, new).await?;
    let (organization, permissions) =
        service::get(&state.db, &state.authz, &actor, created.id).await?;
    Ok((
        StatusCode::CREATED,
        Json(OrganizationDto::new(
            organization,
            &without_unavailable(&state, permissions),
        )),
    ))
}

/// An organization, and what the caller may do to it.
#[utoipa::path(
    get,
    path = "/organizations/{id}",
    operation_id = "get_organization",
    tag = "organizations",
    params(("id" = String, Path, description = "The organization's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The organization.", body = OrganizationDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, or not allowed to read it.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn get(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<OrganizationDto>, AppError> {
    let (organization, permissions) = service::get(
        &state.db,
        &state.authz,
        &actor,
        OrganizationId::from_uuid(id),
    )
    .await?;
    Ok(Json(OrganizationDto::new(
        organization,
        &without_unavailable(&state, permissions),
    )))
}

/// Renames an organization or changes its slug.
#[utoipa::path(
    patch,
    path = "/organizations/{id}",
    operation_id = "update_organization",
    tag = "organizations",
    params(("id" = String, Path, description = "The organization's ID (a UUID).")),
    request_body = OrganizationChangesDto,
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The organization, changed.", body = OrganizationDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to manage the organization.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, or not allowed to read it.",
         body = Problem, content_type = "application/problem+json"),
        (status = CONFLICT, description = "The slug is taken.",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "The slug or name is invalid.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn update(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
    Json(changes): Json<OrganizationChangesDto>,
) -> Result<Json<OrganizationDto>, AppError> {
    let id = OrganizationId::from_uuid(id);
    let changes = OrganizationChanges::try_from(changes)?;
    service::update(&state.db, &state.authz, &actor, id, &changes).await?;
    let (organization, permissions) = service::get(&state.db, &state.authz, &actor, id).await?;
    Ok(Json(OrganizationDto::new(
        organization,
        &without_unavailable(&state, permissions),
    )))
}

/// Deletes an organization, its admins and its team links. Platform
/// admins only; the Default organization cannot be deleted.
#[utoipa::path(
    delete,
    path = "/organizations/{id}",
    operation_id = "delete_organization",
    tag = "organizations",
    params(("id" = String, Path, description = "The organization's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = NO_CONTENT, description = "Deleted."),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to delete the organization.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, or not allowed to read it.",
         body = Problem, content_type = "application/problem+json"),
        (status = CONFLICT, description = "The Default organization cannot be deleted.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn delete(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    service::delete(
        &state.db,
        &state.authz,
        &actor,
        OrganizationId::from_uuid(id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The organization's admins, by display name.
#[utoipa::path(
    get,
    path = "/organizations/{id}/admins",
    operation_id = "list_organization_admins",
    tag = "organizations",
    params(("id" = String, Path, description = "The organization's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The admins.", body = Vec<UserSummaryDto>),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, or not allowed to read it.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn admins(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<UserSummaryDto>>, AppError> {
    let admins = service::admins(
        &state.db,
        &state.authz,
        &actor,
        OrganizationId::from_uuid(id),
    )
    .await?;
    Ok(Json(admins.into_iter().map(UserSummaryDto::from).collect()))
}

/// Makes a user an admin of the organization.
#[utoipa::path(
    put,
    path = "/organizations/{id}/admins/{user_id}",
    operation_id = "add_organization_admin",
    tag = "organizations",
    params(
        ("id" = String, Path, description = "The organization's ID (a UUID)."),
        ("user_id" = String, Path, description = "The user's ID (a UUID)."),
    ),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = NO_CONTENT, description = "The user is an admin."),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to manage the organization's admins.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization or user, or not allowed to read the organization.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn add_admin(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path((id, user)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    service::add_admin(
        &state.db,
        &state.authz,
        &actor,
        OrganizationId::from_uuid(id),
        UserId::from_uuid(user),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a user from the organization's admins.
#[utoipa::path(
    delete,
    path = "/organizations/{id}/admins/{user_id}",
    operation_id = "remove_organization_admin",
    tag = "organizations",
    params(
        ("id" = String, Path, description = "The organization's ID (a UUID)."),
        ("user_id" = String, Path, description = "The user's ID (a UUID)."),
    ),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = NO_CONTENT, description = "The user is no longer an admin."),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to manage the organization's admins.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, the user is not an admin, or not allowed to read the organization.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn remove_admin(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path((id, user)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    service::remove_admin(
        &state.db,
        &state.authz,
        &actor,
        OrganizationId::from_uuid(id),
        UserId::from_uuid(user),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The teams linked to the organization, by slug.
#[utoipa::path(
    get,
    path = "/organizations/{id}/teams",
    operation_id = "list_organization_teams",
    tag = "organizations",
    params(("id" = String, Path, description = "The organization's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The linked teams.", body = Vec<TeamLinkDto>),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "The user has no kanbot role (`forbidden`) or is disabled (`account_disabled`).",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, or not allowed to read it.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn team_links(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<TeamLinkDto>>, AppError> {
    let links = service::team_links(
        &state.db,
        &state.authz,
        &actor,
        OrganizationId::from_uuid(id),
    )
    .await?;
    Ok(Json(links.into_iter().map(TeamLinkDto::from).collect()))
}

/// Links a team to the organization, or changes its access.
#[utoipa::path(
    put,
    path = "/organizations/{id}/teams/{team_id}",
    operation_id = "link_organization_team",
    tag = "organizations",
    params(
        ("id" = String, Path, description = "The organization's ID (a UUID)."),
        ("team_id" = String, Path, description = "The team's ID (a UUID)."),
    ),
    request_body = TeamLinkChangeDto,
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = NO_CONTENT, description = "The team is linked with this access."),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to manage the organization's team links.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization or team, or not allowed to read the organization.",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "The body is not a team link.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn set_team_link(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path((id, team)): Path<(Uuid, Uuid)>,
    Json(change): Json<TeamLinkChangeDto>,
) -> Result<StatusCode, AppError> {
    service::set_team_link(
        &state.db,
        &state.authz,
        &actor,
        OrganizationId::from_uuid(id),
        TeamId::from_uuid(team),
        change.access.into(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Unlinks a team from the organization.
#[utoipa::path(
    delete,
    path = "/organizations/{id}/teams/{team_id}",
    operation_id = "unlink_organization_team",
    tag = "organizations",
    params(
        ("id" = String, Path, description = "The organization's ID (a UUID)."),
        ("team_id" = String, Path, description = "The team's ID (a UUID)."),
    ),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = NO_CONTENT, description = "The team is no longer linked."),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to manage the organization's team links.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, the team is not linked, or not allowed to read the organization.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn remove_team_link(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path((id, team)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    service::remove_team_link(
        &state.db,
        &state.authz,
        &actor,
        OrganizationId::from_uuid(id),
        TeamId::from_uuid(team),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Links the organization to an `OpenShell` workspace; kanbot then keeps the
/// workspace's members in sync: the organization's admins as admins, the
/// members of its teams with write access as users. Platform admins only.
#[utoipa::path(
    put,
    path = "/organizations/{id}/openshell_workspace",
    operation_id = "link_organization_openshell_workspace",
    tag = "organizations",
    params(("id" = String, Path, description = "The organization's ID (a UUID).")),
    request_body = OpenShellLinkDto,
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The organization, linked.", body = OrganizationDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to link the organization, or `OpenShell` refused the user.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, or not allowed to read it.",
         body = Problem, content_type = "application/problem+json"),
        (status = CONFLICT, description = "The server has no `OpenShell` integration, or another organization links the workspace.",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "No such workspace (`/workspace`: `not_found`), or an invalid name.",
         body = Problem, content_type = "application/problem+json"),
        (status = SERVICE_UNAVAILABLE, description = "`OpenShell` or the identity provider cannot be reached.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn link_openshell(
    State(state): State<AppState>,
    Caller(actor): Caller,
    UserAccessToken(token): UserAccessToken,
    Path(id): Path<Uuid>,
    Json(link): Json<OpenShellLinkDto>,
) -> Result<Json<OrganizationDto>, AppError> {
    let workspace = WorkspaceName::parse(&link.workspace)
        .ok_or_else(|| AppError::Validation(vec![FieldError::new("/workspace", "invalid")]))?;
    let id = OrganizationId::from_uuid(id);
    service::set_openshell_workspace(
        &state.db,
        &state.authz,
        state.openshell.as_deref(),
        &actor,
        id,
        Some((&workspace, &token)),
    )
    .await?;
    let (organization, permissions) = service::get(&state.db, &state.authz, &actor, id).await?;
    Ok(Json(OrganizationDto::new(
        organization,
        &without_unavailable(&state, permissions),
    )))
}

/// Unlinks the organization from its `OpenShell` workspace; kanbot then
/// removes the members it added there. Platform admins only.
#[utoipa::path(
    delete,
    path = "/organizations/{id}/openshell_workspace",
    operation_id = "unlink_organization_openshell_workspace",
    tag = "organizations",
    params(("id" = String, Path, description = "The organization's ID (a UUID).")),
    security(("bearer" = []), ("session" = [])),
    responses(
        (status = OK, description = "The organization, unlinked.", body = OrganizationDto),
        (status = UNAUTHORIZED, description = "No valid credentials.",
         body = Problem, content_type = "application/problem+json"),
        (status = FORBIDDEN, description = "Not allowed to unlink the organization.",
         body = Problem, content_type = "application/problem+json"),
        (status = NOT_FOUND, description = "No such organization, or not allowed to read it.",
         body = Problem, content_type = "application/problem+json"),
        (status = CONFLICT, description = "The server has no `OpenShell` integration.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn unlink_openshell(
    State(state): State<AppState>,
    Caller(actor): Caller,
    Path(id): Path<Uuid>,
) -> Result<Json<OrganizationDto>, AppError> {
    let id = OrganizationId::from_uuid(id);
    service::set_openshell_workspace(
        &state.db,
        &state.authz,
        state.openshell.as_deref(),
        &actor,
        id,
        None,
    )
    .await?;
    let (organization, permissions) = service::get(&state.db, &state.authz, &actor, id).await?;
    Ok(Json(OrganizationDto::new(
        organization,
        &without_unavailable(&state, permissions),
    )))
}
