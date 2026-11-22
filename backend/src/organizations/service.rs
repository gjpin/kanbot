//! Business rules for organizations. Every operation asks `authz` first
//! and records changes in the audit log, in the same transaction.

use serde_json::json;
use sqlx::PgPool;

use crate::{
    audit::{
        model::{NewEntry, Target},
        service as audit,
    },
    authz::{
        model::{Action, Actor, Decision, Resource},
        policies::Policies,
        service::{self as authz, allowed_actions},
    },
    error::{AppError, FieldError},
    organizations::{
        model::{Access, Organization, OrganizationChanges, OrganizationId, TeamLink},
        repo,
    },
    teams::model::TeamId,
    users::{
        model::{UserId, UserSummary},
        service as users,
    },
};

fn entry(
    actor: &Actor,
    action: &'static str,
    id: OrganizationId,
    decision: &Decision,
    details: serde_json::Value,
) -> NewEntry {
    NewEntry::new(
        actor.user.id,
        action,
        Target::Organization(id),
        decision,
        details,
    )
}

/// The organizations `actor` may read, by slug.
///
/// # Errors
///
/// A database error.
pub async fn list(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
) -> Result<Vec<Organization>, AppError> {
    let ids: Vec<uuid::Uuid> = authz::visible_organizations(db, policies, actor)
        .await?
        .iter()
        .map(OrganizationId::as_uuid)
        .collect();
    Ok(repo::list(db, &ids).await?)
}

/// The organization, and the actions `actor` may do to it besides
/// reading it.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist or `actor` may not read
/// it, or a database error.
pub async fn get(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
) -> Result<(Organization, Vec<Action>), AppError> {
    let resource = Resource::Organization(id);
    let actions = [
        Action::Read,
        Action::Write,
        Action::ManageOrganization,
        Action::ManageOrganizationAdmins,
        Action::ManageTeamLinks,
        Action::DeleteOrganization,
        Action::LinkOpenShellWorkspace,
    ];
    let requests = actions.map(|action| (action, resource));
    let decisions = authz::decisions(db, policies, actor, &requests).await?;
    let mut allowed = allowed_actions(&actions, &decisions);
    if !allowed.contains(&Action::Read) {
        return Err(AppError::NotFound);
    }
    let organization = repo::get(db, id).await?.ok_or(AppError::NotFound)?;
    // The Default organization cannot be deleted by anyone.
    allowed.retain(|action| {
        *action != Action::Read
            && !(*action == Action::DeleteOrganization && id == OrganizationId::DEFAULT)
    });
    Ok((organization, allowed))
}

/// Creates an organization.
///
/// # Errors
///
/// [`AppError::Forbidden`] unless `actor` may `createOrganization`,
/// [`AppError::Conflict`] if the slug is taken, or a database error.
pub async fn create(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    new: Organization,
) -> Result<Organization, AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::CreateOrganization,
        Resource::Platform,
    )
    .await?;
    let mut tx = db.begin().await?;
    repo::insert(&mut tx, &new)
        .await
        .map_err(AppError::from_write)?;
    audit::record(
        &mut tx,
        &entry(actor, "organization.created", new.id, &decision, json!({})),
    )
    .await?;
    tx.commit().await?;
    tracing::info!(organization.id = %new.id.as_uuid(), user.id = %actor.user.id.as_uuid(), "organization created");
    Ok(new)
}

/// The Default organization's slug, which never changes.
const DEFAULT_SLUG: &str = "default";

/// Renames the organization or changes its slug. A change to the same
/// values is not recorded.
///
/// # Errors
///
/// [`AppError::NotFound`], [`AppError::Forbidden`] (see
/// [`authz::require`]), [`AppError::Conflict`] if the slug is taken or the
/// organization is the Default one (its slug stays `default`), or a
/// database error.
pub async fn update(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
    changes: &OrganizationChanges,
) -> Result<Organization, AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::ManageOrganization,
        Resource::Organization(id),
    )
    .await?;
    if id == OrganizationId::DEFAULT
        && changes
            .slug
            .as_ref()
            .is_some_and(|slug| slug.as_str() != DEFAULT_SLUG)
    {
        return Err(AppError::Conflict);
    }
    let mut tx = db.begin().await?;
    let (updated, modified) = repo::update(&mut tx, id, changes)
        .await
        .map_err(AppError::from_write)?
        .ok_or(AppError::NotFound)?;
    if !modified {
        return Ok(updated);
    }
    audit::record(
        &mut tx,
        &entry(
            actor,
            "organization.updated",
            id,
            &decision,
            json!({ "fields": changes.fields() }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(updated)
}

/// Deletes the organization with its admins and team links.
///
/// # Errors
///
/// [`AppError::NotFound`], [`AppError::Forbidden`] (see
/// [`authz::require`]), [`AppError::Conflict`] for the Default
/// organization, or a database error.
pub async fn delete(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
) -> Result<(), AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::DeleteOrganization,
        Resource::Organization(id),
    )
    .await?;
    if id == OrganizationId::DEFAULT {
        return Err(AppError::Conflict);
    }
    let mut tx = db.begin().await?;
    if !repo::delete(&mut tx, id).await? {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        &entry(actor, "organization.deleted", id, &decision, json!({})),
    )
    .await?;
    tx.commit().await?;
    tracing::info!(organization.id = %id.as_uuid(), user.id = %actor.user.id.as_uuid(), "organization deleted");
    Ok(())
}

/// The organization's admins.
///
/// # Errors
///
/// [`AppError::NotFound`] unless `actor` may read the organization, or a
/// database error.
pub async fn admins(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
) -> Result<Vec<UserSummary>, AppError> {
    authz::require(
        db,
        policies,
        actor,
        Action::Read,
        Resource::Organization(id),
    )
    .await?;
    Ok(repo::admins(db, id).await?)
}

/// Makes `user` an admin of the organization (no change if they are).
///
/// # Errors
///
/// [`AppError::NotFound`] if the organization or the user does not exist,
/// [`AppError::Forbidden`] unless `actor` may `manageOrganizationAdmins`,
/// or a database error.
pub async fn add_admin(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
    user: UserId,
) -> Result<(), AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::ManageOrganizationAdmins,
        Resource::Organization(id),
    )
    .await?;
    users::require_active(db, user).await?;
    let mut tx = db.begin().await?;
    if repo::add_admin(&mut tx, id, user)
        .await
        .map_err(AppError::from_write)?
    {
        audit::record(
            &mut tx,
            &entry(
                actor,
                "organization.admin_added",
                id,
                &decision,
                json!({ "user_id": user.as_uuid() }),
            ),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Removes `user` from the organization's admins.
///
/// # Errors
///
/// [`AppError::NotFound`] if the organization does not exist or `user`
/// is not an admin, [`AppError::Forbidden`] unless `actor` may
/// `manageOrganizationAdmins`, or a database error.
pub async fn remove_admin(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
    user: UserId,
) -> Result<(), AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::ManageOrganizationAdmins,
        Resource::Organization(id),
    )
    .await?;
    let mut tx = db.begin().await?;
    if !repo::remove_admin(&mut tx, id, user).await? {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        &entry(
            actor,
            "organization.admin_removed",
            id,
            &decision,
            json!({ "user_id": user.as_uuid() }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The teams linked to the organization.
///
/// # Errors
///
/// [`AppError::NotFound`] unless `actor` may read the organization, or a
/// database error.
pub async fn team_links(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
) -> Result<Vec<TeamLink>, AppError> {
    authz::require(
        db,
        policies,
        actor,
        Action::Read,
        Resource::Organization(id),
    )
    .await?;
    Ok(repo::team_links(db, id).await?)
}

/// Links `team` to the organization with `access`, or changes its access.
///
/// # Errors
///
/// [`AppError::NotFound`] if the organization or the team does not exist
/// (or `actor` may not see the team), [`AppError::Forbidden`] unless
/// `actor` may `manageTeamLinks`, or a database error.
pub async fn set_team_link(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
    team: TeamId,
    access: Access,
) -> Result<(), AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::ManageTeamLinks,
        Resource::Organization(id),
    )
    .await?;
    // A team the actor may not see cannot be probed or linked.
    authz::require(db, policies, actor, Action::ViewTeam, Resource::Team(team)).await?;
    let mut tx = db.begin().await?;
    let changed = repo::set_team_link(&mut tx, id, team, access)
        .await
        .map_err(AppError::from_write)?;
    if changed {
        audit::record(
            &mut tx,
            &entry(
                actor,
                "organization.team_linked",
                id,
                &decision,
                json!({ "team_id": team.as_uuid(), "access": access.as_str() }),
            ),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Unlinks `team` from the organization.
///
/// # Errors
///
/// [`AppError::NotFound`] if the organization does not exist or the team
/// is not linked, [`AppError::Forbidden`] unless `actor` may
/// `manageTeamLinks`, or a database error.
pub async fn remove_team_link(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: OrganizationId,
    team: TeamId,
) -> Result<(), AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::ManageTeamLinks,
        Resource::Organization(id),
    )
    .await?;
    let mut tx = db.begin().await?;
    if !repo::remove_team_link(&mut tx, id, team).await? {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        &entry(
            actor,
            "organization.team_unlinked",
            id,
            &decision,
            json!({ "team_id": team.as_uuid() }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Links the organization to an `OpenShell` workspace (or unlinks it, with
/// `None`), then wakes the membership sync. `link` is the workspace and the
/// user's own access token: the workspace must exist and be visible to the
/// user, which kanbot asks the gateway with a token for the user
/// ([`crate::openshell::credentials::Credentials::on_behalf_of`]).
///
/// # Errors
///
/// - [`AppError::NotFound`], [`AppError::Forbidden`] (see
///   [`authz::require`]); `Forbidden` too when the gateway refuses the
///   user;
/// - [`AppError::Conflict`] when the integration is off, or another
///   organization links the workspace;
/// - a validation error on `/workspace` when it does not exist;
/// - [`AppError::Unavailable`] when no token or answer can be had.
pub async fn set_openshell_workspace(
    db: &PgPool,
    policies: &Policies,
    openshell: Option<&crate::openshell::OpenShell>,
    actor: &Actor,
    id: OrganizationId,
    link: Option<(
        &crate::openshell::model::WorkspaceName,
        &secrecy::SecretString,
    )>,
) -> Result<(), AppError> {
    use crate::openshell::gateway::GatewayError;

    let decision = authz::require(
        db,
        policies,
        actor,
        Action::LinkOpenShellWorkspace,
        Resource::Organization(id),
    )
    .await?;
    let openshell = openshell.ok_or(AppError::Conflict)?;
    let workspace = link.map(|(workspace, _)| workspace);
    if let Some((workspace, user_token)) = link {
        let token = openshell
            .credentials
            .on_behalf_of(user_token)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "openshell: no token for the user");
                AppError::Unavailable
            })?;
        match openshell.gateway.workspace_exists(&token, workspace).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(AppError::Validation(vec![FieldError::new(
                    "/workspace",
                    "not_found",
                )]));
            }
            Err(GatewayError::Refused) => return Err(AppError::Forbidden),
            Err(error) => {
                tracing::warn!(%error, "openshell: workspace lookup failed");
                return Err(AppError::Unavailable);
            }
        }
    }
    let mut tx = db.begin().await?;
    if !repo::set_openshell_workspace(&mut tx, id, workspace)
        .await
        .map_err(AppError::from_write)?
    {
        return Err(AppError::NotFound);
    }
    let (action, details) = match workspace {
        Some(workspace) => (
            "organization.openshell_linked",
            json!({ "workspace": workspace.as_str() }),
        ),
        None => ("organization.openshell_unlinked", json!({})),
    };
    audit::record(&mut tx, &entry(actor, action, id, &decision, details)).await?;
    tx.commit().await?;
    openshell.wake_sync();
    Ok(())
}
