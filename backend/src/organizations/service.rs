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
        service::{self as authz, VisiblePage, allowed_actions},
    },
    error::AppError,
    names::Slug,
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

/// Admins or linked teams shown when the caller does not say.
pub const DEFAULT_PAGE: i64 = 100;
/// Most admins or linked teams one page holds: an enterprise's
/// organization can have hundreds of each.
pub const MAX_PAGE: i64 = 500;

/// `limit`, or [`DEFAULT_PAGE`], within 1 to [`MAX_PAGE`].
fn page_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
}

/// The first `limit` of `items` (fetched with one more than `limit`), and
/// whether more follow.
fn one_page<T>(mut items: Vec<T>, limit: i64) -> (Vec<T>, bool) {
    let more = usize::try_from(limit).is_ok_and(|limit| items.len() > limit);
    if more {
        items.pop();
    }
    (items, more)
}

/// A page of an organization's admins, and the admin the next one starts
/// after.
pub struct AdminPage {
    pub admins: Vec<UserSummary>,
    pub next: Option<UserId>,
}

/// A page of the teams linked to an organization, and the slug the next
/// one starts after.
pub struct TeamLinkPage {
    pub links: Vec<TeamLink>,
    pub next: Option<Slug>,
}

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

/// A page of the organizations `actor` may read, by slug, after `after`
/// (see [`authz::visible_organizations`]).
///
/// # Errors
///
/// A database error.
pub async fn list(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    after: Option<&Slug>,
    limit: Option<i64>,
) -> Result<VisiblePage<Organization>, AppError> {
    let page = authz::visible_organizations(db, policies, actor, after, limit).await?;
    let ids: Vec<uuid::Uuid> = page.items.iter().map(OrganizationId::as_uuid).collect();
    Ok(VisiblePage {
        items: repo::list(db, &ids).await?,
        next: page.next,
    })
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
    let (updated, fields) = repo::update(&mut tx, id, changes)
        .await
        .map_err(AppError::from_write)?
        .ok_or(AppError::NotFound)?;
    if fields.is_empty() {
        return Ok(updated);
    }
    audit::record(
        &mut tx,
        &entry(
            actor,
            "organization.updated",
            id,
            &decision,
            json!({ "fields": fields }),
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

/// Up to `limit` (default [`DEFAULT_PAGE`], at most [`MAX_PAGE`]) of the
/// organization's admins after the admin `after`, by display name.
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
    after: Option<UserId>,
    limit: Option<i64>,
) -> Result<AdminPage, AppError> {
    authz::require(
        db,
        policies,
        actor,
        Action::Read,
        Resource::Organization(id),
    )
    .await?;
    let limit = page_limit(limit);
    let (admins, more) = one_page(
        repo::admins(db, id, after, limit.saturating_add(1)).await?,
        limit,
    );
    let next = admins.last().filter(|_| more).map(|admin| admin.id);
    Ok(AdminPage { admins, next })
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
    let mut tx = db.begin().await?;
    users::require_active(&mut tx, user).await?;
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

/// Up to `limit` (default [`DEFAULT_PAGE`], at most [`MAX_PAGE`]) of the
/// teams linked to the organization after the slug `after`, by slug.
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
    after: Option<&Slug>,
    limit: Option<i64>,
) -> Result<TeamLinkPage, AppError> {
    authz::require(
        db,
        policies,
        actor,
        Action::Read,
        Resource::Organization(id),
    )
    .await?;
    let limit = page_limit(limit);
    let (links, more) = one_page(
        repo::team_links(db, id, after, limit.saturating_add(1)).await?,
        limit,
    );
    let next = links
        .last()
        .filter(|_| more)
        .map(|link| link.team.slug.clone());
    Ok(TeamLinkPage { links, next })
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
    let mut decision = authz::require(
        db,
        policies,
        actor,
        Action::ManageTeamLinks,
        Resource::Organization(id),
    )
    .await?;
    // A team the actor may not see cannot be probed or linked.
    let view = authz::require(db, policies, actor, Action::ViewTeam, Resource::Team(team)).await?;
    // Both decisions allowed it: the audit entry lists the policies of both.
    decision.policy_ids.extend(view.policy_ids);
    decision.policy_ids.sort();
    decision.policy_ids.dedup();
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
/// `None`); the membership sync picks the change up from the database.
/// Linking checks the workspace first
/// ([`crate::openshell::service::check_link`]): `user_token` gives the
/// user's own access token, asked for only when token exchange is on.
/// Linking it to the workspace it already has changes and records nothing.
///
/// # Errors
///
/// - [`AppError::NotFound`], [`AppError::Forbidden`] (see
///   [`authz::require`]), and those of
///   [`crate::openshell::service::check_link`];
/// - [`AppError::Conflict`] when the integration is off, or another
///   organization links the workspace.
pub async fn set_openshell_workspace(
    db: &PgPool,
    policies: &Policies,
    openshell: Option<&crate::openshell::OpenShell>,
    actor: &Actor,
    id: OrganizationId,
    workspace: Option<&crate::openshell::model::WorkspaceName>,
    user_token: impl AsyncFnOnce() -> Result<secrecy::SecretString, AppError>,
) -> Result<(), AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::LinkOpenShellWorkspace,
        Resource::Organization(id),
    )
    .await?;
    let openshell = openshell.ok_or(AppError::Conflict)?;
    let current = repo::get(db, id).await?.ok_or(AppError::NotFound)?;
    if current.openshell_workspace.as_ref() == workspace {
        return Ok(());
    }
    if let Some(workspace) = workspace {
        crate::openshell::service::check_link(openshell, workspace, user_token).await?;
    }
    let mut tx = db.begin().await?;
    let changed = repo::set_openshell_workspace(&mut tx, id, workspace)
        .await
        .map_err(AppError::from_write)?
        .ok_or(AppError::NotFound)?;
    if !changed {
        // Changed to this meanwhile.
        return Ok(());
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
    Ok(())
}
