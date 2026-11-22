//! Business rules for teams. Every operation asks `authz` first and
//! records changes in the audit log, in the same transaction.

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
    teams::{
        model::{Member, MemberCursor, MembershipSource, Team, TeamChanges, TeamId, TeamRole},
        repo,
    },
    users::{model::UserId, service as users},
};

/// Brings the user's memberships of IdP-synced teams (`teams.idp_group`)
/// in line with their groups claim. Runs on every authenticated request.
///
/// # Errors
///
/// A database error.
pub async fn sync_idp_groups(db: &PgPool, user: UserId, groups: &[String]) -> Result<(), AppError> {
    let (added, removed) = repo::sync_idp_groups(db, user, groups).await?;
    if added > 0 || removed > 0 {
        tracing::info!(user.id = %user.as_uuid(), added, removed, "team memberships synced from the identity provider");
    }
    Ok(())
}

fn entry(
    actor: &Actor,
    action: &'static str,
    id: TeamId,
    decision: &Decision,
    details: serde_json::Value,
) -> NewEntry {
    NewEntry::new(actor.user.id, action, Target::Team(id), decision, details)
}

/// A page of the teams `actor` may see, by slug, after `after` (see
/// [`authz::visible_teams`]).
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
) -> Result<VisiblePage<Team>, AppError> {
    let page = authz::visible_teams(db, policies, actor, after, limit).await?;
    let ids: Vec<uuid::Uuid> = page.items.iter().map(TeamId::as_uuid).collect();
    Ok(VisiblePage {
        items: repo::list(db, &ids).await?,
        next: page.next,
    })
}

/// The team, and the actions `actor` may do to it besides seeing it.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist or `actor` may not see
/// it, or a database error.
pub async fn get(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: TeamId,
) -> Result<(Team, Vec<Action>), AppError> {
    let resource = Resource::Team(id);
    let actions = [
        Action::ViewTeam,
        Action::ManageTeam,
        Action::ManageTeamMembers,
        Action::SetTeamIdpGroup,
    ];
    let requests = actions.map(|action| (action, resource));
    let decisions = authz::decisions(db, policies, actor, &requests).await?;
    let mut allowed = allowed_actions(&actions, &decisions);
    if !allowed.contains(&Action::ViewTeam) {
        return Err(AppError::NotFound);
    }
    let team = repo::get(db, id).await?.ok_or(AppError::NotFound)?;
    // The members of a synced team come from the identity provider.
    let synced = team.idp_group.is_some();
    allowed.retain(|action| {
        *action != Action::ViewTeam && !(*action == Action::ManageTeamMembers && synced)
    });
    Ok((team, allowed))
}

/// Creates a team, with `actor` as its maintainer.
///
/// # Errors
///
/// [`AppError::Forbidden`] unless `actor` may `createTeam` (platform
/// admins and organization admins), [`AppError::Conflict`] if the slug is
/// taken, or a database error.
pub async fn create(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    new: Team,
) -> Result<Team, AppError> {
    let decision =
        authz::require(db, policies, actor, Action::CreateTeam, Resource::Platform).await?;
    let mut tx = db.begin().await?;
    repo::insert(&mut tx, &new, actor.user.id)
        .await
        .map_err(AppError::from_write)?;
    audit::record(
        &mut tx,
        &entry(actor, "team.created", new.id, &decision, json!({})),
    )
    .await?;
    tx.commit().await?;
    tracing::info!(team.id = %new.id.as_uuid(), user.id = %actor.user.id.as_uuid(), "team created");
    Ok(new)
}

/// Renames the team, changes its slug, or sets or clears its identity
/// provider group (which needs `setTeamIdpGroup`, platform admins only).
/// A change to the same values is not recorded.
///
/// # Errors
///
/// [`AppError::NotFound`], [`AppError::Forbidden`] (see
/// [`authz::require`]), [`AppError::Conflict`] if the slug or the
/// identity provider group is taken, or a database error.
pub async fn update(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: TeamId,
    changes: &TeamChanges,
) -> Result<Team, AppError> {
    let resource = Resource::Team(id);
    let mut needed = Vec::new();
    if changes.idp_group.is_some() {
        needed.push(Action::SetTeamIdpGroup);
    }
    if changes.slug.is_some() || changes.name.is_some() || changes.idp_group.is_none() {
        needed.push(Action::ManageTeam);
    }
    let decision = authz::require_all(db, policies, actor, &needed, resource).await?;
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
            "team.updated",
            id,
            &decision,
            json!({ "fields": fields }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(updated)
}

/// Deletes the team, its memberships and its links.
///
/// # Errors
///
/// [`AppError::NotFound`], [`AppError::Forbidden`] (see
/// [`authz::require`]), or a database error.
pub async fn delete(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: TeamId,
) -> Result<(), AppError> {
    let decision =
        authz::require(db, policies, actor, Action::ManageTeam, Resource::Team(id)).await?;
    let mut tx = db.begin().await?;
    if !repo::delete(&mut tx, id).await? {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        &entry(actor, "team.deleted", id, &decision, json!({})),
    )
    .await?;
    tx.commit().await?;
    tracing::info!(team.id = %id.as_uuid(), user.id = %actor.user.id.as_uuid(), "team deleted");
    Ok(())
}

/// Members shown when the caller does not say.
pub const DEFAULT_MEMBER_PAGE: i64 = 100;
/// Most members one page holds: an identity provider group can have
/// thousands.
pub const MAX_MEMBER_PAGE: i64 = 500;

/// A page of a team's members, and where the next one starts.
pub struct MemberPage {
    pub members: Vec<Member>,
    pub next: Option<MemberCursor>,
}

/// Up to `limit` (default [`DEFAULT_MEMBER_PAGE`], at most
/// [`MAX_MEMBER_PAGE`]) of the team's members after `after`.
///
/// # Errors
///
/// [`AppError::NotFound`] unless `actor` may see the team, or a database
/// error.
pub async fn members(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: TeamId,
    after: Option<&MemberCursor>,
    limit: Option<i64>,
) -> Result<MemberPage, AppError> {
    authz::require(db, policies, actor, Action::ViewTeam, Resource::Team(id)).await?;
    let limit = limit
        .unwrap_or(DEFAULT_MEMBER_PAGE)
        .clamp(1, MAX_MEMBER_PAGE);
    let mut members = repo::members(db, id, after, limit.saturating_add(1)).await?;
    let more = usize::try_from(limit).is_ok_and(|limit| members.len() > limit);
    if more {
        members.pop();
    }
    let next = members.last().filter(|_| more).map(MemberCursor::after);
    Ok(MemberPage { members, next })
}

/// Locks the membership for a change. The members of a synced team come
/// from the identity provider: [`AppError::Conflict`]. (A team that is not
/// synced has no synced memberships: clearing its group removed them,
/// under the same lock.) The last maintainer of a team cannot be removed
/// or made a member (`demoted`): the team would be left without one
/// ([`AppError::Conflict`]); add another maintainer first.
async fn editable(
    tx: &mut sqlx::PgConnection,
    id: TeamId,
    user: UserId,
    demoted: bool,
) -> Result<Option<(MembershipSource, TeamRole)>, AppError> {
    let locked = repo::lock_membership(tx, id, user)
        .await?
        .ok_or(AppError::NotFound)?;
    if locked.synced {
        return Err(AppError::Conflict);
    }
    let last_maintainer =
        matches!(locked.membership, Some((_, TeamRole::Maintainer))) && locked.maintainers <= 1;
    if demoted && last_maintainer {
        return Err(AppError::Conflict);
    }
    Ok(locked.membership)
}

/// Adds `user` to the team with `role`, or changes their role.
///
/// # Errors
///
/// [`AppError::NotFound`] if the team or the user does not exist (or the
/// user is disabled), [`AppError::Forbidden`] unless `actor` may
/// `manageTeamMembers`, [`AppError::Conflict`] if the team is synced with
/// an identity provider group or this would demote its last maintainer, or
/// a database error.
pub async fn set_member(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: TeamId,
    user: UserId,
    role: TeamRole,
) -> Result<(), AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::ManageTeamMembers,
        Resource::Team(id),
    )
    .await?;
    let mut tx = db.begin().await?;
    // The user before the team, in the order the identity provider group
    // sync locks them.
    users::require_active(&mut tx, user).await?;
    editable(&mut tx, id, user, role != TeamRole::Maintainer).await?;
    let previous = repo::set_member(&mut tx, id, user, role)
        .await
        .map_err(AppError::from_write)?;
    if previous != Some(role) {
        audit::record(
            &mut tx,
            &entry(
                actor,
                "team.member_set",
                id,
                &decision,
                json!({ "user_id": user.as_uuid(), "role": role.as_str() }),
            ),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Removes `user` from the team.
///
/// # Errors
///
/// [`AppError::NotFound`] if the team does not exist or `user` is not a
/// member, [`AppError::Forbidden`] unless `actor` may
/// `manageTeamMembers`, [`AppError::Conflict`] if the team is synced with
/// an identity provider group or `user` is its last maintainer, or a
/// database error.
pub async fn remove_member(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    id: TeamId,
    user: UserId,
) -> Result<(), AppError> {
    let decision = authz::require(
        db,
        policies,
        actor,
        Action::ManageTeamMembers,
        Resource::Team(id),
    )
    .await?;
    let mut tx = db.begin().await?;
    if editable(&mut tx, id, user, true).await?.is_none()
        || !repo::remove_member(&mut tx, id, user).await?
    {
        return Err(AppError::NotFound);
    }
    audit::record(
        &mut tx,
        &entry(
            actor,
            "team.member_removed",
            id,
            &decision,
            json!({ "user_id": user.as_uuid() }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
