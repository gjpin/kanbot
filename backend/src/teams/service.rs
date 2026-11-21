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
        service::{self as authz, allowed_actions},
    },
    error::AppError,
    teams::{
        model::{Member, MembershipSource, Team, TeamChanges, TeamId, TeamRole},
        repo,
    },
    users::model::UserId,
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

/// The teams `actor` may see, by slug.
///
/// # Errors
///
/// A database error.
pub async fn list(db: &PgPool, policies: &Policies, actor: &Actor) -> Result<Vec<Team>, AppError> {
    let ids: Vec<uuid::Uuid> = authz::visible_teams(db, policies, actor)
        .await?
        .iter()
        .map(TeamId::as_uuid)
        .collect();
    Ok(repo::list(db, &ids).await?)
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
/// provider group
/// (which needs `setTeamIdpGroup`, platform admins only).
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
    let mut policy_ids = Vec::new();
    if changes.idp_group.is_some() {
        let decision =
            authz::require(db, policies, actor, Action::SetTeamIdpGroup, resource).await?;
        policy_ids.extend(decision.policy_ids);
    }
    if changes.slug.is_some() || changes.name.is_some() || changes.idp_group.is_none() {
        let decision = authz::require(db, policies, actor, Action::ManageTeam, resource).await?;
        policy_ids.extend(decision.policy_ids);
    }
    policy_ids.sort();
    policy_ids.dedup();
    let decision = Decision {
        allowed: true,
        policy_ids,
    };
    let mut tx = db.begin().await?;
    let updated = repo::update(&mut tx, id, changes)
        .await
        .map_err(AppError::from_write)?
        .ok_or(AppError::NotFound)?;
    audit::record(
        &mut tx,
        &entry(
            actor,
            "team.updated",
            id,
            &decision,
            json!({ "fields": changes.fields() }),
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

/// The team's members.
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
) -> Result<Vec<Member>, AppError> {
    authz::require(db, policies, actor, Action::ViewTeam, Resource::Team(id)).await?;
    Ok(repo::members(db, id).await?)
}

/// Locks the membership for a change. Members of a synced team, and
/// memberships the sync added, come from the identity provider:
/// [`AppError::Conflict`].
async fn editable(
    tx: &mut sqlx::PgConnection,
    id: TeamId,
    user: UserId,
) -> Result<Option<MembershipSource>, AppError> {
    let (synced, source) = repo::lock_membership(tx, id, user)
        .await?
        .ok_or(AppError::NotFound)?;
    if synced || source == Some(MembershipSource::Idp) {
        return Err(AppError::Conflict);
    }
    Ok(source)
}

/// Adds `user` to the team with `role`, or changes their role.
///
/// # Errors
///
/// [`AppError::NotFound`] if the team or the user does not exist,
/// [`AppError::Forbidden`] unless `actor` may `manageTeamMembers`,
/// [`AppError::Conflict`] if the membership comes from the identity
/// provider, or a database error.
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
    editable(&mut tx, id, user).await?;
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
/// `manageTeamMembers`, [`AppError::Conflict`] if the membership comes
/// from the identity provider, or a database error.
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
    if editable(&mut tx, id, user).await?.is_none()
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
