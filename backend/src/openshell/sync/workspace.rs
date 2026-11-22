//! Syncing one workspace.

use std::collections::BTreeMap;

use secrecy::SecretString;
use sqlx::PgPool;

use super::{Changes, SyncError};
use crate::{
    authz::{
        model::{Action, Resource},
        policies::Policies,
        service as authz,
    },
    openshell::{
        OpenShell,
        gateway::{Added, GatewayError},
        model::{MemberRole, WorkspaceName},
        repo,
    },
    organizations::model::OrganizationId,
    users::model::AuthenticatedUser,
};

/// Makes one gateway call with the service account's token, taken from
/// the cache for each call, so a long run never uses one about to expire.
/// A token the gateway refuses is dropped, and the call made once more
/// with a new one.
async fn call<T, F>(openshell: &OpenShell, call: impl Fn(SecretString) -> F) -> Result<T, SyncError>
where
    F: Future<Output = Result<T, GatewayError>>,
{
    let token = openshell.credentials.service_token().await?;
    match call(token).await {
        Err(GatewayError::Refused) => {
            openshell.credentials.forget_service_token().await;
            let token = openshell.credentials.service_token().await?;
            Ok(call(token).await?)
        }
        outcome => Ok(outcome?),
    }
}

/// Makes `workspace`'s members match `desired`, touching only the members
/// kanbot recorded.
async fn sync_workspace(
    db: &PgPool,
    openshell: &OpenShell,
    workspace: &WorkspaceName,
    desired: BTreeMap<String, MemberRole>,
) -> Result<Changes, SyncError> {
    let gateway = &openshell.gateway;
    let current: BTreeMap<String, Option<MemberRole>> = call(openshell, |token| async move {
        gateway.members(&token, workspace).await
    })
    .await?
    .into_iter()
    .map(|member| (member.subject, member.role))
    .collect();
    let recorded: BTreeMap<String, MemberRole> =
        repo::recorded(db, workspace).await?.into_iter().collect();
    let mut changes = Changes::default();

    for (subject, role) in &desired {
        let ours = recorded.get(subject).copied();
        let theirs = current.get(subject).copied();
        if ours.is_none() && theirs.is_some() {
            // Someone else's member: not kanbot's to change.
            changes.skipped = changes.skipped.saturating_add(1);
            continue;
        }
        if theirs == Some(Some(*role)) {
            if ours != Some(*role) {
                repo::record(db, workspace, subject, *role).await?;
            }
            continue;
        }
        // Recorded first: if the call fails or the instance stops, the
        // next run still knows the member is kanbot's.
        repo::record(db, workspace, subject, *role).await?;
        if theirs.is_some() {
            // A role change: replace the membership.
            call(openshell, |token| async move {
                gateway.remove_member(&token, workspace, subject).await
            })
            .await?;
        }
        let added = call(openshell, |token| async move {
            gateway.add_member(&token, workspace, subject, *role).await
        })
        .await?;
        if added == Added::AlreadyMember && ours.is_none() {
            // Added by someone else since the list: theirs, left alone.
            repo::forget(db, workspace, subject).await?;
            changes.skipped = changes.skipped.saturating_add(1);
        } else {
            // Already there after an earlier attempt of kanbot's: its own.
            changes.added = changes.added.saturating_add(1);
        }
    }
    for subject in recorded.keys() {
        if desired.contains_key(subject) {
            continue;
        }
        call(openshell, |token| async move {
            gateway.remove_member(&token, workspace, subject).await
        })
        .await?;
        repo::forget(db, workspace, subject).await?;
        changes.removed = changes.removed.saturating_add(1);
    }
    Ok(changes)
}

/// Who should be in the organization's workspace, and with which role:
/// each candidate Cedar allows `write`, as admin when they administer the
/// organization and Cedar allows `manageOrganization` too.
async fn desired(
    db: &PgPool,
    policies: &Policies,
    organization: OrganizationId,
    issuer: &str,
) -> Result<BTreeMap<String, MemberRole>, SyncError> {
    let candidates = repo::candidates(db, organization, issuer).await?;
    let users: Vec<AuthenticatedUser> = candidates
        .iter()
        .map(|candidate| AuthenticatedUser {
            id: candidate.id,
            role: candidate.role,
            display_name: None,
            telemetry_opt_in: false,
            groups: candidate.groups.clone(),
            groups_claimed: false,
            client_id: None,
        })
        .collect();
    let decisions = authz::decide_for_users(
        db,
        policies,
        &users,
        &[Action::Write, Action::ManageOrganization],
        Resource::Organization(organization),
    )
    .await
    .map_err(SyncError::Authz)?;
    Ok(candidates
        .into_iter()
        .zip(decisions)
        .filter_map(|(candidate, decisions)| {
            let allowed = |index: usize| decisions.get(index).is_some_and(|d| d.allowed);
            if !allowed(0) {
                return None;
            }
            let role = if candidate.admin && allowed(1) {
                MemberRole::Admin
            } else {
                MemberRole::User
            };
            Some((candidate.subject, role))
        })
        .collect())
}

/// Syncs one linked workspace, if `organization` still links it: the
/// run's list of links may be minutes old, and the workspace another
/// organization's by now.
pub(super) async fn sync_link(
    db: &PgPool,
    policies: &Policies,
    openshell: &OpenShell,
    issuer: &str,
    organization: OrganizationId,
    workspace: &WorkspaceName,
) -> Result<Changes, SyncError> {
    if !repo::links_now(db, organization, workspace).await? {
        return Ok(Changes::default());
    }
    let desired = desired(db, policies, organization, issuer).await?;
    sync_workspace(db, openshell, workspace, desired).await
}

/// Empties a workspace no organization links to any more, unless one
/// links it again by now. One that no longer exists in `OpenShell` has
/// nothing left to remove: forgotten.
pub(super) async fn sync_orphan(
    db: &PgPool,
    openshell: &OpenShell,
    workspace: &WorkspaceName,
) -> Result<Changes, SyncError> {
    if !repo::unlinked_now(db, workspace).await? {
        return Ok(Changes::default());
    }
    match sync_workspace(db, openshell, workspace, BTreeMap::new()).await {
        Err(SyncError::Gateway(GatewayError::NotFound)) => {
            let forgotten = repo::forget_workspace(db, workspace).await?;
            tracing::info!(
                workspace = workspace.as_str(),
                members = i64::try_from(forgotten).unwrap_or(i64::MAX),
                "openshell: an unlinked workspace no longer exists; its members are forgotten"
            );
            Ok(Changes {
                removed: forgotten,
                ..Changes::default()
            })
        }
        other => other,
    }
}
