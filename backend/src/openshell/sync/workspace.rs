//! Syncing one workspace.

use std::collections::BTreeMap;

use sqlx::PgPool;

use super::{Changes, SyncError, lock::SyncLock};
use crate::{
    authz::{
        model::{Action, Resource},
        policies::Policies,
        service as authz,
    },
    openshell::{
        OpenShell, ServiceCallError,
        gateway::{Added, GatewayError},
        model::{MemberRole, WorkspaceName},
        repo,
    },
    organizations::model::OrganizationId,
    users::model::AuthenticatedUser,
};

/// What syncing workspaces works with: the database, the gateway, and the
/// sync's lock, checked before each call that changes a membership.
pub(super) struct Syncing<'a> {
    pub db: &'a PgPool,
    pub openshell: &'a OpenShell,
    pub lock: &'a mut SyncLock,
}

/// A member as the gateway listed them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Listed {
    Absent,
    /// A member, with their role (`None` for one kanbot does not know).
    Present(Option<MemberRole>),
}

/// What putting one desired member in place did.
enum Put {
    /// Already as wanted.
    Unchanged,
    Added,
    /// Someone else's member, left alone.
    Skipped,
}

/// Whether `error`, met syncing one member, concerns the whole workspace
/// (or the whole run), so that syncing the workspace stops at once: no
/// token, a token refused even after a new one, an unavailable gateway, a
/// workspace gone, the database, the lock. A denial or another answer about
/// this one member does not stop the others.
const fn whole_workspace(error: &SyncError) -> bool {
    !matches!(
        error,
        SyncError::Gateway(GatewayError::Denied | GatewayError::Other(_))
    )
}

impl Syncing<'_> {
    /// Removes a member kanbot added, then forgets them.
    async fn remove(&mut self, workspace: &WorkspaceName, subject: &str) -> Result<(), SyncError> {
        self.lock.check().await?;
        let gateway = &self.openshell.gateway;
        self.openshell
            .as_service(
                |token| async move { gateway.remove_member(&token, workspace, subject).await },
            )
            .await?;
        repo::forget(self.db, workspace, subject).await?;
        Ok(())
    }

    /// Makes `subject` a member with `role`, unless someone else added
    /// them. `ours` is kanbot's record of them, `theirs` the gateway's list.
    async fn put(
        &mut self,
        workspace: &WorkspaceName,
        subject: &str,
        role: MemberRole,
        ours: Option<MemberRole>,
        theirs: Listed,
    ) -> Result<Put, SyncError> {
        let db = self.db;
        if ours.is_none() && theirs != Listed::Absent {
            return Ok(Put::Skipped);
        }
        if theirs == Listed::Present(Some(role)) {
            if ours != Some(role) {
                repo::record(db, workspace, subject, role).await?;
            }
            return Ok(Put::Unchanged);
        }
        self.lock.check().await?;
        // Recorded first: if the call fails or the instance stops, the
        // next run still knows the member is kanbot's.
        repo::record(db, workspace, subject, role).await?;
        let gateway = &self.openshell.gateway;
        if theirs != Listed::Absent {
            // A role change: replace the membership.
            self.openshell
                .as_service(|token| async move {
                    gateway.remove_member(&token, workspace, subject).await
                })
                .await?;
            self.lock.check().await?;
        }
        let added = match self
            .openshell
            .as_service(|token| async move {
                gateway.add_member(&token, workspace, subject, role).await
            })
            .await
        {
            Ok(added) => added,
            Err(ServiceCallError::Gateway(error)) if ours.is_none() && error.not_applied() => {
                // Refused outright, so certainly not added; and not in
                // the workspace before, nor recorded. The record just made
                // would claim a member kanbot never added: it goes. (After
                // a timeout or any other failure the add may have happened,
                // so the record stays, and the next run settles it.)
                repo::forget(db, workspace, subject).await?;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        if added == Added::AlreadyMember && ours.is_none() {
            // Added by someone else since the list: theirs, left alone.
            repo::forget(db, workspace, subject).await?;
            Ok(Put::Skipped)
        } else {
            // Already there after an earlier attempt of kanbot's: its own.
            Ok(Put::Added)
        }
    }

    /// Makes `workspace`'s members match `desired`, touching only the
    /// members kanbot recorded, and counts what changed in `changes`.
    /// Removals come first, so taking access away never waits on an add.
    /// A member that fails on their own is skipped and the others still
    /// sync; the workspace then fails with the first such error.
    async fn sync_workspace(
        &mut self,
        workspace: &WorkspaceName,
        desired: &BTreeMap<String, MemberRole>,
        changes: &mut Changes,
    ) -> Result<(), SyncError> {
        let gateway = &self.openshell.gateway;
        let current: BTreeMap<String, Option<MemberRole>> = self
            .openshell
            .as_service(|token| async move { gateway.members(&token, workspace).await })
            .await?
            .into_iter()
            .map(|member| (member.subject, member.role))
            .collect();
        let recorded: BTreeMap<String, MemberRole> = repo::recorded(self.db, workspace)
            .await?
            .into_iter()
            .collect();
        let mut failed: Option<SyncError> = None;
        let mut member_failed = |error: SyncError| {
            if whole_workspace(&error) {
                return Err(error);
            }
            tracing::warn!(
                workspace = workspace.as_str(),
                error = %error,
                "openshell: a member could not be synced; the others go on"
            );
            failed.get_or_insert(error);
            Ok(())
        };

        for subject in recorded.keys() {
            if desired.contains_key(subject) {
                continue;
            }
            match self.remove(workspace, subject).await {
                Ok(()) => changes.removed = changes.removed.saturating_add(1),
                Err(error) => member_failed(error)?,
            }
        }
        for (subject, role) in desired {
            let ours = recorded.get(subject).copied();
            let theirs = current
                .get(subject)
                .copied()
                .map_or(Listed::Absent, Listed::Present);
            match self.put(workspace, subject, *role, ours, theirs).await {
                Ok(Put::Unchanged) => {}
                Ok(Put::Added) => changes.added = changes.added.saturating_add(1),
                Ok(Put::Skipped) => changes.skipped = changes.skipped.saturating_add(1),
                Err(error) => member_failed(error)?,
            }
        }
        failed.map_or(Ok(()), Err)
    }

    /// Syncs one linked workspace, if `organization` still links it: the
    /// run's list of links may be minutes old, and the workspace another
    /// organization's by now.
    pub(super) async fn sync_link(
        &mut self,
        policies: &Policies,
        issuer: &str,
        organization: OrganizationId,
        workspace: &WorkspaceName,
        changes: &mut Changes,
    ) -> Result<(), SyncError> {
        if !repo::links_now(self.db, organization, workspace).await? {
            return Ok(());
        }
        let desired = desired(self.db, policies, organization, issuer).await?;
        self.sync_workspace(workspace, &desired, changes).await
    }

    /// Empties a workspace no organization links to any more, unless one
    /// links it again by now. One that no longer exists in `OpenShell` has
    /// nothing left to remove: its records are forgotten, which removes
    /// nobody and so is not counted.
    pub(super) async fn sync_orphan(
        &mut self,
        workspace: &WorkspaceName,
        changes: &mut Changes,
    ) -> Result<(), SyncError> {
        if !repo::unlinked_now(self.db, workspace).await? {
            return Ok(());
        }
        match self
            .sync_workspace(workspace, &BTreeMap::new(), changes)
            .await
        {
            Err(SyncError::Gateway(GatewayError::NotFound)) => {
                let forgotten = repo::forget_workspace(self.db, workspace).await?;
                tracing::info!(
                    workspace = workspace.as_str(),
                    members = i64::try_from(forgotten).unwrap_or(i64::MAX),
                    "openshell: an unlinked workspace no longer exists; its members are forgotten"
                );
                Ok(())
            }
            other => other,
        }
    }
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
