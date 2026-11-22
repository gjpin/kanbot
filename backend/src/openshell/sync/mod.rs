//! One-way membership sync, kanbot → `OpenShell`: each linked workspace
//! gets the organization's admins as admins and the members of its teams
//! with write access as users, as far as Cedar allows (deployer `forbid`
//! policies apply: `write` for any role, `manageOrganization` too for
//! admin, decided with `context.via == "sync"`). Kanbot changes only the
//! members it added (`openshell_members`); anyone added in `OpenShell`
//! another way is left alone.
//!
//! - One instance syncs at a time: a Postgres advisory lock, held by a
//!   connection of its own (`lock.rs`) and checked before each workspace
//!   and each call that changes a membership. A run that lost it stops.
//! - Each workspace's link is read again just before it syncs.
//! - Within a workspace, removals come first, and a member that fails on
//!   their own does not stop the others.
//! - A workspace that fails is logged and skipped; the others still sync.
//!   It is retried on its own, later each time it fails again
//!   (`backoff.rs`).
//! - Kanbot records a member before adding them, so an interruption never
//!   leaves a member it added unrecorded (which it would then never
//!   remove).

mod backoff;
mod lock;
mod schedule;
mod workspace;

use std::collections::HashSet;

use sqlx::{PgPool, postgres::PgConnectOptions};

use crate::{
    authz::policies::Policies,
    openshell::{
        OpenShell, ServiceCallError, credentials::CredentialError, gateway::GatewayError,
        model::WorkspaceName, repo,
    },
    organizations::model::OrganizationId,
};
use backoff::Backoff;
use lock::SyncLock;
pub use schedule::{SYNC_INTERVAL, Timing, spawn_sync, spawn_sync_with};

/// Why a sync could not run at all, or stopped. Never holds a token.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("no token for the gateway: {0}")]
    Credentials(#[from] CredentialError),
    #[error("gateway call failed: {}", .0.kind())]
    Gateway(#[from] GatewayError),
    #[error("database error: {}", crate::error::database_kind(.0))]
    Database(#[from] sqlx::Error),
    #[error("authorization failed: {}", .0.kind())]
    Authz(crate::error::AppError),
    /// The sync's lock was lost (its connection dropped): another
    /// instance may be syncing, so this run stopped.
    #[error("the sync's lock was lost")]
    LockLost,
}

impl From<ServiceCallError> for SyncError {
    fn from(error: ServiceCallError) -> Self {
        match error {
            ServiceCallError::Credentials(error) => Self::Credentials(error),
            ServiceCallError::Gateway(error) => Self::Gateway(error),
        }
    }
}

/// Options for the sync's own connections (the lock's, the listener's):
/// the pool's, and never ended for being idle, whatever the role or the
/// server sets (`idle_session_timeout`). The lock's session sits idle
/// during gateway calls, and ending it would release the lock; the
/// listener's waits idle for notifications.
fn own_connection_options(db: &PgPool) -> PgConnectOptions {
    (*db.connect_options())
        .clone()
        .options([("idle_session_timeout", "0")])
}

/// What one sync did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: u64,
    pub removed: u64,
    /// Members of the workspace that kanbot did not add, left alone.
    pub skipped: u64,
    /// Workspaces that failed and were skipped.
    pub failed: u64,
}

impl Changes {
    /// Whether the workspaces' members changed.
    const fn changed(self) -> bool {
        self.added > 0 || self.removed > 0
    }

    fn plus(self, other: Self) -> Self {
        Self {
            added: self.added.saturating_add(other.added),
            removed: self.removed.saturating_add(other.removed),
            skipped: self.skipped.saturating_add(other.skipped),
            failed: self.failed.saturating_add(other.failed),
        }
    }
}

/// Which workspaces a run syncs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    /// Every linked workspace and every orphan, except those still waiting
    /// after a failure.
    All,
    /// Only the workspaces that failed and have waited long enough.
    Failed,
}

/// Syncs every linked workspace, then empties the workspaces no
/// organization links to any more. `issuer` is `OIDC_ISSUER`: members are
/// identified by their subject at that issuer. Another instance already
/// syncing: nothing to do (`None`).
///
/// # Errors
///
/// [`SyncError`] when nothing can be synced (no token, the database), or
/// the run lost its lock; a failing workspace is counted in
/// [`Changes::failed`] and skipped.
pub async fn sync_all(
    db: &sqlx::PgPool,
    policies: &Policies,
    openshell: &OpenShell,
    issuer: &str,
) -> Result<Option<Changes>, SyncError> {
    let timing = Timing::default();
    let mut backoff = Backoff::new(timing.retry, timing.interval);
    run(db, policies, openshell, issuer, &mut backoff, Scope::All).await
}

/// One run over the workspaces `scope` and `backoff` select, under the
/// sync's lock.
async fn run(
    db: &sqlx::PgPool,
    policies: &Policies,
    openshell: &OpenShell,
    issuer: &str,
    backoff: &mut Backoff,
    scope: Scope,
) -> Result<Option<Changes>, SyncError> {
    let Some(mut lock) = SyncLock::acquire(db).await? else {
        return Ok(None);
    };
    let outcome = run_locked(db, policies, openshell, issuer, backoff, scope, &mut lock).await;
    // Whatever happened: the work done stands even if releasing fails.
    lock::close(lock.release().await).await;
    outcome.map(Some)
}

async fn run_locked(
    db: &sqlx::PgPool,
    policies: &Policies,
    openshell: &OpenShell,
    issuer: &str,
    backoff: &mut Backoff,
    scope: Scope,
    lock: &mut SyncLock,
) -> Result<Changes, SyncError> {
    let links = repo::links(db).await?;
    let orphans = repo::orphans(db).await?;
    // Workspaces gone from both lists have nothing left to retry.
    let present: HashSet<&WorkspaceName> = links
        .iter()
        .map(|(_, workspace)| workspace)
        .chain(&orphans)
        .collect();
    backoff.retain(|workspace| present.contains(workspace));
    let now = tokio::time::Instant::now();
    let links: Vec<(OrganizationId, WorkspaceName)> = links
        .into_iter()
        .filter(|(_, workspace)| backoff.selects(scope, workspace, now))
        .collect();
    let orphans: Vec<WorkspaceName> = orphans
        .into_iter()
        .filter(|workspace| backoff.selects(scope, workspace, now))
        .collect();
    if links.is_empty() && orphans.is_empty() {
        return Ok(Changes::default());
    }
    // A token at all, or nothing can run.
    openshell.credentials.service_token().await?;
    let mut syncing = workspace::Syncing {
        db,
        openshell,
        lock,
    };
    let mut total = Changes::default();
    for (organization, workspace) in links {
        syncing.lock.check().await?;
        let mut changes = Changes::default();
        let outcome = syncing
            .sync_link(policies, issuer, organization, &workspace, &mut changes)
            .await;
        let settled = settle(backoff, &workspace, Some(organization), changes, outcome)?;
        total = total.plus(settled);
    }
    for workspace in orphans {
        syncing.lock.check().await?;
        let mut changes = Changes::default();
        let outcome = syncing.sync_orphan(&workspace, &mut changes).await;
        total = total.plus(settle(backoff, &workspace, None, changes, outcome)?);
    }
    Ok(total)
}

/// Counts a workspace's changes and outcome, and starts or ends its wait
/// after a failure. A lost lock stops the run: another instance may be
/// syncing.
fn settle(
    backoff: &mut Backoff,
    workspace: &WorkspaceName,
    organization: Option<OrganizationId>,
    changes: Changes,
    outcome: Result<(), SyncError>,
) -> Result<Changes, SyncError> {
    match outcome {
        Ok(()) => {
            backoff.succeeded(workspace);
            Ok(changes)
        }
        Err(SyncError::LockLost) => Err(SyncError::LockLost),
        Err(error) => {
            tracing::warn!(
                workspace = workspace.as_str(),
                organization.id = organization.map(|id| id.as_uuid().to_string()),
                error = %error,
                "openshell: a workspace could not be synced; the others go on"
            );
            backoff.failed(workspace, tokio::time::Instant::now());
            Ok(changes.plus(Changes {
                failed: 1,
                ..Changes::default()
            }))
        }
    }
}
