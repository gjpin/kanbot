//! One-way membership sync, kanbot → `OpenShell`: each linked workspace
//! gets the organization's admins as admins and the members of its teams
//! with write access as users, as far as Cedar allows (deployer `forbid`
//! policies apply: `write` for any role, `manageOrganization` too for
//! admin, decided with `context.via == "sync"`). Kanbot changes only the
//! members it added (`openshell_members`); anyone added in `OpenShell`
//! another way is left alone.
//!
//! - One instance syncs at a time (a Postgres advisory lock).
//! - A workspace that fails is logged and skipped; the others still sync,
//!   and a failed run is retried soon.
//! - Kanbot records a member before adding them, so an interruption never
//!   leaves a member it added unrecorded (which it would then never
//!   remove).

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use opentelemetry::{KeyValue, global};
use secrecy::SecretString;
use sqlx::PgPool;

use crate::{
    authz::{
        model::{Action, Resource},
        policies::Policies,
        service as authz,
    },
    error::AppError,
    openshell::{
        OpenShell,
        credentials::CredentialError,
        gateway::GatewayError,
        model::{MemberRole, WorkspaceName},
        repo,
    },
    organizations::model::OrganizationId,
    users::model::AuthenticatedUser,
};

/// How often every linked workspace is synced, besides when what it reads
/// changes.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(300);
/// A run that failed is retried after this long.
const RETRY_DELAY: Duration = Duration::from_secs(30);
/// Runs are at least this far apart, however many changes arrive.
const MIN_GAP: Duration = Duration::from_secs(5);
/// The channel the database's triggers notify when what the sync reads
/// changes (migration `openshell_sync_notify`).
const CHANNEL: &str = "kanbot_openshell";

/// Why a sync could not run at all. Never holds a token.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("no token for the gateway: {0}")]
    Credentials(#[from] CredentialError),
    #[error("gateway call failed: {}", .0.kind())]
    Gateway(#[from] GatewayError),
    #[error("database error: {}", crate::error::database_kind(.0))]
    Database(#[from] sqlx::Error),
    #[error("authorization failed")]
    Authz,
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

/// Makes `workspace`'s members match `desired`, touching only the members
/// kanbot recorded.
async fn sync_workspace(
    db: &PgPool,
    openshell: &OpenShell,
    token: &SecretString,
    workspace: &WorkspaceName,
    desired: BTreeMap<String, MemberRole>,
) -> Result<Changes, SyncError> {
    let gateway = &openshell.gateway;
    let current: BTreeMap<String, Option<MemberRole>> = gateway
        .members(token, workspace)
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
            gateway.remove_member(token, workspace, subject).await?;
        }
        gateway.add_member(token, workspace, subject, *role).await?;
        changes.added = changes.added.saturating_add(1);
    }
    for subject in recorded.keys() {
        if desired.contains_key(subject) {
            continue;
        }
        gateway.remove_member(token, workspace, subject).await?;
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
    .map_err(|error| match error {
        AppError::Database(error) => SyncError::Database(error),
        _ => SyncError::Authz,
    })?;
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

/// Syncs one linked workspace.
async fn sync_link(
    db: &PgPool,
    policies: &Policies,
    openshell: &OpenShell,
    issuer: &str,
    organization: OrganizationId,
    workspace: &WorkspaceName,
) -> Result<Changes, SyncError> {
    let desired = desired(db, policies, organization, issuer).await?;
    // Per workspace: the cached token is renewed before it can expire
    // during a long run.
    let token = openshell.credentials.service_token().await?;
    sync_workspace(db, openshell, &token, workspace, desired).await
}

/// Empties a workspace no organization links to any more. One that no
/// longer exists in `OpenShell` has nothing left to remove: forgotten.
async fn sync_orphan(
    db: &PgPool,
    openshell: &OpenShell,
    workspace: &WorkspaceName,
) -> Result<Changes, SyncError> {
    let token = openshell.credentials.service_token().await?;
    match sync_workspace(db, openshell, &token, workspace, BTreeMap::new()).await {
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

/// Syncs every linked workspace, then empties the workspaces no
/// organization links to any more. `issuer` is `OIDC_ISSUER`: members are
/// identified by their subject at that issuer. Another instance already
/// syncing: nothing to do (`None`).
///
/// # Errors
///
/// [`SyncError`] when nothing can be synced (no token, the database); a
/// failing workspace is counted in [`Changes::failed`] and skipped.
pub async fn sync_all(
    db: &PgPool,
    policies: &Policies,
    openshell: &OpenShell,
    issuer: &str,
) -> Result<Option<Changes>, SyncError> {
    let mut lock = db.begin().await?;
    if !repo::try_lock(&mut lock).await? {
        return Ok(None);
    }
    let links = repo::links(db).await?;
    let orphans = repo::orphans(db).await?;
    if links.is_empty() && orphans.is_empty() {
        return Ok(Some(Changes::default()));
    }
    // A token at all, or nothing can run.
    openshell.credentials.service_token().await?;
    let mut total = Changes::default();
    let failed = |workspace: &WorkspaceName, organization: Option<OrganizationId>, error| {
        tracing::warn!(
            workspace = workspace.as_str(),
            organization.id = organization.map(|id| id.as_uuid().to_string()),
            error = %error,
            "openshell: a workspace could not be synced; the others go on"
        );
        Changes {
            failed: 1,
            ..Changes::default()
        }
    };
    for (organization, workspace) in links {
        let changes = sync_link(db, policies, openshell, issuer, organization, &workspace)
            .await
            .unwrap_or_else(|error| failed(&workspace, Some(organization), error));
        total = total.plus(changes);
    }
    for workspace in orphans {
        let changes = sync_orphan(db, openshell, &workspace)
            .await
            .unwrap_or_else(|error| failed(&workspace, None, error));
        total = total.plus(changes);
    }
    lock.rollback().await?;
    Ok(Some(total))
}

/// Runs [`sync_all`] on the current Tokio runtime: every
/// [`SYNC_INTERVAL`], when the database says what it reads changed (on any
/// instance), and [`RETRY_DELAY`] after a failure; never more often than
/// [`MIN_GAP`].
pub fn spawn_sync(db: PgPool, policies: Arc<Policies>, openshell: Arc<OpenShell>, issuer: String) {
    tokio::spawn(async move {
        let mut listener = match sqlx::postgres::PgListener::connect_with(&db).await {
            Ok(mut listener) => match listener.listen(CHANNEL).await {
                Ok(()) => Some(listener),
                Err(error) => {
                    tracing::warn!(error.type = AppError::from(error).kind(), "openshell: not listening for changes; syncing on a timer only");
                    None
                }
            },
            Err(error) => {
                tracing::warn!(error.type = AppError::from(error).kind(), "openshell: not listening for changes; syncing on a timer only");
                None
            }
        };
        let mut interval = tokio::time::interval(SYNC_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut retry_at: Option<tokio::time::Instant> = None;
        let mut last_run: Option<tokio::time::Instant> = None;
        loop {
            let retry = async {
                match retry_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            let notified = async {
                match listener.as_mut() {
                    Some(listener) => {
                        if let Err(error) = listener.recv().await {
                            // It reconnects on the next call; do not spin.
                            tracing::warn!(error.type = AppError::from(error).kind(), "openshell: change notifications interrupted");
                            tokio::time::sleep(RETRY_DELAY).await;
                        }
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = interval.tick() => {}
                () = retry => {}
                () = notified => {}
            }
            if let Some(next) = last_run.and_then(|last| last.checked_add(MIN_GAP)) {
                tokio::time::sleep_until(next).await;
            }
            // Changes that came meanwhile are covered by this run.
            if let Some(listener) = listener.as_mut() {
                while let Ok(Ok(Some(_))) =
                    tokio::time::timeout(Duration::ZERO, listener.try_recv()).await
                {
                }
            }
            last_run = Some(tokio::time::Instant::now());
            let outcome = sync_all(&db, &policies, &openshell, &issuer).await;
            let failed = match &outcome {
                Ok(Some(changes)) => changes.failed > 0,
                Ok(None) => false,
                Err(_) => true,
            };
            retry_at = failed
                .then(|| tokio::time::Instant::now().checked_add(RETRY_DELAY))
                .flatten();
            report(&outcome);
        }
    });
}

/// Logs a sync's outcome, and counts it (`kanbot.openshell.sync.members`
/// by change, `kanbot.openshell.sync.failures`). Nothing is logged when
/// nothing changed or failed, so a quiet sync every few minutes stays
/// quiet.
fn report(outcome: &Result<Option<Changes>, SyncError>) {
    let meter = global::meter(crate::telemetry::SCOPE);
    match outcome {
        Ok(Some(changes)) => {
            let members = meter
                .u64_counter("kanbot.openshell.sync.members")
                .with_unit("{member}")
                .with_description("Workspace members the sync added or removed.")
                .build();
            members.add(changes.added, &[KeyValue::new("change", "added")]);
            members.add(changes.removed, &[KeyValue::new("change", "removed")]);
            if changes.failed > 0 {
                meter
                    .u64_counter("kanbot.openshell.sync.failures")
                    .with_unit("{workspace}")
                    .with_description("Workspaces a sync run could not sync.")
                    .build()
                    .add(changes.failed, &[]);
            }
            if changes.changed() || changes.failed > 0 {
                tracing::info!(
                    added = i64::try_from(changes.added).unwrap_or(i64::MAX),
                    removed = i64::try_from(changes.removed).unwrap_or(i64::MAX),
                    skipped = i64::try_from(changes.skipped).unwrap_or(i64::MAX),
                    failed = i64::try_from(changes.failed).unwrap_or(i64::MAX),
                    "openshell membership synced"
                );
            }
        }
        Ok(None) => {}
        Err(error) => {
            meter
                .u64_counter("kanbot.openshell.sync.failures")
                .with_unit("{workspace}")
                .with_description("Workspaces a sync run could not sync.")
                .build()
                .add(1, &[]);
            tracing::warn!(%error, "openshell membership sync failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// The log lines `report` writes for `outcome`.
    fn logged(outcome: &Result<Option<Changes>, SyncError>) -> String {
        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || report(outcome));
        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn reports_only_member_changes_and_failures() {
        let changes = |added, removed, skipped, failed| {
            Ok(Some(Changes {
                added,
                removed,
                skipped,
                failed,
            }))
        };
        let added = logged(&changes(1, 0, 2, 0));
        assert!(added.contains("openshell membership synced"), "{added}");
        assert!(
            added.contains("added=1 removed=0 skipped=2 failed=0"),
            "{added}"
        );
        let removed = logged(&changes(0, 3, 0, 0));
        assert!(removed.contains("added=0 removed=3"), "{removed}");
        let failed = logged(&changes(0, 0, 0, 1));
        assert!(failed.contains("failed=1"), "{failed}");
        assert_eq!(logged(&changes(0, 0, 0, 0)), "");
        // Members left alone are not a change.
        assert_eq!(logged(&changes(0, 0, 5, 0)), "");
        // Another instance syncs: nothing to say.
        assert_eq!(logged(&Ok(None)), "");
        let error = logged(&Err(SyncError::Database(sqlx::Error::PoolTimedOut)));
        assert!(
            error.contains("openshell membership sync failed"),
            "{error}"
        );
        assert!(error.contains("database.pool_timed_out"), "{error}");
    }
}
