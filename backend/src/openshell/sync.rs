//! One-way membership sync, kanbot → `OpenShell`: each linked workspace
//! gets the organization's admins as admins and the members of its teams
//! with write access as users. Kanbot changes only the members it added
//! (`openshell_members`); anyone added in `OpenShell` another way is left
//! alone.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use secrecy::SecretString;
use sqlx::PgPool;

use crate::openshell::{
    OpenShell,
    credentials::CredentialError,
    gateway::GatewayError,
    model::{MemberRole, WorkspaceName},
    repo,
};

/// How often every linked workspace is synced, besides when a link
/// changes.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(300);

/// Why a sync stopped. Never holds a token.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("no token for the gateway")]
    Credentials(#[from] CredentialError),
    #[error("gateway call failed")]
    Gateway(#[from] GatewayError),
    #[error("database error")]
    Database(#[from] sqlx::Error),
}

/// What one sync changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: u64,
    pub removed: u64,
    /// Members of the workspace that kanbot did not add, left alone.
    pub skipped: u64,
}

impl Changes {
    /// Whether the workspace's members changed.
    const fn changed(self) -> bool {
        self.added > 0 || self.removed > 0
    }

    fn plus(self, other: Self) -> Self {
        Self {
            added: self.added.saturating_add(other.added),
            removed: self.removed.saturating_add(other.removed),
            skipped: self.skipped.saturating_add(other.skipped),
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
        let ours = recorded.get(subject);
        match (ours, current.get(subject)) {
            // Someone else's member: not kanbot's to change.
            (None, Some(_)) => {
                changes.skipped = changes.skipped.saturating_add(1);
                continue;
            }
            (Some(recorded_role), Some(Some(current_role)))
                if recorded_role == role && current_role == role =>
            {
                continue;
            }
            (Some(_), Some(_)) => {
                // A role change: replace the membership.
                gateway.remove_member(token, workspace, subject).await?;
            }
            (_, None) => {}
        }
        gateway.add_member(token, workspace, subject, *role).await?;
        repo::record(db, workspace, subject, *role).await?;
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

/// Syncs every linked workspace, then empties the workspaces no
/// organization links to any more. `issuer` is `OIDC_ISSUER`: members are
/// identified by their subject at that issuer.
///
/// # Errors
///
/// [`SyncError`] at the first failure; the next sync picks up from there.
pub async fn sync_all(
    db: &PgPool,
    openshell: &OpenShell,
    issuer: &str,
) -> Result<Changes, SyncError> {
    let links = repo::links(db).await?;
    let orphans = repo::orphans(db).await?;
    if links.is_empty() && orphans.is_empty() {
        return Ok(Changes::default());
    }
    let token = openshell.credentials.service_token().await?;
    let mut total = Changes::default();
    for (organization, workspace) in links {
        let desired = repo::desired(db, organization, issuer)
            .await?
            .into_iter()
            .collect();
        let changes = sync_workspace(db, openshell, &token, &workspace, desired).await?;
        total = total.plus(changes);
    }
    for workspace in orphans {
        let changes = sync_workspace(db, openshell, &token, &workspace, BTreeMap::new()).await?;
        total = total.plus(changes);
    }
    Ok(total)
}

/// Runs [`sync_all`] every [`SYNC_INTERVAL`], and whenever a link changes
/// ([`OpenShell::wake_sync`]), on the current Tokio runtime.
pub fn spawn_sync(db: PgPool, openshell: Arc<OpenShell>, issuer: String) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SYNC_INTERVAL);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = openshell.wake.notified() => {}
            }
            report(&sync_all(&db, &openshell, &issuer).await);
        }
    });
}

/// Logs a sync's outcome: what it changed, or why it failed. Nothing when
/// no member changed, so a quiet sync every few minutes stays quiet.
fn report(outcome: &Result<Changes, SyncError>) {
    match outcome {
        Ok(changes) if !changes.changed() => {}
        Ok(changes) => tracing::info!(
            added = i64::try_from(changes.added).unwrap_or(i64::MAX),
            removed = i64::try_from(changes.removed).unwrap_or(i64::MAX),
            skipped = i64::try_from(changes.skipped).unwrap_or(i64::MAX),
            "openshell membership synced"
        ),
        Err(error) => tracing::warn!(%error, "openshell membership sync failed"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// The log lines `report` writes for `outcome`.
    fn logged(outcome: &Result<Changes, SyncError>) -> String {
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
        let changes = |added, removed, skipped| {
            Ok(Changes {
                added,
                removed,
                skipped,
            })
        };
        let added = logged(&changes(1, 0, 2));
        assert!(added.contains("openshell membership synced"), "{added}");
        assert!(added.contains("added=1 removed=0 skipped=2"), "{added}");
        let removed = logged(&changes(0, 3, 0));
        assert!(removed.contains("added=0 removed=3 skipped=0"), "{removed}");
        assert_eq!(logged(&changes(0, 0, 0)), "");
        // Members left alone are not a change.
        assert_eq!(logged(&changes(0, 0, 5)), "");
        let failed = logged(&Err(SyncError::Database(sqlx::Error::RowNotFound)));
        assert!(
            failed.contains("openshell membership sync failed"),
            "{failed}"
        );
    }
}
