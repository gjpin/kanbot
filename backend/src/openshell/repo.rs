//! Database access for the `OpenShell` membership sync.

use sqlx::{PgConnection, PgPool};

use crate::{
    auth::token::PlatformRole,
    openshell::model::{MemberRole, WorkspaceName},
    organizations::model::OrganizationId,
    users::model::UserId,
};

fn decode(what: &'static str) -> sqlx::Error {
    sqlx::Error::Decode(what.into())
}

/// Every linked organization and its workspace.
#[tracing::instrument(skip_all)]
pub(super) async fn links(
    db: &PgPool,
) -> Result<Vec<(OrganizationId, WorkspaceName)>, sqlx::Error> {
    sqlx::query!(
        r#"SELECT id, openshell_workspace AS "workspace!" FROM organizations
           WHERE openshell_workspace IS NOT NULL ORDER BY openshell_workspace"#
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            OrganizationId::from_uuid(row.id),
            WorkspaceName::parse(&row.workspace)
                .ok_or_else(|| decode("organizations.openshell_workspace"))?,
        ))
    })
    .collect()
}

/// Workspaces kanbot added members to that no organization links to any
/// more (unlinked, or the organization was deleted).
#[tracing::instrument(skip_all)]
pub(super) async fn orphans(db: &PgPool) -> Result<Vec<WorkspaceName>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT DISTINCT workspace FROM openshell_members m
           WHERE NOT EXISTS (
               SELECT 1 FROM organizations o WHERE o.openshell_workspace = m.workspace
           )
           ORDER BY workspace"#
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|raw| WorkspaceName::parse(&raw).ok_or_else(|| decode("openshell_members.workspace")))
    .collect()
}

/// Someone who could be in an organization's workspace: one of its
/// admins, or a member of a team linked to it with write access. Cedar has
/// the last word ([`crate::authz::service::decide_for_users`]).
pub(super) struct Candidate {
    pub id: UserId,
    pub subject: String,
    pub role: PlatformRole,
    pub groups: Vec<String>,
    pub admin: bool,
}

/// The organization's candidates who are not disabled and belong to
/// `issuer`, by subject. Two index-driven lookups (admins, members of
/// write-linked teams), then the users.
#[tracing::instrument(skip_all, fields(organization.id = %organization.as_uuid()))]
pub(super) async fn candidates(
    db: &PgPool,
    organization: OrganizationId,
    issuer: &str,
) -> Result<Vec<Candidate>, sqlx::Error> {
    sqlx::query!(
        r#"
        SELECT u.id, u.subject, u.platform_role, u.groups, bool_or(c.admin) AS "admin!"
        FROM (
            SELECT a.user_id, true AS admin
            FROM organization_admins a
            WHERE a.organization_id = $1
            UNION ALL
            SELECT m.user_id, false
            FROM organization_teams l
            JOIN team_members m ON m.team_id = l.team_id
            WHERE l.organization_id = $1 AND l.access = 'write'
        ) c
        JOIN users u ON u.id = c.user_id
        WHERE u.disabled_at IS NULL AND u.issuer = $2
        GROUP BY u.id, u.subject, u.platform_role, u.groups
        ORDER BY u.subject
        "#,
        organization.as_uuid(),
        issuer,
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| {
        Ok(Candidate {
            id: UserId::from_uuid(row.id),
            subject: row.subject,
            role: PlatformRole::parse(&row.platform_role)
                .ok_or_else(|| decode("users.platform_role"))?,
            groups: row.groups,
            admin: row.admin,
        })
    })
    .collect()
}

/// Forgets every member kanbot added to `workspace` (it no longer exists
/// in `OpenShell`).
#[tracing::instrument(skip_all)]
pub(super) async fn forget_workspace(
    db: &PgPool,
    workspace: &WorkspaceName,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM openshell_members WHERE workspace = $1",
        workspace.as_str()
    )
    .execute(db)
    .await?
    .rows_affected())
}

/// Takes the sync's lock for the transaction `lock`, if no other instance
/// holds it. Released when the transaction ends, or its connection drops.
pub(super) async fn try_lock(lock: &mut PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT pg_try_advisory_xact_lock($1) AS "locked!""#,
        SYNC_LOCK
    )
    .fetch_one(lock)
    .await
}

/// The advisory lock key of the sync: "kanbotOS" in ASCII.
const SYNC_LOCK: i64 = 0x6b61_6e62_6f74_4f53;

/// The members kanbot added to `workspace`. Subject → role.
#[tracing::instrument(skip_all)]
pub(super) async fn recorded(
    db: &PgPool,
    workspace: &WorkspaceName,
) -> Result<Vec<(String, MemberRole)>, sqlx::Error> {
    sqlx::query!(
        "SELECT subject, role FROM openshell_members WHERE workspace = $1 ORDER BY subject",
        workspace.as_str()
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            row.subject,
            MemberRole::parse(&row.role).ok_or_else(|| decode("openshell_members.role"))?,
        ))
    })
    .collect()
}

#[tracing::instrument(skip_all)]
pub(super) async fn record(
    db: &PgPool,
    workspace: &WorkspaceName,
    subject: &str,
    role: MemberRole,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"INSERT INTO openshell_members (workspace, subject, role) VALUES ($1, $2, $3)
           ON CONFLICT (workspace, subject) DO UPDATE SET role = EXCLUDED.role"#,
        workspace.as_str(),
        subject,
        role.as_str()
    )
    .execute(db)
    .await?;
    Ok(())
}

#[tracing::instrument(skip_all)]
pub(super) async fn forget(
    db: &PgPool,
    workspace: &WorkspaceName,
    subject: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM openshell_members WHERE workspace = $1 AND subject = $2",
        workspace.as_str(),
        subject
    )
    .execute(db)
    .await?;
    Ok(())
}
