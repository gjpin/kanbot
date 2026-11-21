//! Database access for the `OpenShell` membership sync.

use sqlx::PgPool;

use crate::{
    openshell::model::{MemberRole, WorkspaceName},
    organizations::model::OrganizationId,
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

/// Who should be in the organization's workspace: its admins as admins,
/// members of teams with write access as users. Disabled users and users
/// of another issuer are left out. Subject → role.
#[tracing::instrument(skip_all, fields(organization.id = %organization.as_uuid()))]
pub(super) async fn desired(
    db: &PgPool,
    organization: OrganizationId,
    issuer: &str,
) -> Result<Vec<(String, MemberRole)>, sqlx::Error> {
    Ok(sqlx::query!(
        r#"
        SELECT u.subject, bool_or(a.user_id IS NOT NULL) AS "admin!"
        FROM users u
        LEFT JOIN organization_admins a
            ON a.user_id = u.id AND a.organization_id = $1
        LEFT JOIN team_members m ON m.user_id = u.id
        LEFT JOIN organization_teams l
            ON l.team_id = m.team_id AND l.organization_id = $1 AND l.access = 'write'
        WHERE u.disabled_at IS NULL
          AND u.issuer = $2
          AND (a.user_id IS NOT NULL OR l.team_id IS NOT NULL)
        GROUP BY u.subject
        ORDER BY u.subject
        "#,
        organization.as_uuid(),
        issuer,
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| {
        let role = if row.admin {
            MemberRole::Admin
        } else {
            MemberRole::User
        };
        (row.subject, role)
    })
    .collect())
}

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
