//! Database access for organizations, their admins and team links.

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::{
    names::{Name, Slug},
    openshell::model::WorkspaceName,
    organizations::model::{Access, Organization, OrganizationChanges, OrganizationId, TeamLink},
    teams::model::{IdpGroup, Team, TeamId},
    users::model::{UserId, UserSummary},
};

fn decode(what: &'static str) -> sqlx::Error {
    sqlx::Error::Decode(what.into())
}

fn organization(
    id: Uuid,
    slug: &str,
    name: &str,
    workspace: Option<&str>,
) -> Result<Organization, sqlx::Error> {
    Ok(Organization {
        id: OrganizationId::from_uuid(id),
        slug: Slug::parse(slug).map_err(|_| decode("organizations.slug"))?,
        name: Name::parse(name).map_err(|_| decode("organizations.name"))?,
        openshell_workspace: workspace
            .map(|raw| {
                WorkspaceName::parse(raw).ok_or_else(|| decode("organizations.openshell_workspace"))
            })
            .transpose()?,
    })
}

/// The organizations among `ids`, by slug.
#[tracing::instrument(skip_all)]
pub(super) async fn list(db: &PgPool, ids: &[Uuid]) -> Result<Vec<Organization>, sqlx::Error> {
    sqlx::query!(
        "SELECT id, slug, name, openshell_workspace FROM organizations WHERE id = ANY($1) ORDER BY slug",
        ids
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| organization(row.id, &row.slug, &row.name, row.openshell_workspace.as_deref()))
    .collect()
}

#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid()))]
pub(super) async fn get(
    db: &PgPool,
    id: OrganizationId,
) -> Result<Option<Organization>, sqlx::Error> {
    sqlx::query!(
        "SELECT id, slug, name, openshell_workspace FROM organizations WHERE id = $1",
        id.as_uuid()
    )
    .fetch_optional(db)
    .await?
    .map(|row| {
        organization(
            row.id,
            &row.slug,
            &row.name,
            row.openshell_workspace.as_deref(),
        )
    })
    .transpose()
}

#[tracing::instrument(skip_all, fields(organization.id = %new.id.as_uuid()))]
pub(super) async fn insert(db: &mut PgConnection, new: &Organization) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO organizations (id, slug, name) VALUES ($1, $2, $3)",
        new.id.as_uuid(),
        new.slug.as_str(),
        new.name.as_str(),
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Applies `changes`, and says whether anything changed (changing a value
/// to itself writes nothing). `None` if the organization does not exist.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid()))]
pub(super) async fn update(
    db: &mut PgConnection,
    id: OrganizationId,
    changes: &OrganizationChanges,
) -> Result<Option<(Organization, bool)>, sqlx::Error> {
    let slug = changes.slug.as_ref().map(Slug::as_str);
    let name = changes.name.as_ref().map(Name::as_str);
    let updated = sqlx::query!(
        r#"
        UPDATE organizations
        SET slug = COALESCE($2, slug), name = COALESCE($3, name), updated_at = now()
        WHERE id = $1 AND (slug <> COALESCE($2, slug) OR name <> COALESCE($3, name))
        RETURNING id, slug, name, openshell_workspace
        "#,
        id.as_uuid(),
        slug,
        name,
    )
    .fetch_optional(&mut *db)
    .await?;
    if let Some(row) = updated {
        let organization = organization(
            row.id,
            &row.slug,
            &row.name,
            row.openshell_workspace.as_deref(),
        )?;
        return Ok(Some((organization, true)));
    }
    sqlx::query!(
        "SELECT id, slug, name, openshell_workspace FROM organizations WHERE id = $1",
        id.as_uuid()
    )
    .fetch_optional(db)
    .await?
    .map(|row| {
        organization(
            row.id,
            &row.slug,
            &row.name,
            row.openshell_workspace.as_deref(),
        )
        .map(|organization| (organization, false))
    })
    .transpose()
}

/// Deletes the organization, its admins and its team links. `false` if it
/// did not exist.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid()))]
pub(super) async fn delete(db: &mut PgConnection, id: OrganizationId) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query!("DELETE FROM organizations WHERE id = $1", id.as_uuid())
            .execute(db)
            .await?
            .rows_affected()
            == 1,
    )
}

/// The organization's admins, by display name.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid()))]
pub(super) async fn admins(
    db: &PgPool,
    id: OrganizationId,
) -> Result<Vec<UserSummary>, sqlx::Error> {
    Ok(sqlx::query!(
        r#"
        SELECT u.id, u.display_name, u.disabled_at IS NOT NULL AS "disabled!"
        FROM organization_admins a
        JOIN users u ON u.id = a.user_id
        WHERE a.organization_id = $1
        ORDER BY u.display_name NULLS LAST, u.id
        "#,
        id.as_uuid()
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| UserSummary {
        id: UserId::from_uuid(row.id),
        display_name: row.display_name,
        disabled: row.disabled,
    })
    .collect())
}

/// Makes `user` an admin. `false` if they already were.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid(), user.id = %user.as_uuid()))]
pub(super) async fn add_admin(
    db: &mut PgConnection,
    id: OrganizationId,
    user: UserId,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query!(
        r#"
        INSERT INTO organization_admins (organization_id, user_id) VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
        id.as_uuid(),
        user.as_uuid()
    )
    .execute(db)
    .await?
    .rows_affected()
        == 1)
}

/// `false` if `user` was not an admin.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid(), user.id = %user.as_uuid()))]
pub(super) async fn remove_admin(
    db: &mut PgConnection,
    id: OrganizationId,
    user: UserId,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM organization_admins WHERE organization_id = $1 AND user_id = $2",
        id.as_uuid(),
        user.as_uuid()
    )
    .execute(db)
    .await?
    .rows_affected()
        == 1)
}

/// The teams linked to the organization, by slug.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid()))]
pub(super) async fn team_links(
    db: &PgPool,
    id: OrganizationId,
) -> Result<Vec<TeamLink>, sqlx::Error> {
    sqlx::query!(
        r#"
        SELECT t.id, t.slug, t.name, t.idp_group, l.access
        FROM organization_teams l
        JOIN teams t ON t.id = l.team_id
        WHERE l.organization_id = $1
        ORDER BY t.slug
        "#,
        id.as_uuid()
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| {
        Ok(TeamLink {
            team: Team {
                id: TeamId::from_uuid(row.id),
                slug: Slug::parse(&row.slug).map_err(|_| decode("teams.slug"))?,
                name: Name::parse(&row.name).map_err(|_| decode("teams.name"))?,
                idp_group: row
                    .idp_group
                    .map(|group| IdpGroup::parse(&group))
                    .transpose()
                    .map_err(|_| decode("teams.idp_group"))?,
            },
            access: Access::parse(&row.access)
                .ok_or_else(|| decode("organization_teams.access"))?,
        })
    })
    .collect()
}

/// Links `team` with `access`, or changes the access of its link.
/// Returns the previous access, if it was linked.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid(), team.id = %team.as_uuid()))]
pub(super) async fn set_team_link(
    db: &mut PgConnection,
    id: OrganizationId,
    team: TeamId,
    access: Access,
) -> Result<bool, sqlx::Error> {
    // One statement: of two concurrent identical links, one changes the
    // row and the other sees it unchanged, so the change is audited once.
    Ok(sqlx::query_scalar!(
        r#"
        INSERT INTO organization_teams (organization_id, team_id, access) VALUES ($1, $2, $3)
        ON CONFLICT (organization_id, team_id) DO UPDATE SET access = EXCLUDED.access
            WHERE organization_teams.access <> EXCLUDED.access
        RETURNING access
        "#,
        id.as_uuid(),
        team.as_uuid(),
        access.as_str()
    )
    .fetch_optional(db)
    .await?
    .is_some())
}

/// `false` if `team` was not linked.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid(), team.id = %team.as_uuid()))]
pub(super) async fn remove_team_link(
    db: &mut PgConnection,
    id: OrganizationId,
    team: TeamId,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM organization_teams WHERE organization_id = $1 AND team_id = $2",
        id.as_uuid(),
        team.as_uuid()
    )
    .execute(db)
    .await?
    .rows_affected()
        == 1)
}

/// Links the organization to `workspace`, or unlinks it (`None`). `false`
/// if the organization does not exist.
#[tracing::instrument(skip_all, fields(organization.id = %id.as_uuid()))]
pub(super) async fn set_openshell_workspace(
    db: &mut PgConnection,
    id: OrganizationId,
    workspace: Option<&WorkspaceName>,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query!(
        "UPDATE organizations SET openshell_workspace = $2, updated_at = now() WHERE id = $1",
        id.as_uuid(),
        workspace.map(WorkspaceName::as_str),
    )
    .execute(db)
    .await?
    .rows_affected()
        == 1)
}
