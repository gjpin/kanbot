//! Database access for authorization: the facts decisions need, and the
//! candidates `visible` filters.

use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    authz::model::{OrganizationFacts, TeamFacts, UserFacts},
    names::Slug,
    organizations::model::{Access, OrganizationId},
    teams::model::TeamId,
    users::model::UserId,
};

/// The user's teams, and whether they administer an organization or
/// maintain a team.
#[tracing::instrument(skip_all, fields(user.id = %user.as_uuid()))]
pub(super) async fn user_facts(db: &PgPool, user: UserId) -> Result<UserFacts, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT
            COALESCE(
                (SELECT array_agg(team_id ORDER BY team_id) FROM team_members WHERE user_id = $1),
                '{}'
            ) AS "teams!",
            EXISTS (
                SELECT 1 FROM team_members WHERE user_id = $1 AND role = 'maintainer'
            ) AS "team_maintainer!",
            EXISTS (SELECT 1 FROM organization_admins WHERE user_id = $1) AS "organization_admin!"
        "#,
        user.as_uuid(),
    )
    .fetch_one(db)
    .await?;
    Ok(UserFacts {
        teams: row.teams.into_iter().map(TeamId::from_uuid).collect(),
        organization_admin: row.organization_admin,
        team_maintainer: row.team_maintainer,
    })
}

/// [`user_facts`] for each of `users` (those that exist), in one query.
#[tracing::instrument(skip_all)]
pub(super) async fn user_facts_many(
    db: &PgPool,
    users: &[Uuid],
) -> Result<Vec<(UserId, UserFacts)>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT
            u.id,
            COALESCE(
                (SELECT array_agg(team_id ORDER BY team_id) FROM team_members WHERE user_id = u.id),
                '{}'
            ) AS "teams!",
            EXISTS (
                SELECT 1 FROM team_members WHERE user_id = u.id AND role = 'maintainer'
            ) AS "team_maintainer!",
            EXISTS (SELECT 1 FROM organization_admins WHERE user_id = u.id) AS "organization_admin!"
        FROM users u
        WHERE u.id = ANY($1)
        "#,
        users,
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                UserId::from_uuid(row.id),
                UserFacts {
                    teams: row.teams.into_iter().map(TeamId::from_uuid).collect(),
                    organization_admin: row.organization_admin,
                    team_maintainer: row.team_maintainer,
                },
            )
        })
        .collect())
}

/// The teams among `ids` that exist, with their maintainers and links.
#[tracing::instrument(skip_all)]
pub(super) async fn team_facts(db: &PgPool, ids: &[Uuid]) -> Result<Vec<TeamFacts>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT
            t.id,
            COALESCE(
                (SELECT array_agg(m.user_id ORDER BY m.user_id) FROM team_members m
                 WHERE m.team_id = t.id AND m.role = 'maintainer'),
                '{}'
            ) AS "maintainers!",
            COALESCE(
                (SELECT array_agg(l.organization_id ORDER BY l.organization_id)
                 FROM organization_teams l WHERE l.team_id = t.id),
                '{}'
            ) AS "link_organizations!",
            COALESCE(
                (SELECT array_agg(l.access ORDER BY l.organization_id)
                 FROM organization_teams l WHERE l.team_id = t.id),
                '{}'
            ) AS "link_access!"
        FROM teams t
        WHERE t.id = ANY($1)
        "#,
        ids,
    )
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|row| {
            let links = row
                .link_organizations
                .into_iter()
                .zip(row.link_access)
                .map(|(organization, access)| {
                    Access::parse(&access)
                        .map(|access| (OrganizationId::from_uuid(organization), access))
                        .ok_or_else(|| sqlx::Error::Decode("organization_teams.access".into()))
                })
                .collect::<Result<_, _>>()?;
            Ok(TeamFacts {
                id: TeamId::from_uuid(row.id),
                maintainers: row.maintainers.into_iter().map(UserId::from_uuid).collect(),
                links,
            })
        })
        .collect()
}

/// The organizations among `ids` that exist, with their admins.
#[tracing::instrument(skip_all)]
pub(super) async fn organization_facts(
    db: &PgPool,
    ids: &[Uuid],
) -> Result<Vec<OrganizationFacts>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT
            o.id,
            COALESCE(
                (SELECT array_agg(a.user_id ORDER BY a.user_id) FROM organization_admins a
                 WHERE a.organization_id = o.id),
                '{}'
            ) AS "admins!"
        FROM organizations o
        WHERE o.id = ANY($1)
        "#,
        ids,
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| OrganizationFacts {
            id: OrganizationId::from_uuid(row.id),
            admins: row.admins.into_iter().map(UserId::from_uuid).collect(),
        })
        .collect())
}

fn slugged(id: Uuid, slug: &str) -> Result<(Uuid, Slug), sqlx::Error> {
    Slug::parse(slug)
        .map(|slug| (id, slug))
        .map_err(|_| sqlx::Error::Decode("slug".into()))
}

/// Every organization the built-in permits could let the user read: all
/// of them for a platform admin, else those they administer or that one
/// of their teams is linked to. Up to `limit`, by slug, after `after`;
/// with their slugs.
#[tracing::instrument(skip_all, fields(user.id = %user.as_uuid()))]
pub(super) async fn candidate_organizations(
    db: &PgPool,
    user: UserId,
    platform_admin: bool,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<(Uuid, Slug)>, sqlx::Error> {
    sqlx::query!(
        r#"
        SELECT o.id, o.slug
        FROM organizations o
        WHERE ($2
               OR o.id IN (SELECT organization_id FROM organization_admins WHERE user_id = $1)
               OR o.id IN (
                   SELECT l.organization_id
                   FROM organization_teams l
                   JOIN team_members m ON m.team_id = l.team_id
                   WHERE m.user_id = $1
               ))
          AND ($3::text IS NULL OR o.slug > $3)
        ORDER BY o.slug
        LIMIT $4
        "#,
        user.as_uuid(),
        platform_admin,
        after,
        limit,
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| slugged(row.id, &row.slug))
    .collect()
}

/// Every team the built-in permits could let the user see: all of them
/// for a platform admin or an organization admin, else their own. Up to
/// `limit`, by slug, after `after`; with their slugs.
#[tracing::instrument(skip_all, fields(user.id = %user.as_uuid()))]
pub(super) async fn candidate_teams(
    db: &PgPool,
    user: UserId,
    platform_admin: bool,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<(Uuid, Slug)>, sqlx::Error> {
    sqlx::query!(
        r#"
        SELECT t.id, t.slug
        FROM teams t
        WHERE ($2
               OR EXISTS (SELECT 1 FROM organization_admins WHERE user_id = $1)
               OR t.id IN (SELECT team_id FROM team_members WHERE user_id = $1))
          AND ($3::text IS NULL OR t.slug > $3)
        ORDER BY t.slug
        LIMIT $4
        "#,
        user.as_uuid(),
        platform_admin,
        after,
        limit,
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| slugged(row.id, &row.slug))
    .collect()
}
