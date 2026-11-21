//! Database access for teams.

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::{
    names::{Name, Slug},
    teams::model::{IdpGroup, Member, MembershipSource, Team, TeamChanges, TeamId, TeamRole},
    users::model::{UserId, UserSummary},
};

/// Makes the user's `idp` memberships match `groups`: a member of every
/// team whose `idp_group` is in `groups`, and of no other team through
/// the sync. Writes nothing when they already match. Returns how many
/// memberships were added and removed.
#[tracing::instrument(skip_all, fields(user.id = %user.as_uuid()))]
pub(super) async fn sync_idp_groups(
    db: &PgPool,
    user: UserId,
    groups: &[String],
) -> Result<(i64, i64), sqlx::Error> {
    let row = sqlx::query!(
        r#"
        WITH wanted AS (
            SELECT id FROM teams WHERE idp_group = ANY($2)
        ),
        removed AS (
            DELETE FROM team_members m
            WHERE m.user_id = $1
              AND m.source = 'idp'
              AND m.team_id NOT IN (SELECT id FROM wanted)
            RETURNING m.team_id
        ),
        added AS (
            INSERT INTO team_members (team_id, user_id, role, source)
            SELECT id, $1, 'member', 'idp' FROM wanted
            ON CONFLICT (team_id, user_id) DO NOTHING
            RETURNING team_id
        )
        SELECT
            (SELECT count(*) FROM added) AS "added!",
            (SELECT count(*) FROM removed) AS "removed!"
        "#,
        user.as_uuid(),
        groups,
    )
    .fetch_one(db)
    .await?;
    Ok((row.added, row.removed))
}

fn decode(what: &'static str) -> sqlx::Error {
    sqlx::Error::Decode(what.into())
}

fn team(id: Uuid, slug: &str, name: &str, idp_group: Option<&str>) -> Result<Team, sqlx::Error> {
    Ok(Team {
        id: TeamId::from_uuid(id),
        slug: Slug::parse(slug).map_err(|_| decode("teams.slug"))?,
        name: Name::parse(name).map_err(|_| decode("teams.name"))?,
        idp_group: idp_group
            .map(IdpGroup::parse)
            .transpose()
            .map_err(|_| decode("teams.idp_group"))?,
    })
}

/// The teams among `ids`, by slug.
#[tracing::instrument(skip_all)]
pub(super) async fn list(db: &PgPool, ids: &[Uuid]) -> Result<Vec<Team>, sqlx::Error> {
    sqlx::query!(
        "SELECT id, slug, name, idp_group FROM teams WHERE id = ANY($1) ORDER BY slug",
        ids
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| team(row.id, &row.slug, &row.name, row.idp_group.as_deref()))
    .collect()
}

#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid()))]
pub(super) async fn get(db: &PgPool, id: TeamId) -> Result<Option<Team>, sqlx::Error> {
    sqlx::query!(
        "SELECT id, slug, name, idp_group FROM teams WHERE id = $1",
        id.as_uuid()
    )
    .fetch_optional(db)
    .await?
    .map(|row| team(row.id, &row.slug, &row.name, row.idp_group.as_deref()))
    .transpose()
}

/// Inserts the team, with `maintainer` as its first (manual) maintainer.
#[tracing::instrument(skip_all, fields(team.id = %new.id.as_uuid()))]
pub(super) async fn insert(
    db: &mut PgConnection,
    new: &Team,
    maintainer: UserId,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO teams (id, slug, name, idp_group) VALUES ($1, $2, $3, $4)",
        new.id.as_uuid(),
        new.slug.as_str(),
        new.name.as_str(),
        new.idp_group.as_ref().map(IdpGroup::as_str),
    )
    .execute(&mut *db)
    .await?;
    sqlx::query!(
        r#"
        INSERT INTO team_members (team_id, user_id, role, source)
        VALUES ($1, $2, 'maintainer', 'manual')
        "#,
        new.id.as_uuid(),
        maintainer.as_uuid(),
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Applies `changes`. When the identity provider group changes, the memberships it
/// replaces go: all of them when a group is set (the sync adds the
/// group's members back as they sign in), the synced ones when it is
/// cleared. `None` if the team does not exist.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid()))]
pub(super) async fn update(
    db: &mut PgConnection,
    id: TeamId,
    changes: &TeamChanges,
) -> Result<Option<Team>, sqlx::Error> {
    let new_group = changes
        .idp_group
        .as_ref()
        .map(|change| change.group().map(IdpGroup::as_str));
    let previous = sqlx::query_scalar!(
        "SELECT idp_group FROM teams WHERE id = $1 FOR UPDATE",
        id.as_uuid()
    )
    .fetch_optional(&mut *db)
    .await?;
    let Some(previous) = previous else {
        return Ok(None);
    };
    let row = sqlx::query!(
        r#"
        UPDATE teams
        SET slug = COALESCE($2, slug),
            name = COALESCE($3, name),
            idp_group = CASE WHEN $4 THEN $5 ELSE idp_group END,
            updated_at = now()
        WHERE id = $1
        RETURNING id, slug, name, idp_group
        "#,
        id.as_uuid(),
        changes.slug.as_ref().map(Slug::as_str),
        changes.name.as_ref().map(Name::as_str),
        new_group.is_some(),
        new_group.flatten(),
    )
    .fetch_one(&mut *db)
    .await?;
    if let Some(group) = new_group
        && group != previous.as_deref()
    {
        sqlx::query!(
            "DELETE FROM team_members WHERE team_id = $1 AND ($2 OR source = 'idp')",
            id.as_uuid(),
            group.is_some(),
        )
        .execute(db)
        .await?;
    }
    team(row.id, &row.slug, &row.name, row.idp_group.as_deref()).map(Some)
}

/// Deletes the team, its memberships and its links. `false` if it did
/// not exist.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid()))]
pub(super) async fn delete(db: &mut PgConnection, id: TeamId) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query!("DELETE FROM teams WHERE id = $1", id.as_uuid())
            .execute(db)
            .await?
            .rows_affected()
            == 1,
    )
}

/// The team's members: maintainers first, then by display name.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid()))]
pub(super) async fn members(db: &PgPool, id: TeamId) -> Result<Vec<Member>, sqlx::Error> {
    sqlx::query!(
        r#"
        SELECT u.id, u.display_name, m.role, m.source
        FROM team_members m
        JOIN users u ON u.id = m.user_id
        WHERE m.team_id = $1
        ORDER BY m.role = 'maintainer' DESC, u.display_name NULLS LAST, u.id
        "#,
        id.as_uuid()
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| {
        Ok(Member {
            user: UserSummary {
                id: UserId::from_uuid(row.id),
                display_name: row.display_name,
            },
            role: TeamRole::parse(&row.role).ok_or_else(|| decode("team_members.role"))?,
            source: MembershipSource::parse(&row.source)
                .ok_or_else(|| decode("team_members.source"))?,
        })
    })
    .collect()
}

/// Whether the team is synced with an identity provider group, and the source of
/// `user`'s membership, if any; both locked until the transaction ends.
/// `None` if the team does not exist.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid(), user.id = %user.as_uuid()))]
pub(super) async fn lock_membership(
    db: &mut PgConnection,
    id: TeamId,
    user: UserId,
) -> Result<Option<(bool, Option<MembershipSource>)>, sqlx::Error> {
    let Some(synced) = sqlx::query_scalar!(
        r#"SELECT idp_group IS NOT NULL AS "synced!" FROM teams WHERE id = $1 FOR UPDATE"#,
        id.as_uuid()
    )
    .fetch_optional(&mut *db)
    .await?
    else {
        return Ok(None);
    };
    let source = sqlx::query_scalar!(
        "SELECT source FROM team_members WHERE team_id = $1 AND user_id = $2 FOR UPDATE",
        id.as_uuid(),
        user.as_uuid()
    )
    .fetch_optional(db)
    .await?
    .map(|source| MembershipSource::parse(&source).ok_or_else(|| decode("team_members.source")))
    .transpose()?;
    Ok(Some((synced, source)))
}

/// Adds `user` as a manual member with `role`, or changes their role.
/// Returns the previous role, if they were a member.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid(), user.id = %user.as_uuid()))]
pub(super) async fn set_member(
    db: &mut PgConnection,
    id: TeamId,
    user: UserId,
    role: TeamRole,
) -> Result<Option<TeamRole>, sqlx::Error> {
    let previous = sqlx::query_scalar!(
        "SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2",
        id.as_uuid(),
        user.as_uuid()
    )
    .fetch_optional(&mut *db)
    .await?
    .map(|role| TeamRole::parse(&role).ok_or_else(|| decode("team_members.role")))
    .transpose()?;
    sqlx::query!(
        r#"
        INSERT INTO team_members (team_id, user_id, role, source) VALUES ($1, $2, $3, 'manual')
        ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role
        "#,
        id.as_uuid(),
        user.as_uuid(),
        role.as_str()
    )
    .execute(db)
    .await?;
    Ok(previous)
}

/// `false` if `user` was not a member.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid(), user.id = %user.as_uuid()))]
pub(super) async fn remove_member(
    db: &mut PgConnection,
    id: TeamId,
    user: UserId,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM team_members WHERE team_id = $1 AND user_id = $2",
        id.as_uuid(),
        user.as_uuid()
    )
    .execute(db)
    .await?
    .rows_affected()
        == 1)
}
