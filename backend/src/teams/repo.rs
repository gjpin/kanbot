//! Database access for teams.

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::{
    names::{Name, Slug},
    teams::model::{
        IdpGroup, Member, MemberCursor, MembershipSource, Team, TeamChanges, TeamId, TeamRole,
    },
    users::model::{UserId, UserSummary},
};

/// Makes the user's `idp` memberships match `groups`: a member of every
/// team whose `idp_group` is in `groups`, and of no other team through
/// the sync. Returns how many memberships were added and removed.
///
/// A read-only check comes first, so the common case (nothing changed)
/// writes and locks nothing. A change runs in a transaction that locks the
/// user (concurrent syncs of one user cannot merge two group lists) and
/// the wanted teams `FOR SHARE`: a concurrent change of a team's group
/// ([`update`], which locks the team `FOR UPDATE`) is waited for and seen,
/// so no membership is added for a group the team no longer has.
#[tracing::instrument(skip_all, fields(user.id = %user.as_uuid()))]
pub(super) async fn sync_idp_groups(
    db: &PgPool,
    user: UserId,
    groups: &[String],
) -> Result<(i64, i64), sqlx::Error> {
    let in_sync = sqlx::query_scalar!(
        r#"
        SELECT
            COALESCE((SELECT array_agg(id ORDER BY id) FROM teams WHERE idp_group = ANY($2)), '{}')
            = COALESCE((SELECT array_agg(team_id ORDER BY team_id) FROM team_members
                        WHERE user_id = $1 AND source = 'idp'), '{}')
            AS "in_sync!"
        "#,
        user.as_uuid(),
        groups,
    )
    .fetch_one(db)
    .await?;
    if in_sync {
        return Ok((0, 0));
    }
    let mut tx = db.begin().await?;
    let exists = sqlx::query_scalar!(
        "SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE",
        user.as_uuid()
    )
    .fetch_optional(&mut *tx)
    .await?;
    if exists.is_none() {
        return Ok((0, 0));
    }
    let wanted = sqlx::query_scalar!(
        "SELECT id FROM teams WHERE idp_group = ANY($1) ORDER BY id FOR SHARE",
        groups,
    )
    .fetch_all(&mut *tx)
    .await?;
    let row = sqlx::query!(
        r#"
        WITH removed AS (
            DELETE FROM team_members m
            WHERE m.user_id = $1
              AND m.source = 'idp'
              AND m.team_id <> ALL($2)
            RETURNING m.team_id
        ),
        added AS (
            INSERT INTO team_members (team_id, user_id, role, source)
            SELECT id, $1, 'member', 'idp' FROM unnest($2::uuid[]) AS wanted(id)
            ON CONFLICT (team_id, user_id) DO NOTHING
            RETURNING team_id
        )
        SELECT
            (SELECT count(*) FROM added) AS "added!",
            (SELECT count(*) FROM removed) AS "removed!"
        "#,
        user.as_uuid(),
        &wanted,
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
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

/// Applies `changes`, and returns the team with the names of the fields
/// that changed (changing a value to itself writes nothing). When the identity provider group changes,
/// the memberships it replaces go: all of them when a group is set (the
/// sync adds the group's members back as they sign in), the synced ones
/// when it is cleared. `None` if the team does not exist.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid()))]
pub(super) async fn update(
    db: &mut PgConnection,
    id: TeamId,
    changes: &TeamChanges,
) -> Result<Option<(Team, Vec<&'static str>)>, sqlx::Error> {
    let new_group = changes
        .idp_group
        .as_ref()
        .map(|change| change.group().map(IdpGroup::as_str));
    let current = sqlx::query!(
        "SELECT id, slug, name, idp_group FROM teams WHERE id = $1 FOR UPDATE",
        id.as_uuid()
    )
    .fetch_optional(&mut *db)
    .await?;
    let Some(current) = current else {
        return Ok(None);
    };
    let current = team(
        current.id,
        &current.slug,
        &current.name,
        current.idp_group.as_deref(),
    )?;
    let fields = changes.changed(&current);
    if fields.is_empty() {
        return Ok(Some((current, fields)));
    }
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
    if fields.contains(&"idp_group") {
        sqlx::query!(
            "DELETE FROM team_members WHERE team_id = $1 AND ($2 OR source = 'idp')",
            id.as_uuid(),
            new_group.flatten().is_some(),
        )
        .execute(db)
        .await?;
    }
    team(row.id, &row.slug, &row.name, row.idp_group.as_deref()).map(|team| Some((team, fields)))
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

/// Up to `limit` of the team's members after `after`: maintainers first,
/// then by display name (unnamed last), then by ID.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid()))]
pub(super) async fn members(
    db: &PgPool,
    id: TeamId,
    after: Option<&MemberCursor>,
    limit: i64,
) -> Result<Vec<Member>, sqlx::Error> {
    sqlx::query!(
        r#"
        SELECT u.id, u.display_name, u.disabled_at IS NOT NULL AS "disabled!", m.role, m.source
        FROM team_members m
        JOIN users u ON u.id = m.user_id
        WHERE m.team_id = $1
          AND ($2::bool IS NULL
               OR (m.role <> 'maintainer', u.display_name IS NULL,
                   COALESCE(u.display_name, ''), u.id)
                  > (NOT $2, $3, $4, $5))
        ORDER BY m.role <> 'maintainer', u.display_name IS NULL,
                 COALESCE(u.display_name, ''), u.id
        LIMIT $6
        "#,
        id.as_uuid(),
        after.map(|after| after.maintainer),
        after.map(|after| after.display_name.is_none()),
        after.map(|after| after.display_name.clone().unwrap_or_default()),
        after.map(|after| after.user.as_uuid()),
        limit,
    )
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| {
        Ok(Member {
            user: UserSummary {
                id: UserId::from_uuid(row.id),
                display_name: row.display_name,
                disabled: row.disabled,
            },
            role: TeamRole::parse(&row.role).ok_or_else(|| decode("team_members.role"))?,
            source: MembershipSource::parse(&row.source)
                .ok_or_else(|| decode("team_members.source"))?,
        })
    })
    .collect()
}

/// A membership locked for a change.
pub(super) struct LockedMembership {
    /// The team is synced with an identity provider group.
    pub synced: bool,
    /// The user's membership, if any: its source and role.
    pub membership: Option<(MembershipSource, TeamRole)>,
    /// How many maintainers the team has.
    pub maintainers: i64,
}

/// The team (whether it is synced, and its maintainer count) and `user`'s
/// membership, if any; locked until the transaction ends, so changes of a
/// team's members are serialized. `None` if the team does not exist.
#[tracing::instrument(skip_all, fields(team.id = %id.as_uuid(), user.id = %user.as_uuid()))]
pub(super) async fn lock_membership(
    db: &mut PgConnection,
    id: TeamId,
    user: UserId,
) -> Result<Option<LockedMembership>, sqlx::Error> {
    let Some(synced) = sqlx::query_scalar!(
        r#"SELECT idp_group IS NOT NULL AS "synced!" FROM teams WHERE id = $1 FOR UPDATE"#,
        id.as_uuid()
    )
    .fetch_optional(&mut *db)
    .await?
    else {
        return Ok(None);
    };
    let membership = sqlx::query!(
        "SELECT source, role FROM team_members WHERE team_id = $1 AND user_id = $2 FOR UPDATE",
        id.as_uuid(),
        user.as_uuid()
    )
    .fetch_optional(&mut *db)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>((
            MembershipSource::parse(&row.source).ok_or_else(|| decode("team_members.source"))?,
            TeamRole::parse(&row.role).ok_or_else(|| decode("team_members.role"))?,
        ))
    })
    .transpose()?;
    let maintainers = sqlx::query_scalar!(
        r#"SELECT count(*) AS "count!" FROM team_members
           WHERE team_id = $1 AND role = 'maintainer'"#,
        id.as_uuid()
    )
    .fetch_one(db)
    .await?;
    Ok(Some(LockedMembership {
        synced,
        membership,
        maintainers,
    }))
}

/// Adds `user` as a manual member with `role`, or changes their role (the
/// membership is manual from then on). Returns the previous role, if they
/// were a member. Callers refuse synced teams, and a team that is not
/// synced has no synced memberships: [`update`] removes them when it
/// clears the group, under the team's lock.
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
        ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role, source = 'manual'
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
