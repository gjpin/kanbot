//! Database access for teams.

use sqlx::PgPool;

use crate::users::model::UserId;

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
