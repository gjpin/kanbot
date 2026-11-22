//! Database access for users.

use sqlx::{PgConnection, PgPool};

use crate::{
    auth::token::Principal,
    users::model::{SeenUser, UserId, UserQuery, UserSummary},
};

/// Records that the principal's user was seen, creating the user on first
/// sight. It writes only when the user is new, was last seen over 5 minutes
/// ago, or their display name, role or groups changed; otherwise it only
/// reads, and locks nothing. (`INSERT ... ON CONFLICT DO UPDATE ... WHERE`
/// would lock the row on every call, even when its `WHERE` is false.) A
/// token without a display name or groups claim keeps the stored ones.
#[tracing::instrument(skip_all)]
pub(super) async fn record_seen(
    db: &PgPool,
    principal: &Principal,
) -> Result<SeenUser, sqlx::Error> {
    if let Some(seen) = update_seen(db, principal).await? {
        return Ok(seen);
    }
    if let Some(seen) = insert_seen(db, principal).await? {
        return Ok(seen);
    }
    // Another request created the user meanwhile: the insert waited for it
    // to commit, so this statement sees it.
    update_seen(db, principal)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

/// The principal's user, if it exists, updated only when that is due: last
/// seen over 5 minutes ago, or a changed display name, role or groups. A
/// plain `UPDATE` locks only the rows its `WHERE` matches.
async fn update_seen(db: &PgPool, principal: &Principal) -> Result<Option<SeenUser>, sqlx::Error> {
    let groups: Option<&[String]> = principal.groups.as_deref();
    let row = sqlx::query!(
        r#"
        WITH updated AS (
            UPDATE users
            SET display_name = COALESCE($3, display_name),
                platform_role = $4,
                groups = COALESCE($5::text[], groups),
                last_seen_at = now()
            WHERE issuer = $1 AND subject = $2
              AND (last_seen_at < now() - interval '5 minutes'
                   OR ($3::text IS NOT NULL AND display_name IS DISTINCT FROM $3)
                   OR platform_role <> $4
                   OR ($5::text[] IS NOT NULL AND groups IS DISTINCT FROM $5))
            RETURNING id, disabled_at IS NOT NULL AS disabled, telemetry_opt_in, groups
        )
        SELECT id AS "id!", disabled AS "disabled!", telemetry_opt_in AS "telemetry_opt_in!",
               groups AS "groups!"
        FROM updated
        UNION ALL
        SELECT id, disabled_at IS NOT NULL, telemetry_opt_in, groups
        FROM users
        WHERE issuer = $1 AND subject = $2 AND NOT EXISTS (SELECT 1 FROM updated)
        "#,
        principal.issuer,
        principal.subject,
        principal.display_name,
        principal.role.as_str(),
        groups,
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|row| SeenUser {
        id: UserId::from_uuid(row.id),
        disabled: row.disabled,
        telemetry_opt_in: row.telemetry_opt_in,
        groups: row.groups,
    }))
}

/// Creates the principal's user. `None` if it exists already: another
/// request created it, and this one waited for that to commit.
async fn insert_seen(db: &PgPool, principal: &Principal) -> Result<Option<SeenUser>, sqlx::Error> {
    let groups: Option<&[String]> = principal.groups.as_deref();
    let row = sqlx::query!(
        r#"
        INSERT INTO users (id, issuer, subject, display_name, platform_role, groups)
        VALUES ($1, $2, $3, $4, $5, COALESCE($6::text[], '{}'))
        ON CONFLICT (issuer, subject) DO NOTHING
        RETURNING id, disabled_at IS NOT NULL AS "disabled!", telemetry_opt_in, groups
        "#,
        UserId::new().as_uuid(),
        principal.issuer,
        principal.subject,
        principal.display_name,
        principal.role.as_str(),
        groups,
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|row| SeenUser {
        id: UserId::from_uuid(row.id),
        disabled: row.disabled,
        telemetry_opt_in: row.telemetry_opt_in,
        groups: row.groups,
    }))
}

/// Sets the user's telemetry consent. `false` if the user does not exist.
#[tracing::instrument(skip_all, fields(user.id = %id.as_uuid()))]
pub(super) async fn set_telemetry_opt_in(
    db: &PgPool,
    id: UserId,
    opt_in: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE users SET telemetry_opt_in = $2 WHERE id = $1",
        id.as_uuid(),
        opt_in,
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Marks the user disabled. `false` if the user does not exist.
#[tracing::instrument(skip_all, fields(user.id = %id.as_uuid()))]
pub(super) async fn disable(db: &mut PgConnection, id: UserId) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query!(
        "UPDATE users SET disabled_at = COALESCE(disabled_at, now()) WHERE id = $1",
        id.as_uuid()
    )
    .execute(db)
    .await?
    .rows_affected()
        == 1)
}

/// Whether the user exists and is not disabled.
#[tracing::instrument(skip_all, fields(user.id = %id.as_uuid()))]
pub(super) async fn is_active(db: &PgPool, id: UserId) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query_scalar!(
        r#"SELECT disabled_at IS NULL AS "active!" FROM users WHERE id = $1"#,
        id.as_uuid()
    )
    .fetch_optional(db)
    .await?
    .unwrap_or(false))
}

/// Up to `limit` users who are not disabled and whose display name
/// contains `query` (any case), by display name.
#[tracing::instrument(skip_all)]
pub(super) async fn search(
    db: &PgPool,
    query: &UserQuery,
    limit: i64,
) -> Result<Vec<UserSummary>, sqlx::Error> {
    // LIKE's wildcards in the query match themselves (escaped with `\`,
    // named in the query, not left to the default).
    let pattern = format!(
        "%{}%",
        query
            .as_str()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let rows = sqlx::query!(
        r#"
        SELECT id, display_name
        FROM users
        WHERE disabled_at IS NULL AND COALESCE(display_name, '') ILIKE $1 ESCAPE '\'
        ORDER BY display_name NULLS LAST, id
        LIMIT $2
        "#,
        pattern,
        limit,
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| UserSummary {
            id: UserId::from_uuid(row.id),
            display_name: row.display_name,
            disabled: false,
        })
        .collect())
}
