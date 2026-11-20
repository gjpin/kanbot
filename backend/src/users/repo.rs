//! Database access for users.

use sqlx::PgPool;

use crate::{
    auth::token::Principal,
    users::model::{SeenUser, UserId},
};

/// Records that the principal's user was seen, creating the user on first
/// sight. One statement: it writes only when the user is new, was last
/// seen over 5 minutes ago, or their display name or role changed.
///
/// `None` only when another request created the same user concurrently;
/// the caller retries.
#[tracing::instrument(skip_all)]
pub(super) async fn record_seen(
    db: &PgPool,
    principal: &Principal,
) -> Result<Option<SeenUser>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        WITH upserted AS (
            INSERT INTO users (id, issuer, subject, display_name, platform_role)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (issuer, subject) DO UPDATE
                SET display_name = EXCLUDED.display_name,
                    platform_role = EXCLUDED.platform_role,
                    last_seen_at = now()
                WHERE users.last_seen_at < now() - interval '5 minutes'
                   OR users.display_name IS DISTINCT FROM EXCLUDED.display_name
                   OR users.platform_role <> EXCLUDED.platform_role
            RETURNING id, disabled_at IS NOT NULL AS disabled, telemetry_opt_in
        )
        SELECT id AS "id!", disabled AS "disabled!", telemetry_opt_in AS "telemetry_opt_in!"
        FROM upserted
        UNION ALL
        SELECT id, disabled_at IS NOT NULL, telemetry_opt_in
        FROM users
        WHERE issuer = $2 AND subject = $3 AND NOT EXISTS (SELECT 1 FROM upserted)
        "#,
        UserId::new().as_uuid(),
        principal.issuer,
        principal.subject,
        principal.display_name,
        principal.role.as_str(),
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|row| SeenUser {
        id: UserId::from_uuid(row.id),
        disabled: row.disabled,
        telemetry_opt_in: row.telemetry_opt_in,
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
