//! Database access for the audit log.

use sqlx::{PgConnection, PgPool};

use crate::{
    audit::model::{Entry, NewEntry},
    users::model::{UserId, UserSummary},
};

/// Adds `entry`, in the caller's transaction.
#[tracing::instrument(skip_all, fields(audit.action = entry.action))]
pub(super) async fn insert(db: &mut PgConnection, entry: &NewEntry) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO audit_log (actor_user_id, action, target_type, target_id, policy_ids, details)
        VALUES ($1, $2, $3, $4, $5, $6::text::jsonb)
        "#,
        entry.actor.as_uuid(),
        entry.action,
        entry.target.type_name(),
        entry.target.id(),
        &entry.policy_ids,
        entry.details.to_string(),
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Up to `limit` entries older than `before` (all if `None`), newest first.
#[tracing::instrument(skip_all)]
pub(super) async fn list(
    db: &PgPool,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<Entry>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT
            a.id,
            to_char(a.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "at!",
            a.actor_user_id,
            u.display_name,
            a.action,
            a.target_type,
            a.target_id,
            a.policy_ids,
            a.details::text AS "details!"
        FROM audit_log a
        JOIN users u ON u.id = a.actor_user_id
        WHERE $1::bigint IS NULL OR a.id < $1
        ORDER BY a.id DESC
        LIMIT $2
        "#,
        before,
        limit,
    )
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(Entry {
                id: row.id,
                at: row.at,
                actor: UserSummary {
                    id: UserId::from_uuid(row.actor_user_id),
                    display_name: row.display_name,
                },
                action: row.action,
                target_type: row.target_type,
                target_id: row.target_id,
                policy_ids: row.policy_ids,
                details: serde_json::from_str(&row.details)
                    .map_err(|error| sqlx::Error::Decode(error.into()))?,
            })
        })
        .collect()
}
