//! Business rules for teams.

use sqlx::PgPool;

use crate::{error::AppError, teams::repo, users::model::UserId};

/// Brings the user's memberships of IdP-synced teams (`teams.idp_group`)
/// in line with their groups claim. Runs on every authenticated request.
///
/// # Errors
///
/// A database error.
pub async fn sync_idp_groups(db: &PgPool, user: UserId, groups: &[String]) -> Result<(), AppError> {
    let (added, removed) = repo::sync_idp_groups(db, user, groups).await?;
    if added > 0 || removed > 0 {
        tracing::info!(user.id = %user.as_uuid(), added, removed, "team memberships synced from the identity provider");
    }
    Ok(())
}
