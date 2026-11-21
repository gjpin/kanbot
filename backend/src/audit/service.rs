//! The audit log: who changed organizations and teams, and which policies
//! allowed it.

use sqlx::{PgConnection, PgPool};

use crate::{
    audit::{
        model::{Entry, NewEntry},
        repo,
    },
    authz::{
        model::{Action, Actor, Resource},
        policies::Policies,
        service as authz,
    },
    error::AppError,
};

/// Most entries one page holds.
pub const MAX_PAGE: i64 = 100;

/// Records a change, in the transaction that makes it.
///
/// # Errors
///
/// A database error.
pub async fn record(db: &mut PgConnection, entry: &NewEntry) -> Result<(), AppError> {
    repo::insert(db, entry).await?;
    Ok(())
}

/// Up to `limit` (at most [`MAX_PAGE`]) entries older than `before`,
/// newest first.
///
/// # Errors
///
/// [`AppError::Forbidden`] unless `actor` may `viewAudit`, or a database
/// error.
pub async fn list(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<Entry>, AppError> {
    authz::require(db, policies, actor, Action::ViewAudit, Resource::Platform).await?;
    Ok(repo::list(db, before, limit.clamp(1, MAX_PAGE)).await?)
}
