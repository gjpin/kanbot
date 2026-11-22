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

/// Entries shown when the caller does not say.
pub const DEFAULT_PAGE: i64 = 50;

/// A page of the audit log, and the `before` of the next page if there is
/// one.
pub struct Page {
    pub entries: Vec<Entry>,
    pub next_before: Option<i64>,
}

/// Up to `limit` (default [`DEFAULT_PAGE`], at most [`MAX_PAGE`]) entries
/// older than `before`, newest first.
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
    limit: Option<i64>,
) -> Result<Page, AppError> {
    authz::require(db, policies, actor, Action::ViewAudit, Resource::Platform).await?;
    let limit = limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    // One more than asked: only then is there a next page.
    let mut entries = repo::list(db, before, limit.saturating_add(1)).await?;
    let more = usize::try_from(limit).is_ok_and(|limit| entries.len() > limit);
    if more {
        entries.pop();
    }
    let next_before = entries.last().filter(|_| more).map(|entry| entry.id);
    Ok(Page {
        entries,
        next_before,
    })
}
