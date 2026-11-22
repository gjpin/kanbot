//! Deleting expired login attempts, codes and sessions.

use sqlx::PgPool;

use crate::sessions::repo;

/// Rows deleted per statement by [`cleanup`].
pub const CLEANUP_BATCH: i64 = 1000;
/// How long one run may delete: short statements, but no limit on how
/// many fit, so cleanup keeps up with sign-ins started at the sign-in
/// routes' rate limit.
const CLEANUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
/// How often [`spawn_cleanup`] runs [`cleanup`].
const CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Deletes expired login attempts, one-time codes and sessions, `batch`
/// rows per statement, until a statement deletes fewer or `budget` has
/// passed. Returns how many rows went.
///
/// # Errors
///
/// A database error; what was deleted before it stays deleted.
pub async fn cleanup(
    db: &PgPool,
    batch: i64,
    budget: std::time::Duration,
) -> Result<u64, sqlx::Error> {
    let started = tokio::time::Instant::now();
    let mut deleted = 0_u64;
    for table in 0..3 {
        while started.elapsed() < budget {
            let count = match table {
                0 => repo::delete_expired_attempts(db, batch).await?,
                1 => repo::delete_expired_codes(db, batch).await?,
                _ => repo::delete_expired_sessions(db, batch).await?,
            };
            deleted = deleted.saturating_add(count);
            if count < u64::try_from(batch).unwrap_or(u64::MAX) {
                break;
            }
        }
    }
    Ok(deleted)
}

/// Runs [`cleanup`] every minute on the current Tokio runtime.
pub fn spawn_cleanup(db: PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            match cleanup(&db, CLEANUP_BATCH, CLEANUP_BUDGET).await {
                Ok(deleted) => tracing::debug!(
                    deleted = i64::try_from(deleted).unwrap_or(i64::MAX),
                    "expired sessions cleaned up"
                ),
                Err(error) => tracing::warn!(
                    error.type = crate::error::AppError::from(error).kind(),
                    "session cleanup failed"
                ),
            }
        }
    });
}
