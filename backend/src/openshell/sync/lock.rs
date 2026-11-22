//! The sync's advisory lock, held for the session of a connection of its
//! own: not a transaction left idle across gateway calls (which a server
//! timeout would end, silently releasing the lock), and not one of the
//! pool's connections, held for the whole run.

use std::time::Duration;

use sqlx::{Connection, PgConnection, PgPool};

use super::SyncError;
use crate::{error::database_kind, openshell::repo};

/// How long opening the lock's connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The sync's lock, held.
pub(super) struct SyncLock {
    connection: PgConnection,
}

impl SyncLock {
    /// Takes the lock on a new connection made like the pool's, if no
    /// other instance holds it (`None`).
    pub(super) async fn acquire(db: &PgPool) -> Result<Option<Self>, SyncError> {
        let options = db.connect_options();
        let mut connection =
            tokio::time::timeout(CONNECT_TIMEOUT, PgConnection::connect_with(&options))
                .await
                .map_err(|_| sqlx::Error::Io(std::io::ErrorKind::TimedOut.into()))??;
        if repo::try_lock(&mut connection).await? {
            return Ok(Some(Self { connection }));
        }
        if let Err(error) = connection.close().await {
            tracing::debug!(
                error.type = database_kind(&error),
                "openshell: closing a connection failed"
            );
        }
        Ok(None)
    }

    /// Fails with [`SyncError::LockLost`] unless the lock is still held:
    /// its connection alive, its session holding it.
    pub(super) async fn check(&mut self) -> Result<(), SyncError> {
        match repo::holds_lock(&mut self.connection).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(SyncError::LockLost),
            Err(error) => {
                tracing::warn!(
                    error.type = database_kind(&error),
                    "openshell: the sync's lock connection failed"
                );
                Err(SyncError::LockLost)
            }
        }
    }

    /// Releases the lock; its connection is the caller's to close. A
    /// failure is only logged: the lock ends with its session anyway.
    pub(super) async fn release(mut self) -> PgConnection {
        match repo::unlock(&mut self.connection).await {
            Ok(true) => {}
            Ok(false) => tracing::warn!("openshell: the sync's lock was no longer held"),
            Err(error) => tracing::warn!(
                error.type = database_kind(&error),
                "openshell: the sync's lock could not be released; it ends with its connection"
            ),
        }
        self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn one_holder_at_a_time_until_released(pool: PgPool) {
        let mut lock = SyncLock::acquire(&pool).await.unwrap().unwrap();
        lock.check().await.unwrap();
        assert!(SyncLock::acquire(&pool).await.unwrap().is_none());

        let mut connection = lock.release().await;
        assert!(!repo::holds_lock(&mut connection).await.unwrap());
        assert!(
            !repo::unlock(&mut connection).await.unwrap(),
            "released once"
        );
        let mut next = SyncLock::acquire(&pool).await.unwrap().unwrap();
        next.check().await.unwrap();
        assert!(!repo::try_lock(&mut connection).await.unwrap());
    }

    #[sqlx::test]
    async fn a_lock_whose_connection_died_is_lost(pool: PgPool) {
        let mut lock = SyncLock::acquire(&pool).await.unwrap().unwrap();
        let pid = sqlx::query_scalar!(r#"SELECT pg_backend_pid() AS "pid!""#)
            .fetch_one(&mut lock.connection)
            .await
            .unwrap();
        let ended = sqlx::query_scalar!(r#"SELECT pg_terminate_backend($1) AS "ended!""#, pid)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(ended);
        assert!(matches!(lock.check().await, Err(SyncError::LockLost)));
    }
}
