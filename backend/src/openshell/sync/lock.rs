//! The sync's advisory lock, held for the session of a connection of its
//! own: not a transaction left idle across gateway calls (which a server
//! timeout would end, silently releasing the lock), and not one of the
//! pool's connections, held for the whole run. The session is never ended
//! for being idle (`idle_session_timeout`, [`super::own_connection_options`]).

use std::time::Duration;

use sqlx::{Connection, PgConnection, PgPool};

use super::SyncError;
use crate::{error::database_kind, openshell::repo};

/// How long opening the lock's connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a query on the lock's connection may take, or closing it: a
/// connection that stopped answering must not hold up the run. Longer than
/// the pool's statement timeout, which the connection shares.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// `query`, given at most [`QUERY_TIMEOUT`].
async fn bounded<T>(query: impl Future<Output = Result<T, sqlx::Error>>) -> Result<T, sqlx::Error> {
    tokio::time::timeout(QUERY_TIMEOUT, query)
        .await
        .map_err(|_| sqlx::Error::Io(std::io::ErrorKind::TimedOut.into()))?
}

/// The sync's lock, held.
pub(super) struct SyncLock {
    connection: PgConnection,
}

impl SyncLock {
    /// Takes the lock on a new connection made like the pool's, if no
    /// other instance holds it (`None`).
    pub(super) async fn acquire(db: &PgPool) -> Result<Option<Self>, SyncError> {
        let options = super::own_connection_options(db);
        let mut connection =
            tokio::time::timeout(CONNECT_TIMEOUT, PgConnection::connect_with(&options))
                .await
                .map_err(|_| sqlx::Error::Io(std::io::ErrorKind::TimedOut.into()))??;
        if bounded(repo::try_lock(&mut connection)).await? {
            return Ok(Some(Self { connection }));
        }
        close(connection).await;
        Ok(None)
    }

    /// Fails with [`SyncError::LockLost`] unless the lock is still held:
    /// its connection alive and answering, its session holding it.
    pub(super) async fn check(&mut self) -> Result<(), SyncError> {
        match bounded(repo::holds_lock(&mut self.connection)).await {
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

    /// Releases the lock; its connection is the caller's to [`close`]. A
    /// failure is only logged: the lock ends with its session anyway.
    pub(super) async fn release(mut self) -> PgConnection {
        match bounded(repo::unlock(&mut self.connection)).await {
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

/// Closes a connection of the lock's; one that does not answer in time is
/// dropped, which ends its session too.
pub(super) async fn close(connection: PgConnection) {
    if let Err(error) = bounded(connection.close()).await {
        tracing::debug!(
            error.type = database_kind(&error),
            "openshell: closing the sync's lock connection failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use sqlx::postgres::PgPoolOptions;

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

    #[sqlx::test]
    async fn the_lock_survives_an_idle_session_timeout(pool: PgPool) {
        // As if the role or the server ended idle sessions after 300 ms.
        let options = (*pool.connect_options())
            .clone()
            .options([("idle_session_timeout", "300ms")]);
        let strict = PgPoolOptions::new().connect_lazy_with(options);
        let mut lock = SyncLock::acquire(&strict).await.unwrap().unwrap();
        // Idle for longer, as during a slow gateway call.
        tokio::time::sleep(Duration::from_millis(900)).await;
        lock.check().await.unwrap();
    }

    /// A TCP proxy to the database at `port` that stops passing bytes on
    /// in either direction once `frozen` is set: a connection that stopped
    /// answering, without closing.
    async fn freezing_proxy(port: u16) -> (u16, Arc<AtomicBool>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn pass(
            mut from: tokio::net::tcp::OwnedReadHalf,
            mut to: tokio::net::tcp::OwnedWriteHalf,
            frozen: Arc<AtomicBool>,
        ) {
            let mut buffer = vec![0_u8; 8192];
            while let Ok(read) = from.read(&mut buffer).await {
                if read == 0 {
                    return;
                }
                if frozen.load(Ordering::SeqCst) {
                    std::future::pending::<()>().await;
                }
                if to.write_all(&buffer[..read]).await.is_err() {
                    return;
                }
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let frozen = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&frozen);
        tokio::spawn(async move {
            loop {
                let (inbound, _) = listener.accept().await.unwrap();
                let outbound = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                let (in_read, in_write) = inbound.into_split();
                let (out_read, out_write) = outbound.into_split();
                tokio::spawn(pass(in_read, out_write, Arc::clone(&flag)));
                tokio::spawn(pass(out_read, in_write, Arc::clone(&flag)));
            }
        });
        (proxy_port, frozen)
    }

    #[sqlx::test]
    async fn a_lock_whose_connection_stopped_answering_is_lost(pool: PgPool) {
        let options = pool.connect_options();
        let (port, frozen) = freezing_proxy(options.get_port()).await;
        let proxied = PgPoolOptions::new().connect_lazy_with((*options).clone().port(port));
        let mut lock = SyncLock::acquire(&proxied).await.unwrap().unwrap();
        lock.check().await.unwrap();
        frozen.store(true, Ordering::SeqCst);
        let checked = tokio::time::timeout(QUERY_TIMEOUT.saturating_mul(2), lock.check())
            .await
            .expect("the check does not wait for good");
        assert!(matches!(checked, Err(SyncError::LockLost)));
    }
}
