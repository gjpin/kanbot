//! Running the sync in the background: on a timer, when the database says
//! what it reads changed, and again after failures.

use std::{sync::Arc, time::Duration};

use opentelemetry::{KeyValue, global};
use sqlx::{
    PgPool,
    postgres::{PgListener, PgPoolOptions},
};
use tokio::time::Instant;

use super::{Changes, Scope, SyncError, backoff::Backoff};
use crate::{authz::policies::Policies, error::database_kind, openshell::OpenShell};

/// How often every linked workspace is synced, besides when what it reads
/// changes.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(300);
/// A run that failed is retried after this long.
const RETRY_DELAY: Duration = Duration::from_secs(30);
/// Runs are at least this far apart, however many changes arrive.
const MIN_GAP: Duration = Duration::from_secs(5);
/// Listening for changes is tried again after this long when it fails...
const LISTEN_RETRY: Duration = Duration::from_secs(1);
/// ... doubling each time, up to this.
const LISTEN_RETRY_MAX: Duration = Duration::from_secs(60);
/// How long opening the listener's connection may take.
const LISTEN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The channel the database's triggers notify when what the sync reads
/// changes (migration `openshell_sync_notify`).
const CHANNEL: &str = "kanbot_openshell";

/// When the background sync runs. The server uses [`Timing::default`].
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// Every linked workspace is synced this often, besides when what it
    /// reads changes.
    pub interval: Duration,
    /// A run that failed is retried after this long. So is a workspace
    /// that failed, waiting twice as long each time it fails again, up to
    /// `interval`.
    pub retry: Duration,
    /// Runs are at least this far apart, however many changes arrive.
    pub min_gap: Duration,
    /// Listening for changes is tried again after this long when it
    /// fails, twice as long each time, up to `listen_retry_max`.
    pub listen_retry: Duration,
    pub listen_retry_max: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            interval: SYNC_INTERVAL,
            retry: RETRY_DELAY,
            min_gap: MIN_GAP,
            listen_retry: LISTEN_RETRY,
            listen_retry_max: LISTEN_RETRY_MAX,
        }
    }
}

/// The database's change notifications, on a connection of their own
/// (made like the pool's, never one of the pool's): the listener holds it
/// for good. Listening that fails is tried again, with a growing wait.
struct Notifications {
    pool: PgPool,
    listener: Option<PgListener>,
    /// The wait before listening is tried again.
    wait: Duration,
    first_wait: Duration,
    max_wait: Duration,
    /// Whether notifications may have been lost since listening last
    /// worked.
    missed: bool,
}

impl Notifications {
    fn new(db: &PgPool, timing: &Timing) -> Self {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .max_lifetime(None)
            .idle_timeout(None)
            .acquire_timeout(LISTEN_CONNECT_TIMEOUT)
            .connect_lazy_with(super::own_connection_options(db));
        Self {
            pool,
            listener: None,
            wait: timing.listen_retry,
            first_wait: timing.listen_retry,
            max_wait: timing.listen_retry_max,
            missed: false,
        }
    }

    /// A listener that never reconnects on its own. With sqlx's eager
    /// reconnect, `try_recv` reconnects before it returns `Ok(None)` (the
    /// connection dropped, notifications may be lost); a `try_recv`
    /// cancelled meanwhile (by `select!`, or the drain's zero timeout)
    /// would lose that signal, and the next call reconnect silently. Here
    /// `Ok(None)` comes at once, and [`Self::lost`] reconnects through
    /// [`Self::changed`], which then reports the gap.
    async fn listen(&self) -> Result<PgListener, sqlx::Error> {
        let mut listener = PgListener::connect_with(&self.pool).await?;
        listener.eager_reconnect(false);
        listener.listen(CHANNEL).await?;
        Ok(listener)
    }

    /// The listener's connection dropped (`error`, or `None` when it just
    /// ended): what comes until listening works again is lost.
    fn lost(&mut self, error: Option<&sqlx::Error>) {
        tracing::warn!(
            error.type = error.map(database_kind),
            "openshell: change notifications interrupted"
        );
        self.listener = None;
        self.missed = true;
    }

    /// Takes the notifications that already came, without waiting: the run
    /// about to start covers them. A connection found dropped is handled
    /// as in [`Self::changed`].
    async fn drain(&mut self) {
        while let Some(listener) = self.listener.as_mut() {
            match tokio::time::timeout(Duration::ZERO, listener.try_recv()).await {
                Ok(Ok(Some(_))) => {}
                // Nothing more yet.
                Err(_) => return,
                Ok(Ok(None)) => self.lost(None),
                Ok(Err(error)) => self.lost(Some(&error)),
            }
        }
    }

    /// Returns when what the sync reads may have changed: a notification
    /// came, or some may have been lost and listening works again.
    async fn changed(&mut self) {
        loop {
            if let Some(listener) = self.listener.as_mut() {
                match listener.try_recv().await {
                    Ok(Some(_)) => return,
                    Ok(None) => self.lost(None),
                    Err(error) => self.lost(Some(&error)),
                }
            } else {
                match self.listen().await {
                    Ok(listener) => {
                        self.listener = Some(listener);
                        self.wait = self.first_wait;
                        if std::mem::take(&mut self.missed) {
                            return;
                        }
                        continue;
                    }
                    Err(error) => tracing::warn!(
                        error.type = database_kind(&error),
                        "openshell: not listening for changes; trying again"
                    ),
                }
            }
            self.missed = true;
            let wait = self.wait;
            self.wait = wait.saturating_mul(2).min(self.max_wait);
            tokio::time::sleep(wait).await;
        }
    }
}

/// Runs the sync on the current Tokio runtime with [`Timing::default`].
pub fn spawn_sync(db: PgPool, policies: Arc<Policies>, openshell: Arc<OpenShell>, issuer: String) {
    spawn_sync_with(db, policies, openshell, issuer, Timing::default());
}

/// Runs the sync on the current Tokio runtime: every `timing.interval`,
/// when the database says what it reads changed (on any instance), and
/// `timing.retry` after a failure; never more often than
/// `timing.min_gap`. A workspace that fails is retried on its own.
pub fn spawn_sync_with(
    db: PgPool,
    policies: Arc<Policies>,
    openshell: Arc<OpenShell>,
    issuer: String,
    timing: Timing,
) {
    tokio::spawn(async move {
        let mut notifications = Notifications::new(&db, &timing);
        let mut backoff = Backoff::new(timing.retry, timing.interval);
        let mut interval = tokio::time::interval(timing.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // When a failed run is tried again, in full.
        let mut rerun_at: Option<Instant> = None;
        let mut last_run: Option<Instant> = None;
        loop {
            // A full rerun covers the failed workspaces too.
            let retry_at = rerun_at.or_else(|| backoff.next_retry());
            let retry = async {
                match retry_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            let scope = tokio::select! {
                _ = interval.tick() => Scope::All,
                () = notifications.changed() => Scope::All,
                () = retry => if rerun_at.is_some() { Scope::All } else { Scope::Failed },
            };
            if let Some(next) = last_run.and_then(|last| last.checked_add(timing.min_gap)) {
                tokio::time::sleep_until(next).await;
            }
            // Changes that came meanwhile are covered by this run.
            notifications.drain().await;
            last_run = Some(Instant::now());
            let outcome =
                super::run(&db, &policies, &openshell, &issuer, &mut backoff, scope).await;
            rerun_at = match &outcome {
                Err(_) => Instant::now().checked_add(timing.retry),
                Ok(Some(_)) => None,
                Ok(None) => {
                    // Another instance syncs: its runs, not these failures,
                    // are what counts now.
                    backoff.clear();
                    None
                }
            };
            report(&outcome);
        }
    });
}

/// Logs a sync's outcome, and counts it (`kanbot.openshell.sync.members`
/// by change, `kanbot.openshell.sync.failures`). Nothing is logged when
/// nothing changed or failed, so a quiet sync every few minutes stays
/// quiet.
fn report(outcome: &Result<Option<Changes>, SyncError>) {
    let meter = global::meter(crate::telemetry::SCOPE);
    match outcome {
        Ok(Some(changes)) => {
            let members = meter
                .u64_counter("kanbot.openshell.sync.members")
                .with_unit("{member}")
                .with_description("Workspace members the sync added or removed.")
                .build();
            members.add(changes.added, &[KeyValue::new("change", "added")]);
            members.add(changes.removed, &[KeyValue::new("change", "removed")]);
            meter
                .u64_counter("kanbot.openshell.sync.failures")
                .with_unit("{workspace}")
                .with_description("Workspaces a sync run could not sync.")
                .build()
                .add(changes.failed, &[]);
            if changes.changed() || changes.failed > 0 {
                tracing::info!(
                    added = i64::try_from(changes.added).unwrap_or(i64::MAX),
                    removed = i64::try_from(changes.removed).unwrap_or(i64::MAX),
                    skipped = i64::try_from(changes.skipped).unwrap_or(i64::MAX),
                    failed = i64::try_from(changes.failed).unwrap_or(i64::MAX),
                    "openshell membership synced"
                );
            }
        }
        Ok(None) => {}
        Err(error) => {
            meter
                .u64_counter("kanbot.openshell.sync.failures")
                .with_unit("{workspace}")
                .with_description("Workspaces a sync run could not sync.")
                .build()
                .add(1, &[]);
            tracing::warn!(%error, "openshell membership sync failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// The log lines `report` writes for `outcome`.
    fn logged(outcome: &Result<Option<Changes>, SyncError>) -> String {
        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || report(outcome));
        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn reports_only_member_changes_and_failures() {
        let changes = |added, removed, skipped, failed| {
            Ok(Some(Changes {
                added,
                removed,
                skipped,
                failed,
            }))
        };
        let added = logged(&changes(1, 0, 2, 0));
        assert!(added.contains("openshell membership synced"), "{added}");
        assert!(
            added.contains("added=1 removed=0 skipped=2 failed=0"),
            "{added}"
        );
        let removed = logged(&changes(0, 3, 0, 0));
        assert!(removed.contains("added=0 removed=3"), "{removed}");
        let failed = logged(&changes(0, 0, 0, 1));
        assert!(failed.contains("failed=1"), "{failed}");
        assert_eq!(logged(&changes(0, 0, 0, 0)), "");
        // Members left alone are not a change.
        assert_eq!(logged(&changes(0, 0, 5, 0)), "");
        // Another instance syncs: nothing to say.
        assert_eq!(logged(&Ok(None)), "");
        let error = logged(&Err(SyncError::Database(sqlx::Error::PoolTimedOut)));
        assert!(
            error.contains("openshell membership sync failed"),
            "{error}"
        );
        assert!(error.contains("database.pool_timed_out"), "{error}");
        let lost = logged(&Err(SyncError::LockLost));
        assert!(lost.contains("the sync's lock was lost"), "{lost}");
    }

    fn quick() -> Timing {
        Timing {
            listen_retry: Duration::from_millis(50),
            listen_retry_max: Duration::from_millis(100),
            ..Timing::default()
        }
    }

    /// The sessions listening in this test's database.
    async fn listeners(pool: &PgPool) -> Vec<i32> {
        sqlx::query_scalar!(
            r#"SELECT pid AS "pid!" FROM pg_stat_activity
               WHERE datname = current_database() AND query LIKE 'LISTEN%'"#
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// Listening, with nothing missed: `changed` waits.
    async fn listening(pool: &PgPool) -> Notifications {
        let mut notifications = Notifications::new(pool, &quick());
        let waited = tokio::time::timeout(Duration::from_millis(300), notifications.changed());
        assert!(waited.await.is_err(), "nothing changed yet");
        assert_eq!(listeners(pool).await.len(), 1);
        notifications
    }

    /// Ends the listener's session, and waits until its end has reached
    /// the listener's socket.
    async fn drop_listener(pool: &PgPool) {
        let [pid] = listeners(pool).await[..] else {
            panic!("one listener")
        };
        let ended = sqlx::query_scalar!(r#"SELECT pg_terminate_backend($1) AS "ended!""#, pid)
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(ended);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    /// `changed` returns soon: what may have been missed is reported.
    async fn reports_a_change(notifications: &mut Notifications) {
        tokio::time::timeout(Duration::from_secs(5), notifications.changed())
            .await
            .expect("a change is reported");
    }

    #[sqlx::test]
    async fn notifications_wake_the_sync(pool: PgPool) {
        let mut notifications = listening(&pool).await;
        sqlx::query!("NOTIFY kanbot_openshell")
            .execute(&pool)
            .await
            .unwrap();
        reports_a_change(&mut notifications).await;
    }

    #[sqlx::test]
    async fn a_connection_lost_while_waiting_is_reported_even_if_the_wait_is_cancelled(
        pool: PgPool,
    ) {
        let mut notifications = listening(&pool).await;
        drop_listener(&pool).await;
        // A timer or a retry wins the select! at once.
        let cancelled = tokio::time::timeout(Duration::ZERO, notifications.changed()).await;
        assert!(cancelled.is_err());
        reports_a_change(&mut notifications).await;
        assert_eq!(listeners(&pool).await.len(), 1, "listening again");
    }

    #[sqlx::test]
    async fn a_connection_lost_while_draining_is_reported(pool: PgPool) {
        let mut notifications = listening(&pool).await;
        drop_listener(&pool).await;
        notifications.drain().await;
        reports_a_change(&mut notifications).await;
        assert_eq!(listeners(&pool).await.len(), 1, "listening again");
    }

    #[sqlx::test]
    async fn the_listener_survives_an_idle_session_timeout(pool: PgPool) {
        // As if the role or the server ended idle sessions after 600 ms.
        let options = (*pool.connect_options())
            .clone()
            .options([("idle_session_timeout", "600ms")]);
        let strict = PgPoolOptions::new().connect_lazy_with(options);
        let mut notifications = listening(&strict).await;
        let before = listeners(&pool).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(listeners(&pool).await, before, "the same session");
        sqlx::query!("NOTIFY kanbot_openshell")
            .execute(&pool)
            .await
            .unwrap();
        reports_a_change(&mut notifications).await;
    }
}
