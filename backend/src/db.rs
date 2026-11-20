//! Database connection pool and schema migrations. Feature `repo` modules
//! take a `&PgPool`.

use std::{num::NonZeroU32, time::Duration};

use opentelemetry::{KeyValue, metrics::Meter};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{
    Connection,
    migrate::{Migrate, MigrateError, Migrator},
    postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions},
};

/// Pool size when none is configured (`DATABASE_MAX_CONNECTIONS`).
const DEFAULT_MAX_CONNECTIONS: u32 = 10;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);
const STATEMENT_TIMEOUT: &str = "5s";

/// How long `migrate` may take to connect.
const MIGRATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a migration may wait for a table lock. Waiting DDL blocks every
/// query queued behind it, so a busy table fails the migration instead of
/// stalling the app.
const MIGRATION_LOCK_TIMEOUT: &str = "5s";

/// The table where sqlx records applied migrations (its default name).
const MIGRATIONS_TABLE: &str = "_sqlx_migrations";
/// PostgreSQL `undefined_table`.
const UNDEFINED_TABLE: &str = "42P01";

/// The migrations in `migrations/`, embedded at compile time.
pub static MIGRATOR: Migrator = sqlx::migrate!();

/// Builds the pool from a connection string, with up to `max_connections`
/// connections. Connections are opened lazily, on first use.
///
/// # Errors
///
/// Returns an error if `url` is not a valid PostgreSQL connection string.
pub fn pool(url: &SecretString, max_connections: NonZeroU32) -> Result<PgPool, sqlx::Error> {
    Ok(sized_pool(connect_options(url)?, max_connections))
}

/// Builds the pool from parsed options, with the default size and the
/// statement timeout.
#[must_use]
pub fn pool_with(options: PgConnectOptions) -> PgPool {
    sized_pool(
        options,
        NonZeroU32::new(DEFAULT_MAX_CONNECTIONS).unwrap_or(NonZeroU32::MIN),
    )
}

fn sized_pool(options: PgConnectOptions, max_connections: NonZeroU32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max_connections.get())
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_lazy_with(options.options([("statement_timeout", STATEMENT_TIMEOUT)]))
}

/// `db.client.connection.pool.name` of the app's pool.
const POOL_NAME: &str = "kanbot";

/// Reports the pool's connections as the semantic-convention metric
/// `db.client.connection.count`, split by `db.client.connection.state`
/// (`idle`, `used`), each time metrics are collected.
pub fn observe_pool(meter: &Meter, pool: PgPool) {
    meter
        .i64_observable_up_down_counter("db.client.connection.count")
        .with_unit("{connection}")
        .with_description("Number of connections in the pool, by state.")
        .with_callback(move |observer| {
            let size = pool.size();
            let idle = u32::try_from(pool.num_idle()).map_or(size, |idle| idle.min(size));
            for (state, count) in [("idle", idle), ("used", size.saturating_sub(idle))] {
                observer.observe(
                    i64::from(count),
                    &[
                        KeyValue::new("db.client.connection.state", state),
                        KeyValue::new("db.client.connection.pool.name", POOL_NAME),
                    ],
                );
            }
        })
        .build();
}

fn connect_options(url: &SecretString) -> Result<PgConnectOptions, sqlx::Error> {
    url.expose_secret().parse::<PgConnectOptions>()
}

/// Applies every pending migration in `migrator` over a single connection.
///
/// The connection has no statement timeout (a migration may legitimately
/// take long) but a lock timeout. sqlx holds an advisory lock while
/// migrating, so concurrent runs wait for each other instead of racing.
///
/// # Errors
///
/// Returns an error if `url` is invalid, the database cannot be reached in
/// time, or a migration fails. A failed migration is rolled back.
pub async fn migrate(url: &SecretString, migrator: &Migrator) -> Result<(), MigrateError> {
    let options = connect_options(url)?.options([("lock_timeout", MIGRATION_LOCK_TIMEOUT)]);
    let mut conn = tokio::time::timeout(
        MIGRATION_CONNECT_TIMEOUT,
        PgConnection::connect_with(&options),
    )
    .await
    .map_err(|_| sqlx::Error::Io(std::io::ErrorKind::TimedOut.into()))??;
    migrator.run(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

/// Whether every migration in `migrator` has been applied, unchanged (same
/// checksum), and none is left half-applied.
///
/// # Errors
///
/// Returns an error if the database cannot be queried.
pub async fn migrations_are_current(
    conn: &mut PgConnection,
    migrator: &Migrator,
) -> Result<bool, sqlx::Error> {
    let expected: Vec<_> = migrator
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .collect();
    if expected.is_empty() {
        return Ok(true);
    }

    let applied = match applied_migrations(conn).await {
        Ok(applied) => applied,
        Err(MigrateError::Execute(sqlx::Error::Database(error)))
            if error.code().as_deref() == Some(UNDEFINED_TABLE) =>
        {
            // `migrate` has never run against this database.
            return Ok(false);
        }
        Err(MigrateError::Execute(error)) => return Err(error),
        Err(error) => return Err(sqlx::Error::Migrate(Box::new(error))),
    };
    Ok(expected.iter().all(|migration| {
        applied.iter().any(|(version, checksum)| {
            *version == migration.version && checksum == migration.checksum.as_ref()
        })
    }))
}

/// `(version, checksum)` of every applied migration, or an empty list when
/// one is half-applied (a failed migration that ran outside a transaction).
async fn applied_migrations(conn: &mut PgConnection) -> Result<Vec<(i64, Vec<u8>)>, MigrateError> {
    if conn.dirty_version(MIGRATIONS_TABLE).await?.is_some() {
        return Ok(Vec::new());
    }
    Ok(conn
        .list_applied_migrations(MIGRATIONS_TABLE)
        .await?
        .into_iter()
        .map(|applied| (applied.version, applied.checksum.into_owned()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_pool_has_the_configured_size() {
        let url = SecretString::from("postgres://kanbot@127.0.0.1:1/kanbot");
        let pool = pool(&url, NonZeroU32::new(7).unwrap()).unwrap();
        assert_eq!(pool.options().get_max_connections(), 7);
        let default = pool_with(connect_options(&url).unwrap());
        assert_eq!(default.options().get_max_connections(), 10);
    }
}
