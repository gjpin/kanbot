pub mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use kanbot_backend::http::MAX_BODY_BYTES;
use sqlx::{
    PgPool, SqlStr,
    migrate::{Migration, Migrator},
};
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok() {
    let response = common::app_without_db()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"ok");
}

/// One migration, not applied by `#[sqlx::test]` (which applies only
/// `migrations/`).
static PENDING: Migrator = sqlx::migrate!("tests/fixtures/readiness_migrations");
static REVERSIBLE: Migrator = sqlx::migrate!("tests/fixtures/reversible_migrations");

async fn ready_status(app: Router) -> StatusCode {
    app.oneshot(Request::get("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[sqlx::test]
async fn ready_is_ok_with_database(pool: PgPool) {
    assert_eq!(
        ready_status(common::app_with_pool(pool)).await,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn ready_is_unavailable_until_signing_keys_load(pool: PgPool) {
    let idp = common::idp::TestIdp::start().await;
    let keys = idp.key_cache(&[]);
    let app = || common::app_with_keys(pool.clone(), &kanbot_backend::db::MIGRATOR, keys.clone());

    let response = app()
        .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "unavailable");

    keys.refresh().await.unwrap();

    assert_eq!(ready_status(app()).await, StatusCode::OK);
}

#[tokio::test]
async fn ready_is_unavailable_without_keys_even_before_the_database() {
    // The database is unreachable: the key check comes first, and fails.
    let keys = common::idp::unloaded_key_cache();
    let options = sqlx::postgres::PgConnectOptions::new_without_pgpass()
        .host("127.0.0.1")
        .port(1);
    let app = common::app_with_keys(
        kanbot_backend::db::pool_with(options),
        &kanbot_backend::db::MIGRATOR,
        keys,
    );
    assert_eq!(ready_status(app).await, StatusCode::SERVICE_UNAVAILABLE);
}

#[sqlx::test]
async fn ready_is_unavailable_until_migrations_are_applied(pool: PgPool) {
    let response = common::app_with(pool.clone(), &PENDING)
        .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "unavailable");

    PENDING.run(&pool).await.unwrap();

    assert_eq!(
        ready_status(common::app_with(pool, &PENDING)).await,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn ready_is_unavailable_when_an_applied_migration_changed(pool: PgPool) {
    PENDING.run(&pool).await.unwrap();
    let applied = PENDING.iter().next().unwrap();
    let edited = Migration::new(
        applied.version,
        applied.description.clone(),
        applied.migration_type,
        SqlStr::from_static("CREATE TABLE edited (id integer);"),
        false,
    );
    let edited: &'static Migrator = Box::leak(Box::new(Migrator::with_migrations(vec![edited])));

    assert_eq!(
        ready_status(common::app_with(pool, edited)).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[sqlx::test]
async fn ready_is_unavailable_with_a_half_applied_migration(pool: PgPool) {
    PENDING.run(&pool).await.unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET success = false")
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        ready_status(common::app_with(pool, &PENDING)).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[sqlx::test]
async fn ready_ignores_down_migrations(pool: PgPool) {
    REVERSIBLE.run(&pool).await.unwrap();

    assert_eq!(
        ready_status(common::app_with(pool, &REVERSIBLE)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn ready_is_unavailable_without_database() {
    let response = common::app_without_db()
        .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "unavailable");
    let body = body.to_string();
    assert!(
        !body.contains("127.0.0.1") && !body.contains("refused"),
        "error details must not reach the client: {body}"
    );
}

#[tokio::test]
async fn unknown_route_is_not_found() {
    let response = common::app_without_db()
        .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let size = MAX_BODY_BYTES.checked_add(1).unwrap();
    let request = Request::get("/health")
        .header(header::CONTENT_LENGTH, size)
        .body(Body::from(vec![0_u8; size]))
        .unwrap();

    let response = common::app_without_db().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A database `migrate` has never run against: no migrations table at all.
#[sqlx::test(migrations = false)]
async fn ready_is_unavailable_before_the_first_migrate(pool: PgPool) {
    assert_eq!(
        ready_status(common::app_with(pool, &PENDING)).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// Any other failure to read the migrations table is a server error, not
/// "not ready".
#[sqlx::test(migrations = false)]
async fn ready_fails_when_the_migrations_table_is_unreadable(pool: PgPool) {
    sqlx::query("CREATE TABLE _sqlx_migrations (unexpected integer)")
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        ready_status(common::app_with(pool, &PENDING)).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}
