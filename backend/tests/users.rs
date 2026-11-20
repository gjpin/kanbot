//! Users: recorded once per identity on authenticated requests, kept up to
//! date with few writes, and refused once disabled.

use kanbot_backend::{
    auth::token::{PlatformRole, Principal},
    error::AppError,
    users::{model::UserId, service},
};
use sqlx::PgPool;

fn principal(subject: &str) -> Principal {
    Principal {
        issuer: "https://auth.example.com".to_owned(),
        subject: subject.to_owned(),
        role: PlatformRole::User,
        client_id: Some("kanbot-cli".to_owned()),
        display_name: Some("Alice".to_owned()),
        groups: vec!["kanbot-user".to_owned()],
    }
}

async fn user_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar!(r#"SELECT count(*) AS "count!" FROM users"#)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The row's version: it changes on every write.
async fn row_version(pool: &PgPool, id: UserId) -> String {
    sqlx::query_scalar!(
        r#"SELECT xmin::text AS "version!" FROM users WHERE id = $1"#,
        id.as_uuid()
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test]
async fn creates_a_user_on_first_sight_only(pool: PgPool) {
    let first = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();
    let second = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();

    assert_eq!(first.id, second.id);
    assert_eq!(first.role, PlatformRole::User);
    assert_eq!(first.display_name.as_deref(), Some("Alice"));
    assert!(!first.telemetry_opt_in);
    assert_eq!(user_count(&pool).await, 1);

    let row = sqlx::query!(
        "SELECT issuer, subject, display_name, platform_role FROM users WHERE id = $1",
        first.id.as_uuid()
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.issuer, "https://auth.example.com");
    assert_eq!(row.subject, "alice");
    assert_eq!(row.display_name.as_deref(), Some("Alice"));
    assert_eq!(row.platform_role, "user");
}

#[sqlx::test]
async fn a_user_is_the_issuer_and_subject_pair(pool: PgPool) {
    let alice = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();
    let bob = service::authenticate(&pool, &principal("bob"))
        .await
        .unwrap();
    let mut elsewhere = principal("alice");
    elsewhere.issuer = "https://other.example.com".to_owned();
    let other_alice = service::authenticate(&pool, &elsewhere).await.unwrap();

    assert_ne!(alice.id, bob.id);
    assert_ne!(alice.id, other_alice.id);
    assert_eq!(user_count(&pool).await, 3);
}

#[sqlx::test]
async fn concurrent_first_requests_create_one_user(pool: PgPool) {
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..10 {
        let pool = pool.clone();
        requests.spawn(async move { service::authenticate(&pool, &principal("alice")).await });
    }
    let ids: Vec<UserId> = requests
        .join_all()
        .await
        .into_iter()
        .map(|user| user.unwrap().id)
        .collect();

    assert!(ids.iter().all(|id| *id == ids[0]));
    assert_eq!(user_count(&pool).await, 1);
}

#[sqlx::test]
async fn does_not_write_a_recently_seen_unchanged_user(pool: PgPool) {
    let user = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();
    let version = row_version(&pool, user.id).await;

    service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();

    assert_eq!(row_version(&pool, user.id).await, version);
}

#[sqlx::test]
async fn updates_last_seen_after_five_minutes(pool: PgPool) {
    let user = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();
    sqlx::query!(
        "UPDATE users SET last_seen_at = now() - interval '6 minutes' WHERE id = $1",
        user.id.as_uuid()
    )
    .execute(&pool)
    .await
    .unwrap();

    service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();

    let recent = sqlx::query_scalar!(
        r#"SELECT last_seen_at > now() - interval '1 minute' AS "recent!" FROM users WHERE id = $1"#,
        user.id.as_uuid()
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(recent);
}

#[sqlx::test]
async fn keeps_last_seen_within_five_minutes(pool: PgPool) {
    let user = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();
    sqlx::query!(
        "UPDATE users SET last_seen_at = now() - interval '4 minutes' WHERE id = $1",
        user.id.as_uuid()
    )
    .execute(&pool)
    .await
    .unwrap();
    let version = row_version(&pool, user.id).await;

    service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();

    assert_eq!(row_version(&pool, user.id).await, version);
}

#[sqlx::test]
async fn updates_a_changed_display_name_or_role(pool: PgPool) {
    let user = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();

    let mut renamed = principal("alice");
    renamed.display_name = Some("Alice Liddell".to_owned());
    service::authenticate(&pool, &renamed).await.unwrap();
    let mut promoted = renamed.clone();
    promoted.role = PlatformRole::Admin;
    let admin = service::authenticate(&pool, &promoted).await.unwrap();
    assert_eq!(admin.role, PlatformRole::Admin);

    let row = sqlx::query!(
        "SELECT display_name, platform_role FROM users WHERE id = $1",
        user.id.as_uuid()
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.display_name.as_deref(), Some("Alice Liddell"));
    assert_eq!(row.platform_role, "admin");

    let mut nameless = promoted;
    nameless.display_name = None;
    service::authenticate(&pool, &nameless).await.unwrap();
    let name = sqlx::query_scalar!(
        "SELECT display_name FROM users WHERE id = $1",
        user.id.as_uuid()
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(name, None);
}

#[sqlx::test]
async fn disabled_users_are_refused(pool: PgPool) {
    let user = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();
    sqlx::query!(
        "UPDATE users SET disabled_at = now() WHERE id = $1",
        user.id.as_uuid()
    )
    .execute(&pool)
    .await
    .unwrap();

    let result = service::authenticate(&pool, &principal("alice")).await;

    assert!(matches!(result, Err(AppError::AccountDisabled)));
    // Other users are unaffected.
    service::authenticate(&pool, &principal("bob"))
        .await
        .unwrap();
}

#[sqlx::test]
async fn telemetry_consent_is_stored(pool: PgPool) {
    let user = service::authenticate(&pool, &principal("alice"))
        .await
        .unwrap();

    service::set_telemetry_opt_in(&pool, user.id, true)
        .await
        .unwrap();
    assert!(
        service::authenticate(&pool, &principal("alice"))
            .await
            .unwrap()
            .telemetry_opt_in
    );

    service::set_telemetry_opt_in(&pool, user.id, false)
        .await
        .unwrap();
    assert!(
        !service::authenticate(&pool, &principal("alice"))
            .await
            .unwrap()
            .telemetry_opt_in
    );
}

#[sqlx::test]
async fn consent_of_an_unknown_user_is_not_found(pool: PgPool) {
    let result = service::set_telemetry_opt_in(&pool, UserId::new(), true).await;
    assert!(matches!(result, Err(AppError::NotFound)));
}
