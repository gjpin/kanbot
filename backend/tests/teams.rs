//! Teams: identity provider group sync, and the `/teams` routes.

pub mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use common::idp::access_token;
use kanbot_backend::{teams::service, users::model::UserId};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn insert_user(pool: &PgPool) -> UserId {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, issuer, subject, platform_role) VALUES ($1, 'https://idp', $2, 'user')",
        id,
        id.to_string()
    )
    .execute(pool)
    .await
    .unwrap();
    UserId::from_uuid(id)
}

async fn insert_team(pool: &PgPool, slug: &str, idp_group: Option<&str>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO teams (id, slug, name, idp_group) VALUES ($1, $2, 'Team', $3)",
        id,
        slug,
        idp_group
    )
    .execute(pool)
    .await
    .unwrap();
    id
}

/// The user's memberships: (team, role, source), by team ID.
async fn memberships(pool: &PgPool, user: UserId) -> Vec<(Uuid, String, String)> {
    sqlx::query!(
        "SELECT team_id, role, source FROM team_members WHERE user_id = $1 ORDER BY team_id",
        user.as_uuid()
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| (row.team_id, row.role, row.source))
    .collect()
}

/// The versions of every membership row: they change on every write.
async fn row_versions(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar!(
        r#"SELECT xmin::text AS "version!" FROM team_members ORDER BY team_id, user_id"#
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn groups(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[sqlx::test]
async fn sync_adds_and_removes_idp_memberships(pool: PgPool) {
    let user = insert_user(&pool).await;
    let platform = insert_team(&pool, "platform", Some("platform-team")).await;
    let ops = insert_team(&pool, "ops", Some("ops-team")).await;
    insert_team(&pool, "manual", None).await;

    service::sync_idp_groups(&pool, user, &groups(&["platform-team", "unrelated"]))
        .await
        .unwrap();
    assert_eq!(
        memberships(&pool, user).await,
        [(platform, "member".to_owned(), "idp".to_owned())]
    );

    service::sync_idp_groups(&pool, user, &groups(&["ops-team"]))
        .await
        .unwrap();
    assert_eq!(
        memberships(&pool, user).await,
        [(ops, "member".to_owned(), "idp".to_owned())]
    );

    service::sync_idp_groups(&pool, user, &[]).await.unwrap();
    assert_eq!(memberships(&pool, user).await, []);
}

#[sqlx::test]
async fn sync_leaves_manual_memberships_alone(pool: PgPool) {
    let user = insert_user(&pool).await;
    let manual = insert_team(&pool, "manual", None).await;
    sqlx::query!(
        "INSERT INTO team_members (team_id, user_id, role, source) VALUES ($1, $2, 'maintainer', 'manual')",
        manual,
        user.as_uuid()
    )
    .execute(&pool)
    .await
    .unwrap();
    let synced = insert_team(&pool, "synced", Some("synced")).await;

    service::sync_idp_groups(&pool, user, &groups(&["synced"]))
        .await
        .unwrap();
    service::sync_idp_groups(&pool, user, &[]).await.unwrap();

    assert_eq!(
        memberships(&pool, user).await,
        [(manual, "maintainer".to_owned(), "manual".to_owned())]
    );
    assert_ne!(manual, synced);
}

#[sqlx::test]
async fn sync_writes_only_when_something_changed(pool: PgPool) {
    let user = insert_user(&pool).await;
    insert_team(&pool, "a", Some("a")).await;
    insert_team(&pool, "b", Some("b")).await;
    let other = insert_user(&pool).await;
    service::sync_idp_groups(&pool, user, &groups(&["a", "b"]))
        .await
        .unwrap();
    service::sync_idp_groups(&pool, other, &groups(&["a"]))
        .await
        .unwrap();
    let before = row_versions(&pool).await;
    assert_eq!(before.len(), 3);

    service::sync_idp_groups(&pool, user, &groups(&["b", "a"]))
        .await
        .unwrap();
    assert_eq!(row_versions(&pool).await, before);

    // Another user's change leaves this user's rows alone.
    service::sync_idp_groups(&pool, other, &[]).await.unwrap();
    assert_eq!(memberships(&pool, user).await.len(), 2);
}

async fn get_me(app: &Router, token: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::get("/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[sqlx::test]
async fn every_authenticated_request_syncs_the_groups(pool: PgPool) {
    let app = common::app_with_pool(pool.clone());
    let team = insert_team(&pool, "platform", Some("platform-team")).await;

    assert_eq!(
        get_me(
            &app,
            &access_token("alice", &["kanbot-user", "platform-team"])
        )
        .await,
        StatusCode::OK
    );
    let alice = UserId::from_uuid(
        sqlx::query_scalar!("SELECT id FROM users WHERE subject = 'alice'")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    assert_eq!(
        memberships(&pool, alice).await,
        [(team, "member".to_owned(), "idp".to_owned())]
    );

    assert_eq!(
        get_me(&app, &access_token("alice", &["kanbot-user"])).await,
        StatusCode::OK
    );
    assert_eq!(memberships(&pool, alice).await, []);
}
