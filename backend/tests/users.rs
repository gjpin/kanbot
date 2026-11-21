//! Users: recorded once per identity on authenticated requests, kept up to
//! date with few writes, and refused once disabled; and the `/me` routes,
//! through the authentication middleware.

pub mod common;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::idp::{access_token, claims, sign};
use http_body_util::BodyExt;
use kanbot_backend::{
    auth::token::{PlatformRole, Principal},
    error::AppError,
    users::{model::UserId, service},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

fn principal(subject: &str) -> Principal {
    Principal {
        issuer: "https://auth.example.com".to_owned(),
        subject: subject.to_owned(),
        role: PlatformRole::User,
        client_id: Some("kanbot-cli".to_owned()),
        display_name: Some("Alice".to_owned()),
        groups: vec!["kanbot-user".to_owned()],
        expires_at: 1_800_000_000,
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

/// Sends a request with an optional `Authorization` header and JSON body;
/// returns the status, the `WWW-Authenticate` header and the JSON body.
async fn call(
    app: Router,
    method: Method,
    path: &str,
    authorization: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Option<String>, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|value| value.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, challenge, body)
}

async fn get_me(pool: &PgPool, authorization: Option<&str>) -> (StatusCode, Option<String>, Value) {
    call(
        common::app_with_pool(pool.clone()),
        Method::GET,
        "/me",
        authorization,
        None,
    )
    .await
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[sqlx::test]
async fn me_without_credentials_asks_for_a_bearer_token(pool: PgPool) {
    let (status, challenge, body) = get_me(&pool, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(challenge.as_deref(), Some("Bearer"));
    assert_eq!(body["code"], "unauthorized");
}

#[sqlx::test]
async fn invalid_credentials_are_refused_without_a_reason(pool: PgPool) {
    let expired = with(claims("alice", &["kanbot-user"]), "exp", json!(1_000));
    for authorization in [
        bearer("not-a-jwt"),
        bearer(&sign("rsa-a", &expired)),
        "Basic YWxpY2U6c2VjcmV0".to_owned(),
        "Bearer".to_owned(),
        bearer(""),
    ] {
        let (status, challenge, body) = get_me(&pool, Some(&authorization)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{authorization}");
        assert_eq!(
            challenge.as_deref(),
            Some(r#"Bearer error="invalid_token""#),
            "{authorization}"
        );
        assert_eq!(body["code"], "unauthorized");
        assert_eq!(body.as_object().unwrap().get("detail"), None);
    }
    assert_eq!(user_count(&pool).await, 0);
}

#[sqlx::test]
async fn invalid_credentials_are_refused_on_public_routes_too(pool: PgPool) {
    let (status, challenge, _) = call(
        common::app_with_pool(pool),
        Method::GET,
        "/health",
        Some(&bearer("not-a-jwt")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge.as_deref(),
        Some(r#"Bearer error="invalid_token""#)
    );
}

#[sqlx::test]
async fn two_authorization_headers_are_refused(pool: PgPool) {
    let token = bearer(&access_token("alice", &["kanbot-user"]));
    let request = Request::get("/me")
        .header(header::AUTHORIZATION, &token)
        .header(header::AUTHORIZATION, &token)
        .body(Body::empty())
        .unwrap();
    let response = common::app_with_pool(pool).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

fn with(mut claims: Value, field: &str, value: Value) -> Value {
    claims[field] = value;
    claims
}

#[sqlx::test]
async fn me_returns_the_user(pool: PgPool) {
    let (status, _, body) = get_me(
        &pool,
        Some(&bearer(&access_token("alice", &["kanbot-user"]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["display_name"], "alice (display)");
    assert_eq!(body["platform_role"], "user");
    assert_eq!(body["telemetry_opt_in"], false);
    let id = body["id"].as_str().unwrap().to_owned();

    let (_, _, again) = get_me(
        &pool,
        Some(&bearer(&access_token("alice", &["kanbot-user"]))),
    )
    .await;
    assert_eq!(again["id"], id.as_str());
    assert_eq!(user_count(&pool).await, 1);
}

#[sqlx::test]
async fn me_reports_admins(pool: PgPool) {
    let (status, _, body) = get_me(
        &pool,
        Some(&bearer(&access_token("root", &["kanbot-admin"]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["platform_role"], "admin");
}

#[sqlx::test]
async fn me_updates_the_display_name(pool: PgPool) {
    get_me(
        &pool,
        Some(&bearer(&access_token("alice", &["kanbot-user"]))),
    )
    .await;
    let renamed = with(claims("alice", &["kanbot-user"]), "name", json!("Alice L."));

    let (_, _, body) = get_me(&pool, Some(&bearer(&sign("rsa-a", &renamed)))).await;

    assert_eq!(body["display_name"], "Alice L.");
    let stored = sqlx::query_scalar!("SELECT display_name FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored.as_deref(), Some("Alice L."));
}

#[sqlx::test]
async fn a_token_without_a_kanbot_role_is_forbidden(pool: PgPool) {
    let (status, challenge, body) =
        get_me(&pool, Some(&bearer(&access_token("carol", &["staff"])))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(challenge, None);
    assert_eq!(body["code"], "forbidden");
    assert_eq!(user_count(&pool).await, 0);
}

#[sqlx::test]
async fn a_disabled_user_is_forbidden(pool: PgPool) {
    let token = bearer(&access_token("alice", &["kanbot-user"]));
    get_me(&pool, Some(&token)).await;
    sqlx::query!("UPDATE users SET disabled_at = now()")
        .execute(&pool)
        .await
        .unwrap();

    let (status, _, body) = get_me(&pool, Some(&token)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "account_disabled");
}

#[sqlx::test]
async fn tokens_are_unavailable_until_keys_load(pool: PgPool) {
    let app = common::app_with_keys(
        pool.clone(),
        &kanbot_backend::db::MIGRATOR,
        common::idp::unloaded_key_cache(),
    );
    let (status, challenge, body) = call(
        app,
        Method::GET,
        "/me",
        Some(&bearer(&access_token("alice", &["kanbot-user"]))),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(challenge, None);
    assert_eq!(body["code"], "unavailable");
}

async fn put_preferences(pool: &PgPool, token: &str, body: Value) -> (StatusCode, Value) {
    let (status, _, body) = call(
        common::app_with_pool(pool.clone()),
        Method::PUT,
        "/me/preferences",
        Some(&bearer(token)),
        Some(body),
    )
    .await;
    (status, body)
}

#[sqlx::test]
async fn preferences_set_telemetry_consent(pool: PgPool) {
    let token = access_token("alice", &["kanbot-user"]);

    let (status, body) = put_preferences(&pool, &token, json!({ "telemetry_opt_in": true })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["telemetry_opt_in"], true);
    assert_eq!(body["platform_role"], "user");
    let (_, _, me) = get_me(&pool, Some(&bearer(&token))).await;
    assert_eq!(me["telemetry_opt_in"], true);

    let (_, body) = put_preferences(&pool, &token, json!({ "telemetry_opt_in": false })).await;
    assert_eq!(body["telemetry_opt_in"], false);
    let (_, _, me) = get_me(&pool, Some(&bearer(&token))).await;
    assert_eq!(me["telemetry_opt_in"], false);
}

#[sqlx::test]
async fn preferences_reject_unknown_or_missing_fields(pool: PgPool) {
    let token = access_token("alice", &["kanbot-user"]);
    for body in [
        json!({ "telemetry_opt_in": true, "admin": true }),
        json!({}),
        json!({ "telemetry_opt_in": "yes" }),
    ] {
        let (status, problem) = put_preferences(&pool, &token, body.clone()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(problem["code"], "validation_failed", "{body}");
    }
    let (_, _, me) = get_me(&pool, Some(&bearer(&token))).await;
    assert_eq!(me["telemetry_opt_in"], false);
}

#[sqlx::test]
async fn preferences_need_credentials(pool: PgPool) {
    let (status, challenge, _) = call(
        common::app_with_pool(pool),
        Method::PUT,
        "/me/preferences",
        None,
        Some(json!({ "telemetry_opt_in": true })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(challenge.as_deref(), Some("Bearer"));
}

mod search_and_permissions {
    use axum::http::StatusCode;
    use serde_json::{Value, json};
    use sqlx::PgPool;

    use super::common::api::{Api, admin, user};

    fn names(list: &Value) -> Vec<&str> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|user| user["display_name"].as_str().unwrap())
            .collect()
    }

    #[sqlx::test]
    async fn me_lists_the_platform_permissions(pool: PgPool) {
        let api = Api::new(pool);
        let root = admin("root");
        assert_eq!(
            api.get("/me", &root).await.1["permissions"],
            json!([
                "create_organization",
                "create_team",
                "search_users",
                "view_audit"
            ])
        );
        let carol = user("carol", &[]);
        assert_eq!(api.get("/me", &carol).await.1["permissions"], json!([]));
        let carol_id = api.user_id(&carol).await;
        api.put(
            &format!("/organizations/00000000-0000-0000-0000-000000000001/admins/{carol_id}"),
            &root,
            None,
        )
        .await;
        assert_eq!(
            api.get("/me", &carol).await.1["permissions"],
            json!(["create_team", "search_users"])
        );
        let (status, me) = api
            .call(
                axum::http::Method::PUT,
                "/me/preferences",
                &carol,
                Some(json!({ "telemetry_opt_in": true })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me["permissions"], json!(["create_team", "search_users"]));
        assert_eq!(me["telemetry_opt_in"], true);
    }

    #[sqlx::test]
    async fn user_search_finds_users_by_name(pool: PgPool) {
        let api = Api::new(pool.clone());
        let root = admin("root");
        for subject in ["alice", "alina", "bob", "100%_sure"] {
            api.user_id(&user(subject, &[])).await;
        }
        let (status, found) = api.get("/users?query=ALI", &root).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(names(&found), ["alice (display)", "alina (display)"]);
        assert_eq!(
            found[0].as_object().unwrap().len(),
            2,
            "id and display_name only"
        );

        // LIKE wildcards match only themselves.
        assert_eq!(
            names(&api.get("/users?query=%25_", &root).await.1),
            ["100%_sure (display)"]
        );
        assert_eq!(
            names(&api.get("/users?query=a_i", &root).await.1),
            Vec::<&str>::new()
        );

        // Everyone, by name, without a query.
        assert_eq!(
            api.get("/users", &root).await.1.as_array().unwrap().len(),
            5
        );

        // Disabled users are left out.
        sqlx::query!("UPDATE users SET disabled_at = now() WHERE subject = 'alina'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            names(&api.get("/users?query=ali", &root).await.1),
            ["alice (display)"]
        );

        let (status, body) = api
            .get(&format!("/users?query={}", "x".repeat(101)), &root)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["errors"],
            json!([{ "pointer": "/query", "code": "too_long" }])
        );
        assert_eq!(
            api.get(&format!("/users?query={}", "x".repeat(100)), &root)
                .await
                .0,
            StatusCode::OK
        );
    }

    #[sqlx::test]
    async fn user_search_returns_at_most_twenty(pool: PgPool) {
        let api = Api::new(pool);
        let root = admin("root");
        for index in 0..25 {
            api.user_id(&user(&format!("user{index:02}"), &[])).await;
        }
        let (_, found) = api.get("/users?query=user", &root).await;
        assert_eq!(found.as_array().unwrap().len(), 20);
        assert_eq!(found[0]["display_name"], "user00 (display)");
    }

    #[sqlx::test]
    async fn only_admins_and_maintainers_search_users(pool: PgPool) {
        let api = Api::new(pool);
        let root = admin("root");
        let bob = user("bob", &[]);
        let bob_id = api.user_id(&bob).await;
        assert_eq!(
            api.get("/users?query=a", &bob).await.0,
            StatusCode::FORBIDDEN
        );
        let team = api.team(&root, "platform").await;
        api.put(
            &format!("/teams/{team}/members/{bob_id}"),
            &root,
            Some(json!({ "role": "member" })),
        )
        .await;
        assert_eq!(
            api.get("/users?query=a", &bob).await.0,
            StatusCode::FORBIDDEN
        );
        api.put(
            &format!("/teams/{team}/members/{bob_id}"),
            &root,
            Some(json!({ "role": "maintainer" })),
        )
        .await;
        assert_eq!(api.get("/users?query=a", &bob).await.0, StatusCode::OK);
    }
}
