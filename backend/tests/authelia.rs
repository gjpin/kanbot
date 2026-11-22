//! End to end against the local Authelia (`compose.yaml`): real access
//! tokens, validated through discovery and the real JWKS.
//!
//! Needs `sh dev/auth-setup.sh`, `docker compose up -d` and
//! `127.0.0.1 auth.kanbot.internal` in `/etc/hosts`. Fails, never skips,
//! when Authelia is not there.

pub mod common;

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use common::authelia::{self, CA_FILE, ISSUER, dev_password};
use http_body_util::BodyExt;
use kanbot_backend::{
    auth::{discovery::IdpClient, keys::KeyCache},
    db,
};
use serde_json::Value;

use sqlx::PgPool;
use tower::ServiceExt;

/// The app, validating tokens from the local Authelia for `audience`.
async fn app(pool: PgPool, audience: &str) -> Router {
    let config = common::idp::config(
        ISSUER,
        &[
            ("OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP", "false"),
            ("OIDC_CA_FILE", CA_FILE),
            ("OIDC_AUDIENCE", audience),
        ],
    );
    let client = IdpClient::new(&config).unwrap();
    let keys = Arc::new(KeyCache::new(Arc::new(config), client));
    keys.refresh()
        .await
        .expect("the local Authelia must be running (see backend/AGENTS.md)");
    common::app_with_keys(pool, &db::MIGRATOR, keys)
}

async fn token(username: &str) -> String {
    authelia::access_token(username, &dev_password(username))
        .await
        .expect("login at the local Authelia")
}

async fn me(app: Router, token: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::get("/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[sqlx::test]
async fn an_admin_signs_in(pool: PgPool) {
    let (status, body) = me(app(pool, "kanbot-api").await, &token("alice").await).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["platform_role"], "admin");
    assert_eq!(body["display_name"], "Alice (admin)");
}

#[sqlx::test]
async fn a_user_signs_in(pool: PgPool) {
    let app = app(pool, "kanbot-api").await;
    for username in ["bob", "dave"] {
        let (status, body) = me(app.clone(), &token(username).await).await;
        assert_eq!(status, StatusCode::OK, "{username}: {body}");
        assert_eq!(body["platform_role"], "user", "{username}");
    }
}

#[sqlx::test]
async fn a_user_without_a_kanbot_role_is_forbidden(pool: PgPool) {
    let (status, body) = me(app(pool, "kanbot-api").await, &token("carol").await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "forbidden");
}

#[sqlx::test]
async fn a_token_for_another_audience_is_refused(pool: PgPool) {
    let (status, body) = me(app(pool, "other-api").await, &token("alice").await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "unauthorized");
}

#[tokio::test]
async fn a_wrong_password_gets_no_token() {
    let result = authelia::access_token("alice", "wrong-password").await;
    let error = result.unwrap_err().to_string();
    // Authelia itself refused: not an unreachable server.
    assert_eq!(error, "first factor: 401 Unauthorized");
}

/// The app with the login flow against the local Authelia.
async fn signing_app(pool: PgPool) -> Router {
    app(pool, "kanbot-api").await
}

#[sqlx::test]
async fn the_web_sign_in_works_end_to_end_and_refreshes(pool: PgPool) {
    let app = signing_app(pool.clone()).await;

    // The web app navigates to /auth/login.
    let response = app
        .clone()
        .oneshot(
            Request::get("/auth/login?platform=web")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let authorize =
        reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert!(
        authorize
            .as_str()
            .starts_with(&format!("{ISSUER}/api/oidc/authorization?"))
    );
    let login_cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    // The user signs in at Authelia, which sends the browser back.
    let callback = authelia::authorize("alice", &dev_password("alice"), authorize)
        .await
        .unwrap();
    assert_eq!(
        callback.as_str().split('?').next(),
        Some("http://localhost:3000/auth/callback")
    );
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/auth/callback?{}", callback.query().unwrap()))
                .header(header::COOKIE, &login_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost:3000/"
    );
    let session_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .find(|cookie| cookie.starts_with("__Host-kanbot_session="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let me = |app: Router, cookie: String| async move {
        let response = app
            .oneshot(
                Request::get("/me")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice::<Value>(&body).unwrap())
    };
    let (status, body) = me(app.clone(), session_cookie.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["platform_role"], "admin");

    // A real refresh with Authelia's refresh token (offline_access).
    let before = sqlx::query_scalar!("SELECT idp_refresh_token FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(before.is_some(), "Authelia issued a refresh token");
    sqlx::query!("UPDATE sessions SET access_expires_at = now() + interval '10 seconds'")
        .execute(&pool)
        .await
        .unwrap();
    let (status, body) = me(app.clone(), session_cookie).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = sqlx::query!(
        r#"SELECT idp_refresh_token, access_expires_at > now() + interval '1 minute' AS "renewed!"
           FROM sessions"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(after.renewed, "a new access token was stored");
    assert_ne!(
        after.idp_refresh_token, before,
        "Authelia rotates refresh tokens"
    );
}
