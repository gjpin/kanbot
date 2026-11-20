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
    let client = IdpClient::new(&config.extra_root_certificates).unwrap();
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
