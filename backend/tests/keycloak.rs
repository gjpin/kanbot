//! End to end against the local Keycloak (`compose.yaml`,
//! `dev/keycloak/`), the second identity provider: real access tokens
//! validated through discovery and the JWKS, and the web sign-in through
//! kanbot with a real refresh.
//!
//! Needs `sh dev/auth-setup.sh`, `docker compose up -d` and
//! `127.0.0.1 auth.kanbot.internal` in `/etc/hosts`. Fails, never skips,
//! when Keycloak is not there.

pub mod common;

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{
    authelia::{CA_FILE, dev_password},
    keycloak::{self, ISSUER},
};
use http_body_util::BodyExt;
use kanbot_backend::{
    auth::{discovery::IdpClient, keys::KeyCache},
    db,
    http::HttpSettings,
    state::AppState,
};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// The app, validating Keycloak's tokens, with the login flow against it.
async fn app(pool: PgPool) -> Router {
    let config = common::idp::config(
        ISSUER,
        &[
            ("OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP", "false"),
            ("OIDC_CA_FILE", CA_FILE),
            ("OIDC_AUDIENCE", "kanbot-api"),
        ],
    );
    let client = IdpClient::new(&config.extra_root_certificates).unwrap();
    let keys = Arc::new(KeyCache::new(Arc::new(config), client));
    keys.refresh()
        .await
        .expect("the local Keycloak must be running (see backend/AGENTS.md)");
    common::serve(
        AppState {
            db: pool,
            migrator: &db::MIGRATOR,
            keys,
            // Keycloak refuses scopes it does not know: no `groups` scope;
            // the client's mapper puts the groups in the tokens.
            sessions: common::session_config_with_scopes("openid profile email offline_access"),
            authz: common::policies(),
            openshell: None,
        },
        HttpSettings::new(),
        None,
    )
}

async fn get(
    app: &Router,
    uri: &str,
    credentials: (header::HeaderName, String),
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::get(uri)
                .header(credentials.0, credentials.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn bearer(token: &str) -> (header::HeaderName, String) {
    (header::AUTHORIZATION, format!("Bearer {token}"))
}

#[sqlx::test]
async fn keycloak_access_tokens_sign_users_in(pool: PgPool) {
    let app = app(pool).await;
    let (status, alice) = get(&app, "/me", bearer(&keycloak::access_token("alice").await)).await;
    assert_eq!(status, StatusCode::OK, "{alice}");
    assert_eq!(alice["platform_role"], "admin");
    assert_eq!(alice["display_name"], "Alice Admin");

    let (status, bob) = get(&app, "/me", bearer(&keycloak::access_token("bob").await)).await;
    assert_eq!(status, StatusCode::OK, "{bob}");
    assert_eq!(bob["platform_role"], "user");

    let (status, carol) = get(&app, "/me", bearer(&keycloak::access_token("carol").await)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{carol}");
}

#[sqlx::test]
async fn keycloak_groups_sync_teams(pool: PgPool) {
    let team = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO teams (id, slug, name, idp_group) VALUES ($1, 'contractors', 'Contractors', 'contractors')",
        team
    )
    .execute(&pool)
    .await
    .unwrap();
    let app = app(pool.clone()).await;
    let (status, _) = get(&app, "/me", bearer(&keycloak::access_token("dave").await)).await;
    assert_eq!(status, StatusCode::OK);
    let members = sqlx::query_scalar!(
        "SELECT u.subject FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = $1",
        team
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(members.len(), 1, "dave joined through the groups claim");
}

#[sqlx::test]
async fn a_wrong_password_is_refused_by_keycloak(pool: PgPool) {
    let app = app(pool).await;
    let response = app
        .oneshot(
            Request::get("/auth/login?platform=web")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let authorize =
        reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let result = tokio::spawn(keycloak::authorize("alice", "wrong-password", authorize)).await;
    assert!(
        result.is_err(),
        "Keycloak must not redirect after a wrong password"
    );
}

#[sqlx::test]
async fn the_web_sign_in_works_with_keycloak_and_refreshes(pool: PgPool) {
    let app = app(pool.clone()).await;

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
            .starts_with(&format!("{ISSUER}/protocol/openid-connect/auth?"))
    );
    let login_cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let callback = keycloak::authorize("alice", &dev_password("alice"), authorize).await;
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
    let session = response
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

    let (status, body) = get(&app, "/me", (header::COOKIE, session.clone())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["platform_role"], "admin");

    // A real refresh with Keycloak's refresh token (offline_access).
    let has_refresh =
        sqlx::query_scalar!(r#"SELECT idp_refresh_token IS NOT NULL AS "has!" FROM sessions"#)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(has_refresh, "Keycloak issued a refresh token");
    sqlx::query!("UPDATE sessions SET access_expires_at = now() + interval '10 seconds'")
        .execute(&pool)
        .await
        .unwrap();
    let (status, body) = get(&app, "/me", (header::COOKIE, session)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let renewed = sqlx::query_scalar!(
        r#"SELECT access_expires_at > now() + interval '1 minute' AS "renewed!" FROM sessions"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(renewed, "a new access token was stored");
}
