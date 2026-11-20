//! Sessions and the login flow.

pub mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use common::idp::TestIdp;
use http_body_util::BodyExt;
use kanbot_backend::{db, sessions::secrets};
use reqwest::Url;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// A PKCE challenge of the right shape.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The app, with the test identity provider discovered.
async fn app(pool: PgPool, idp: &TestIdp) -> Router {
    common::app_with_keys(pool, &db::MIGRATOR, idp.loaded_key_cache(&[]).await)
}

async fn get(app: &Router, uri: &str) -> Response {
    app.clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn problem(response: Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn location(response: &Response) -> Url {
    Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap()
}

fn query(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, issuer, subject, platform_role) VALUES ($1, 'iss', $2, 'user')",
        id,
        id.to_string(),
    )
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_attempt(
    pool: &PgPool,
    platform: &str,
    binding: Option<&[u8]>,
    redirect: Option<&str>,
    challenge: Option<&str>,
) -> Result<(), sqlx::Error> {
    let state_hash = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO login_attempts
           (id, state_hash, nonce_hash, pkce_verifier, platform, browser_binding_hash,
            app_redirect_uri, app_code_challenge, expires_at)
         VALUES ($1, $2, 'n', 'v', $3, $4, $5, $6, now() + interval '10 minutes')",
        Uuid::new_v4(),
        state_hash.as_bytes().as_slice(),
        platform,
        binding,
        redirect,
        challenge,
    )
    .execute(pool)
    .await
    .map(|_| ())
}

#[sqlx::test]
async fn a_login_attempt_is_either_web_or_native(pool: PgPool) {
    insert_attempt(&pool, "web", Some(b"binding"), None, None)
        .await
        .unwrap();
    insert_attempt(&pool, "native", None, Some("app:/auth/done"), Some("c"))
        .await
        .unwrap();

    for (platform, binding, redirect, challenge) in [
        ("web", None, None, None),
        ("web", Some(&b"binding"[..]), Some("app:/auth/done"), None),
        ("native", None, Some("app:/auth/done"), None),
        ("native", None, None, Some("c")),
        (
            "native",
            Some(&b"binding"[..]),
            Some("app:/auth/done"),
            Some("c"),
        ),
        ("cli", None, None, None),
    ] {
        assert!(
            insert_attempt(&pool, platform, binding, redirect, challenge)
                .await
                .is_err(),
            "{platform} {binding:?} {redirect:?} {challenge:?}"
        );
    }
}

async fn insert_session(
    pool: &PgPool,
    user_id: Uuid,
    kind: &str,
    token_hash: Option<&[u8]>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO sessions
           (id, token_hash, user_id, kind, idp_access_token, access_expires_at,
            idle_expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, 'at', now(), now(), now())",
        id,
        token_hash,
        user_id,
        kind,
    )
    .execute(pool)
    .await
    .map(|_| id)
}

#[sqlx::test]
async fn only_native_sessions_may_wait_for_their_token(pool: PgPool) {
    let user_id = user(&pool).await;
    insert_session(&pool, user_id, "native", None)
        .await
        .unwrap();
    insert_session(&pool, user_id, "web", Some(b"hash-1"))
        .await
        .unwrap();
    assert!(insert_session(&pool, user_id, "web", None).await.is_err());
    assert!(
        insert_session(&pool, user_id, "native", Some(b"hash-1"))
            .await
            .is_err(),
        "token hashes are unique"
    );
    assert!(
        insert_session(&pool, user_id, "cli", Some(b"hash-2"))
            .await
            .is_err()
    );
}

#[sqlx::test]
async fn deleting_a_user_deletes_their_sessions_and_codes(pool: PgPool) {
    let user_id = user(&pool).await;
    let session = insert_session(&pool, user_id, "native", None)
        .await
        .unwrap();
    sqlx::query!(
        "INSERT INTO login_codes (code_hash, session_id, app_code_challenge, expires_at)
         VALUES ('code', $1, 'c', now())",
        session,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
        .execute(&pool)
        .await
        .unwrap();

    let left = sqlx::query_scalar!(
        r#"SELECT (SELECT count(*) FROM sessions) + (SELECT count(*) FROM login_codes) AS "n!""#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}

#[sqlx::test]
async fn web_login_redirects_to_the_idp_with_pkce_state_and_nonce(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;

    let response = get(&app, "/auth/login?platform=web").await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let url = location(&response);
    assert_eq!(
        format!("{}://{}{}", url.scheme(), url.authority(), url.path()),
        format!("{}/authorize", idp.issuer)
    );
    assert_eq!(query(&url, "response_type").as_deref(), Some("code"));
    assert_eq!(query(&url, "client_id").as_deref(), Some("kanbot"));
    assert_eq!(
        query(&url, "redirect_uri").as_deref(),
        Some("http://localhost:3000/auth/callback")
    );
    assert_eq!(
        query(&url, "scope").as_deref(),
        Some("openid profile email groups offline_access")
    );
    assert_eq!(
        query(&url, "code_challenge_method").as_deref(),
        Some("S256")
    );
    let state = query(&url, "state").unwrap();
    let nonce = query(&url, "nonce").unwrap();
    let challenge = query(&url, "code_challenge").unwrap();
    for value in [&state, &nonce, &challenge] {
        assert_eq!(value.len(), 43, "{value}");
    }
    assert_ne!(state, nonce);

    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    let (binding, attributes) = cookie
        .strip_prefix("__Host-kanbot_login=")
        .unwrap()
        .split_once(';')
        .unwrap();
    assert_eq!(binding.len(), 43);
    for attribute in [
        "Path=/",
        "Max-Age=600",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
    ] {
        assert!(attributes.contains(attribute), "{cookie}");
    }
    assert!(!attributes.contains("Domain"), "{cookie}");

    // Only hashes are stored; the verifier is encrypted.
    let row = sqlx::query!(
        r#"SELECT state_hash, nonce_hash, pkce_verifier, platform, browser_binding_hash,
                  app_redirect_uri, used_at IS NULL AS "unused!",
                  expires_at > now() + interval '9 minutes' AND expires_at <= now() + interval '10 minutes' AS "ten_minutes!"
           FROM login_attempts"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.state_hash, secrets::hash(&state));
    assert_eq!(row.nonce_hash, secrets::hash(&nonce));
    assert_eq!(row.browser_binding_hash.unwrap(), secrets::hash(binding));
    assert_eq!(row.platform, "web");
    assert_eq!(row.app_redirect_uri, None);
    assert!(row.unused && row.ten_minutes);
    assert!(
        !row.pkce_verifier
            .windows(43)
            .any(|w| w == challenge.as_bytes())
    );
}

#[sqlx::test]
async fn native_login_records_the_app_redirect_and_challenge(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;

    for redirect in [
        "dev.sideral.kanbot%3A%2Fauth%2Fdone",
        "http%3A%2F%2F127.0.0.1%3A43210%2Fauth%2Fdone",
    ] {
        let response = get(
            &app,
            &format!(
                "/auth/login?platform=native&redirect_uri={redirect}\
                 &code_challenge={CHALLENGE}&code_challenge_method=S256"
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{redirect}");
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        // The IdP still redirects only to the backend.
        assert_eq!(
            query(&location(&response), "redirect_uri").as_deref(),
            Some("http://localhost:3000/auth/callback")
        );
    }
    let rows = sqlx::query!(
        "SELECT platform, app_redirect_uri, app_code_challenge, browser_binding_hash
         FROM login_attempts ORDER BY created_at"
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].platform, "native");
    assert_eq!(rows[0].app_code_challenge.as_deref(), Some(CHALLENGE));
    assert_eq!(rows[0].browser_binding_hash, None);
    let redirects: Vec<_> = rows
        .iter()
        .map(|row| row.app_redirect_uri.clone().unwrap())
        .collect();
    assert!(redirects.contains(&"dev.sideral.kanbot:/auth/done".to_owned()));
    assert!(redirects.contains(&"http://127.0.0.1:43210/auth/done".to_owned()));
}

#[sqlx::test]
async fn login_refuses_parameters_that_do_not_fit(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let native = |redirect: &str, challenge: &str, method: &str| {
        format!(
            "/auth/login?platform=native&redirect_uri={redirect}\
             &code_challenge={challenge}&code_challenge_method={method}"
        )
    };
    for (uri, pointer, code) in [
        (
            native(
                "https%3A%2F%2Fevil.example%2Fauth%2Fdone",
                CHALLENGE,
                "S256",
            ),
            "/redirect_uri",
            "not_allowed",
        ),
        (
            native(
                "http%3A%2F%2Flocalhost%3A43210%2Fauth%2Fdone",
                CHALLENGE,
                "S256",
            ),
            "/redirect_uri",
            "not_allowed",
        ),
        (
            native("dev.sideral.kanbot%3A%2Fauth%2Fdone", "short", "S256"),
            "/code_challenge",
            "invalid",
        ),
        (
            native("dev.sideral.kanbot%3A%2Fauth%2Fdone", CHALLENGE, "plain"),
            "/code_challenge_method",
            "not_allowed",
        ),
        (
            "/auth/login?platform=native&code_challenge_method=S256".to_owned(),
            "/redirect_uri",
            "required",
        ),
        (
            "/auth/login?platform=web&redirect_uri=dev.sideral.kanbot%3A%2Fauth%2Fdone".to_owned(),
            "/redirect_uri",
            "not_allowed",
        ),
    ] {
        let response = get(&app, &uri).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{uri}");
        let body = problem(response).await;
        assert!(
            body["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|error| error["pointer"] == pointer && error["code"] == code),
            "{uri}: {body}"
        );
    }
    for uri in [
        "/auth/login",
        "/auth/login?platform=cli",
        "/auth/login?platform=web&next=https://evil.example",
    ] {
        assert_eq!(
            get(&app, uri).await.status(),
            StatusCode::BAD_REQUEST,
            "{uri}"
        );
    }
    let stored = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM login_attempts"#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
}

#[sqlx::test]
async fn login_is_unavailable_before_discovery(pool: PgPool) {
    let app = common::app_with_pool(pool);
    let response = get(&app, "/auth/login?platform=web").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem(response).await["code"], "unavailable");
}
