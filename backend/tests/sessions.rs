//! Sessions and the login flow.

pub mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use common::idp::{Reply, TestIdp, issued_claims, now, sign};
use http_body_util::BodyExt;
use kanbot_backend::{
    db,
    sessions::{
        crypto::{self, Field},
        secrets,
    },
};
use reqwest::Url;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::time::Duration;
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

/// A started sign-in: the parameters sent to the identity provider, and the web login
/// cookie.
struct Started {
    state: String,
    nonce: String,
    challenge: String,
    binding: Option<String>,
}

async fn start(app: &Router, uri: &str) -> Started {
    let response = get(app, uri).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let url = location(&response);
    let binding = response.headers().get(header::SET_COOKIE).map(|cookie| {
        cookie
            .to_str()
            .unwrap()
            .strip_prefix("__Host-kanbot_login=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    });
    Started {
        state: query(&url, "state").unwrap(),
        nonce: query(&url, "nonce").unwrap(),
        challenge: query(&url, "code_challenge").unwrap(),
        binding,
    }
}

const NATIVE_LOGIN: &str = "/auth/login?platform=native&redirect_uri=dev.sideral.kanbot%3A%2Fauth%2Fdone\
                            &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                            &code_challenge_method=S256";

/// ID-token claims for the `kanbot` client.
fn id_claims(idp: &TestIdp, subject: &str, nonce: &str) -> Value {
    json!({
        "iss": idp.issuer,
        "aud": "kanbot",
        "azp": "kanbot",
        "sub": subject,
        "exp": now().checked_add(300).unwrap(),
        "iat": now(),
        "nonce": nonce,
    })
}

/// Makes the identity provider answer the next code exchange with these tokens.
fn answer(idp: &TestIdp, access: &Value, id: &Value) {
    idp.set_token(Reply::Json(json!({
        "access_token": sign("rsa-a", access),
        "id_token": sign("p256", id),
        "refresh_token": "refresh-from-idp",
        "token_type": "Bearer",
        "expires_in": 300,
    })));
}

async fn callback(app: &Router, state: &str, extra: &str, binding: Option<&str>) -> Response {
    let mut request = Request::get(format!("/auth/callback?state={state}&code=code-1{extra}"));
    if let Some(binding) = binding {
        request = request.header(header::COOKIE, format!("__Host-kanbot_login={binding}"));
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

async fn session_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM sessions"#)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn web_sign_in_sets_a_session_cookie(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let started = start(&app, "/auth/login?platform=web").await;
    let access = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    answer(&idp, &access, &id_claims(&idp, "alice", &started.nonce));

    // Extra parameters are ignored; `iss` (RFC 9207) must be the issuer.
    let iss = idp.issuer.replace(':', "%3A").replace('/', "%2F");
    let response = callback(
        &app,
        &started.state,
        &format!("&iss={iss}&scope=openid"),
        started.binding.as_deref(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost:3000/"
    );
    let cookies = set_cookies(&response);
    let session = cookies
        .iter()
        .find(|cookie| cookie.starts_with("__Host-kanbot_session="))
        .unwrap();
    let token = session
        .strip_prefix("__Host-kanbot_session=")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    assert!(token.starts_with("kbs_") && token.len() == 47, "{token}");
    for attribute in [
        "Path=/",
        "Max-Age=2592000",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
    ] {
        assert!(session.contains(attribute), "{session}");
    }
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-kanbot_login=;")
                && cookie.contains("Max-Age=0")),
        "{cookies:?}"
    );

    // The code exchange: client_secret_basic, the callback URL, the verifier.
    let requests = idp.token_requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request.authorization.as_deref(),
        Some("Basic a2FuYm90OmthbmJvdC1kZXYtY2xpZW50LXNlY3JldA==")
    );
    assert_eq!(request.form["grant_type"], "authorization_code");
    assert_eq!(request.form["code"], "code-1");
    assert_eq!(
        request.form["redirect_uri"],
        "http://localhost:3000/auth/callback"
    );
    let verifier = secrecy::SecretString::from(request.form["code_verifier"].clone());
    assert_eq!(secrets::pkce_challenge(&verifier), started.challenge);

    // The session: the token's hash, the user, sealed IdP tokens.
    let row = sqlx::query!(
        r#"SELECT s.id, s.token_hash, s.kind, s.idp_access_token, s.idp_refresh_token,
                  s.idp_id_token, u.subject,
                  s.access_expires_at = to_timestamp($1::bigint) AS "expiry_matches!",
                  s.absolute_expires_at > now() + interval '29 days' AS "absolute_set!",
                  s.idle_expires_at > now() + interval '6 days'
                    AND s.idle_expires_at < now() + interval '8 days' AS "idle_set!"
           FROM sessions s JOIN users u ON u.id = s.user_id"#,
        i64::try_from(access["exp"].as_u64().unwrap()).unwrap(),
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.token_hash.unwrap(), secrets::hash(token));
    assert_eq!(row.kind, "web");
    assert_eq!(row.subject, "alice");
    assert!(row.expiry_matches && row.absolute_set && row.idle_set);
    let keys = &common::session_config().keys;
    let opened = |field, sealed: &[u8]| crypto::open(keys, row.id, field, sealed).unwrap();
    assert_eq!(
        opened(Field::AccessToken, &row.idp_access_token).expose_secret(),
        sign("rsa-a", &access)
    );
    assert_eq!(
        opened(Field::RefreshToken, &row.idp_refresh_token.unwrap()).expose_secret(),
        "refresh-from-idp"
    );
    assert!(
        opened(Field::IdToken, &row.idp_id_token.unwrap())
            .expose_secret()
            .starts_with("ey")
    );
}

fn error_location(response: &Response) -> String {
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

#[sqlx::test]
async fn a_state_works_once_and_only_with_its_login_cookie(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let started = start(&app, "/auth/login?platform=web").await;
    answer(
        &idp,
        &issued_claims(&idp.issuer, "alice", &["kanbot-user"]),
        &id_claims(&idp, "alice", &started.nonce),
    );
    let failed = "http://localhost:3000/login?error=login_failed";

    // Another browser (no cookie, or another cookie) cannot finish it.
    let response = callback(&app, &started.state, "", None).await;
    assert_eq!(error_location(&response), failed);
    let other = secrets::issue("").unwrap();
    let response = callback(&app, &started.state, "", Some(other.value.expose_secret())).await;
    assert_eq!(error_location(&response), failed);
    assert_eq!(idp.token_requests().len(), 0);

    // Its own browser can, once.
    let response = callback(&app, &started.state, "", started.binding.as_deref()).await;
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost:3000/"
    );
    let response = callback(&app, &started.state, "", started.binding.as_deref()).await;
    assert_eq!(error_location(&response), failed);
    assert_eq!(session_count(&pool).await, 1);

    // An unknown state, or none at all.
    let response = callback(&app, "unknown", "", started.binding.as_deref()).await;
    assert_eq!(error_location(&response), failed);
    let response = get(&app, "/auth/callback?code=x").await;
    assert_eq!(error_location(&response), failed);
}

#[sqlx::test]
async fn an_expired_attempt_cannot_finish(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let started = start(&app, "/auth/login?platform=web").await;
    sqlx::query!("UPDATE login_attempts SET expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    let response = callback(&app, &started.state, "", started.binding.as_deref()).await;
    assert_eq!(
        error_location(&response),
        "http://localhost:3000/login?error=login_failed"
    );
}

#[sqlx::test]
async fn the_id_token_must_be_for_kanbot_and_this_nonce(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let access = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    let changes: [(&str, Value); 6] = [
        ("nonce", json!("another-nonce")),
        ("nonce", Value::Null),
        ("aud", json!("kanbot-api")),
        ("aud", json!(["kanbot", "other"])),
        ("azp", json!("other")),
        ("iss", json!("https://other.example")),
    ];
    for (claim, value) in changes {
        let started = start(&app, "/auth/login?platform=web").await;
        let mut id = id_claims(&idp, "alice", &started.nonce);
        if claim == "aud" && value.is_array() {
            id.as_object_mut().unwrap().remove("azp");
        }
        if value.is_null() {
            id.as_object_mut().unwrap().remove(claim);
        } else {
            id[claim] = value.clone();
        }
        answer(&idp, &access, &id);
        let response = callback(&app, &started.state, "", started.binding.as_deref()).await;
        assert_eq!(
            error_location(&response),
            "http://localhost:3000/login?error=login_failed",
            "{claim}={value}"
        );
    }
    // Several audiences are fine with azp = kanbot.
    let started = start(&app, "/auth/login?platform=web").await;
    let mut id = id_claims(&idp, "alice", &started.nonce);
    id["aud"] = json!(["kanbot", "other"]);
    answer(&idp, &access, &id);
    let response = callback(&app, &started.state, "", started.binding.as_deref()).await;
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost:3000/"
    );
    assert_eq!(session_count(&pool).await, 1);
}

#[sqlx::test]
async fn refusals_have_a_stable_error_and_create_nothing(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let web = |error: &str| format!("http://localhost:3000/login?error={error}");

    // No kanbot role.
    let started = start(&app, "/auth/login?platform=web").await;
    answer(
        &idp,
        &issued_claims(&idp.issuer, "carol", &["staff"]),
        &id_claims(&idp, "carol", &started.nonce),
    );
    let response = callback(&app, &started.state, "", started.binding.as_deref()).await;
    assert_eq!(error_location(&response), web("no_role"));

    // An access token for another audience.
    let started = start(&app, "/auth/login?platform=web").await;
    let mut access = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    access["aud"] = json!("other-api");
    answer(&idp, &access, &id_claims(&idp, "alice", &started.nonce));
    let response = callback(&app, &started.state, "", started.binding.as_deref()).await;
    assert_eq!(error_location(&response), web("login_failed"));

    // The user declined at the IdP.
    let started = start(&app, "/auth/login?platform=web").await;
    let response = get(
        &app,
        &format!("/auth/callback?state={}&error=access_denied", started.state),
    )
    .await;
    // (no cookie: the state is not even consumed)
    assert_eq!(error_location(&response), web("login_failed"));
    let mut request = Request::get(format!(
        "/auth/callback?state={}&error=access_denied&error_description=secret+detail",
        started.state
    ));
    request = request.header(
        header::COOKIE,
        format!("__Host-kanbot_login={}", started.binding.unwrap()),
    );
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(error_location(&response), web("access_denied"));

    // The IdP refuses the code.
    let started = start(&app, "/auth/login?platform=web").await;
    idp.set_token(Reply::Status(StatusCode::BAD_REQUEST));
    let response = callback(&app, &started.state, "", started.binding.as_deref()).await;
    assert_eq!(error_location(&response), web("login_failed"));

    assert_eq!(session_count(&pool).await, 0);
}

#[sqlx::test]
async fn a_disabled_user_is_denied(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let sign_in = || async {
        let started = start(&app, "/auth/login?platform=web").await;
        answer(
            &idp,
            &issued_claims(&idp.issuer, "alice", &["kanbot-user"]),
            &id_claims(&idp, "alice", &started.nonce),
        );
        callback(&app, &started.state, "", started.binding.as_deref()).await
    };
    sign_in().await;
    sqlx::query!("UPDATE users SET disabled_at = now()")
        .execute(&pool)
        .await
        .unwrap();
    let response = sign_in().await;
    assert_eq!(
        error_location(&response),
        "http://localhost:3000/login?error=access_denied"
    );
    assert_eq!(session_count(&pool).await, 1);
}

#[sqlx::test]
async fn native_sign_in_hands_a_one_time_code_to_the_app(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let started = start(&app, NATIVE_LOGIN).await;
    answer(
        &idp,
        &issued_claims(&idp.issuer, "bob", &["kanbot-user"]),
        &id_claims(&idp, "bob", &started.nonce),
    );

    let response = callback(&app, &started.state, "", None).await;

    let location = error_location(&response);
    let code = location
        .strip_prefix("dev.sideral.kanbot:/auth/done?code=")
        .unwrap();
    assert!(code.starts_with("kbc_") && code.len() == 47, "{location}");
    assert!(
        !set_cookies(&response)
            .iter()
            .any(|cookie| cookie.starts_with("__Host-kanbot_session")),
    );
    let row = sqlx::query!(
        r#"SELECT s.kind, s.token_hash, c.code_hash, c.app_code_challenge, c.used_at IS NULL AS "unused!",
                  c.expires_at <= now() + interval '60 seconds'
                    AND c.expires_at > now() + interval '50 seconds' AS "one_minute!"
           FROM sessions s JOIN login_codes c ON c.session_id = s.id"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.kind, "native");
    assert_eq!(
        row.token_hash, None,
        "no session token before the code is redeemed"
    );
    assert_eq!(row.code_hash, secrets::hash(code));
    assert_eq!(row.app_code_challenge, CHALLENGE);
    assert!(row.unused && row.one_minute);
}

#[sqlx::test]
async fn native_refusals_go_back_to_the_app(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let started = start(&app, NATIVE_LOGIN).await;
    answer(
        &idp,
        &issued_claims(&idp.issuer, "carol", &["staff"]),
        &id_claims(&idp, "carol", &started.nonce),
    );
    let response = callback(&app, &started.state, "", None).await;
    assert_eq!(
        error_location(&response),
        "dev.sideral.kanbot:/auth/done?error=no_role"
    );
}

/// The verifier whose S256 challenge is [`CHALLENGE`] (RFC 7636, appendix B).
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Signs in natively and returns the one-time code.
async fn native_code(app: &Router, idp: &TestIdp, subject: &str) -> String {
    let started = start(app, NATIVE_LOGIN).await;
    answer(
        idp,
        &issued_claims(&idp.issuer, subject, &["kanbot-user"]),
        &id_claims(idp, subject, &started.nonce),
    );
    let response = callback(app, &started.state, "", None).await;
    error_location(&response)
        .strip_prefix("dev.sideral.kanbot:/auth/done?code=")
        .unwrap()
        .to_owned()
}

async fn redeem(app: &Router, body: &Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, problem(response).await)
}

#[sqlx::test]
async fn a_native_app_redeems_its_code_once(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let code = native_code(&app, &idp, "bob").await;

    let (status, body) = redeem(&app, &json!({ "code": code, "code_verifier": VERIFIER })).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["session_token"].as_str().unwrap();
    assert!(token.starts_with("kbs_") && token.len() == 47);
    let expires_at = body["expires_at"].as_str().unwrap();
    assert!(
        expires_at.ends_with('Z') && expires_at.len() == 20,
        "{expires_at}"
    );
    let row = sqlx::query!(
        r#"SELECT token_hash,
                  to_char(absolute_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "expires!"
           FROM sessions"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.token_hash.unwrap(), secrets::hash(token));
    assert_eq!(row.expires, expires_at);

    // Single use.
    let (status, body) = redeem(&app, &json!({ "code": code, "code_verifier": VERIFIER })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "bad_request");
}

#[sqlx::test]
async fn a_wrong_verifier_burns_the_code(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let code = native_code(&app, &idp, "bob").await;
    let wrong = "x".repeat(43);

    let (status, _) = redeem(&app, &json!({ "code": code, "code_verifier": wrong })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = redeem(&app, &json!({ "code": code, "code_verifier": VERIFIER })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The session can never be handed over now: it is gone.
    assert_eq!(session_count(&pool).await, 0);
}

#[sqlx::test]
async fn an_expired_code_cannot_be_redeemed(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let code = native_code(&app, &idp, "bob").await;
    sqlx::query!("UPDATE login_codes SET expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    let (status, _) = redeem(&app, &json!({ "code": code, "code_verifier": VERIFIER })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn redeeming_needs_a_well_formed_request(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let code = native_code(&app, &idp, "bob").await;
    for (body, status) in [
        (
            json!({ "code": code, "code_verifier": "short" }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({ "code": code, "code_verifier": format!("{VERIFIER}!") }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({ "code": code, "code_verifier": "a".repeat(129) }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (json!({ "code": code }), StatusCode::UNPROCESSABLE_ENTITY),
        (
            json!({ "code": code, "code_verifier": VERIFIER, "extra": 1 }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({ "code": "kbs_not-a-code", "code_verifier": VERIFIER }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "code": "", "code_verifier": VERIFIER }),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(redeem(&app, &body).await.0, status, "{body}");
    }
    // None of these spent the code.
    let (status, _) = redeem(&app, &json!({ "code": code, "code_verifier": VERIFIER })).await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test]
async fn config_tells_apps_where_to_sign_in(pool: PgPool) {
    let response = get(&common::app_with_pool(pool.clone()), "/auth/config").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = problem(response).await;
    assert_eq!(body["login_url"], "http://localhost:3000/auth/login");
    assert_eq!(body["telemetry_available"], false);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));

    let relay = kanbot_backend::telemetry_relay::routes(
        "http://127.0.0.1:1".parse().unwrap(),
        kanbot_backend::http::middleware::rate_limit::RateLimits::DEFAULT.telemetry,
    )
    .unwrap();
    let with_relay = common::serve(
        kanbot_backend::state::AppState {
            db: pool,
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
            sessions: common::session_config(),
            authz: common::policies(),
            openshell: None,
        },
        kanbot_backend::http::HttpSettings::new(),
        Some(relay),
    );
    let body = problem(get(&with_relay, "/auth/config").await).await;
    assert_eq!(body["telemetry_available"], true);
}

/// Signs in on the web; returns the session token.
async fn web_session(app: &Router, idp: &TestIdp, subject: &str) -> String {
    let started = start(app, "/auth/login?platform=web").await;
    answer(
        idp,
        &issued_claims(&idp.issuer, subject, &["kanbot-user"]),
        &id_claims(idp, subject, &started.nonce),
    );
    let response = callback(app, &started.state, "", started.binding.as_deref()).await;
    set_cookies(&response)
        .iter()
        .find_map(|cookie| cookie.strip_prefix("__Host-kanbot_session="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn me_with(app: &Router, header_name: header::HeaderName, value: &str) -> Response {
    app.clone()
        .oneshot(
            Request::get("/me")
                .header(header_name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn me_by_cookie(app: &Router, token: &str) -> Response {
    me_with(
        app,
        header::COOKIE,
        &format!("__Host-kanbot_session={token}"),
    )
    .await
}

async fn me_by_bearer(app: &Router, token: &str) -> Response {
    me_with(app, header::AUTHORIZATION, &format!("Bearer {token}")).await
}

#[sqlx::test]
async fn sessions_authenticate_by_cookie_and_by_bearer(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let web = web_session(&app, &idp, "alice").await;
    let code = native_code(&app, &idp, "bob").await;
    let (_, body) = redeem(&app, &json!({ "code": code, "code_verifier": VERIFIER })).await;
    let native = body["session_token"].as_str().unwrap().to_owned();

    let response = me_by_cookie(&app, &web).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(problem(response).await["display_name"], "alice (display)");
    let response = me_by_bearer(&app, &native).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(problem(response).await["display_name"], "bob (display)");
    // A web token also works as a bearer token (same session).
    assert_eq!(me_by_bearer(&app, &web).await.status(), StatusCode::OK);
}

#[sqlx::test]
async fn unknown_sessions_are_refused(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let unknown = secrets::issue(secrets::SESSION_TOKEN).unwrap();
    let unknown = unknown.value.expose_secret();

    // As a bearer token: 401, like any bad credential.
    let response = me_by_bearer(&app, unknown).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        r#"Bearer error="invalid_token""#
    );

    // As a cookie: the browser forgets it and continues anonymously.
    let response = me_by_cookie(&app, unknown).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert!(set_cookies(&response).iter().any(|cookie| {
        cookie.starts_with("__Host-kanbot_session=;") && cookie.contains("Max-Age=0")
    }));
    let response = app
        .clone()
        .oneshot(
            Request::get("/auth/login?platform=web")
                .header(header::COOKIE, format!("__Host-kanbot_session={unknown}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "can sign in again"
    );
}

#[sqlx::test]
async fn sessions_end_when_idle_or_too_old(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    for column in ["idle", "absolute"] {
        let token = web_session(&app, &idp, "alice").await;
        assert_eq!(me_by_bearer(&app, &token).await.status(), StatusCode::OK);
        let hash = secrets::hash(&token);
        if column == "idle" {
            sqlx::query!(
                "UPDATE sessions SET idle_expires_at = now() - interval '1 second' WHERE token_hash = $1",
                hash.as_slice()
            )
            .execute(&pool)
            .await
            .unwrap();
        } else {
            sqlx::query!(
                "UPDATE sessions SET absolute_expires_at = now() - interval '1 second' WHERE token_hash = $1",
                hash.as_slice()
            )
            .execute(&pool)
            .await
            .unwrap();
        }
        assert_eq!(
            me_by_bearer(&app, &token).await.status(),
            StatusCode::UNAUTHORIZED,
            "{column}"
        );
    }
}

#[sqlx::test]
async fn use_extends_the_idle_expiry_at_most_once_a_minute(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    let version = || async {
        sqlx::query_scalar!(r#"SELECT xmin::text AS "v!" FROM sessions"#)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let before = version().await;
    me_by_bearer(&app, &token).await;
    assert_eq!(version().await, before, "used within the minute: no write");

    sqlx::query!(
        "UPDATE sessions SET last_used_at = now() - interval '2 minutes',
                             idle_expires_at = now() + interval '1 hour'"
    )
    .execute(&pool)
    .await
    .unwrap();
    me_by_bearer(&app, &token).await;
    let extended = sqlx::query_scalar!(
        r#"SELECT idle_expires_at > now() + interval '6 days'
                  AND last_used_at > now() - interval '10 seconds' AS "ok!" FROM sessions"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(extended);

    // Never past the absolute expiry.
    sqlx::query!(
        "UPDATE sessions SET last_used_at = now() - interval '2 minutes',
                             absolute_expires_at = now() + interval '1 hour'"
    )
    .execute(&pool)
    .await
    .unwrap();
    me_by_bearer(&app, &token).await;
    let capped = sqlx::query_scalar!(
        r#"SELECT idle_expires_at = absolute_expires_at AS "ok!" FROM sessions"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(capped);
}

/// Makes the session's access token due for a refresh.
async fn expire_soon(pool: &PgPool) {
    sqlx::query!("UPDATE sessions SET access_expires_at = now() + interval '30 seconds'")
        .execute(pool)
        .await
        .unwrap();
}

/// Makes the identity provider answer refreshes with a new access token
/// for `subject` with `groups`, and `refresh_token` if any.
fn answer_refresh(
    idp: &TestIdp,
    subject: &str,
    groups: &[&str],
    refresh_token: Option<&str>,
) -> Value {
    let mut access = issued_claims(&idp.issuer, subject, groups);
    access["exp"] = json!(now().checked_add(900).unwrap());
    let mut body = json!({
        "access_token": sign("rsa-a", &access),
        "token_type": "Bearer",
        "expires_in": 900,
    });
    if let Some(refresh_token) = refresh_token {
        body["refresh_token"] = json!(refresh_token);
    }
    idp.set_token(Reply::Json(body));
    access
}

async fn stored_refresh_token(pool: &PgPool) -> String {
    let row = sqlx::query!("SELECT id, idp_refresh_token FROM sessions")
        .fetch_one(pool)
        .await
        .unwrap();
    crypto::open(
        &common::session_config().keys,
        row.id,
        Field::RefreshToken,
        &row.idp_refresh_token.unwrap(),
    )
    .unwrap()
    .expose_secret()
    .to_owned()
}

#[sqlx::test]
async fn an_expiring_access_token_is_refreshed_and_rotated(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    let access = answer_refresh(&idp, "alice", &["kanbot-admin"], Some("rotated-refresh"));

    let response = me_by_bearer(&app, &token).await;

    assert_eq!(response.status(), StatusCode::OK);
    // Roles come from the new token.
    assert_eq!(problem(response).await["platform_role"], "admin");
    let requests = idp.token_requests();
    assert_eq!(requests.len(), 2);
    let refresh = &requests[1];
    assert_eq!(refresh.form["grant_type"], "refresh_token");
    assert_eq!(refresh.form["refresh_token"], "refresh-from-idp");
    assert!(
        refresh
            .authorization
            .as_deref()
            .unwrap()
            .starts_with("Basic ")
    );
    assert_eq!(stored_refresh_token(&pool).await, "rotated-refresh");
    let expiry_matches = sqlx::query_scalar!(
        r#"SELECT access_expires_at = to_timestamp($1::bigint) AS "ok!" FROM sessions"#,
        i64::try_from(access["exp"].as_u64().unwrap()).unwrap()
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(expiry_matches);

    // Not due any more: no new refresh.
    assert_eq!(me_by_bearer(&app, &token).await.status(), StatusCode::OK);
    assert_eq!(idp.token_requests().len(), 2);
}

#[sqlx::test]
async fn a_refresh_without_rotation_keeps_the_refresh_token(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    answer_refresh(&idp, "alice", &["kanbot-user"], None);

    assert_eq!(me_by_bearer(&app, &token).await.status(), StatusCode::OK);
    assert_eq!(stored_refresh_token(&pool).await, "refresh-from-idp");
}

#[sqlx::test]
async fn concurrent_requests_refresh_once(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    answer_refresh(&idp, "alice", &["kanbot-user"], Some("rotated-refresh"));

    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let app = app.clone();
        let token = token.clone();
        requests.spawn(async move { me_by_bearer(&app, &token).await.status() });
    }
    for status in requests.join_all().await {
        assert_eq!(status, StatusCode::OK);
    }
    // The sign-in's code exchange, then one refresh.
    assert_eq!(idp.token_requests().len(), 2);
}

#[sqlx::test]
async fn a_refused_refresh_ends_the_session(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    idp.set_token(Reply::Error(
        StatusCode::BAD_REQUEST,
        json!({ "error": "invalid_grant", "error_description": "Token is not active" }),
    ));

    let response = me_by_bearer(&app, &token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // A bearer token that stopped working is a bad credential.
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        r#"Bearer error="invalid_token""#
    );
    assert_eq!(response.headers().get(header::SET_COOKIE), None);
    assert_eq!(session_count(&pool).await, 0);
}

#[sqlx::test]
async fn other_refusals_of_a_refresh_keep_the_session(pool: PgPool) {
    // A wrong client secret or a proxy's 400 is not the user's doing:
    // their session survives it.
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    for reply in [
        Reply::Error(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "invalid_client" }),
        ),
        Reply::Error(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_request" }),
        ),
        Reply::Status(StatusCode::BAD_REQUEST),
    ] {
        expire_soon(&pool).await;
        idp.set_token(reply);
        assert_eq!(me_by_bearer(&app, &token).await.status(), StatusCode::OK);
        assert_eq!(session_count(&pool).await, 1);
        // The lease was given back: the next request tries again.
        let leased = sqlx::query_scalar!(
            r#"SELECT refreshing_until IS NOT NULL AS "leased!" FROM sessions"#
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!leased);
    }
}

/// Replaces the stored access token with one that has expired.
async fn expire_now(pool: &PgPool, idp: &TestIdp) {
    let mut expired = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    expired["exp"] = json!(now().checked_sub(120).unwrap());
    let id = sqlx::query_scalar!("SELECT id FROM sessions")
        .fetch_one(pool)
        .await
        .unwrap();
    let sealed = crypto::seal(
        &common::session_config().keys,
        id,
        Field::AccessToken,
        &secrecy::SecretString::from(sign("rsa-a", &expired)),
    )
    .unwrap();
    sqlx::query!(
        "UPDATE sessions SET idp_access_token = $1, access_expires_at = now() - interval '2 minutes'",
        sealed
    )
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test]
async fn requests_with_an_expired_token_wait_for_the_one_refresh(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_now(&pool, &idp).await;
    let mut access = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    access["exp"] = json!(now().checked_add(900).unwrap());
    idp.set_token(Reply::Slow(
        Duration::from_millis(400),
        json!({ "access_token": sign("rsa-a", &access), "token_type": "Bearer" }),
    ));

    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..6 {
        let app = app.clone();
        let token = token.clone();
        requests.spawn(async move { me_by_bearer(&app, &token).await.status() });
    }
    // While the identity provider takes its time, the session row is not
    // locked: kanbot holds no transaction across the call.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query!("SELECT id FROM sessions FOR UPDATE NOWAIT")
        .fetch_one(&mut *tx)
        .await
        .expect("the session row is not locked during a refresh");
    tx.rollback().await.unwrap();

    for status in requests.join_all().await {
        assert_eq!(status, StatusCode::OK);
    }
    // The sign-in's code exchange, then one refresh for all of them.
    assert_eq!(idp.token_requests().len(), 2);
}

#[sqlx::test]
async fn a_refreshed_token_of_another_user_ends_the_session(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    answer_refresh(&idp, "mallory", &["kanbot-user"], None);

    assert_eq!(
        me_by_bearer(&app, &token).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(session_count(&pool).await, 0);
    let mallory =
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM users WHERE subject = 'mallory'"#)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(mallory, 0, "never recorded");
}

#[sqlx::test]
async fn a_refreshed_id_token_is_kept_only_if_it_verifies(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    let stored_id_token = || async {
        let row = sqlx::query!("SELECT id, idp_id_token FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        crypto::open(
            &common::session_config().keys,
            row.id,
            Field::IdToken,
            &row.idp_id_token.unwrap(),
        )
        .unwrap()
        .expose_secret()
        .to_owned()
    };
    let original = stored_id_token().await;

    expire_soon(&pool).await;
    let mut access = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    access["exp"] = json!(now().checked_add(900).unwrap());
    let mut forged = id_claims(&idp, "alice", "n");
    forged["aud"] = json!("someone-else");
    idp.set_token(Reply::Json(json!({
        "access_token": sign("rsa-a", &access),
        "id_token": sign("rsa-a", &forged),
    })));
    assert_eq!(me_by_bearer(&app, &token).await.status(), StatusCode::OK);
    assert_eq!(stored_id_token().await, original);

    expire_soon(&pool).await;
    let fresh = sign("rsa-a", &id_claims(&idp, "alice", "n"));
    idp.set_token(Reply::Json(json!({
        "access_token": sign("rsa-a", &access),
        "id_token": fresh,
    })));
    assert_eq!(me_by_bearer(&app, &token).await.status(), StatusCode::OK);
    assert_eq!(stored_id_token().await, fresh);
}

#[sqlx::test]
async fn sessions_wait_for_the_keys_instead_of_ending(pool: PgPool) {
    // A new instance has not loaded the identity provider's keys yet:
    // sessions get 503, and are neither ended nor forgotten.
    let idp = TestIdp::start().await;
    let ready = app(pool.clone(), &idp).await;
    let token = web_session(&ready, &idp, "alice").await;
    let starting = common::app_with_keys(pool.clone(), &db::MIGRATOR, idp.key_cache(&[]));

    let response = me_by_cookie(&starting, &token).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get(header::SET_COOKIE), None);
    assert_eq!(
        me_by_bearer(&starting, &token).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Even when a refresh is due.
    expire_soon(&pool).await;
    assert_eq!(
        me_by_bearer(&starting, &token).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(session_count(&pool).await, 1);
    assert_eq!(me_by_bearer(&ready, &token).await.status(), StatusCode::OK);
}

#[sqlx::test]
async fn a_refreshed_token_whose_key_is_not_known_yet_is_kept(pool: PgPool) {
    // The identity provider rotated to a key kanbot has not fetched (the
    // JWKS still serves the old set): the rotated refresh token is kept,
    // the request is 503, and the next one works once the keys catch up.
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    let mut access = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    access["exp"] = json!(now().checked_add(900).unwrap());
    idp.set_token(Reply::Json(json!({
        "access_token": sign("rsa-b", &access),
        "refresh_token": "rotated-refresh",
    })));
    idp.set_keys(&["rsa-a"]);

    assert_eq!(
        me_by_bearer(&app, &token).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(stored_refresh_token(&pool).await, "rotated-refresh");
    idp.set_keys(&["rsa-a", "rsa-b"]);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(me_by_bearer(&app, &token).await.status(), StatusCode::OK);
    assert_eq!(idp.token_requests().len(), 2, "no second refresh");
}

#[sqlx::test]
async fn a_refreshed_token_without_a_role_ends_the_session(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    answer_refresh(&idp, "alice", &["staff"], None);

    let response = me_by_bearer(&app, &token).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(session_count(&pool).await, 0);
}

#[sqlx::test]
async fn an_unreachable_idp_keeps_a_still_valid_session(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    idp.set_token(Reply::Status(StatusCode::SERVICE_UNAVAILABLE));

    // The stored token is still valid for a few seconds.
    assert_eq!(me_by_bearer(&app, &token).await.status(), StatusCode::OK);
    assert_eq!(session_count(&pool).await, 1);
}

#[sqlx::test]
async fn an_unreachable_idp_with_an_expired_token_is_unavailable(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    let mut expired = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    expired["exp"] = json!(now().checked_sub(120).unwrap());
    let id = sqlx::query_scalar!("SELECT id FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let sealed = crypto::seal(
        &common::session_config().keys,
        id,
        Field::AccessToken,
        &secrecy::SecretString::from(sign("rsa-a", &expired)),
    )
    .unwrap();
    sqlx::query!(
        "UPDATE sessions SET idp_access_token = $1, access_expires_at = now() - interval '2 minutes'",
        sealed
    )
    .execute(&pool)
    .await
    .unwrap();
    idp.set_token(Reply::Status(StatusCode::SERVICE_UNAVAILABLE));

    let response = me_by_bearer(&app, &token).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        session_count(&pool).await,
        1,
        "the session survives an IdP outage"
    );
}

async fn logout(app: &Router, credentials: (header::HeaderName, String)) -> Response {
    app.clone()
        .oneshot(
            Request::post("/auth/logout")
                .header(credentials.0, credentials.1)
                .header(header::ORIGIN, "http://localhost:3000")
                .header("x-kanbot-csrf", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[sqlx::test]
async fn logout_ends_the_session(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    let cookie = (header::COOKIE, format!("__Host-kanbot_session={token}"));

    let response = logout(&app, cookie.clone()).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookies(&response).iter().any(|cookie| {
        cookie.starts_with("__Host-kanbot_session=;") && cookie.contains("Max-Age=0")
    }));
    assert_eq!(problem(response).await["logout_url"], Value::Null);
    assert_eq!(session_count(&pool).await, 0);
    assert_eq!(
        me_by_bearer(&app, &token).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // Signing out again: the cookie is just stale now.
    assert_eq!(
        logout(&app, cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test]
async fn logout_returns_the_idp_logout_url_when_there_is_one(pool: PgPool) {
    let idp = TestIdp::start().await;
    let mut document = idp.discovery_document();
    document["end_session_endpoint"] = json!(format!("{}/logout", idp.issuer));
    idp.set_discovery(Reply::Json(document));
    let app = app(pool.clone(), &idp).await;
    // A native app never opens a browser to sign out: no URL for it.
    let code = native_code(&app, &idp, "bob").await;
    let (_, body) = redeem(&app, &json!({ "code": code, "code_verifier": VERIFIER })).await;
    let token = body["session_token"].as_str().unwrap();
    let response = logout(&app, (header::AUTHORIZATION, format!("Bearer {token}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::SET_COOKIE), None);
    assert_eq!(problem(response).await["logout_url"], Value::Null);

    let token = web_session(&app, &idp, "alice").await;
    let response = logout(&app, (header::AUTHORIZATION, format!("Bearer {token}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let url = Url::parse(problem(response).await["logout_url"].as_str().unwrap()).unwrap();
    assert_eq!(url.path(), "/logout");
    assert_eq!(query(&url, "client_id").as_deref(), Some("kanbot"));
    assert_eq!(
        query(&url, "post_logout_redirect_uri").as_deref(),
        Some("http://localhost:3000/")
    );
    let hint = query(&url, "id_token_hint").unwrap();
    assert_eq!(hint.split('.').count(), 3, "the ID token from the sign-in");
    assert_eq!(session_count(&pool).await, 0);
}

#[sqlx::test]
async fn logout_revokes_the_refresh_token_when_the_idp_can(pool: PgPool) {
    let idp = TestIdp::start().await;
    let mut document = idp.discovery_document();
    // The test identity provider records every POST to /token.
    document["revocation_endpoint"] = json!(format!("{}/token", idp.issuer));
    idp.set_discovery(Reply::Json(document));
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    idp.set_token(Reply::Status(StatusCode::OK));

    let response = logout(&app, (header::AUTHORIZATION, format!("Bearer {token}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    // In the background: wait for it.
    for _ in 0..50 {
        if idp.token_requests().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let requests = idp.token_requests();
    let revocation = &requests[1];
    assert_eq!(revocation.form["token"], "refresh-from-idp");
    assert_eq!(revocation.form["token_type_hint"], "refresh_token");
    assert!(
        revocation
            .authorization
            .as_deref()
            .unwrap()
            .starts_with("Basic ")
    );
}

#[sqlx::test]
async fn sign_in_routes_refuse_head(pool: PgPool) {
    // HEAD would run the handler: a link checker could use up a sign-in.
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    for uri in ["/auth/login?platform=web", "/auth/callback?state=x&code=y"] {
        let response = app
            .clone()
            .oneshot(Request::head(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{uri}");
        assert_eq!(response.headers()[header::ALLOW], "GET");
    }
    let attempts = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM login_attempts"#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(attempts, 0);
}

#[sqlx::test]
async fn a_callback_from_another_issuer_is_refused(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let started = start(&app, "/auth/login?platform=web").await;
    let access = issued_claims(&idp.issuer, "alice", &["kanbot-user"]);
    answer(&idp, &access, &id_claims(&idp, "alice", &started.nonce));

    let response = callback(
        &app,
        &started.state,
        "&iss=https%3A%2F%2Fevil.example",
        started.binding.as_deref(),
    )
    .await;
    assert_eq!(
        error_location(&response),
        "http://localhost:3000/login?error=login_failed"
    );
    assert_eq!(session_count(&pool).await, 0);
}

#[sqlx::test]
async fn logout_needs_a_session(pool: PgPool) {
    let app = common::app_with_pool(pool);
    let jwt = common::idp::access_token("alice", &["kanbot-user"]);
    let response = logout(&app, (header::AUTHORIZATION, format!("Bearer {jwt}"))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

async fn send(app: &Router, request: axum::http::request::Builder) -> StatusCode {
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[sqlx::test]
async fn cookie_sessions_need_csrf_proof_to_change_anything(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    let cookie = format!("__Host-kanbot_session={token}");
    let put = |origin: Option<&str>, csrf: Option<&str>| {
        let mut request = Request::put("/me/preferences")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(csrf) = csrf {
            request = request.header("x-kanbot-csrf", csrf);
        }
        request
    };
    for (origin, csrf) in [
        (None, None),
        (Some("http://localhost:3000"), None),
        (None, Some("1")),
        (Some("https://evil.example"), Some("1")),
        (Some("http://localhost:3000"), Some("0")),
        (Some("http://localhost:3001"), Some("1")),
        (Some("null"), Some("1")),
    ] {
        assert_eq!(
            send(&app, put(origin, csrf)).await,
            StatusCode::FORBIDDEN,
            "{origin:?} {csrf:?}"
        );
    }
    // Two values for either header are refused too.
    let doubled = put(Some("http://localhost:3000"), Some("1")).header("x-kanbot-csrf", "1");
    assert_eq!(send(&app, doubled).await, StatusCode::FORBIDDEN);

    // With both, the request reaches the route (which then wants a body).
    let allowed = put(Some("http://localhost:3000"), Some("1"));
    assert_eq!(send(&app, allowed).await, StatusCode::BAD_REQUEST);

    // Reading needs no proof.
    let read = Request::get("/me").header(header::COOKIE, &cookie);
    assert_eq!(send(&app, read).await, StatusCode::OK);

    // A cross-site request is refused before the session is used at all:
    // it does not even keep the session alive.
    sqlx::query!("UPDATE sessions SET last_used_at = now() - interval '1 hour'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, put(Some("https://evil.example"), Some("1"))).await,
        StatusCode::FORBIDDEN
    );
    let touched = sqlx::query_scalar!(
        r#"SELECT last_used_at > now() - interval '1 minute' AS "touched!" FROM sessions"#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!touched);
}

#[sqlx::test]
async fn bearer_sessions_need_no_csrf_proof(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    let request =
        Request::post("/auth/logout").header(header::AUTHORIZATION, format!("Bearer {token}"));
    assert_eq!(send(&app, request).await, StatusCode::OK);
}

#[sqlx::test]
async fn cleanup_deletes_what_has_expired_in_batches(pool: PgPool) {
    let user_id = user(&pool).await;
    let live_web = insert_session(&pool, user_id, "web", Some(b"live"))
        .await
        .unwrap();
    let waiting = insert_session(&pool, user_id, "native", None)
        .await
        .unwrap();
    sqlx::query!(
        "UPDATE sessions SET idle_expires_at = now() + interval '1 day',
                             absolute_expires_at = now() + interval '2 days'"
    )
    .execute(&pool)
    .await
    .unwrap();
    for i in 0..5_u8 {
        insert_session(&pool, user_id, "web", Some(&[b'x', i]))
            .await
            .unwrap();
    }
    // A native session that never got its token, long ago.
    let abandoned = insert_session(&pool, user_id, "native", None)
        .await
        .unwrap();
    sqlx::query!(
        "UPDATE sessions SET created_at = now() - interval '1 hour',
                             idle_expires_at = now() + interval '1 day',
                             absolute_expires_at = now() + interval '2 days'
         WHERE id = $1",
        abandoned
    )
    .execute(&pool)
    .await
    .unwrap();
    insert_attempt(&pool, "web", Some(b"binding"), None, None)
        .await
        .unwrap();
    insert_attempt(&pool, "web", Some(b"binding"), None, None)
        .await
        .unwrap();
    sqlx::query!(
        "UPDATE login_attempts SET expires_at = now() - interval '1 second'
         WHERE id = (SELECT id FROM login_attempts LIMIT 1)"
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO login_codes (code_hash, session_id, app_code_challenge, expires_at)
         VALUES ('old', $1, 'c', now() - interval '1 second'),
                ('new', $1, 'c', now() + interval '1 minute')",
        waiting
    )
    .execute(&pool)
    .await
    .unwrap();

    // Batches of 2: the 6 ended sessions take 4 statements, more than one
    // run used to allow per table.
    let deleted =
        kanbot_backend::sessions::service::cleanup(&pool, 2, std::time::Duration::from_secs(20))
            .await
            .unwrap();

    assert_eq!(deleted, 1 + 1 + 6);
    let sessions: Vec<Uuid> = sqlx::query_scalar!("SELECT id FROM sessions ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    let mut expected = vec![live_web, waiting];
    expected.sort();
    assert_eq!(sessions, expected);
    let left = sqlx::query_scalar!(
        r#"SELECT (SELECT count(*) FROM login_attempts) * 10 + (SELECT count(*) FROM login_codes) AS "n!""#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 10 + 1);
    // Nothing more to do.
    assert_eq!(
        kanbot_backend::sessions::service::cleanup(&pool, 2, std::time::Duration::from_secs(20))
            .await
            .unwrap(),
        0
    );
    // Out of time: nothing is deleted, nothing fails.
    sqlx::query!("UPDATE sessions SET idle_expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        kanbot_backend::sessions::service::cleanup(&pool, 2, std::time::Duration::ZERO)
            .await
            .unwrap(),
        0
    );
}

#[sqlx::test]
async fn cleanup_keeps_up_with_any_backlog(pool: PgPool) {
    // More expired rows than ten statements delete: one run takes them all.
    for _ in 0..15 {
        let state = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO login_attempts
               (id, state_hash, nonce_hash, pkce_verifier, platform, browser_binding_hash,
                expires_at)
             VALUES ($1, $2, 'n', 'v', 'web', 'b', now() - interval '1 second')",
            Uuid::new_v4(),
            state.as_bytes().as_slice(),
        )
        .execute(&pool)
        .await
        .unwrap();
    }
    let deleted = kanbot_backend::sessions::service::cleanup(&pool, 1, Duration::from_secs(20))
        .await
        .unwrap();
    assert_eq!(deleted, 15);
}

#[sqlx::test]
async fn a_user_disabled_in_the_database_loses_every_session(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let first = web_session(&app, &idp, "alice").await;
    web_session(&app, &idp, "alice").await;
    web_session(&app, &idp, "bob").await;
    sqlx::query!("UPDATE users SET disabled_at = now() WHERE subject = 'alice'")
        .execute(&pool)
        .await
        .unwrap();

    let response = me_by_bearer(&app, &first).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(problem(response).await["code"], "account_disabled");
    assert_eq!(session_count(&pool).await, 1, "only bob's session is left");
}

#[sqlx::test]
async fn disabling_a_user_ends_their_sessions(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    web_session(&app, &idp, "bob").await;
    let alice = sqlx::query_scalar!("SELECT id FROM users WHERE subject = 'alice'")
        .fetch_one(&pool)
        .await
        .unwrap();

    kanbot_backend::users::service::disable(
        &pool,
        kanbot_backend::users::model::UserId::from_uuid(alice),
    )
    .await
    .unwrap();

    assert_eq!(session_count(&pool).await, 1);
    assert_eq!(
        me_by_bearer(&app, &token).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let disabled = sqlx::query_scalar!(
        r#"SELECT disabled_at IS NOT NULL AS "d!" FROM users WHERE id = $1"#,
        alice
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(disabled);
    assert!(matches!(
        kanbot_backend::users::service::disable(&pool, kanbot_backend::users::model::UserId::new())
            .await,
        Err(kanbot_backend::error::AppError::NotFound)
    ));
}

#[sqlx::test]
async fn sessions_survive_a_key_rotation(pool: PgPool) {
    const OLD: &str = "test1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const NEW: &str = "test2:AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    let idp = TestIdp::start().await;
    let keys = idp.loaded_key_cache(&[]).await;
    let with_keys = |raw: &str| {
        common::serve(
            kanbot_backend::state::AppState {
                db: pool.clone(),
                migrator: &db::MIGRATOR,
                keys: keys.clone(),
                sessions: common::session_config_with_keys(raw),
                authz: common::policies(),
                openshell: None,
            },
            kanbot_backend::http::HttpSettings::new(),
            None,
        )
    };
    let token = web_session(&with_keys(OLD), &idp, "alice").await;

    // The new key encrypts; the old one still opens what it sealed.
    let rotated = with_keys(&format!("{NEW},{OLD}"));
    assert_eq!(
        me_by_bearer(&rotated, &token).await.status(),
        StatusCode::OK
    );
    expire_soon(&pool).await;
    answer_refresh(&idp, "alice", &["kanbot-user"], Some("rotated-refresh"));
    assert_eq!(
        me_by_bearer(&rotated, &token).await.status(),
        StatusCode::OK
    );
    let sealed = sqlx::query_scalar!("SELECT idp_access_token FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        &sealed[1..7],
        b"\x05test2",
        "refreshed tokens use the new key"
    );
    // A refresh token that was not rotated is sealed again with the new
    // key too, so retiring the old key does not end the session.
    let unrotated = web_session(&with_keys(OLD), &idp, "carol").await;
    sqlx::query!(
        "UPDATE sessions SET access_expires_at = now() + interval '30 seconds'
         WHERE user_id = (SELECT id FROM users WHERE subject = 'carol')"
    )
    .execute(&pool)
    .await
    .unwrap();
    answer_refresh(&idp, "carol", &["kanbot-user"], None);
    assert_eq!(
        me_by_bearer(&rotated, &unrotated).await.status(),
        StatusCode::OK
    );
    let sealed = sqlx::query_scalar!(
        "SELECT idp_refresh_token FROM sessions
         WHERE user_id = (SELECT id FROM users WHERE subject = 'carol')"
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&sealed[1..7], b"\x05test2");

    // Without the old key, sessions it sealed can no longer be used...
    let other = web_session(&with_keys(OLD), &idp, "bob").await;
    let only_new = with_keys(NEW);
    assert_eq!(
        me_by_bearer(&only_new, &other).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // ...while those resealed with the new key still work.
    assert_eq!(
        me_by_bearer(&only_new, &token).await.status(),
        StatusCode::OK
    );
}

#[sqlx::test]
async fn reading_methods_need_no_csrf_proof(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    let cookie = format!("__Host-kanbot_session={token}");
    for method in [axum::http::Method::HEAD, axum::http::Method::OPTIONS] {
        let request = Request::builder()
            .method(method.clone())
            .uri("/me")
            .header(header::COOKIE, &cookie);
        assert_ne!(send(&app, request).await, StatusCode::FORBIDDEN, "{method}");
    }
}

#[sqlx::test]
async fn a_cookie_session_the_idp_ended_is_forgotten(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    expire_soon(&pool).await;
    idp.set_token(Reply::Error(
        StatusCode::BAD_REQUEST,
        json!({ "error": "invalid_grant" }),
    ));

    let response = me_by_cookie(&app, &token).await;

    // Anonymous, not a bad credential: the browser can sign in again.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert!(set_cookies(&response).iter().any(|cookie| {
        cookie.starts_with("__Host-kanbot_session=;") && cookie.contains("Max-Age=0")
    }));
    assert_eq!(session_count(&pool).await, 0);
}

#[sqlx::test]
async fn a_stored_token_without_a_role_is_forbidden(pool: PgPool) {
    let idp = TestIdp::start().await;
    let app = app(pool.clone(), &idp).await;
    let token = web_session(&app, &idp, "alice").await;
    let id = sqlx::query_scalar!("SELECT id FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let no_role = issued_claims(&idp.issuer, "alice", &["staff"]);
    let sealed = crypto::seal(
        &common::session_config().keys,
        id,
        Field::AccessToken,
        &secrecy::SecretString::from(sign("rsa-a", &no_role)),
    )
    .unwrap();
    sqlx::query!("UPDATE sessions SET idp_access_token = $1", sealed)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        me_by_bearer(&app, &token).await.status(),
        StatusCode::FORBIDDEN
    );
}
