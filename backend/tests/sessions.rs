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

    let response = callback(
        &app,
        &started.state,
        "&iss=x&scope=openid",
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

    let waiting = sqlx::query_scalar!("SELECT token_hash FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(waiting, None, "no session token was handed out");
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
        },
        kanbot_backend::http::HttpSettings::new(),
        Some(relay),
    );
    let body = problem(get(&with_relay, "/auth/config").await).await;
    assert_eq!(body["telemetry_available"], true);
}
