//! The telemetry relay: forwarding OTLP/HTTP batches to the collector, only
//! for authenticated users who opted in, and the limits that keep it from
//! being abused.

pub mod common;

use std::{
    num::NonZeroU32,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, Uri, header},
    response::Response,
    routing::post,
};
use common::idp::access_token;
use http_body_util::BodyExt;
use kanbot_backend::{
    db,
    http::{HttpSettings, middleware::rate_limit::RateLimit},
    state::AppState,
    telemetry_relay::{self, MAX_BODY_BYTES},
};
use reqwest::Url;
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// What the fake collector received: path, content type, body, header
/// names.
type Received = Arc<Mutex<Vec<(String, Option<String>, Vec<u8>, Vec<String>)>>>;

/// A fake OTLP collector that records every request and answers with
/// `status` and `response_body`.
async fn collector(status: StatusCode, response_body: &'static [u8]) -> (Url, Received) {
    let received = Received::default();
    let app = Router::new()
        .route(
            "/{*path}",
            post(
                move |State(received): State<Received>,
                      uri: Uri,
                      headers: HeaderMap,
                      body: Bytes| async move {
                    received.lock().unwrap().push((
                        uri.path().to_owned(),
                        headers
                            .get(header::CONTENT_TYPE)
                            .map(|value| value.to_str().unwrap().to_owned()),
                        body.to_vec(),
                        headers
                            .keys()
                            .map(|name| name.as_str().to_owned())
                            .collect(),
                    ));
                    (
                        status,
                        [(header::CONTENT_TYPE, "application/x-protobuf")],
                        response_body,
                    )
                },
            ),
        )
        .with_state(Arc::clone(&received));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}").parse().unwrap(), received)
}

/// A limit high enough never to interfere.
const GENEROUS: RateLimit = RateLimit {
    per_second: NonZeroU32::new(1_000_000).unwrap(),
    burst: NonZeroU32::new(1_000_000).unwrap(),
};

/// The full app with the relay to `upstream`, limited per user by `limit`.
fn app_limited(pool: &PgPool, upstream: Url, limit: RateLimit) -> Router {
    let relay = telemetry_relay::routes(upstream, limit).unwrap();
    common::serve(
        AppState {
            db: pool.clone(),
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
            sessions: common::session_config(),
        },
        HttpSettings::new(),
        Some(relay),
    )
}

/// The full app with the relay to `upstream`, where `alice` has opted in.
async fn app(pool: &PgPool, upstream: Url) -> Router {
    let app = app_limited(pool, upstream, GENEROUS);
    opt_in(&app, "alice", true).await;
    app
}

/// Sets `subject`'s telemetry consent through the API.
async fn opt_in(app: &Router, subject: &str, opt_in: bool) {
    let response = app
        .clone()
        .oneshot(
            Request::put("/me/preferences")
                .header(header::AUTHORIZATION, bearer(subject))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "telemetry_opt_in": opt_in }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

fn bearer(subject: &str) -> String {
    format!("Bearer {}", access_token(subject, &["kanbot-user"]))
}

/// An export request from `alice`.
fn export(signal: &str, content_type: &str, body: impl Into<Body>) -> Request<Body> {
    export_as(Some("alice"), signal, content_type, body)
}

/// An export request from `subject`, or without credentials.
fn export_as(
    subject: Option<&str>,
    signal: &str,
    content_type: &str,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut request =
        Request::post(format!("/telemetry/v1/{signal}")).header(header::CONTENT_TYPE, content_type);
    if let Some(subject) = subject {
        request = request.header(header::AUTHORIZATION, bearer(subject));
    }
    request.body(body.into()).unwrap()
}

async fn body_of(response: Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

async fn problem_code(response: Response) -> String {
    let body: Value = serde_json::from_slice(&body_of(response).await).unwrap();
    body["code"].as_str().unwrap().to_owned()
}

#[sqlx::test]
async fn forwards_each_signal_to_the_collector(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"partial-success").await;
    let app = app(&pool, upstream).await;

    for signal in ["traces", "logs", "metrics"] {
        let response = app
            .clone()
            .oneshot(export(
                signal,
                "application/x-protobuf",
                format!("{signal}-batch"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{signal}");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/x-protobuf"
        );
        assert_eq!(body_of(response).await, b"partial-success");
    }

    let received = received.lock().unwrap();
    let paths: Vec<_> = received.iter().map(|(path, ..)| path.as_str()).collect();
    assert_eq!(paths, ["/v1/traces", "/v1/logs", "/v1/metrics"]);
    assert_eq!(received[0].1.as_deref(), Some("application/x-protobuf"));
    assert_eq!(received[0].2, b"traces-batch");
}

#[sqlx::test]
async fn forwards_json_and_normalizes_the_content_type(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"{}").await;

    let response = app(&pool, upstream)
        .await
        .oneshot(export("traces", "Application/JSON; charset=utf-8", "{}"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        received.lock().unwrap()[0].1.as_deref(),
        Some("application/json")
    );
}

#[sqlx::test]
async fn forwards_no_client_headers(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let request = Request::post("/telemetry/v1/traces")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .header(header::AUTHORIZATION, bearer("alice"))
        .header(header::COOKIE, "session=secret")
        .body(Body::from("batch"))
        .unwrap();

    let response = app(&pool, upstream).await.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let received = received.lock().unwrap();
    let names = &received[0].3;
    assert!(names.contains(&"content-type".to_owned()), "{names:?}");
    for credential in ["authorization", "cookie"] {
        assert!(!names.contains(&credential.to_owned()), "{names:?}");
    }
}

#[sqlx::test]
async fn rejects_other_content_types_without_forwarding(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(&pool, upstream).await;

    for content_type in ["text/plain", "application/x-www-form-urlencoded", ""] {
        let response = app
            .clone()
            .oneshot(export("traces", content_type, "batch"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type}"
        );
        assert_eq!(problem_code(response).await, "unsupported_media_type");
    }
    let without_type = Request::post("/telemetry/v1/traces")
        .header(header::AUTHORIZATION, bearer("alice"))
        .body(Body::from("batch"))
        .unwrap();
    let response = app.oneshot(without_type).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(received.lock().unwrap().is_empty());
}

#[sqlx::test]
async fn rejects_compressed_bodies(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(&pool, upstream).await;

    let gzip = Request::post("/telemetry/v1/traces")
        .header(header::AUTHORIZATION, bearer("alice"))
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(Body::from("batch"))
        .unwrap();
    let response = app.clone().oneshot(gzip).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(received.lock().unwrap().is_empty());

    let identity = Request::post("/telemetry/v1/traces")
        .header(header::AUTHORIZATION, bearer("alice"))
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .header(header::CONTENT_ENCODING, "identity")
        .body(Body::from("batch"))
        .unwrap();
    assert_eq!(
        app.oneshot(identity).await.unwrap().status(),
        StatusCode::OK
    );
}

#[sqlx::test]
async fn rejects_oversized_batches_without_forwarding(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(&pool, upstream).await;

    let response = app
        .clone()
        .oneshot(export(
            "traces",
            "application/x-protobuf",
            vec![0_u8; MAX_BODY_BYTES.checked_add(1).unwrap()],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(problem_code(response).await, "payload_too_large");
    assert!(received.lock().unwrap().is_empty());

    let response = app
        .oneshot(export(
            "traces",
            "application/x-protobuf",
            vec![0_u8; MAX_BODY_BYTES],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test]
async fn collector_rejection_is_a_bad_request(pool: PgPool) {
    let (upstream, _) = collector(StatusCode::BAD_REQUEST, b"collector detail").await;

    let response = app(&pool, upstream)
        .await
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_of(response).await;
    assert!(!String::from_utf8_lossy(&body).contains("collector detail"));
}

#[sqlx::test]
async fn collector_overload_is_temporary(pool: PgPool) {
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (upstream, _) = collector(status, b"").await;
        let response = app(&pool, upstream)
            .await
            .oneshot(export("traces", "application/x-protobuf", "batch"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{status}"
        );
        assert_eq!(problem_code(response).await, "unavailable");
    }
}

#[sqlx::test]
async fn unreachable_collector_is_temporary(pool: PgPool) {
    let closed: Url = "http://127.0.0.1:1".parse().unwrap();

    let response = app(&pool, closed)
        .await
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[sqlx::test]
async fn large_collector_responses_are_dropped(pool: PgPool) {
    static LARGE: [u8; 100 * 1024] = [b'x'; 100 * 1024];
    let (upstream, _) = collector(StatusCode::OK, &LARGE).await;

    let response = app(&pool, upstream)
        .await
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_of(response).await, Vec::<u8>::new());
}

#[sqlx::test]
async fn relay_routes_exist_only_when_configured(pool: PgPool) {
    let app = common::serve(
        AppState {
            db: pool,
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
            sessions: common::session_config(),
        },
        HttpSettings::new(),
        None,
    );

    let response = app
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn relay_accepts_only_post(pool: PgPool) {
    let (upstream, _) = collector(StatusCode::OK, b"").await;
    let response = app(&pool, upstream)
        .await
        .oneshot(
            Request::get("/telemetry/v1/traces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[sqlx::test]
async fn batch_limit_is_512_kib(pool: PgPool) {
    let (upstream, _) = collector(StatusCode::OK, b"").await;
    let app = app(&pool, upstream).await;

    for (size, status) in [
        (500 * 1024, StatusCode::OK),
        (600 * 1024, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let response = app
            .clone()
            .oneshot(export("traces", "application/x-protobuf", vec![0_u8; size]))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{size} bytes");
    }
}

#[sqlx::test]
async fn collector_responses_up_to_64_kib_are_passed_through(pool: PgPool) {
    static EXACTLY_64_KIB: [u8; 64 * 1024] = [b'x'; 64 * 1024];
    let (upstream, _) = collector(StatusCode::OK, &EXACTLY_64_KIB).await;

    let response = app(&pool, upstream)
        .await
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(body_of(response).await.len(), 64 * 1024);
}

#[sqlx::test]
async fn requires_an_authenticated_user(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(&pool, upstream).await;

    let response = app
        .clone()
        .oneshot(export_as(None, "traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(problem_code(response).await, "unauthorized");

    let mut request = export_as(None, "traces", "application/x-protobuf", "batch");
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, "Bearer forged".parse().unwrap());
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    assert!(received.lock().unwrap().is_empty());
}

#[sqlx::test]
async fn requires_consent(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(&pool, upstream).await;

    // bob never opted in.
    let response = app
        .clone()
        .oneshot(export_as(
            Some("bob"),
            "traces",
            "application/x-protobuf",
            "batch",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(problem_code(response).await, "telemetry_disabled");

    // alice opted in, then out.
    opt_in(&app, "alice", false).await;
    let response = app
        .clone()
        .oneshot(export("logs", "application/x-protobuf", "batch"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(problem_code(response).await, "telemetry_disabled");
    assert!(received.lock().unwrap().is_empty());

    opt_in(&app, "alice", true).await;
    let response = app
        .oneshot(export("logs", "application/x-protobuf", "batch"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(received.lock().unwrap().len(), 1);
}

#[sqlx::test]
async fn forwards_no_user_identity(pool: PgPool) {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(&pool, upstream).await;

    let response = app
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let received = received.lock().unwrap();
    let (_, _, body, names) = &received[0];
    assert_eq!(body, b"batch");
    assert_eq!(
        names.iter().filter(|name| name.starts_with("x-")).count(),
        0,
        "{names:?}"
    );
    for name in names {
        assert!(
            ["content-type", "content-length", "accept", "host"].contains(&name.as_str()),
            "unexpected header {name}"
        );
    }
}

#[sqlx::test]
async fn rate_limits_each_user(pool: PgPool) {
    let (upstream, _) = collector(StatusCode::OK, b"").await;
    let limit = RateLimit {
        per_second: NonZeroU32::new(1).unwrap(),
        burst: NonZeroU32::new(3).unwrap(),
    };
    let app = app_limited(&pool, upstream, limit);
    opt_in(&app, "alice", true).await;
    opt_in(&app, "bob", true).await;

    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(export("traces", "application/x-protobuf", "batch"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let rejected = app
        .clone()
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rejected.headers()[header::RETRY_AFTER], "1");
    assert_eq!(problem_code(rejected).await, "rate_limited");

    // Another user has their own budget.
    let response = app
        .clone()
        .oneshot(export_as(
            Some("bob"),
            "traces",
            "application/x-protobuf",
            "batch",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Requests without a user are not counted (and are refused).
    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(export_as(None, "traces", "application/x-protobuf", "batch"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
