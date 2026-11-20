//! The telemetry relay: forwarding OTLP/HTTP batches to the collector, and
//! the limits that keep a public endpoint from being abused.

pub mod common;

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Extension, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode, Uri, header},
    response::Response,
    routing::post,
};
use http_body_util::BodyExt;
use kanbot_backend::{
    db,
    http::{self, client_ip::TrustedProxies},
    state::AppState,
    telemetry_relay::{self, MAX_BODY_BYTES, RATE_LIMIT_BURST},
};
use reqwest::Url;
use serde_json::Value;
use sqlx::postgres::PgConnectOptions;
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

/// The full app with the relay to `upstream`, as `peer` connects to it.
fn app(upstream: Url, trusted: TrustedProxies, peer: SocketAddr) -> Router {
    let options = PgConnectOptions::new_without_pgpass()
        .host("127.0.0.1")
        .port(1);
    let relay = telemetry_relay::routes(upstream, Arc::new(trusted)).unwrap();
    http::router(
        AppState {
            db: db::pool_with(options),
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
        },
        &[],
        Some(relay),
    )
    // What `into_make_service_with_connect_info` adds to every request.
    .layer(Extension(ConnectInfo(peer)))
}

fn client() -> SocketAddr {
    "203.0.113.9:50000".parse().unwrap()
}

fn export(signal: &str, content_type: &str, body: impl Into<Body>) -> Request<Body> {
    Request::post(format!("/telemetry/v1/{signal}"))
        .header(header::CONTENT_TYPE, content_type)
        .body(body.into())
        .unwrap()
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

#[tokio::test]
async fn forwards_each_signal_to_the_collector() {
    let (upstream, received) = collector(StatusCode::OK, b"partial-success").await;
    let app = app(upstream, TrustedProxies::default(), client());

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

#[tokio::test]
async fn forwards_json_and_normalizes_the_content_type() {
    let (upstream, received) = collector(StatusCode::OK, b"{}").await;

    let response = app(upstream, TrustedProxies::default(), client())
        .oneshot(export("traces", "Application/JSON; charset=utf-8", "{}"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        received.lock().unwrap()[0].1.as_deref(),
        Some("application/json")
    );
}

#[tokio::test]
async fn forwards_no_client_headers() {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let request = Request::post("/telemetry/v1/traces")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .header(header::COOKIE, "session=secret")
        .body(Body::from("batch"))
        .unwrap();

    let response = app(upstream, TrustedProxies::default(), client())
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let received = received.lock().unwrap();
    let names = &received[0].3;
    assert!(names.contains(&"content-type".to_owned()), "{names:?}");
    for credential in ["authorization", "cookie"] {
        assert!(!names.contains(&credential.to_owned()), "{names:?}");
    }
}

#[tokio::test]
async fn rejects_other_content_types_without_forwarding() {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(upstream, TrustedProxies::default(), client());

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
        .body(Body::from("batch"))
        .unwrap();
    let response = app.oneshot(without_type).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_compressed_bodies() {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(upstream, TrustedProxies::default(), client());

    let gzip = Request::post("/telemetry/v1/traces")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(Body::from("batch"))
        .unwrap();
    let response = app.clone().oneshot(gzip).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(received.lock().unwrap().is_empty());

    let identity = Request::post("/telemetry/v1/traces")
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .header(header::CONTENT_ENCODING, "identity")
        .body(Body::from("batch"))
        .unwrap();
    assert_eq!(
        app.oneshot(identity).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn rejects_oversized_batches_without_forwarding() {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let app = app(upstream, TrustedProxies::default(), client());

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

#[tokio::test]
async fn collector_rejection_is_a_bad_request() {
    let (upstream, _) = collector(StatusCode::BAD_REQUEST, b"collector detail").await;

    let response = app(upstream, TrustedProxies::default(), client())
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_of(response).await;
    assert!(!String::from_utf8_lossy(&body).contains("collector detail"));
}

#[tokio::test]
async fn collector_overload_is_temporary() {
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (upstream, _) = collector(status, b"").await;
        let response = app(upstream, TrustedProxies::default(), client())
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

#[tokio::test]
async fn unreachable_collector_is_temporary() {
    let closed: Url = "http://127.0.0.1:1".parse().unwrap();

    let response = app(closed, TrustedProxies::default(), client())
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn large_collector_responses_are_dropped() {
    static LARGE: [u8; 100 * 1024] = [b'x'; 100 * 1024];
    let (upstream, _) = collector(StatusCode::OK, &LARGE).await;

    let response = app(upstream, TrustedProxies::default(), client())
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_of(response).await, Vec::<u8>::new());
}

/// Sends batches as `peer`, with `forwarded_for` if any, until the relay
/// stops accepting them; returns how many it accepted and the rejection.
async fn exhaust(app: &Router, forwarded_for: Option<&str>) -> (u32, Response) {
    for accepted in 0..=RATE_LIMIT_BURST {
        let mut request = export("traces", "application/x-protobuf", "batch");
        if let Some(forwarded_for) = forwarded_for {
            request
                .headers_mut()
                .insert("x-forwarded-for", forwarded_for.parse().unwrap());
        }
        let response = app.clone().oneshot(request).await.unwrap();
        if response.status() != StatusCode::OK {
            return (accepted, response);
        }
    }
    panic!("the relay never rate limited");
}

#[tokio::test]
async fn rate_limits_each_client() {
    let (upstream, _) = collector(StatusCode::OK, b"").await;
    let app = app(upstream.clone(), TrustedProxies::default(), client());

    let (accepted, rejected) = exhaust(&app, None).await;

    assert_eq!(accepted, RATE_LIMIT_BURST);
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(rejected.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(problem_code(rejected).await, "rate_limited");

    // Another client has its own budget.
    let other = self::app(
        upstream,
        TrustedProxies::default(),
        "198.51.100.7:1234".parse().unwrap(),
    );
    let response = other
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn spoofed_forwarded_for_does_not_escape_the_limit() {
    let (upstream, _) = collector(StatusCode::OK, b"").await;
    // The peer is not a trusted proxy, so X-Forwarded-For is ignored.
    let app = app(upstream, TrustedProxies::default(), client());

    for spoofed in 0..=RATE_LIMIT_BURST {
        let mut request = export("traces", "application/x-protobuf", "batch");
        request.headers_mut().insert(
            "x-forwarded-for",
            format!("10.0.0.{spoofed}").parse().unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        if spoofed < RATE_LIMIT_BURST {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
}

#[tokio::test]
async fn behind_a_trusted_proxy_each_forwarded_client_has_its_own_limit() {
    let (upstream, _) = collector(StatusCode::OK, b"").await;
    let proxy: SocketAddr = "10.0.0.1:40000".parse().unwrap();
    let app = app(
        upstream,
        TrustedProxies::parse_list("10.0.0.0/8").unwrap(),
        proxy,
    );

    let (accepted, rejected) = exhaust(&app, Some("203.0.113.9")).await;
    assert_eq!(accepted, RATE_LIMIT_BURST);
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);

    let mut request = export("traces", "application/x-protobuf", "batch");
    request
        .headers_mut()
        .insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn relay_routes_exist_only_when_configured() {
    let options = PgConnectOptions::new_without_pgpass()
        .host("127.0.0.1")
        .port(1);
    let app = http::router(
        AppState {
            db: db::pool_with(options),
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
        },
        &[],
        None,
    )
    .layer(Extension(ConnectInfo(client())));

    let response = app
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn relay_accepts_only_post() {
    let (upstream, _) = collector(StatusCode::OK, b"").await;
    let response = app(upstream, TrustedProxies::default(), client())
        .oneshot(
            Request::get("/telemetry/v1/traces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn without_connect_info_requests_fail_closed() {
    let (upstream, received) = collector(StatusCode::OK, b"").await;
    let options = PgConnectOptions::new_without_pgpass()
        .host("127.0.0.1")
        .port(1);
    let relay = telemetry_relay::routes(upstream, Arc::new(TrustedProxies::default())).unwrap();
    let app = http::router(
        AppState {
            db: db::pool_with(options),
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
        },
        &[],
        Some(relay),
    );

    let response = app
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn batch_limit_is_512_kib() {
    let (upstream, _) = collector(StatusCode::OK, b"").await;
    let app = app(upstream, TrustedProxies::default(), client());

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

#[tokio::test]
async fn collector_responses_up_to_64_kib_are_passed_through() {
    static EXACTLY_64_KIB: [u8; 64 * 1024] = [b'x'; 64 * 1024];
    let (upstream, _) = collector(StatusCode::OK, &EXACTLY_64_KIB).await;

    let response = app(upstream, TrustedProxies::default(), client())
        .oneshot(export("traces", "application/x-protobuf", "batch"))
        .await
        .unwrap();

    assert_eq!(body_of(response).await.len(), 64 * 1024);
}
