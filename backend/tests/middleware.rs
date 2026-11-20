//! The middleware stack, exercised with test routes wrapped by
//! `http::with_middleware`.

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    routing::get,
};
use http_body_util::BodyExt;
use kanbot_backend::http::{
    REQUEST_TIMEOUT,
    middleware::security_headers::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
        X_CONTENT_TYPE_OPTIONS,
    },
    with_middleware,
};
use tower::ServiceExt;

const ALLOWED_ORIGIN: &str = "https://app.example.com";

fn app() -> Router {
    let routes = Router::new()
        .route("/ok", get(|| async { "ok" }))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(REQUEST_TIMEOUT.saturating_mul(2)).await;
                "too late"
            }),
        )
        .route("/panic", get(|| async { panic!("handler bug") }))
        .route(
            "/cacheable",
            get(|| async { ([(header::CACHE_CONTROL, "max-age=60")], "ok") }),
        )
        .route(
            "/authorization-is-sensitive",
            get(|headers: HeaderMap| async move {
                headers
                    .get(header::AUTHORIZATION)
                    .is_some_and(HeaderValue::is_sensitive)
                    .to_string()
            }),
        );
    with_middleware(routes, &[HeaderValue::from_static(ALLOWED_ORIGIN)])
}

// Paused time auto-advances while the runtime is idle, so the timeout fires
// without waiting 10 real seconds.
#[tokio::test(start_paused = true)]
async fn slow_request_times_out_with_service_unavailable() {
    let response = app()
        .oneshot(Request::get("/slow").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn panicking_handler_returns_internal_server_error() {
    let response = app()
        .oneshot(Request::get("/panic").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

fn preflight(origin: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri("/ok")
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn preflight_from_allowed_origin_is_allowed() {
    let response = app().oneshot(preflight(ALLOWED_ORIGIN)).await.unwrap();

    let headers = response.headers();
    assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], ALLOWED_ORIGIN);
    let methods = headers[header::ACCESS_CONTROL_ALLOW_METHODS]
        .to_str()
        .unwrap();
    assert!(methods.contains("POST"), "{methods}");
    let allowed_headers = headers[header::ACCESS_CONTROL_ALLOW_HEADERS]
        .to_str()
        .unwrap();
    assert!(
        allowed_headers.contains("content-type"),
        "{allowed_headers}"
    );
    assert!(
        allowed_headers.contains("authorization"),
        "{allowed_headers}"
    );
    assert_eq!(headers[header::ACCESS_CONTROL_MAX_AGE], "3600");
}

#[tokio::test]
async fn preflight_from_other_origin_is_not_allowed() {
    let response = app()
        .oneshot(preflight("https://evil.example.com"))
        .await
        .unwrap();

    assert!(
        !response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
}

#[tokio::test]
async fn simple_request_from_allowed_origin_gets_cors_header() {
    let request = Request::get("/ok")
        .header(header::ORIGIN, ALLOWED_ORIGIN)
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        ALLOWED_ORIGIN
    );
}

async fn response_to(uri: &str) -> axum::response::Response {
    app()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn assert_security_headers(response: &axum::response::Response) {
    let headers = response.headers();
    for (name, value) in [
        (header::CACHE_CONTROL, CACHE_CONTROL),
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::REFERRER_POLICY, REFERRER_POLICY),
        (header::STRICT_TRANSPORT_SECURITY, STRICT_TRANSPORT_SECURITY),
        (header::X_CONTENT_TYPE_OPTIONS, X_CONTENT_TYPE_OPTIONS),
    ] {
        assert_eq!(headers.get(&name).unwrap(), value, "{name}");
    }
}

#[tokio::test]
async fn responses_carry_security_headers() {
    let response = response_to("/ok").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(&response);
    assert_eq!(
        response.headers()[header::CONTENT_SECURITY_POLICY],
        "default-src 'none'; frame-ancestors 'none'"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn error_responses_carry_security_headers() {
    for uri in ["/nope", "/panic"] {
        assert_security_headers(&response_to(uri).await);
    }
}

#[tokio::test(start_paused = true)]
async fn timed_out_responses_carry_security_headers() {
    assert_security_headers(&response_to("/slow").await);
}

#[tokio::test]
async fn preflight_responses_carry_security_headers() {
    let response = app().oneshot(preflight(ALLOWED_ORIGIN)).await.unwrap();

    assert_security_headers(&response);
}

#[tokio::test]
async fn handler_cache_control_is_kept() {
    let response = response_to("/cacheable").await;

    assert_eq!(response.headers()[header::CACHE_CONTROL], "max-age=60");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        X_CONTENT_TYPE_OPTIONS
    );
}

#[tokio::test]
async fn authorization_header_is_marked_sensitive() {
    let request = Request::get("/authorization-is-sensitive")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"true");
}
