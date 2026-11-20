//! Secure by default: every operation in the API contract requires
//! authentication, except an explicit public list. Adding a public route
//! means adding it here, on purpose.

pub mod common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use kanbot_backend::{
    db,
    http::{self, BEARER_SCHEME, middleware::rate_limit::RateLimits},
    state::AppState,
    telemetry_relay,
};
use serde_json::Value;
use tower::ServiceExt;

/// Operations anyone may call, as `METHOD path`.
const PUBLIC: [&str; 2] = ["GET /health", "GET /ready"];

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Every operation in the contract, as (method, path, operation).
fn operations() -> Vec<(String, String, Value)> {
    let document = serde_json::to_value(http::openapi()).unwrap();
    let mut operations = Vec::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for method in METHODS {
            if let Some(operation) = item.get(method) {
                operations.push((method.to_uppercase(), path.clone(), operation.clone()));
            }
        }
    }
    operations
}

/// `path` with every `{parameter}` replaced by a valid-looking value.
fn concrete(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "00000000-0000-4000-8000-000000000000"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn the_public_list_is_current() {
    let operations: Vec<String> = operations()
        .into_iter()
        .map(|(method, path, _)| format!("{method} {path}"))
        .collect();
    for public in PUBLIC {
        assert!(
            operations.iter().any(|op| op == public),
            "{public} no longer exists"
        );
    }
}

#[test]
fn protected_operations_declare_bearer_security_and_its_errors() {
    for (method, path, operation) in operations() {
        let name = format!("{method} {path}");
        if PUBLIC.contains(&name.as_str()) {
            assert_eq!(operation.get("security"), None, "{name} is public");
            continue;
        }
        let security = operation["security"].as_array();
        assert!(
            security.is_some_and(|requirements| requirements
                .iter()
                .any(|requirement| requirement.get(BEARER_SCHEME).is_some())),
            "{name} must declare security(({BEARER_SCHEME:?} = []))"
        );
        for status in ["401", "403"] {
            assert!(
                operation["responses"].get(status).is_some(),
                "{name} must document its {status} response"
            );
        }
    }
}

#[tokio::test]
async fn protected_operations_refuse_requests_without_credentials() {
    let mut checked = 0_u32;
    for (method, path, _) in operations() {
        let name = format!("{method} {path}");
        if PUBLIC.contains(&name.as_str()) {
            continue;
        }
        let request = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).unwrap())
            .uri(concrete(&path))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let response = common::app_without_db().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer",
            "{name}"
        );
        checked = checked.checked_add(1).unwrap();
    }
    assert!(checked > 0, "no protected operation was checked");
}

#[test]
fn the_bearer_scheme_is_a_jwt() {
    let document = serde_json::to_value(http::openapi()).unwrap();
    let scheme = &document["components"]["securitySchemes"][BEARER_SCHEME];
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "bearer");
    assert_eq!(scheme["bearerFormat"], "JWT");
}

/// The telemetry relay follows OTLP/HTTP, not the contract, so it is not in
/// the document above: it is checked here by name.
#[tokio::test]
async fn telemetry_relay_routes_refuse_requests_without_credentials() {
    let relay = telemetry_relay::routes(
        "http://127.0.0.1:1".parse().unwrap(),
        RateLimits::DEFAULT.telemetry,
    )
    .unwrap();
    let options = sqlx::postgres::PgConnectOptions::new_without_pgpass()
        .host("127.0.0.1")
        .port(1);
    let app = http::router(
        AppState {
            db: db::pool_with(options),
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
        },
        &[],
        Some(relay),
    );
    for signal in ["traces", "logs", "metrics"] {
        let request = Request::post(format!("/telemetry/v1/{signal}"))
            .header(header::CONTENT_TYPE, "application/x-protobuf")
            .body(Body::from("batch"))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{signal}");
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }
}
