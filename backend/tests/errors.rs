//! Every error response is a problem details body, whoever produced it:
//! a handler, an axum rejection, the router or a middleware.

use axum::{
    Json, Router,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use http_body_util::BodyExt;
use kanbot_backend::{
    error::{AppError, FieldError},
    http::{MAX_BODY_BYTES, REQUEST_TIMEOUT, problem::PROBLEM_JSON, with_middleware},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tower::ServiceExt;

const ALLOWED_ORIGIN: &str = "https://app.example.com";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewItem {
    title: String,
}

fn app() -> Router {
    let routes = Router::new()
        .route(
            "/items",
            post(|Json(item): Json<NewItem>| async move { item.title }),
        )
        .route(
            "/missing",
            get(|| async { Err::<(), _>(AppError::NotFound) }),
        )
        .route(
            "/invalid",
            get(|| async {
                Err::<(), _>(AppError::Validation(vec![FieldError::new(
                    "/title", "too_long",
                )]))
            }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(REQUEST_TIMEOUT.saturating_mul(2)).await;
            }),
        )
        .route("/panic", get(|| async { panic!("secret panic message") }));
    with_middleware(routes, &[HeaderValue::from_static(ALLOWED_ORIGIN)])
}

async fn send(request: Request<Body>) -> Response {
    app().oneshot(request).await.unwrap()
}

/// Asserts `response` is a problem with `status` and `code`, and returns its
/// headers and body.
async fn assert_problem(response: Response, status: StatusCode, code: &str) -> (HeaderMap, Value) {
    assert_eq!(response.status(), status);
    let (parts, body) = response.into_parts();
    assert_eq!(parts.headers[header::CONTENT_TYPE], PROBLEM_JSON);
    let body = body.collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["status"], status.as_u16(), "{body}");
    assert_eq!(body["code"], code, "{body}");
    assert_eq!(body["type"], format!("urn:kanbot:problem:{code}"));
    assert!(body["title"].is_string(), "{body}");
    (parts.headers, body)
}

fn post_json(body: &'static str) -> Request<Body> {
    Request::post("/items")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn handler_errors_are_problems() {
    let response = send(Request::get("/missing").body(Body::empty()).unwrap()).await;
    assert_problem(response, StatusCode::NOT_FOUND, "not_found").await;
}

#[tokio::test]
async fn validation_errors_list_the_fields() {
    let response = send(Request::get("/invalid").body(Body::empty()).unwrap()).await;
    let (_, body) = assert_problem(
        response,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
    )
    .await;
    assert_eq!(
        body["errors"],
        json!([{ "pointer": "/title", "code": "too_long" }])
    );
}

#[tokio::test]
async fn unknown_route_is_a_problem() {
    let response = send(Request::get("/nope").body(Body::empty()).unwrap()).await;
    assert_problem(response, StatusCode::NOT_FOUND, "not_found").await;
}

#[tokio::test]
async fn wrong_method_is_a_problem_and_keeps_allow() {
    let response = send(Request::get("/items").body(Body::empty()).unwrap()).await;
    let (headers, _) = assert_problem(
        response,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    )
    .await;
    assert_eq!(headers[header::ALLOW], "POST");
}

#[tokio::test]
async fn malformed_json_is_a_problem_without_parser_details() {
    let response = send(post_json(r#"{"title": "secret-input"#)).await;
    let (_, body) = assert_problem(response, StatusCode::BAD_REQUEST, "bad_request").await;
    assert!(!body.to_string().contains("secret-input"), "{body}");
    assert!(!body.to_string().contains("line"), "{body}");
}

#[tokio::test]
async fn wrongly_typed_json_is_a_validation_problem_without_details() {
    for json in [
        r#"{"title": 42}"#,
        r"{}",
        r#"{"title": "ok", "secret_field": 1}"#,
    ] {
        let response = send(post_json(json)).await;
        let (_, body) = assert_problem(
            response,
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
        )
        .await;
        // Only the standard members: no detail naming the field or value.
        let mut members: Vec<_> = body.as_object().unwrap().keys().collect();
        members.sort();
        assert_eq!(members, ["code", "status", "title", "type"], "{json}");
    }
}

#[tokio::test]
async fn missing_content_type_is_a_problem() {
    let request = Request::post("/items")
        .body(Body::from(r#"{"title": "x"}"#))
        .unwrap();
    let response = send(request).await;
    assert_problem(
        response,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    )
    .await;
}

#[tokio::test]
async fn oversized_body_is_a_problem() {
    let size = MAX_BODY_BYTES.checked_add(1).unwrap();
    let request = Request::post("/items")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, size)
        .body(Body::from(vec![b' '; size]))
        .unwrap();
    let response = send(request).await;
    assert_problem(response, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large").await;
}

#[tokio::test]
async fn panic_is_a_problem_without_the_message() {
    let response = send(Request::get("/panic").body(Body::empty()).unwrap()).await;
    let (_, body) = assert_problem(response, StatusCode::INTERNAL_SERVER_ERROR, "internal").await;
    assert!(!body.to_string().contains("secret"), "{body}");
    assert!(!body.to_string().contains("panicked"), "{body}");
}

#[tokio::test(start_paused = true)]
async fn timeout_is_a_problem() {
    let response = send(Request::get("/slow").body(Body::empty()).unwrap()).await;
    assert_problem(response, StatusCode::SERVICE_UNAVAILABLE, "unavailable").await;
}

#[tokio::test]
async fn browsers_can_read_error_responses() {
    let request = Request::builder()
        .method(Method::GET)
        .uri("/missing")
        .header(header::ORIGIN, ALLOWED_ORIGIN)
        .body(Body::empty())
        .unwrap();
    let (headers, _) =
        assert_problem(send(request).await, StatusCode::NOT_FOUND, "not_found").await;
    assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], ALLOWED_ORIGIN);
}

#[tokio::test]
async fn successful_responses_are_untouched() {
    let response = send(post_json(r#"{"title": "x"}"#)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"x");
}

/// What a failed write becomes, for real Postgres errors.
#[sqlx::test]
async fn failed_writes_map_to_conflict_not_found_or_database(pool: sqlx::PgPool) {
    let write = |slug: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query!(
                "INSERT INTO organizations (id, slug, name) VALUES ($1, $2, 'Org')",
                uuid::Uuid::new_v4(),
                slug
            )
            .execute(&pool)
            .await
            .map(|_| ())
        }
    };
    // The Default organization already has this slug.
    let duplicate = write("default").await.unwrap_err();
    assert!(matches!(
        AppError::from_write(duplicate),
        AppError::Conflict
    ));
    let missing_user = sqlx::query!(
        "INSERT INTO organization_admins (organization_id, user_id) VALUES ($1, $2)",
        uuid::Uuid::from_u128(1),
        uuid::Uuid::new_v4()
    )
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(matches!(
        AppError::from_write(missing_user),
        AppError::NotFound
    ));
    // Neither: a check constraint stays a database error (a bug: 500).
    let invalid = write("Not A Slug").await.unwrap_err();
    assert!(matches!(
        AppError::from_write(invalid),
        AppError::Database(_)
    ));
    assert!(matches!(
        AppError::from_write(sqlx::Error::PoolTimedOut),
        AppError::Database(sqlx::Error::PoolTimedOut)
    ));
}
