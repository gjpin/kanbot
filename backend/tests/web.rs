//! Serving the Flutter web build (`WEB_DIR`) next to the API.

pub mod common;

use std::path::PathBuf;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use kanbot_backend::{
    db,
    http::{HttpSettings, web::WEB_CONTENT_SECURITY_POLICY},
    state::AppState,
};
use sqlx::postgres::PgConnectOptions;
use tower::ServiceExt;

/// A web build in a temporary directory.
struct WebDir(PathBuf);

impl WebDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("kanbot-web-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(
            dir.join("index.html"),
            "<!doctype html><title>kanbot</title>",
        )
        .unwrap();
        std::fs::write(dir.join("main.dart.js"), "console.log(1)").unwrap();
        std::fs::write(dir.join("assets/data.json"), "{}").unwrap();
        Self(dir)
    }
}

impl Drop for WebDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn app(web_dir: Option<&WebDir>) -> Router {
    let options = PgConnectOptions::new_without_pgpass()
        .host("127.0.0.1")
        .port(1);
    common::serve(
        AppState {
            db: db::pool_with(options),
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
            sessions: common::session_config(),
            authz: common::policies(),
            openshell: None,
        },
        HttpSettings {
            web_dir: web_dir.map(|dir| dir.0.clone()),
            ..HttpSettings::new()
        },
        None,
    )
}

async fn get(app: &Router, method: Method, path: &str, accept: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::ACCEPT, accept)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn header_of(response: &Response, name: header::HeaderName) -> &str {
    response.headers()[name].to_str().unwrap()
}

const HTML: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

#[tokio::test]
async fn serves_the_app_with_its_policy_and_no_caching() {
    let dir = WebDir::new();
    let app = app(Some(&dir));
    for path in [
        "/",
        "/index.html",
        "/boards/42",
        "/login?error=login_failed",
    ] {
        let response = get(&app, Method::GET, path, HTML).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(header_of(&response, header::CONTENT_TYPE).starts_with("text/html"));
        assert_eq!(header_of(&response, header::CACHE_CONTROL), "no-store");
        assert_eq!(
            header_of(&response, header::CONTENT_SECURITY_POLICY),
            WEB_CONTENT_SECURITY_POLICY
        );
        assert_eq!(
            header_of(&response, header::X_CONTENT_TYPE_OPTIONS),
            "nosniff"
        );
        assert!(
            body(response).await.contains("<title>kanbot</title>"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn serves_other_files_with_revalidation() {
    let dir = WebDir::new();
    let app = app(Some(&dir));
    for (path, content_type, contents) in [
        ("/main.dart.js", "text/javascript", "console.log(1)"),
        ("/assets/data.json", "application/json", "{}"),
    ] {
        let response = get(&app, Method::GET, path, "*/*").await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(header_of(&response, header::CONTENT_TYPE).starts_with(content_type));
        assert_eq!(header_of(&response, header::CACHE_CONTROL), "no-cache");
        assert!(response.headers().contains_key(header::LAST_MODIFIED));
        assert_eq!(
            header_of(&response, header::CONTENT_SECURITY_POLICY),
            "default-src 'none'; frame-ancestors 'none'"
        );
        assert_eq!(body(response).await, contents);
    }
    let head = get(&app, Method::HEAD, "/main.dart.js", "*/*").await;
    assert_eq!(head.status(), StatusCode::OK);
}

#[tokio::test]
async fn api_routes_and_non_html_requests_stay_the_api() {
    let dir = WebDir::new();
    let app = app(Some(&dir));
    let response = get(&app, Method::GET, "/me", HTML).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = get(&app, Method::GET, "/health", "*/*").await;
    assert_eq!(body(response).await, "ok");
    for (method, path, accept) in [
        (Method::GET, "/no-such-route", "application/json"),
        (Method::GET, "/missing.js", "*/*"),
        (Method::POST, "/boards/42", HTML),
        (Method::GET, "/../Cargo.toml", "application/json"),
    ] {
        let response = get(&app, method.clone(), path, accept).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(
            header_of(&response, header::CONTENT_TYPE),
            "application/problem+json"
        );
    }
}

#[tokio::test]
async fn files_outside_the_web_dir_are_never_served() {
    let dir = WebDir::new();
    let app = app(Some(&dir));
    for path in [
        "/../Cargo.toml",
        "/%2e%2e/Cargo.toml",
        "/assets/../../Cargo.toml",
    ] {
        let response = get(&app, Method::GET, path, "*/*").await;
        assert_ne!(response.status(), StatusCode::OK, "{path}");
        let response = get(&app, Method::GET, path, HTML).await;
        assert!(!body(response).await.contains("[package]"), "{path}");
    }
}

#[tokio::test]
async fn without_a_web_dir_nothing_is_served() {
    let response = get(&app(None), Method::GET, "/", HTML).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unchanged_files_are_revalidated_with_304() {
    let dir = WebDir::new();
    let app = app(Some(&dir));
    let first = get(&app, Method::GET, "/main.dart.js", "*/*").await;
    let modified = header_of(&first, header::LAST_MODIFIED).to_owned();

    let response = app
        .clone()
        .oneshot(
            Request::get("/main.dart.js")
                .header(header::IF_MODIFIED_SINCE, modified)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(header_of(&response, header::CACHE_CONTROL), "no-cache");
}
