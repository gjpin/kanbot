//! A JSON client for the API under test, with tokens from the test
//! identity provider.

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use crate::common::idp::access_token;

/// The app under test, called with a bearer token.
#[derive(Clone)]
pub struct Api {
    app: Router,
}

/// A platform admin's token.
#[must_use]
pub fn admin(subject: &str) -> String {
    access_token(subject, &["kanbot-admin"])
}

/// A plain user's token, with extra `groups`.
#[must_use]
pub fn user(subject: &str, groups: &[&str]) -> String {
    let mut all = vec!["kanbot-user"];
    all.extend_from_slice(groups);
    access_token(subject, &all)
}

impl Api {
    /// The full app over `pool`, with the built-in policies.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            app: crate::common::app_with_pool(pool),
        }
    }

    /// `app` as it is.
    #[must_use]
    pub fn of(app: Router) -> Self {
        Self { app }
    }

    /// Sends `body` (if any) as JSON with `token`; the status, and the
    /// body as JSON (`Null` when empty).
    ///
    /// # Panics
    ///
    /// If the request fails or the body is not JSON.
    pub async fn call(
        &self,
        method: Method,
        uri: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, body)
    }

    pub async fn get(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.call(Method::GET, uri, token, None).await
    }

    pub async fn post(&self, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::POST, uri, token, Some(body)).await
    }

    pub async fn patch(&self, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.call(Method::PATCH, uri, token, Some(body)).await
    }

    pub async fn put(&self, uri: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call(Method::PUT, uri, token, body).await
    }

    pub async fn delete(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.call(Method::DELETE, uri, token, None).await
    }

    /// The ID of `token`'s user, signing them in if needed.
    ///
    /// # Panics
    ///
    /// If `/me` fails.
    pub async fn user_id(&self, token: &str) -> Uuid {
        let (status, me) = self.get("/me", token).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        me["id"].as_str().unwrap().parse().unwrap()
    }

    /// Creates an organization as `token`'s user; its ID.
    ///
    /// # Panics
    ///
    /// Unless it is created.
    pub async fn organization(&self, token: &str, slug: &str) -> Uuid {
        let (status, body) = self
            .post(
                "/organizations",
                token,
                serde_json::json!({ "slug": slug, "name": slug }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_str().unwrap().parse().unwrap()
    }

    /// Creates a team as `token`'s user; its ID.
    ///
    /// # Panics
    ///
    /// Unless it is created.
    pub async fn team(&self, token: &str, slug: &str) -> Uuid {
        let (status, body) = self
            .post(
                "/teams",
                token,
                serde_json::json!({ "slug": slug, "name": slug }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_str().unwrap().parse().unwrap()
    }
}
