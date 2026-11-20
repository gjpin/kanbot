//! Error types: [`AppError`] for request handling, [`StartupError`] for
//! bringing the server up.

use std::borrow::Cow;

use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    cli::UsageError,
    config::ConfigError,
    http::problem::{ErrorCode, Problem},
};

/// Every handler returns `Result<_, AppError>`. The response is a problem
/// details body (see [`crate::http::problem`]) with a stable `code`; the
/// underlying error is logged, never sent to the client.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// The request is malformed in a way no field error describes.
    #[error("bad request")]
    BadRequest,
    /// No valid credentials.
    #[error("unauthorized")]
    Unauthorized,
    /// Valid credentials, but not allowed to do this.
    #[error("forbidden")]
    Forbidden,
    /// The resource does not exist, or the caller may not know it exists.
    #[error("not found")]
    NotFound,
    /// The request conflicts with the current state (a duplicate, a stale
    /// version).
    #[error("conflict")]
    Conflict,
    /// One or more fields are invalid.
    #[error("validation failed")]
    Validation(Vec<FieldError>),
    /// The request body's content type or encoding is not accepted.
    #[error("unsupported media type")]
    UnsupportedMediaType,
    /// The service cannot handle requests yet (or right now). Retrying later
    /// may work.
    #[error("service unavailable")]
    Unavailable,
    #[error("database error")]
    Database(#[from] sqlx::Error),
}

/// One invalid field of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct FieldError {
    /// JSON Pointer (RFC 6901) to the field in the request body, for example
    /// `/title` or `/labels/2`.
    #[schema(value_type = String)]
    pub pointer: Cow<'static, str>,
    /// Why it is invalid, as a stable `snake_case` code (`too_long`,
    /// `required`, ...). Never the invalid value itself.
    pub code: &'static str,
}

impl FieldError {
    #[must_use]
    pub fn new(pointer: impl Into<Cow<'static, str>>, code: &'static str) -> Self {
        Self {
            pointer: pointer.into(),
            code,
        }
    }
}

impl AppError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::BadRequest => ErrorCode::BadRequest,
            Self::Unauthorized => ErrorCode::Unauthorized,
            Self::Forbidden => ErrorCode::Forbidden,
            Self::NotFound => ErrorCode::NotFound,
            Self::Conflict => ErrorCode::Conflict,
            Self::Validation(_) => ErrorCode::ValidationFailed,
            Self::UnsupportedMediaType => ErrorCode::UnsupportedMediaType,
            // The database is unreachable or overloaded, or the service is
            // not ready: retrying later may work.
            Self::Database(
                sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_),
            )
            | Self::Unavailable => ErrorCode::Unavailable,
            // Anything else (a failed query, a decode error) is a bug.
            Self::Database(_) => ErrorCode::Internal,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = self.code();
        if code.status().is_server_error() {
            tracing::error!(error = ?self, ?code, "request failed");
        } else {
            tracing::debug!(?code, "request rejected");
        }
        match self {
            Self::Validation(errors) => Problem::validation(errors),
            _ => Problem::new(code),
        }
        .into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("invalid arguments")]
    Usage(#[from] UsageError),
    #[error("invalid configuration")]
    Config(#[from] ConfigError),
    #[error("invalid database options")]
    Database(#[from] sqlx::Error),
    #[error("failed to start the async runtime")]
    Runtime(#[source] std::io::Error),
    #[error("failed to bind the listener")]
    Bind(#[source] std::io::Error),
    #[error("server error")]
    Serve(#[source] std::io::Error),
    #[error("migration failed")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("failed to set up telemetry")]
    Telemetry(#[from] crate::telemetry::TelemetryError),
    #[error("failed to set up the telemetry relay")]
    Relay(#[from] crate::telemetry_relay::RelayError),
    #[error("failed to build the identity provider's HTTP client")]
    IdpClient(#[source] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use axum::http::{StatusCode, header};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};

    use super::*;
    use crate::http::problem::PROBLEM_JSON;

    async fn problem(error: AppError) -> (StatusCode, Value) {
        let response = error.into_response();
        assert_eq!(response.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn each_error_has_its_status_and_code() {
        for (error, status, code) in [
            (AppError::BadRequest, 400, "bad_request"),
            (AppError::Unauthorized, 401, "unauthorized"),
            (AppError::Forbidden, 403, "forbidden"),
            (AppError::NotFound, 404, "not_found"),
            (AppError::Conflict, 409, "conflict"),
            (AppError::Validation(vec![]), 422, "validation_failed"),
            (
                AppError::UnsupportedMediaType,
                415,
                "unsupported_media_type",
            ),
            (AppError::Unavailable, 503, "unavailable"),
        ] {
            let (actual_status, body) = problem(error).await;
            assert_eq!(actual_status.as_u16(), status, "{code}");
            assert_eq!(body["status"], status, "{code}");
            assert_eq!(body["code"], code);
        }
    }

    #[tokio::test]
    async fn unreachable_database_is_unavailable() {
        for error in [
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
            sqlx::Error::Io(std::io::Error::other("connection reset")),
        ] {
            let (status, body) = problem(AppError::Database(error)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["code"], "unavailable");
        }
    }

    #[tokio::test]
    async fn other_database_errors_are_internal_and_not_leaked() {
        for error in [
            sqlx::Error::RowNotFound,
            sqlx::Error::ColumnNotFound("secret_column".to_owned()),
        ] {
            let (status, body) = problem(AppError::Database(error)).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(body["code"], "internal");
            assert!(!body.to_string().contains("secret_column"), "{body}");
        }
    }

    #[tokio::test]
    async fn validation_lists_the_invalid_fields() {
        let (_, body) = problem(AppError::Validation(vec![
            FieldError::new("/title", "too_long"),
            FieldError::new(format!("/labels/{}", 2), "required"),
        ]))
        .await;

        assert_eq!(
            body["errors"],
            json!([
                { "pointer": "/title", "code": "too_long" },
                { "pointer": "/labels/2", "code": "required" },
            ])
        );
    }
}
