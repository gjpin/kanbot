//! Error types: [`AppError`] for request handling, [`StartupError`] for
//! bringing the server up.

use std::borrow::Cow;

use axum::{
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
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
    /// No credentials. The response asks for a bearer token.
    #[error("unauthorized")]
    Unauthorized,
    /// Credentials were presented but are not valid (RFC 6750
    /// `invalid_token`). Never says why.
    #[error("invalid token")]
    InvalidToken,
    /// Valid credentials, but not allowed to do this.
    #[error("forbidden")]
    Forbidden,
    /// Valid credentials of a user who has been disabled in kanbot.
    #[error("account disabled")]
    AccountDisabled,
    /// The user has not opted in to sending telemetry.
    #[error("telemetry disabled")]
    TelemetryDisabled,
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
    /// A failure that is a bug or a broken host (no randomness, a
    /// cipher error), named for the log.
    #[error("internal error: {0}")]
    Internal(&'static str),
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
            Self::Unauthorized | Self::InvalidToken => ErrorCode::Unauthorized,
            Self::Forbidden => ErrorCode::Forbidden,
            Self::AccountDisabled => ErrorCode::AccountDisabled,
            Self::TelemetryDisabled => ErrorCode::TelemetryDisabled,
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
            Self::Database(_) | Self::Internal(_) => ErrorCode::Internal,
        }
    }
}

impl AppError {
    /// A failed write: a unique violation (a duplicate slug) is a
    /// [`AppError::Conflict`], a foreign key violation (the user or team it
    /// refers to does not exist) is [`AppError::NotFound`], anything else a
    /// database error.
    #[must_use]
    pub fn from_write(error: sqlx::Error) -> Self {
        match error.as_database_error() {
            Some(database) if database.is_unique_violation() => Self::Conflict,
            Some(database) if database.is_foreign_key_violation() => Self::NotFound,
            _ => Self::Database(error),
        }
    }
}

impl AppError {
    /// What may be logged about the error: its kind, and for a database
    /// error its SQLSTATE and constraint name. Never the error's message
    /// or `Debug` form: Postgres puts row values in them (`Key
    /// (subject)=(...) already exists`).
    /// The error's kind, safe to log (see [`AppError::log_kind`]).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.log_kind()
    }

    fn log_kind(&self) -> &'static str {
        match self {
            Self::Database(error) => match error {
                sqlx::Error::Configuration(_) => "database.configuration",
                sqlx::Error::InvalidArgument(_) => "database.invalid_argument",
                sqlx::Error::Database(_) => "database.database",
                sqlx::Error::Io(_) => "database.io",
                sqlx::Error::Tls(_) => "database.tls",
                sqlx::Error::Protocol(_) => "database.protocol",
                sqlx::Error::RowNotFound => "database.row_not_found",
                sqlx::Error::TypeNotFound { .. } => "database.type_not_found",
                sqlx::Error::ColumnIndexOutOfBounds { .. } => "database.column_index_out_of_bounds",
                sqlx::Error::ColumnNotFound(_) => "database.column_not_found",
                sqlx::Error::ColumnDecode { .. } => "database.column_decode",
                sqlx::Error::Encode(_) => "database.encode",
                sqlx::Error::Decode(_) => "database.decode",
                sqlx::Error::PoolTimedOut => "database.pool_timed_out",
                sqlx::Error::PoolClosed => "database.pool_closed",
                sqlx::Error::WorkerCrashed => "database.worker_crashed",
                sqlx::Error::Migrate(_) => "database.migrate",
                _ => "database.other",
            },
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::InvalidToken => "invalid_token",
            Self::Forbidden => "forbidden",
            Self::AccountDisabled => "account_disabled",
            Self::TelemetryDisabled => "telemetry_disabled",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Validation(_) => "validation",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::Unavailable => "unavailable",
            Self::Internal(what) => what,
        }
    }

    fn database_details(&self) -> (Option<String>, Option<String>) {
        match self {
            Self::Database(sqlx::Error::Database(error)) => (
                error.code().map(Cow::into_owned),
                error.constraint().map(str::to_owned),
            ),
            _ => (None, None),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = self.code();
        if code.status().is_server_error() {
            let (sqlstate, constraint) = self.database_details();
            tracing::error!(
                error.type = self.log_kind(),
                db.response.status_code = sqlstate,
                db.constraint = constraint,
                ?code,
                "request failed"
            );
        } else {
            tracing::debug!(?code, "request rejected");
        }
        let challenge = match &self {
            Self::Unauthorized => Some(HeaderValue::from_static("Bearer")),
            Self::InvalidToken => Some(HeaderValue::from_static(r#"Bearer error="invalid_token""#)),
            _ => None,
        };
        let mut response = match self {
            Self::Validation(errors) => Problem::validation(errors),
            _ => Problem::new(code),
        }
        .into_response();
        if let Some(challenge) = challenge {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, challenge);
        }
        response
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
    #[error("invalid rate limit")]
    RateLimit(#[from] crate::http::middleware::rate_limit::InvalidRateLimit),
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
            (AppError::InvalidToken, 401, "unauthorized"),
            (AppError::Forbidden, 403, "forbidden"),
            (AppError::AccountDisabled, 403, "account_disabled"),
            (AppError::TelemetryDisabled, 403, "telemetry_disabled"),
            (AppError::NotFound, 404, "not_found"),
            (AppError::Conflict, 409, "conflict"),
            (AppError::Validation(vec![]), 422, "validation_failed"),
            (
                AppError::UnsupportedMediaType,
                415,
                "unsupported_media_type",
            ),
            (AppError::Unavailable, 503, "unavailable"),
            (AppError::Internal("crypto"), 500, "internal"),
        ] {
            let (actual_status, body) = problem(error).await;
            assert_eq!(actual_status.as_u16(), status, "{code}");
            assert_eq!(body["status"], status, "{code}");
            assert_eq!(body["code"], code);
        }
    }

    #[test]
    fn unauthorized_responses_challenge_for_a_bearer_token() {
        let challenge = |error: AppError| {
            error
                .into_response()
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .cloned()
        };
        assert_eq!(challenge(AppError::Unauthorized).unwrap(), "Bearer");
        assert_eq!(
            challenge(AppError::InvalidToken).unwrap(),
            r#"Bearer error="invalid_token""#
        );
        assert_eq!(challenge(AppError::Forbidden), None);
        assert_eq!(challenge(AppError::AccountDisabled), None);
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

    /// A Postgres-style unique violation whose message holds a row value.
    #[derive(Debug)]
    struct UniqueViolation;

    impl std::fmt::Display for UniqueViolation {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("duplicate key: Key (subject)=(alice-secret) already exists")
        }
    }

    impl std::error::Error for UniqueViolation {}

    impl sqlx::error::DatabaseError for UniqueViolation {
        fn message(&self) -> &'static str {
            "duplicate key: Key (subject)=(alice-secret) already exists"
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed("23505"))
        }
        fn constraint(&self) -> Option<&str> {
            Some("users_issuer_subject_key")
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::UniqueViolation
        }
    }

    /// What `into_response` logs for `error`, as formatted text.
    fn logged(error: AppError) -> String {
        #[derive(Clone, Default)]
        struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || drop(error.into_response()));
        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn logs_database_errors_without_row_values() {
        let log = logged(AppError::Database(sqlx::Error::Database(Box::new(
            UniqueViolation,
        ))));
        assert!(log.contains("database.database"), "{log}");
        assert!(log.contains("23505"), "{log}");
        assert!(log.contains("users_issuer_subject_key"), "{log}");
        assert!(!log.contains("alice-secret"), "{log}");
        assert!(!log.contains("duplicate key"), "{log}");
    }

    #[test]
    fn logs_other_database_errors_by_kind_only() {
        let log = logged(AppError::Database(sqlx::Error::ColumnNotFound(
            "secret_column".to_owned(),
        )));
        assert!(log.contains("database.column_not_found"), "{log}");
        assert!(!log.contains("secret_column"), "{log}");
        let log = logged(AppError::Database(sqlx::Error::Protocol(
            "row value".to_owned(),
        )));
        assert!(log.contains("database.protocol"), "{log}");
        assert!(!log.contains("row value"), "{log}");
    }

    #[test]
    fn kind_is_the_logged_kind() {
        assert_eq!(AppError::Unavailable.kind(), "unavailable");
        assert_eq!(
            AppError::Database(sqlx::Error::PoolTimedOut).kind(),
            "database.pool_timed_out"
        );
    }

    #[test]
    fn names_each_error_kind() {
        for (error, kind) in [
            (AppError::BadRequest, "bad_request"),
            (AppError::Unauthorized, "unauthorized"),
            (AppError::Forbidden, "forbidden"),
            (AppError::AccountDisabled, "account_disabled"),
            (AppError::TelemetryDisabled, "telemetry_disabled"),
            (AppError::InvalidToken, "invalid_token"),
            (AppError::NotFound, "not_found"),
            (AppError::Conflict, "conflict"),
            (AppError::Validation(vec![]), "validation"),
            (AppError::UnsupportedMediaType, "unsupported_media_type"),
            (AppError::Unavailable, "unavailable"),
            (AppError::Internal("randomness"), "randomness"),
            (
                AppError::Database(sqlx::Error::RowNotFound),
                "database.row_not_found",
            ),
            (
                AppError::Database(sqlx::Error::PoolTimedOut),
                "database.pool_timed_out",
            ),
            (
                AppError::Database(sqlx::Error::PoolClosed),
                "database.pool_closed",
            ),
            (
                AppError::Database(sqlx::Error::WorkerCrashed),
                "database.worker_crashed",
            ),
            (
                AppError::Database(sqlx::Error::Io(std::io::Error::other("x"))),
                "database.io",
            ),
            (
                AppError::Database(sqlx::Error::Decode("x".into())),
                "database.decode",
            ),
            (
                AppError::Database(sqlx::Error::Encode("x".into())),
                "database.encode",
            ),
            (
                AppError::Database(sqlx::Error::TypeNotFound {
                    type_name: "x".to_owned(),
                }),
                "database.type_not_found",
            ),
            (
                AppError::Database(sqlx::Error::ColumnIndexOutOfBounds { index: 1, len: 0 }),
                "database.column_index_out_of_bounds",
            ),
            (
                AppError::Database(sqlx::Error::Configuration("x".into())),
                "database.configuration",
            ),
            (
                AppError::Database(sqlx::Error::InvalidArgument("x".to_owned())),
                "database.invalid_argument",
            ),
            (
                AppError::Database(sqlx::Error::Tls("x".into())),
                "database.tls",
            ),
            (
                AppError::Database(sqlx::Error::ColumnDecode {
                    index: "0".to_owned(),
                    source: "x".into(),
                }),
                "database.column_decode",
            ),
            (
                AppError::Database(sqlx::Error::Migrate(Box::new(
                    sqlx::migrate::MigrateError::VersionMissing(1),
                ))),
                "database.migrate",
            ),
            (
                AppError::Database(sqlx::Error::InvalidSavePointStatement),
                "database.other",
            ),
        ] {
            assert_eq!(error.log_kind(), kind);
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
