//! RFC 9457 problem details: the body of every error response.
//!
//! ```json
//! {
//!   "type": "urn:kanbot:problem:validation_failed",
//!   "title": "Validation failed",
//!   "status": 422,
//!   "code": "validation_failed",
//!   "errors": [{ "pointer": "/title", "code": "too_long" }]
//! }
//! ```
//!
//! Clients switch on `code`. A problem never carries free-form details: no
//! echo of the input, no SQL errors, no messages from libraries.

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use opentelemetry::trace::TraceContextExt;
use serde::Serialize;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use utoipa::ToSchema;

use crate::error::FieldError;

/// Content type of a problem details body.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// Stable, machine-readable error codes. Clients depend on these strings:
/// add new codes, but never rename or reuse one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    PayloadTooLarge,
    UnsupportedMediaType,
    ValidationFailed,
    RateLimited,
    Internal,
    Unavailable,
}

impl ErrorCode {
    /// The status a response with this code carries, unless it was derived
    /// from another status (see [`ErrorCode::for_status`]).
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Conflict => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::ValidationFailed => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The code for an error response that did not come from [`AppError`]
    /// (an axum rejection, a middleware, a panic). Unknown client errors are
    /// `bad_request`; unknown server errors are `internal`, except gateway
    /// failures, which are temporary.
    ///
    /// [`AppError`]: crate::error::AppError
    #[must_use]
    pub fn for_status(status: StatusCode) -> Self {
        match status {
            StatusCode::UNAUTHORIZED => Self::Unauthorized,
            StatusCode::FORBIDDEN => Self::Forbidden,
            StatusCode::NOT_FOUND => Self::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => Self::MethodNotAllowed,
            StatusCode::CONFLICT => Self::Conflict,
            StatusCode::PAYLOAD_TOO_LARGE => Self::PayloadTooLarge,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Self::UnsupportedMediaType,
            StatusCode::UNPROCESSABLE_ENTITY => Self::ValidationFailed,
            StatusCode::TOO_MANY_REQUESTS => Self::RateLimited,
            StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => Self::Unavailable,
            status if status.is_server_error() => Self::Internal,
            _ => Self::BadRequest,
        }
    }

    /// A short, fixed, human-readable summary. Not localized: clients show
    /// their own message for each code.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::BadRequest => "Bad request",
            Self::Unauthorized => "Authentication required",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not found",
            Self::MethodNotAllowed => "Method not allowed",
            Self::Conflict => "Conflict",
            Self::PayloadTooLarge => "Request body too large",
            Self::UnsupportedMediaType => "Unsupported media type",
            Self::ValidationFailed => "Validation failed",
            Self::RateLimited => "Too many requests",
            Self::Internal => "Internal error",
            Self::Unavailable => "Service unavailable",
        }
    }

    const fn type_uri(self) -> &'static str {
        match self {
            Self::BadRequest => "urn:kanbot:problem:bad_request",
            Self::Unauthorized => "urn:kanbot:problem:unauthorized",
            Self::Forbidden => "urn:kanbot:problem:forbidden",
            Self::NotFound => "urn:kanbot:problem:not_found",
            Self::MethodNotAllowed => "urn:kanbot:problem:method_not_allowed",
            Self::Conflict => "urn:kanbot:problem:conflict",
            Self::PayloadTooLarge => "urn:kanbot:problem:payload_too_large",
            Self::UnsupportedMediaType => "urn:kanbot:problem:unsupported_media_type",
            Self::ValidationFailed => "urn:kanbot:problem:validation_failed",
            Self::RateLimited => "urn:kanbot:problem:rate_limited",
            Self::Internal => "urn:kanbot:problem:internal",
            Self::Unavailable => "urn:kanbot:problem:unavailable",
        }
    }
}

/// A problem details body (RFC 9457), with the `code` and `errors`
/// extension members.
#[derive(Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct Problem {
    /// `urn:kanbot:problem:<code>`.
    #[serde(rename = "type")]
    #[schema(example = "urn:kanbot:problem:not_found")]
    pub type_uri: &'static str,
    pub title: &'static str,
    /// Always the status of the response that carries the problem.
    pub status: u16,
    pub code: ErrorCode,
    /// The invalid fields of a `validation_failed` problem.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(required = false)]
    pub errors: Vec<FieldError>,
    /// The W3C trace id of the request (32 hex digits), when telemetry is
    /// on. Lets support find the request's trace and logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false, example = "4bf92f3577b34da6a3ce929d0e0e4736")]
    pub trace_id: Option<String>,
}

impl Problem {
    /// A problem with `code`, sent with the code's own status.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self::with_status(code, code.status())
    }

    /// A problem for an error response with `status` that has no body of
    /// its own.
    #[must_use]
    pub fn for_status(status: StatusCode) -> Self {
        Self::with_status(ErrorCode::for_status(status), status)
    }

    fn with_status(code: ErrorCode, status: StatusCode) -> Self {
        Self {
            type_uri: code.type_uri(),
            title: code.title(),
            status: status.as_u16(),
            code,
            errors: Vec::new(),
            trace_id: current_trace_id(),
        }
    }

    /// A `validation_failed` problem listing the invalid fields.
    #[must_use]
    pub fn validation(errors: Vec<FieldError>) -> Self {
        Self {
            errors,
            ..Self::new(ErrorCode::ValidationFailed)
        }
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = self.status_code();
        match serde_json::to_vec(&self) {
            Ok(body) => (
                status,
                [(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON))],
                body,
            )
                .into_response(),
            Err(error) => {
                // Unreachable for these field types; never fail to answer.
                tracing::error!(%error, "failed to serialize a problem");
                status.into_response()
            }
        }
    }
}

/// Middleware (`axum::middleware::map_response`): gives every error response
/// that is not already a problem a problem body for its status, so clients
/// see one error format. Replaces bodies written by axum rejections (which
/// can echo parts of the request), the default 404 and 405, the body limit,
/// the timeout and the panic handler. Headers such as `Allow` are kept.
pub async fn ensure_problem_body(response: Response) -> Response {
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) || is_problem(&response) {
        return response;
    }
    let (mut parts, _) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    let (problem_parts, body) = Problem::for_status(status).into_response().into_parts();
    parts.headers.extend(problem_parts.headers);
    Response::from_parts(parts, Body::new(body))
}

/// The trace id of the current request span, if it is part of a trace.
fn current_trace_id() -> Option<String> {
    let context = tracing::Span::current().context();
    let span = context.span();
    let span_context = span.span_context();
    span_context
        .is_valid()
        .then(|| span_context.trace_id().to_string())
}

fn is_problem(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value == PROBLEM_JSON)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const ALL_CODES: [ErrorCode; 12] = [
        ErrorCode::BadRequest,
        ErrorCode::Unauthorized,
        ErrorCode::Forbidden,
        ErrorCode::NotFound,
        ErrorCode::MethodNotAllowed,
        ErrorCode::Conflict,
        ErrorCode::PayloadTooLarge,
        ErrorCode::UnsupportedMediaType,
        ErrorCode::ValidationFailed,
        ErrorCode::RateLimited,
        ErrorCode::Internal,
        ErrorCode::Unavailable,
    ];

    #[test]
    fn every_code_round_trips_through_its_status() {
        for code in ALL_CODES {
            assert_eq!(ErrorCode::for_status(code.status()), code, "{code:?}");
        }
    }

    #[test]
    fn type_uri_and_wire_code_match() {
        for code in ALL_CODES {
            let wire = serde_json::to_value(code).unwrap();
            let wire = wire.as_str().unwrap();
            assert_eq!(code.type_uri(), format!("urn:kanbot:problem:{wire}"));
        }
    }

    #[test]
    fn unknown_statuses_get_generic_codes() {
        for (status, code) in [
            (StatusCode::NOT_ACCEPTABLE, ErrorCode::BadRequest),
            (StatusCode::URI_TOO_LONG, ErrorCode::BadRequest),
            (StatusCode::BAD_GATEWAY, ErrorCode::Unavailable),
            (StatusCode::GATEWAY_TIMEOUT, ErrorCode::Unavailable),
            (StatusCode::NOT_IMPLEMENTED, ErrorCode::Internal),
        ] {
            assert_eq!(ErrorCode::for_status(status), code, "{status}");
        }
    }

    #[test]
    fn serializes_to_the_documented_shape() {
        let problem = Problem::validation(vec![FieldError::new("/title", "too_long")]);

        assert_eq!(
            serde_json::to_value(&problem).unwrap(),
            json!({
                "type": "urn:kanbot:problem:validation_failed",
                "title": "Validation failed",
                "status": 422,
                "code": "validation_failed",
                "errors": [{ "pointer": "/title", "code": "too_long" }],
            })
        );
    }

    #[test]
    fn omits_empty_errors() {
        let value = serde_json::to_value(Problem::new(ErrorCode::NotFound)).unwrap();
        assert_eq!(value.get("errors"), None::<&Value>);
    }

    #[test]
    fn for_status_keeps_the_actual_status() {
        let problem = Problem::for_status(StatusCode::NOT_ACCEPTABLE);
        assert_eq!(problem.status, 406);
        assert_eq!(problem.code, ErrorCode::BadRequest);
    }
}
