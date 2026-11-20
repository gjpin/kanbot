//! Security headers on every response, and redaction of credential headers.
//!
//! The API serves JSON only, so the policy forbids everything a browser could
//! do with a response besides reading it from `fetch`. A handler that sets one
//! of these headers itself keeps its own value.

use axum::{
    Router,
    http::{HeaderName, HeaderValue, header},
};
use tower_http::{sensitive_headers::SetSensitiveHeadersLayer, set_header::SetResponseHeaderLayer};

/// Responses may carry personal data: never store them in any cache.
pub const CACHE_CONTROL: &str = "no-store";
/// Nothing may load, run or frame a response.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";
pub const REFERRER_POLICY: &str = "no-referrer";
/// One year. No `includeSubDomains`: that is a decision for the whole domain,
/// made where TLS terminates. Browsers ignore the header over plain HTTP.
pub const STRICT_TRANSPORT_SECURITY: &str = "max-age=31536000";
pub const X_CONTENT_TYPE_OPTIONS: &str = "nosniff";

/// Headers that carry credentials. They are marked sensitive so that logging
/// and tracing never record their values.
pub const SENSITIVE_HEADERS: [HeaderName; 3] =
    [header::AUTHORIZATION, header::COOKIE, header::SET_COOKIE];

/// Adds the security headers to every response from `app`.
pub fn add_security_headers(app: Router) -> Router {
    [
        (header::CACHE_CONTROL, CACHE_CONTROL),
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::REFERRER_POLICY, REFERRER_POLICY),
        (header::STRICT_TRANSPORT_SECURITY, STRICT_TRANSPORT_SECURITY),
        (header::X_CONTENT_TYPE_OPTIONS, X_CONTENT_TYPE_OPTIONS),
    ]
    .into_iter()
    .fold(app, |app, (name, value)| {
        app.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ))
    })
}

/// Marks [`SENSITIVE_HEADERS`] as sensitive in requests and responses.
pub fn mark_sensitive_headers(app: Router) -> Router {
    app.layer(SetSensitiveHeadersLayer::new(SENSITIVE_HEADERS))
}
