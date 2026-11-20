//! Forwarding one OTLP/HTTP export request to the collector.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};

use super::Relay;
use crate::{error::AppError, http::extract::AuthUser, users::model::AuthenticatedUser};

/// Largest collector response passed back to the client. OTLP responses
/// are tiny (an optional partial-success message).
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

pub(super) async fn traces(
    State(relay): State<Relay>,
    AuthUser(user): AuthUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    consented(&user)?;
    forward(&relay, "traces", &headers, body).await
}

pub(super) async fn logs(
    State(relay): State<Relay>,
    AuthUser(user): AuthUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    consented(&user)?;
    forward(&relay, "logs", &headers, body).await
}

pub(super) async fn metrics(
    State(relay): State<Relay>,
    AuthUser(user): AuthUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    consented(&user)?;
    forward(&relay, "metrics", &headers, body).await
}

/// Only users who opted in may send telemetry.
fn consented(user: &AuthenticatedUser) -> Result<(), AppError> {
    if user.telemetry_opt_in {
        Ok(())
    } else {
        Err(AppError::TelemetryDisabled)
    }
}

/// Sends `body` to `<upstream>/v1/<signal>` with only its content type: no
/// client headers (cookies, tokens) reach the collector.
///
/// A collector that rejects the data gets the client a `400`; one that is
/// unreachable, overloaded or slow gets it a `503`, which OTLP exporters
/// retry with backoff.
async fn forward(
    relay: &Relay,
    signal: &'static str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let content_type = otlp_content_type(headers).ok_or(AppError::UnsupportedMediaType)?;
    // Compressed bodies would let a small request expand into a large one
    // at the collector; the app's exporters do not compress.
    if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|encoding| encoding != "identity")
    {
        return Err(AppError::UnsupportedMediaType);
    }

    let url = format!(
        "{}/v1/{signal}",
        relay.upstream.as_str().trim_end_matches('/')
    );
    let response = relay
        .client
        .post(url)
        .header(header::CONTENT_TYPE, content_type)
        .body(body)
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, signal, "telemetry collector unreachable");
            AppError::Unavailable
        })?;

    let status = response.status();
    if !status.is_success() {
        tracing::warn!(%status, signal, "telemetry collector refused a batch");
        return Err(
            if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
                AppError::BadRequest
            } else {
                AppError::Unavailable
            },
        );
    }
    let response_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let body = response.bytes().await.map_err(|error| {
        tracing::warn!(%error, signal, "telemetry collector response failed");
        AppError::Unavailable
    })?;
    let body = if body.len() > MAX_RESPONSE_BYTES {
        Bytes::new()
    } else {
        body
    };
    let mut response = (status, body).into_response();
    if let Some(response_type) = response_type {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, response_type);
    }
    Ok(response)
}

/// The OTLP/HTTP content type of the request: protobuf or JSON, ignoring
/// parameters and case.
fn otlp_content_type(headers: &HeaderMap) -> Option<HeaderValue> {
    let media_type = headers
        .get(header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    match media_type.as_str() {
        "application/x-protobuf" => Some(HeaderValue::from_static("application/x-protobuf")),
        "application/json" => Some(HeaderValue::from_static("application/json")),
        _ => None,
    }
}
