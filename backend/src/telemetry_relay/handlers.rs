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
    // at the collector; the app's exporters do not compress. Every
    // Content-Encoding header counts, not just the first.
    if headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|encoding| !encoding.as_bytes().eq_ignore_ascii_case(b"identity"))
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
        .header(header::CONTENT_TYPE, content_type.clone())
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
    // The answer is passed on only in the request's own OTLP type: the
    // client gets it from kanbot's origin, so an HTML page from a proxy
    // must not be.
    let passed_on = otlp_content_type(response.headers()).filter(|answer| *answer == content_type);
    // In chunks, stopping at the cap: a collector (or proxy) sending a huge
    // or endless body must not fill the memory.
    let mut response = response;
    let mut body = Vec::new();
    let mut too_large = false;
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        tracing::warn!(%error, signal, "telemetry collector response failed");
        AppError::Unavailable
    })? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            too_large = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(match passed_on {
        Some(content_type) if !too_large => {
            (status, [(header::CONTENT_TYPE, content_type)], body).into_response()
        }
        _ => status.into_response(),
    })
}

/// The OTLP/HTTP content type of a request or response: protobuf or JSON,
/// ignoring parameters and case. `None` for anything else, and for more
/// than one Content-Type header.
fn otlp_content_type(headers: &HeaderMap) -> Option<HeaderValue> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let media_type = value
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
