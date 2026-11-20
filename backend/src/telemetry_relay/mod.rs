//! The telemetry relay: the app sends its OTLP/HTTP telemetry to
//! `/telemetry/v1/{traces,logs,metrics}` on the API, which forwards it to a
//! collector that has no public endpoint.
//!
//! The app cannot hold collector credentials (anything in the app can be
//! extracted), so the relay is what limits abuse: only authenticated users
//! who opted in (`users.telemetry_opt_in`) may send, with a body size limit,
//! a content type allowlist and a per-user rate limit. The relay never adds
//! the user's identity to what it forwards. The collector should still
//! filter what it accepts (see `backend/otel-collector/`).
//!
//! These routes follow the OTLP/HTTP specification, not the API contract,
//! so they are not part of `openapi.json`.

mod handlers;

use std::time::Duration;

use axum::{Router, extract::DefaultBodyLimit, routing::post};
use reqwest::Url;

use crate::http::middleware::rate_limit::{self, RateLimit};

/// Largest accepted telemetry batch, in bytes. The app's exporters send a
/// batch every few seconds, well below this.
pub const MAX_BODY_BYTES: usize = 512 * 1024;
/// Limit for the whole upstream request, including the response body.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("failed to build the upstream HTTP client")]
    Client(#[from] reqwest::Error),
    #[error(transparent)]
    RateLimit(#[from] rate_limit::InvalidRateLimit),
}

/// Forwards to the collector at `upstream`.
#[derive(Clone)]
struct Relay {
    client: reqwest::Client,
    upstream: Url,
}

/// The relay routes, with their own state, body limit and per-user rate
/// limit (`RATE_LIMIT_TELEMETRY_*`), ready to merge into the app before the
/// authentication middleware and the middleware stack.
///
/// # Errors
///
/// Returns [`RelayError`] if the HTTP client cannot be built or the limit's
/// period rounds to zero.
pub fn routes(upstream: Url, limit: RateLimit) -> Result<Router, RelayError> {
    let relay = Relay {
        client: reqwest::Client::builder()
            .timeout(UPSTREAM_TIMEOUT)
            .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        upstream,
    };
    let routes = Router::new()
        .route("/telemetry/v1/traces", post(handlers::traces))
        .route("/telemetry/v1/logs", post(handlers::logs))
        .route("/telemetry/v1/metrics", post(handlers::metrics))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(relay);
    Ok(rate_limit::limit_per_user(routes, limit)?)
}
