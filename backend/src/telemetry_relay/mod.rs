//! The telemetry relay: the app sends its OTLP/HTTP telemetry to
//! `/telemetry/v1/{traces,logs,metrics}` on the API, which forwards it to a
//! collector that has no public endpoint.
//!
//! The app cannot hold collector credentials (anything in the app can be
//! extracted), so the relay is what limits abuse: a body size limit, a
//! content type allowlist and a per-client rate limit. The collector should
//! still filter what it accepts (see `backend/otel-collector/`).
//!
//! These routes follow the OTLP/HTTP specification, not the API contract,
//! so they are not part of `openapi.json`.

mod handlers;

use std::{sync::Arc, time::Duration};

use axum::{Router, extract::DefaultBodyLimit, routing::post};
use reqwest::Url;

use crate::http::{client_ip::TrustedProxies, middleware::rate_limit};

/// Largest accepted telemetry batch, in bytes. The app's exporters send a
/// batch every few seconds, well below this.
pub const MAX_BODY_BYTES: usize = 512 * 1024;
/// Burst of requests a client may send at once.
pub const RATE_LIMIT_BURST: u32 = 30;
/// One more request allowed per client every this long (120 per minute).
pub const RATE_LIMIT_PERIOD: Duration = Duration::from_millis(500);
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

/// The relay routes, with their own state, body limit and rate limit,
/// ready to merge into the app before the middleware stack.
///
/// # Errors
///
/// Returns [`RelayError`] if the HTTP client cannot be built.
pub fn routes(upstream: Url, trusted_proxies: Arc<TrustedProxies>) -> Result<Router, RelayError> {
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
    Ok(rate_limit::limit_per_client(
        routes,
        trusted_proxies,
        RATE_LIMIT_PERIOD,
        RATE_LIMIT_BURST,
    )?)
}
