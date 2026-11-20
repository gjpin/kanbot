//! Per-client rate limiting (`tower_governor`), keyed by the client IP
//! address from [`crate::http::client_ip`].
//!
//! Requires the server to provide `ConnectInfo<SocketAddr>`
//! (`into_make_service_with_connect_info`), which `kanbot_backend::run`
//! does. Rejected requests get a `429` problem with `Retry-After`.

use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    extract::ConnectInfo,
    http::{HeaderValue, Request, header},
    response::{IntoResponse, Response},
};
use tower_governor::{
    GovernorError, GovernorLayer, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
};

use crate::http::{
    client_ip::{TrustedProxies, client_ip},
    problem::{ErrorCode, Problem},
};

/// A configured limit: `per_second` requests on average, with bursts of up
/// to `burst`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    pub per_second: NonZeroU32,
    pub burst: NonZeroU32,
}

impl RateLimit {
    const fn new(per_second: u32, burst: u32) -> Self {
        Self {
            per_second: nonzero(per_second),
            burst: nonzero(burst),
        }
    }

    /// How long it takes to earn back one request.
    #[must_use]
    pub fn period(self) -> Duration {
        Duration::from_secs(1)
            .checked_div(self.per_second.get())
            .unwrap_or(Duration::from_secs(1))
    }
}

const fn nonzero(value: u32) -> NonZeroU32 {
    match NonZeroU32::new(value) {
        Some(value) => value,
        None => NonZeroU32::MIN,
    }
}

/// Every rate limit of the API (`RATE_LIMIT_*`). See `backend/AGENTS.md`
/// for how the defaults were sized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimits {
    /// Per client IP, all requests.
    pub ip: RateLimit,
    /// Per client IP, requests that fail authentication.
    pub auth_failure: RateLimit,
    /// Per authenticated user.
    pub user: RateLimit,
    /// Per authenticated user, the telemetry relay.
    pub telemetry: RateLimit,
}

impl RateLimits {
    pub const DEFAULT: Self = Self {
        ip: RateLimit::new(2000, 4000),
        auth_failure: RateLimit::new(50, 500),
        user: RateLimit::new(20, 100),
        telemetry: RateLimit::new(1, 20),
    };
}

/// How often the limiter forgets clients it has not seen for a while, so
/// its memory does not grow with every address that ever connected.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Keys requests by client IP address.
#[derive(Clone)]
pub struct ClientIpKey {
    trusted_proxies: Arc<TrustedProxies>,
}

impl KeyExtractor for ClientIpKey {
    type Key = IpAddr;

    fn extract<T>(&self, request: &Request<T>) -> Result<IpAddr, GovernorError> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .ok_or(GovernorError::UnableToExtractKey)?
            .0
            .ip();
        Ok(client_ip(
            peer,
            request.headers().get_all("x-forwarded-for"),
            &self.trusted_proxies,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid rate limit: the period and burst size must be positive")]
pub struct InvalidRateLimit;

/// Limits every route of `router` per client: a burst of `burst` requests,
/// refilled at one request per `period`. Spawns a task (on the current
/// Tokio runtime) that periodically drops idle clients.
///
/// # Errors
///
/// Returns [`InvalidRateLimit`] if `period` or `burst` is zero.
pub fn limit_per_client<S>(
    router: Router<S>,
    trusted_proxies: Arc<TrustedProxies>,
    period: Duration,
    burst: u32,
) -> Result<Router<S>, InvalidRateLimit>
where
    S: Clone + Send + Sync + 'static,
{
    let config = GovernorConfigBuilder::default()
        .key_extractor(ClientIpKey { trusted_proxies })
        .period(period)
        .burst_size(burst)
        .finish()
        .ok_or(InvalidRateLimit)?;
    let limiter = Arc::clone(config.limiter());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            limiter.retain_recent();
        }
    });
    Ok(router.layer(GovernorLayer::new(config).error_handler(|error| rejection(&error))))
}

fn rejection(error: &GovernorError) -> Response {
    match *error {
        GovernorError::TooManyRequests { wait_time, .. } => {
            let mut response = Problem::new(ErrorCode::RateLimited).into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(wait_time));
            response
        }
        GovernorError::UnableToExtractKey => {
            tracing::error!("rate limiter: no peer address (served without connect info)");
            Problem::new(ErrorCode::Internal).into_response()
        }
        GovernorError::Other { code, .. } => Problem::for_status(code).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_is_the_time_to_earn_one_request() {
        assert_eq!(RateLimit::new(1, 1).period(), Duration::from_secs(1));
        assert_eq!(RateLimit::new(4, 1).period(), Duration::from_millis(250));
        assert_eq!(RateLimit::new(2000, 1).period(), Duration::from_micros(500));
    }
}
