//! Per-client rate limiting (`tower_governor`), keyed by the client IP
//! address from [`crate::http::client_ip`].
//!
//! Requires the server to provide `ConnectInfo<SocketAddr>`
//! (`into_make_service_with_connect_info`), which `kanbot_backend::run`
//! does. Rejected requests get a `429` problem with `Retry-After`.

use std::{
    net::{IpAddr, SocketAddr},
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
