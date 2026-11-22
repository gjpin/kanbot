//! Rate limiting. Rejected requests get a `429` problem with `Retry-After`.
//!
//! - Per client IP (`tower_governor`), keyed by the address from
//!   [`crate::http::client_ip`]. Requires the server to provide
//!   `ConnectInfo<SocketAddr>` (`into_make_service_with_connect_info`),
//!   which `kanbot_backend::run` does.
//! - Per authenticated user: the general limit is spent by the
//!   authentication middleware (`auth::middleware`), keyed by the session
//!   token or the access token's subject, before any database work.
//!   [`limit_per_user`] adds a separate one to a group of routes (the
//!   telemetry relay), keyed by user ID. Anonymous requests pass.
//!
//! The failed-authentication limit is in `auth::failures`: it must refuse a
//! client before checking its credentials, which `governor` cannot do
//! without spending budget.
//!
//! Limits are kept in memory per server instance.

use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::{HeaderValue, Request, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{
    DefaultKeyedRateLimiter, Quota, RateLimiter,
    clock::{Clock, DefaultClock},
};
use tower_governor::{
    GovernorError, GovernorLayer, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
};

use crate::{
    http::{
        client_ip::{TrustedProxies, client_ip},
        problem::{ErrorCode, Problem},
    },
    users::model::{AuthenticatedUser, UserId},
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
    /// Per client IP, the routes that start or finish a sign-in.
    pub login: RateLimit,
    /// Per authenticated user.
    pub user: RateLimit,
    /// Per authenticated user, the telemetry relay.
    pub telemetry: RateLimit,
}

impl RateLimits {
    pub const DEFAULT: Self = Self {
        ip: RateLimit::new(2000, 4000),
        auth_failure: RateLimit::new(50, 500),
        login: RateLimit::new(100, 500),
        user: RateLimit::new(20, 100),
        telemetry: RateLimit::new(1, 20),
    };
}

/// How often the limiter forgets clients it has not seen for a while, so
/// its memory does not grow with every address that ever connected.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// The rate-limit key of a client address: an IPv4 address as is, an IPv6
/// address by its /64 prefix, since one client usually holds a whole /64.
#[must_use]
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            for segment in segments.iter_mut().skip(4) {
                *segment = 0;
            }
            IpAddr::from(segments)
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// The address of the client that sent `request` (see
/// [`client_ip`]), or `None` if the server provided no peer address.
pub fn request_client_ip<T>(
    request: &Request<T>,
    trusted_proxies: &TrustedProxies,
) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()?
        .0
        .ip();
    Some(client_ip(
        peer,
        request.headers().get_all("x-forwarded-for"),
        trusted_proxies,
    ))
}

/// The rate-limit key of the client that sent `request` (see [`ip_key`]),
/// or `None` if the server provided no peer address.
pub fn client_key<T>(request: &Request<T>, trusted_proxies: &TrustedProxies) -> Option<IpAddr> {
    request_client_ip(request, trusted_proxies).map(ip_key)
}

/// Keys requests by client (see [`client_key`]).
#[derive(Clone)]
pub struct ClientIpKey {
    trusted_proxies: Arc<TrustedProxies>,
}

impl KeyExtractor for ClientIpKey {
    type Key = IpAddr;

    fn extract<T>(&self, request: &Request<T>) -> Result<IpAddr, GovernorError> {
        client_key(request, &self.trusted_proxies).ok_or(GovernorError::UnableToExtractKey)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid rate limit: the period and burst size must be positive")]
pub struct InvalidRateLimit;

/// Limits every route of `router` per client (see [`client_key`]).
/// Spawns a task (on the current Tokio runtime) that periodically drops
/// idle clients. Requests without a peer address fail closed (`500`).
///
/// # Errors
///
/// Returns [`InvalidRateLimit`] if the limit's period rounds to zero.
pub fn limit_per_client<S>(
    router: Router<S>,
    trusted_proxies: Arc<TrustedProxies>,
    limit: RateLimit,
) -> Result<Router<S>, InvalidRateLimit>
where
    S: Clone + Send + Sync + 'static,
{
    let config = GovernorConfigBuilder::default()
        .key_extractor(ClientIpKey { trusted_proxies })
        .period(limit.period())
        .burst_size(limit.burst.get())
        .finish()
        .ok_or(InvalidRateLimit)?;
    let limiter = Arc::clone(config.limiter());
    spawn_periodic(move || {
        limiter.retain_recent();
        // The map keeps its largest size otherwise.
        limiter.shrink_to_fit();
    });
    Ok(router.layer(GovernorLayer::new(config).error_handler(|error| rejection(&error))))
}

/// A `429 rate_limited` problem asking to retry after `seconds` (at least
/// one).
#[must_use]
pub fn too_many_requests(seconds: u64) -> Response {
    let mut response = Problem::new(ErrorCode::RateLimited).into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
    response
}

fn rejection(error: &GovernorError) -> Response {
    match *error {
        GovernorError::TooManyRequests { wait_time, .. } => too_many_requests(wait_time),
        GovernorError::UnableToExtractKey => {
            tracing::error!("rate limiter: no peer address (served without connect info)");
            Problem::new(ErrorCode::Internal).into_response()
        }
        GovernorError::Other { code, .. } => Problem::for_status(code).into_response(),
    }
}

/// Limits every route of `router` per authenticated user (see the module
/// documentation), with `governor`'s keyed limiter. Must sit inside the
/// authentication middleware. Spawns a task (on the current Tokio runtime)
/// that periodically forgets idle users.
///
/// # Errors
///
/// Returns [`InvalidRateLimit`] if the limit's period rounds to zero.
pub fn limit_per_user<S>(router: Router<S>, limit: RateLimit) -> Result<Router<S>, InvalidRateLimit>
where
    S: Clone + Send + Sync + 'static,
{
    let quota = Quota::with_period(limit.period())
        .ok_or(InvalidRateLimit)?
        .allow_burst(limit.burst);
    let limiter: Arc<DefaultKeyedRateLimiter<UserId>> = Arc::new(RateLimiter::keyed(quota));
    let cleanup = Arc::clone(&limiter);
    spawn_periodic(move || {
        cleanup.retain_recent();
        cleanup.shrink_to_fit();
    });
    Ok(router.layer(axum::middleware::from_fn_with_state(limiter, per_user)))
}

/// `wait` in whole seconds, rounded up.
#[must_use]
pub fn whole_seconds(wait: Duration) -> u64 {
    wait.as_secs()
        .saturating_add(u64::from(wait.subsec_nanos() > 0))
}

/// Runs `task` every [`CLEANUP_INTERVAL`] on the current Tokio runtime.
pub fn spawn_periodic(task: impl Fn() + Send + 'static) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            task();
        }
    });
}

async fn per_user(
    State(limiter): State<Arc<DefaultKeyedRateLimiter<UserId>>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(user) = request.extensions().get::<AuthenticatedUser>() else {
        return next.run(request).await;
    };
    match limiter.check_key(&user.id) {
        Ok(()) => next.run(request).await,
        Err(not_until) => too_many_requests(whole_seconds(
            not_until.wait_time_from(DefaultClock::default().now()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn spawn_periodic_runs_the_task_every_interval() {
        let runs = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = Arc::clone(&runs);
        spawn_periodic(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        // The first tick is immediate, then one per interval.
        tokio::time::sleep(CLEANUP_INTERVAL.saturating_mul(2) + Duration::from_millis(1)).await;
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn rounds_waits_up_to_whole_seconds() {
        assert_eq!(whole_seconds(Duration::ZERO), 0);
        assert_eq!(whole_seconds(Duration::from_millis(1)), 1);
        assert_eq!(whole_seconds(Duration::from_secs(1)), 1);
        assert_eq!(whole_seconds(Duration::from_millis(1001)), 2);
    }

    #[test]
    fn keys_ipv4_by_address_and_ipv6_by_slash_64() {
        let key = |ip: &str| ip_key(ip.parse().unwrap()).to_string();
        assert_eq!(key("203.0.113.9"), "203.0.113.9");
        assert_eq!(key("::ffff:203.0.113.9"), "203.0.113.9");
        assert_eq!(key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2::");
        assert_eq!(key("2001:db8:1:2::1"), "2001:db8:1:2::");
        assert_eq!(key("2001:db8:1:3::1"), "2001:db8:1:3::");
        assert_eq!(key("::1"), "::");
    }

    #[test]
    fn period_is_the_time_to_earn_one_request() {
        assert_eq!(RateLimit::new(1, 1).period(), Duration::from_secs(1));
        assert_eq!(RateLimit::new(4, 1).period(), Duration::from_millis(250));
        assert_eq!(RateLimit::new(2000, 1).period(), Duration::from_micros(500));
    }
}
