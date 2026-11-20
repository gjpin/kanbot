//! Rate limiting. Rejected requests get a `429` problem with `Retry-After`.
//!
//! - Per client IP (`tower_governor`), keyed by the address from
//!   [`crate::http::client_ip`]. Requires the server to provide
//!   `ConnectInfo<SocketAddr>` (`into_make_service_with_connect_info`),
//!   which `kanbot_backend::run` does.
//! - Per authenticated user ([`limit_per_user`]), keyed by the user ID the
//!   authentication middleware put in the request. Anonymous requests pass.
//!
//! Limits are kept in memory per server instance.

use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::{HeaderValue, Request, header},
    middleware::Next,
    response::{IntoResponse, Response},
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

/// A `429 rate_limited` problem asking to retry after `seconds`.
fn too_many_requests(seconds: u64) -> Response {
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

/// An in-memory rate limiter per key, using the generic cell rate
/// algorithm (GCRA): each key stores the theoretical arrival time of its
/// next request, so its state is one `Instant`.
pub struct KeyedLimiter<K> {
    /// Time to earn back one request.
    period: Duration,
    /// How far ahead of `now` a key's arrival time may be: `burst - 1`
    /// periods.
    tolerance: Duration,
    arrivals: Mutex<HashMap<K, Instant>>,
}

impl<K: Eq + Hash> KeyedLimiter<K> {
    #[must_use]
    pub fn new(limit: RateLimit) -> Self {
        let period = limit.period();
        Self {
            period,
            tolerance: period
                .checked_mul(limit.burst.get().saturating_sub(1))
                .unwrap_or(Duration::MAX),
            arrivals: Mutex::new(HashMap::new()),
        }
    }

    /// Admits one request for `key` at `now`, or says how long to wait.
    ///
    /// # Errors
    ///
    /// The time until a request for `key` would be admitted.
    pub fn check(&self, key: K, now: Instant) -> Result<(), Duration> {
        let mut arrivals = self.arrivals.lock().unwrap_or_else(PoisonError::into_inner);
        let arrival = arrivals.get(&key).copied().map_or(now, |at| at.max(now));
        let ahead = arrival.saturating_duration_since(now);
        if ahead > self.tolerance {
            return Err(ahead.saturating_sub(self.tolerance));
        }
        let next = arrival.checked_add(self.period).unwrap_or(arrival);
        arrivals.insert(key, next);
        Ok(())
    }

    /// Forgets keys that are back to a full burst at `now`, so memory does
    /// not grow with every key ever seen.
    pub fn retain_recent(&self, now: Instant) {
        self.arrivals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, arrival| *arrival > now);
    }

    /// How many keys are tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.arrivals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Limits every route of `router` per authenticated user (see the module
/// documentation). Must sit inside the authentication middleware. Spawns a
/// task (on the current Tokio runtime) that periodically forgets idle
/// users.
pub fn limit_per_user<S>(router: Router<S>, limit: RateLimit) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let limiter = Arc::new(KeyedLimiter::<UserId>::new(limit));
    let cleanup = Arc::clone(&limiter);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            cleanup.retain_recent(Instant::now());
        }
    });
    router.layer(axum::middleware::from_fn_with_state(limiter, per_user))
}

async fn per_user(
    State(limiter): State<Arc<KeyedLimiter<UserId>>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(user) = request.extensions().get::<AuthenticatedUser>() else {
        return next.run(request).await;
    };
    match limiter.check(user.id, Instant::now()) {
        Ok(()) => next.run(request).await,
        Err(wait) => {
            // Whole seconds, rounded up.
            let seconds = wait
                .as_secs()
                .saturating_add(u64::from(wait.subsec_nanos() > 0));
            too_many_requests(seconds)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(per_second: u32, burst: u32) -> KeyedLimiter<&'static str> {
        KeyedLimiter::new(RateLimit::new(per_second, burst))
    }

    fn at(start: Instant, millis: u64) -> Instant {
        start.checked_add(Duration::from_millis(millis)).unwrap()
    }

    #[test]
    fn admits_a_burst_then_one_per_period() {
        let limiter = limiter(2, 3);
        let start = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.check("a", start), Ok(()));
        }
        assert_eq!(limiter.check("a", start), Err(Duration::from_millis(500)));
        assert_eq!(
            limiter.check("a", at(start, 499)),
            Err(Duration::from_millis(1))
        );
        assert_eq!(limiter.check("a", at(start, 500)), Ok(()));
        assert_eq!(
            limiter.check("a", at(start, 500)),
            Err(Duration::from_millis(500))
        );
        // After a long pause, a full burst again, not more.
        let later = at(start, 60_000);
        for _ in 0..3 {
            assert_eq!(limiter.check("a", later), Ok(()));
        }
        assert!(limiter.check("a", later).is_err());
    }

    #[test]
    fn a_burst_of_one_admits_one_per_period() {
        let limiter = limiter(1, 1);
        let start = Instant::now();
        assert_eq!(limiter.check("a", start), Ok(()));
        assert_eq!(limiter.check("a", start), Err(Duration::from_secs(1)));
        assert_eq!(limiter.check("a", at(start, 1000)), Ok(()));
    }

    #[test]
    fn keys_have_separate_budgets() {
        let limiter = limiter(1, 1);
        let now = Instant::now();
        assert_eq!(limiter.check("a", now), Ok(()));
        assert!(limiter.check("a", now).is_err());
        assert_eq!(limiter.check("b", now), Ok(()));
    }

    #[test]
    fn a_refused_request_does_not_spend_budget() {
        let limiter = limiter(1, 1);
        let start = Instant::now();
        assert_eq!(limiter.check("a", start), Ok(()));
        for _ in 0..10 {
            assert!(limiter.check("a", at(start, 100)).is_err());
        }
        assert_eq!(limiter.check("a", at(start, 1000)), Ok(()));
    }

    #[test]
    fn forgets_keys_back_to_a_full_burst() {
        let limiter = limiter(1, 2);
        let start = Instant::now();
        limiter.check("a", start).unwrap();
        limiter.check("b", at(start, 900)).unwrap();
        assert_eq!(limiter.len(), 2);
        limiter.retain_recent(at(start, 1000));
        assert_eq!(limiter.len(), 1);
        limiter.retain_recent(at(start, 1900));
        assert!(limiter.is_empty());
    }

    #[test]
    fn period_is_the_time_to_earn_one_request() {
        assert_eq!(RateLimit::new(1, 1).period(), Duration::from_secs(1));
        assert_eq!(RateLimit::new(4, 1).period(), Duration::from_millis(250));
        assert_eq!(RateLimit::new(2000, 1).period(), Duration::from_micros(500));
    }
}
