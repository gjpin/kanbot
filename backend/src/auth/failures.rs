//! The failed-authentication limit (`RATE_LIMIT_AUTH_FAILURE_*`): see
//! [`FailureLimiter`].

use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use crate::http::middleware::rate_limit::RateLimit;

/// Failed authentications per client, as a generic cell rate algorithm
/// (GCRA) limiter: each client stores the theoretical arrival time of its
/// next failure, so its state is one `Instant`.
///
/// Unlike `governor`, it can tell whether a client is over budget without
/// spending any ([`FailureLimiter::peek`]), which the middleware needs to
/// refuse a client before checking its credentials.
pub struct FailureLimiter<K> {
    /// Time to earn back one request.
    period: Duration,
    /// How far ahead of `now` a key's arrival time may be: `burst - 1`
    /// periods.
    tolerance: Duration,
    arrivals: Mutex<HashMap<K, Instant>>,
}

impl<K: Eq + Hash> FailureLimiter<K> {
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

    /// Whether a request for `key` at `now` would be admitted, without
    /// spending any budget.
    ///
    /// # Errors
    ///
    /// The time until a request for `key` would be admitted.
    pub fn peek(&self, key: &K, now: Instant) -> Result<(), Duration> {
        let arrivals = self.arrivals.lock().unwrap_or_else(PoisonError::into_inner);
        let ahead = arrivals
            .get(key)
            .map_or(Duration::ZERO, |at| at.saturating_duration_since(now));
        if ahead > self.tolerance {
            Err(ahead.saturating_sub(self.tolerance))
        } else {
            Ok(())
        }
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    fn limiter(per_second: u32, burst: u32) -> FailureLimiter<&'static str> {
        FailureLimiter::new(RateLimit {
            per_second: NonZeroU32::new(per_second).unwrap(),
            burst: NonZeroU32::new(burst).unwrap(),
        })
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
    fn peek_does_not_spend_budget() {
        let limiter = limiter(1, 2);
        let start = Instant::now();
        assert_eq!(limiter.peek(&"a", start), Ok(()));
        assert!(limiter.is_empty());
        limiter.check("a", start).unwrap();
        assert_eq!(limiter.peek(&"a", start), Ok(()));
        limiter.check("a", start).unwrap();
        assert_eq!(limiter.peek(&"a", start), Err(Duration::from_secs(1)));
        assert_eq!(limiter.peek(&"a", at(start, 1000)), Ok(()));
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
}
