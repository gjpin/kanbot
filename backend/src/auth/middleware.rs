//! The authentication middleware: turns the request's credentials into an
//! [`AuthenticatedUser`] in the request extensions.
//!
//! - No credentials: the request continues anonymously. Routes that need a
//!   user refuse it through the [`AuthUser`](crate::http::extract::AuthUser)
//!   extractor.
//! - Invalid credentials: `401` at once, never treated as anonymous.
//! - Valid credentials: the user is recorded and attached to the request.

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Meter},
};

use crate::{
    auth::{
        keys::KeyLookup,
        token::{Rejection, UnverifiedToken},
    },
    error::AppError,
    http::{
        client_ip::TrustedProxies,
        middleware::rate_limit::{
            KeyedLimiter, RateLimit, client_key, spawn_cleanup, too_many_requests, whole_seconds,
        },
        problem::{ErrorCode, Problem},
    },
    state::AppState,
    users::{model::AuthenticatedUser, service as users},
};

/// `kanbot.auth.token.rejections`: refused credentials, by bounded
/// `reason` (a [`Rejection::reason`], or `disabled`).
#[derive(Clone)]
pub struct AuthMetrics {
    rejections: Counter<u64>,
}

impl AuthMetrics {
    /// Creates the instruments on the global meter. Call after telemetry is
    /// initialized.
    #[must_use]
    pub fn global() -> Self {
        Self::new(&global::meter(crate::telemetry::SCOPE))
    }

    #[must_use]
    pub fn new(meter: &Meter) -> Self {
        Self {
            rejections: meter
                .u64_counter("kanbot.auth.token.rejections")
                .with_unit("{rejection}")
                .with_description("Credentials refused, by reason.")
                .build(),
        }
    }

    fn rejected(&self, reason: &'static str) {
        self.rejections.add(1, &[KeyValue::new("reason", reason)]);
    }
}

/// The middleware's state.
#[derive(Clone)]
pub struct Authentication {
    app: AppState,
    trusted_proxies: Arc<TrustedProxies>,
    /// Failed authentications per client (`RATE_LIMIT_AUTH_FAILURE_*`).
    failures: Arc<KeyedLimiter<IpAddr>>,
    metrics: AuthMetrics,
}

impl Authentication {
    /// Spawns a task (on the current Tokio runtime) that periodically
    /// forgets clients of the failure limiter.
    #[must_use]
    pub fn new(
        app: AppState,
        trusted_proxies: Arc<TrustedProxies>,
        failure_limit: RateLimit,
        metrics: AuthMetrics,
    ) -> Self {
        let failures = Arc::new(KeyedLimiter::new(failure_limit));
        spawn_cleanup(&failures);
        Self {
            app,
            trusted_proxies,
            failures,
            metrics,
        }
    }
}

/// What the request presented.
enum Credentials<'a> {
    None,
    Bearer(&'a str),
    /// An `Authorization` header that is not `Bearer <token>`.
    Unusable,
}

fn credentials(headers: &HeaderMap) -> Credentials<'_> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Credentials::None;
    };
    if values.next().is_some() {
        return Credentials::Unusable;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(token)
        })
        .map_or(Credentials::Unusable, Credentials::Bearer)
}

/// Why a request with credentials got no user.
enum Refusal {
    Token(Rejection),
    Error(AppError),
}

impl From<Rejection> for Refusal {
    fn from(rejection: Rejection) -> Self {
        Self::Token(rejection)
    }
}

/// Middleware (`axum::middleware::from_fn_with_state`).
///
/// A client that has used up its failed-authentication budget gets `429`
/// for any request with credentials, before they are checked; requests
/// without credentials are not affected.
pub async fn authenticate(
    State(auth): State<Authentication>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match credentials(request.headers()) {
        Credentials::None => return next.run(request).await,
        Credentials::Unusable => None,
        Credentials::Bearer(token) => Some(token),
    };
    let Some(client) = client_key(&request, &auth.trusted_proxies) else {
        tracing::error!("authentication: no peer address (served without connect info)");
        return Problem::new(ErrorCode::Internal).into_response();
    };
    if let Err(wait) = auth.failures.peek(&client, Instant::now()) {
        return too_many_requests(whole_seconds(wait));
    }
    let result = match token {
        Some(token) => user(&auth.app, token).await,
        None => Err(Refusal::Token(Rejection::Malformed)),
    };
    match result {
        Ok(user) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(refusal) => refuse(&auth, client, refusal).into_response(),
    }
}

/// Records a refusal and turns it into the response's error. The reason
/// goes to the metric (and a debug log), never to the client.
fn refuse(auth: &Authentication, client: IpAddr, refusal: Refusal) -> AppError {
    match refusal {
        Refusal::Token(rejection) => {
            tracing::debug!(reason = rejection.reason(), "token rejected");
            auth.metrics.rejected(rejection.reason());
            if rejection == Rejection::NoRole {
                // Valid credentials, just no access: not a failed login.
                AppError::Forbidden
            } else {
                // Over budget only matters for the next request.
                let _ = auth.failures.check(client, Instant::now());
                AppError::InvalidToken
            }
        }
        Refusal::Error(AppError::AccountDisabled) => {
            auth.metrics.rejected("disabled");
            AppError::AccountDisabled
        }
        Refusal::Error(error) => error,
    }
}

/// The user of a bearer token. A token whose key cannot be checked yet
/// (keys not loaded) is `503`, not `401`: it may well be valid.
async fn user(state: &AppState, token: &str) -> Result<AuthenticatedUser, Refusal> {
    let unverified = UnverifiedToken::parse(token)?;
    let key = match state.keys.key(unverified.kid()).await {
        KeyLookup::Found(key) => key,
        KeyLookup::Unknown => return Err(Rejection::UnknownKey.into()),
        KeyLookup::NotLoaded => return Err(Refusal::Error(AppError::Unavailable)),
    };
    let principal = unverified.verify(&key, state.keys.config(), now())?;
    users::authenticate(&state.db, &principal)
        .await
        .map_err(Refusal::Error)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
