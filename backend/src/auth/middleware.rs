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
    http::{HeaderMap, Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Meter},
};

use crate::{
    auth::{
        failures::FailureLimiter,
        keys::KeyLookup,
        token::{Rejection, UnverifiedToken},
    },
    error::AppError,
    http::{
        client_ip::TrustedProxies,
        middleware::rate_limit::{
            RateLimit, client_key, spawn_periodic, too_many_requests, whole_seconds,
        },
        problem::{ErrorCode, Problem},
    },
    sessions::{self, secrets, service::SessionRefusal},
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
    failures: Arc<FailureLimiter<IpAddr>>,
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
        let failures = Arc::new(FailureLimiter::new(failure_limit));
        let cleanup = Arc::clone(&failures);
        spawn_periodic(move || cleanup.retain_recent(Instant::now()));
        Self {
            app,
            trusted_proxies,
            failures,
            metrics,
        }
    }
}

/// What the request presented. `Authorization` wins over the cookie.
enum Credentials<'a> {
    None,
    /// An access token from the identity provider (a JWT).
    Bearer(&'a str),
    /// A kanbot session token, `kbs_...`.
    Session {
        token: &'a str,
        from_cookie: bool,
    },
    /// An `Authorization` header that is not `Bearer <token>`.
    Unusable,
}

fn credentials(headers: &HeaderMap) -> Credentials<'_> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return match sessions::cookie(headers, sessions::SESSION_COOKIE) {
            Some(token) => Credentials::Session {
                token,
                from_cookie: true,
            },
            None => Credentials::None,
        };
    };
    if values.next().is_some() {
        return Credentials::Unusable;
    }
    let Some(token) = value.to_str().ok().and_then(|value| {
        let (scheme, token) = value.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then_some(token)
    }) else {
        return Credentials::Unusable;
    };
    if token.starts_with(secrets::SESSION_TOKEN) {
        Credentials::Session {
            token,
            from_cookie: false,
        }
    } else {
        Credentials::Bearer(token)
    }
}

/// The session behind the request, for logout and CSRF checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentSession {
    pub id: uuid::Uuid,
    pub kind: sessions::model::Platform,
    /// Sent as the cookie (a browser), not a bearer header.
    pub from_cookie: bool,
}

/// Why a request with credentials got no user.
enum Refusal {
    Token(Rejection),
    /// A session cookie that no longer works: not an error.
    StaleCookie(Rejection),
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
    let credentials = credentials(request.headers());
    if let Credentials::None = credentials {
        return next.run(request).await;
    }
    let Some(client) = client_key(&request, &auth.trusted_proxies) else {
        tracing::error!("authentication: no peer address (served without connect info)");
        return Problem::new(ErrorCode::Internal).into_response();
    };
    if let Err(wait) = auth.failures.peek(&client, Instant::now()) {
        return too_many_requests(whole_seconds(wait));
    }
    let result = match credentials {
        Credentials::None | Credentials::Unusable => Err(Refusal::Token(Rejection::Malformed)),
        Credentials::Bearer(token) => user(&auth.app, token).await.map(|user| (user, None)),
        Credentials::Session { token, from_cookie } => {
            session_user(&auth.app, token, from_cookie).await
        }
    };
    match result {
        Ok((_, Some(session)))
            if session.from_cookie
                && !csrf_safe(&request, &auth.app.sessions.public_url.origin()) =>
        {
            tracing::info!(session.id = %session.id, "cross-site request refused");
            AppError::Forbidden.into_response()
        }
        Ok((user, session)) => {
            request.extensions_mut().insert(user);
            if let Some(session) = session {
                request.extensions_mut().insert(session);
            }
            next.run(request).await
        }
        Err(Refusal::StaleCookie(rejection)) => {
            // A browser still holding a session that ended: forget it and
            // carry on anonymously, so it can sign in again.
            auth.metrics.rejected(rejection.reason());
            let mut response = next.run(request).await;
            response
                .headers_mut()
                .append(header::SET_COOKIE, sessions::clear_session_cookie());
            response
        }
        Err(refusal) => refuse(&auth, client, refusal).into_response(),
    }
}

/// The header a kanbot web app sends on state-changing requests.
pub const CSRF_HEADER: &str = "x-kanbot-csrf";

/// Whether a request authenticated by the session cookie may run: reading
/// is always allowed; a state-changing method needs `Origin` equal to
/// `PUBLIC_URL`'s origin and `X-Kanbot-CSRF: 1`, which a cross-site page
/// cannot send without a CORS preflight that kanbot refuses.
fn csrf_safe(request: &Request, public_origin: &str) -> bool {
    let method = request.method();
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return true;
    }
    let headers = request.headers();
    let single = |name: &str| {
        let mut values = headers.get_all(name).iter();
        let value = values.next()?;
        values.next().is_none().then_some(value)
    };
    single(header::ORIGIN.as_str()).is_some_and(|origin| origin == public_origin)
        && single(CSRF_HEADER).is_some_and(|value| value == "1")
}

/// The user of a session token, and the session.
async fn session_user(
    state: &AppState,
    token: &str,
    from_cookie: bool,
) -> Result<(AuthenticatedUser, Option<CurrentSession>), Refusal> {
    match sessions::service::authenticate_session(&state.db, &state.keys, &state.sessions, token)
        .await
    {
        Ok(session) => Ok((
            session.user,
            Some(CurrentSession {
                id: session.session_id,
                kind: session.kind,
                from_cookie,
            }),
        )),
        Err(SessionRefusal::Invalid) if from_cookie => {
            Err(Refusal::StaleCookie(Rejection::SessionInvalid))
        }
        Err(SessionRefusal::Ended) if from_cookie => {
            Err(Refusal::StaleCookie(Rejection::SessionEnded))
        }
        Err(SessionRefusal::Invalid) => Err(Rejection::SessionInvalid.into()),
        Err(SessionRefusal::Ended) => Err(Rejection::SessionEnded.into()),
        Err(SessionRefusal::NoRole) => Err(Rejection::NoRole.into()),
        Err(SessionRefusal::Error(error)) => Err(Refusal::Error(error)),
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
        // Handled by the caller; never an error response.
        Refusal::StaleCookie(_) => AppError::InvalidToken,
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
