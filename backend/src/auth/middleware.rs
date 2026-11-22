//! The authentication middleware: turns the request's credentials into an
//! [`AuthenticatedUser`] in the request extensions.
//!
//! - No credentials: the request continues anonymously. Routes that need a
//!   user refuse it through the [`AuthUser`](crate::http::extract::AuthUser)
//!   extractor.
//! - Invalid credentials: `401` at once, never treated as anonymous.
//! - Valid credentials: the user is recorded, their IdP-synced team
//!   memberships are brought up to date (when the token carries the groups
//!   claim), and the user is attached to the request.
//!
//! Cheap checks come first, so a refused request costs no database work:
//! the failed-authentication budget, then CSRF for the session cookie, then
//! the per-user limit (keyed by the session token, or by the subject of a
//! verified access token).
//!
//! Signing out uses [`identify`] instead: the same, except that a session
//! is only found from its token, so that it can end while the identity
//! provider is unreachable.

use std::{net::IpAddr, sync::Arc, time::Instant};

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

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter, clock::Clock};

use crate::{
    auth::{
        failures::FailureLimiter,
        keys::KeyLookup,
        token::{Rejection, UnverifiedToken, now},
    },
    error::AppError,
    http::{
        client_ip::{ClientIp, TrustedProxies},
        middleware::rate_limit::{
            InvalidRateLimit, RateLimit, ip_key, request_client_ip, spawn_periodic,
            too_many_requests, whole_seconds,
        },
        problem::{ErrorCode, Problem},
    },
    sessions::{self, secrets, service::SessionRefusal},
    state::AppState,
    teams::service as teams,
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
    /// Requests per user (`RATE_LIMIT_USER_*`), keyed by [`user_key`].
    users: Arc<DefaultKeyedRateLimiter<[u8; 32]>>,
    metrics: AuthMetrics,
}

/// The limits [`Authentication`] applies.
#[derive(Clone, Copy, Debug)]
pub struct AuthLimits {
    /// Failed authentications per client (`RATE_LIMIT_AUTH_FAILURE_*`).
    pub failure: RateLimit,
    /// Requests per user (`RATE_LIMIT_USER_*`).
    pub user: RateLimit,
}

impl Authentication {
    /// Spawns tasks (on the current Tokio runtime) that periodically forget
    /// idle clients and users.
    ///
    /// # Errors
    ///
    /// [`InvalidRateLimit`] if a limit's period rounds to zero.
    pub fn new(
        app: AppState,
        trusted_proxies: Arc<TrustedProxies>,
        limits: AuthLimits,
        metrics: AuthMetrics,
    ) -> Result<Self, InvalidRateLimit> {
        if limits.failure.period().is_zero() {
            return Err(InvalidRateLimit);
        }
        let failures = Arc::new(FailureLimiter::new(limits.failure));
        let cleanup = Arc::clone(&failures);
        spawn_periodic(move || cleanup.retain_recent(Instant::now()));
        let quota = Quota::with_period(limits.user.period())
            .ok_or(InvalidRateLimit)?
            .allow_burst(limits.user.burst);
        let users: Arc<DefaultKeyedRateLimiter<[u8; 32]>> = Arc::new(RateLimiter::keyed(quota));
        let cleanup = Arc::clone(&users);
        spawn_periodic(move || {
            cleanup.retain_recent();
            cleanup.shrink_to_fit();
        });
        Ok(Self {
            app,
            trusted_proxies,
            failures,
            users,
            metrics,
        })
    }

    /// Spends one request of `key`'s per-user budget, or says how long to
    /// wait.
    fn spend(&self, key: &[u8; 32]) -> Result<(), std::time::Duration> {
        self.users.check_key(key).map_err(|not_until| {
            not_until.wait_time_from(governor::clock::DefaultClock::default().now())
        })
    }
}

/// The per-user limiter's key for a verified access token's subject. The
/// issuer is fixed, so the subject names the user.
fn user_key(subject: &str) -> [u8; 32] {
    secrets::hash(&format!("subject:{subject}"))
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

/// The access token a bearer request presented, for a call to another
/// service on the user's behalf (token exchange). Never log it.
#[derive(Clone)]
pub struct BearerToken(pub secrecy::SecretString);

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
    /// Over the per-user limit, for this long.
    Limited(std::time::Duration),
}

impl From<Rejection> for Refusal {
    fn from(rejection: Rejection) -> Self {
        Self::Token(rejection)
    }
}

/// What a session must pass.
#[derive(Clone, Copy)]
enum SessionCheck {
    /// Every rule: the stored access token (refreshed when due) passes the
    /// bearer rules and gives the request its user.
    Full,
    /// Only that the session exists and is live, found from its token's
    /// hash: no identity provider, no user. For signing out.
    Identify,
}

/// Middleware (`axum::middleware::from_fn_with_state`).
///
/// A client that has used up its failed-authentication budget gets `429`
/// for any request with credentials, before they are checked; requests
/// without credentials are not affected.
pub async fn authenticate(
    State(auth): State<Authentication>,
    request: Request,
    next: Next,
) -> Response {
    run(auth, request, next, SessionCheck::Full).await
}

/// Middleware for signing out (`POST /auth/logout`): as [`authenticate`],
/// with the same limits and CSRF check, except that a session (cookie or
/// `kbs_` bearer) is only identified from its token. It never calls the
/// identity provider, so a session can end while that is unreachable or
/// its keys have not loaded; the request gets the [`CurrentSession`] and
/// no user. Any other credentials are checked exactly as
/// [`authenticate`] does.
pub async fn identify(
    State(auth): State<Authentication>,
    request: Request,
    next: Next,
) -> Response {
    run(auth, request, next, SessionCheck::Identify).await
}

async fn run(
    auth: Authentication,
    mut request: Request,
    next: Next,
    check: SessionCheck,
) -> Response {
    let credentials = credentials(request.headers());
    if let Credentials::None = credentials {
        return next.run(request).await;
    }
    let Some(ip) = request_client_ip(&request, &auth.trusted_proxies) else {
        tracing::error!("authentication: no peer address (served without connect info)");
        return Problem::new(ErrorCode::Internal).into_response();
    };
    let client = ip_key(ip);
    if let Err(wait) = auth.failures.peek(&client, Instant::now()) {
        return too_many_requests(whole_seconds(wait));
    }
    if let Credentials::Session {
        from_cookie: true, ..
    } = credentials
        && !csrf_safe(&request, &auth.app.sessions.public_url.origin())
    {
        tracing::info!("cross-site request refused");
        return AppError::Forbidden.into_response();
    }
    let bearer = match credentials {
        Credentials::Bearer(token) => Some(secrecy::SecretString::from(token.to_owned())),
        _ => None,
    };
    let result = match credentials {
        Credentials::None | Credentials::Unusable => Err(Refusal::Token(Rejection::Malformed)),
        Credentials::Bearer(token) => user(&auth, token).await.map(|user| (Some(user), None)),
        Credentials::Session { token, from_cookie } => {
            // Unknown shapes cannot match a session; they fail below.
            if let Some(hash) = secrets::presented(secrets::SESSION_TOKEN, token)
                && let Err(wait) = auth.spend(&hash)
            {
                return too_many_requests(whole_seconds(wait));
            }
            match check {
                SessionCheck::Full => session_user(&auth.app, token, from_cookie)
                    .await
                    .map(|(user, session)| (Some(user), Some(session))),
                SessionCheck::Identify => identified_session(&auth.app, token, from_cookie)
                    .await
                    .map(|session| (None, Some(session))),
            }
        }
    };
    let result = match result {
        Ok((Some(user), session)) if user.groups_claimed => {
            match teams::sync_idp_groups(&auth.app.db, user.id, &user.groups).await {
                Ok(()) => Ok((Some(user), session)),
                Err(error) => Err(Refusal::Error(error)),
            }
        }
        other => other,
    };
    match result {
        Ok((user, session)) => {
            if let Some(user) = user {
                request.extensions_mut().insert(user);
            }
            request.extensions_mut().insert(ClientIp(ip));
            if let Some(token) = bearer {
                request.extensions_mut().insert(BearerToken(token));
            }
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
        Err(Refusal::Limited(wait)) => too_many_requests(whole_seconds(wait)),
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
) -> Result<(AuthenticatedUser, CurrentSession), Refusal> {
    sessions::service::authenticate_session(&state.db, &state.keys, &state.sessions, token)
        .await
        .map(|session| {
            (
                session.user,
                CurrentSession {
                    id: session.session_id,
                    kind: session.kind,
                    from_cookie,
                },
            )
        })
        .map_err(|refusal| session_refusal(refusal, from_cookie))
}

/// The live session of a session token, from the token alone.
async fn identified_session(
    state: &AppState,
    token: &str,
    from_cookie: bool,
) -> Result<CurrentSession, Refusal> {
    sessions::service::identify_session(&state.db, &state.sessions, token)
        .await
        .map(|session| CurrentSession {
            id: session.id,
            kind: session.kind,
            from_cookie,
        })
        .map_err(|refusal| session_refusal(refusal, from_cookie))
}

fn session_refusal(refusal: SessionRefusal, from_cookie: bool) -> Refusal {
    match refusal {
        SessionRefusal::Invalid if from_cookie => Refusal::StaleCookie(Rejection::SessionInvalid),
        SessionRefusal::Ended if from_cookie => Refusal::StaleCookie(Rejection::SessionEnded),
        SessionRefusal::Invalid => Rejection::SessionInvalid.into(),
        SessionRefusal::Ended => Rejection::SessionEnded.into(),
        SessionRefusal::NoRole => Rejection::NoRole.into(),
        SessionRefusal::Error(error) => Refusal::Error(error),
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
        Refusal::StaleCookie(_) | Refusal::Limited(_) => AppError::InvalidToken,
    }
}

/// The user of a bearer token. A token whose key cannot be checked yet
/// (keys not loaded, or too many requests waiting for a refresh) is `503`,
/// not `401`: it may well be valid. The
/// per-user limit applies once the token is verified, before the database.
async fn user(auth: &Authentication, token: &str) -> Result<AuthenticatedUser, Refusal> {
    let state = &auth.app;
    let unverified = UnverifiedToken::parse(token)?;
    let key = match state.keys.key(unverified.kid()).await {
        KeyLookup::Found(key) => key,
        KeyLookup::Unknown => return Err(Rejection::UnknownKey.into()),
        KeyLookup::NotLoaded | KeyLookup::Busy => {
            return Err(Refusal::Error(AppError::Unavailable));
        }
    };
    let principal = unverified.verify(&key, state.keys.config(), now())?;
    auth.spend(&user_key(&principal.subject))
        .map_err(Refusal::Limited)?;
    users::authenticate(&state.db, &principal)
        .await
        .map_err(Refusal::Error)
}
