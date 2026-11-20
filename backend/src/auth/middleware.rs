//! The authentication middleware: turns the request's credentials into an
//! [`AuthenticatedUser`] in the request extensions.
//!
//! - No credentials: the request continues anonymously. Routes that need a
//!   user refuse it through the [`AuthUser`](crate::http::extract::AuthUser)
//!   extractor.
//! - Invalid credentials: `401` at once, never treated as anonymous.
//! - Valid credentials: the user is recorded and attached to the request.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    auth::{
        keys::KeyLookup,
        token::{Rejection, UnverifiedToken},
    },
    error::AppError,
    state::AppState,
    users::{model::AuthenticatedUser, service as users},
};

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

/// Middleware (`axum::middleware::from_fn_with_state`).
pub async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match credentials(request.headers()) {
        Credentials::None => return next.run(request).await,
        Credentials::Unusable => return AppError::InvalidToken.into_response(),
        Credentials::Bearer(token) => token,
    };
    match user(&state, token).await {
        Ok(user) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

/// The user of a bearer token. A token whose key cannot be checked yet
/// (keys not loaded) is `503`, not `401`: it may well be valid.
async fn user(state: &AppState, token: &str) -> Result<AuthenticatedUser, AppError> {
    let unverified = UnverifiedToken::parse(token).map_err(reject)?;
    let key = match state.keys.key(unverified.kid()).await {
        KeyLookup::Found(key) => key,
        KeyLookup::Unknown => return Err(reject(Rejection::UnknownKey)),
        KeyLookup::NotLoaded => return Err(AppError::Unavailable),
    };
    let principal = unverified
        .verify(&key, state.keys.config(), now())
        .map_err(reject)?;
    users::authenticate(&state.db, &principal).await
}

/// The response for a refused token: `403` for a valid token without a
/// kanbot role, `401` otherwise. The reason is never sent.
fn reject(rejection: Rejection) -> AppError {
    tracing::debug!(reason = rejection.reason(), "token rejected");
    match rejection {
        Rejection::NoRole => AppError::Forbidden,
        _ => AppError::InvalidToken,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
