//! A request's session: who it belongs to, and the access token it holds.

use std::{sync::Arc, time::Duration};

use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use uuid::Uuid;

use super::{KeyFailure, expired, key_for, refresh::refresh};
use crate::{
    auth::{
        keys::KeyCache,
        token::{Rejection, now},
    },
    error::AppError,
    sessions::{
        config::SessionConfig,
        crypto::{self, Field},
        model::Platform,
        repo, secrets,
    },
    users::{model::UserId, service as users},
};

/// Why a session gives no user.
pub enum SessionRefusal {
    /// Unknown, idle too long, or past its absolute lifetime.
    Invalid,
    /// The identity provider refused to refresh it, the refreshed token
    /// was refused, or its token expired with no refresh token to replace
    /// it: the session has been deleted.
    Ended,
    /// The access token is valid but carries no kanbot role.
    NoRole,
    /// A failure of the server or the identity provider.
    Error(AppError),
}

impl From<AppError> for SessionRefusal {
    fn from(error: AppError) -> Self {
        Self::Error(error)
    }
}

impl From<sqlx::Error> for SessionRefusal {
    fn from(error: sqlx::Error) -> Self {
        Self::Error(error.into())
    }
}

/// The user behind a session, and the session.
pub struct SessionUser {
    pub user: crate::users::model::AuthenticatedUser,
    pub session_id: Uuid,
    pub kind: Platform,
}

/// The user of a session token (`kbs_...`, from the cookie or a bearer
/// header). The stored access token is checked with exactly the bearer
/// rules, after a refresh when it expires within a minute.
///
/// A disabled user's session is refused before anything else, the
/// identity provider included, and all of that user's sessions end.
///
/// # Errors
///
/// [`SessionRefusal`].
pub async fn authenticate_session(
    db: &PgPool,
    keys: &Arc<KeyCache>,
    config: &Arc<SessionConfig>,
    token: &str,
) -> Result<SessionUser, SessionRefusal> {
    let hash = secrets::presented(secrets::SESSION_TOKEN, token).ok_or(SessionRefusal::Invalid)?;
    let idle = idle(config);
    let session = repo::find_session(db, &hash, idle)
        .await?
        .ok_or(SessionRefusal::Invalid)?;
    if session.user_disabled {
        users::end_sessions(db, UserId::from_uuid(session.user_id)).await?;
        return Err(SessionRefusal::Error(AppError::AccountDisabled));
    }
    let principal = match session.refresh {
        repo::RefreshDue::No => {
            verify_stored(keys, config, session.id, &session.idp_access_token).await?
        }
        repo::RefreshDue::Yes | repo::RefreshDue::WithoutRefreshToken => {
            refresh(db, keys, config, &session).await?
        }
    };
    let user = match users::authenticate(db, &principal).await {
        Ok(user) => user,
        Err(AppError::AccountDisabled) => {
            // Disabled since the session was found: end all of their
            // sessions.
            users::end_sessions(db, UserId::from_uuid(session.user_id)).await?;
            return Err(SessionRefusal::Error(AppError::AccountDisabled));
        }
        Err(error) => return Err(error.into()),
    };
    if user.id.as_uuid() != session.user_id {
        // Cannot happen unless the issuer or subject claim was reconfigured.
        tracing::warn!(session.id = %session.id, "session token belongs to another user");
        repo::delete_session(db, session.id).await?;
        return Err(SessionRefusal::Invalid);
    }
    // Only a session that authenticated this request counts as used.
    if session.touch_due {
        repo::touch_session(db, session.id, idle).await?;
    }
    let kind = Platform::parse(&session.kind).unwrap_or(Platform::Web);
    Ok(SessionUser {
        user,
        session_id: session.id,
        kind,
    })
}

/// A live session, found by [`identify_session`].
pub struct IdentifiedSession {
    pub id: Uuid,
    pub kind: Platform,
}

/// The live session (neither idle too long nor past its absolute
/// lifetime) of a session token, from the token's hash alone: neither the
/// stored access token nor the user is checked, and the identity provider
/// is never called. Only to end the session (logout), which must work
/// while the identity provider is unreachable or its keys have not loaded.
///
/// # Errors
///
/// [`SessionRefusal::Invalid`] for an unknown or ended session, or a
/// database error.
pub async fn identify_session(
    db: &PgPool,
    config: &SessionConfig,
    token: &str,
) -> Result<IdentifiedSession, SessionRefusal> {
    let hash = secrets::presented(secrets::SESSION_TOKEN, token).ok_or(SessionRefusal::Invalid)?;
    let session = repo::find_session(db, &hash, idle(config))
        .await?
        .ok_or(SessionRefusal::Invalid)?;
    Ok(IdentifiedSession {
        id: session.id,
        kind: Platform::parse(&session.kind).unwrap_or(Platform::Web),
    })
}

fn idle(config: &SessionConfig) -> repo::Idle {
    repo::Idle {
        seconds: config.idle_timeout.as_secs_f64(),
        slack_seconds: touch_slack(config.idle_timeout),
    }
}

/// The identity provider access token behind a session, for a call to
/// another service on the user's behalf (token exchange). Never log it.
///
/// # Errors
///
/// [`AppError::Unauthorized`] if the session is gone or over (idle too
/// long, or past its absolute lifetime), or another
/// [`AppError`].
pub async fn stored_access_token(
    db: &PgPool,
    config: &SessionConfig,
    session_id: Uuid,
) -> Result<SecretString, AppError> {
    let sealed = repo::live_session_access_token(db, session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    crypto::open(&config.keys, session_id, Field::AccessToken, &sealed)
        .map_err(|_| AppError::Internal("session token cannot be opened"))
}

/// How far a session's idle expiry may fall behind a full idle timeout
/// before a use moves it forward, in seconds: a tenth of the timeout, at
/// most a minute. A session is written at most once per slack, and ends
/// at most that much before the configured idle timeout.
fn touch_slack(idle_timeout: Duration) -> f64 {
    (idle_timeout.as_secs_f64() / 10.0).min(60.0)
}

/// Checks a stored access token with the bearer rules. Until the identity
/// provider's keys have loaded, that cannot be done: `503`, never a
/// refusal that would end the session. Neither can it for a key kanbot
/// has not fetched yet: a stored token came from the token endpoint, so
/// its key is new (the identity provider is rotating), not forged; while
/// the token has not expired, that is a `503` as well.
pub(super) async fn verify_stored(
    keys: &KeyCache,
    config: &SessionConfig,
    session_id: Uuid,
    sealed: &[u8],
) -> Result<crate::auth::token::Principal, SessionRefusal> {
    let token = crypto::open(&config.keys, session_id, Field::AccessToken, sealed)
        .map_err(|_| SessionRefusal::Invalid)?;
    let (unverified, key) = key_for(keys, token.expose_secret())
        .await
        .map_err(|failure| match failure {
            KeyFailure::NotLoaded => SessionRefusal::Error(AppError::Unavailable),
            KeyFailure::Rejected(Rejection::UnknownKey)
                if !expired(token.expose_secret(), now()) =>
            {
                SessionRefusal::Error(AppError::Unavailable)
            }
            KeyFailure::Rejected(_) => SessionRefusal::Invalid,
        })?;
    unverified
        .verify(&key, keys.config(), now())
        .map_err(|rejection| match rejection {
            Rejection::NoRole => SessionRefusal::NoRole,
            _ => SessionRefusal::Invalid,
        })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::touch_slack;

    #[test]
    fn the_touch_slack_is_a_tenth_of_the_idle_timeout_up_to_a_minute() {
        assert!((touch_slack(Duration::from_secs(30)) - 3.0).abs() < f64::EPSILON);
        assert!((touch_slack(Duration::from_secs(600)) - 60.0).abs() < f64::EPSILON);
        assert!((touch_slack(Duration::from_hours(7 * 24)) - 60.0).abs() < f64::EPSILON);
    }
}
