//! A request's session: who it belongs to, and the access token it holds.

use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use uuid::Uuid;

use super::{KeyFailure, key_for, now, refresh::refresh};
use crate::{
    auth::{keys::KeyCache, token::Rejection},
    error::AppError,
    sessions::{
        config::SessionConfig,
        crypto::{self, Field},
        model::Platform,
        repo, secrets,
    },
    users::service as users,
};

/// Why a session gives no user.
pub enum SessionRefusal {
    /// Unknown, idle too long, or past its absolute lifetime.
    Invalid,
    /// The identity provider refused to refresh it, or the refreshed token
    /// was refused: the session has been deleted.
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
/// # Errors
///
/// [`SessionRefusal`].
pub async fn authenticate_session(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    token: &str,
) -> Result<SessionUser, SessionRefusal> {
    let hash = secrets::presented(secrets::SESSION_TOKEN, token).ok_or(SessionRefusal::Invalid)?;
    let session = repo::find_session(db, &hash)
        .await?
        .ok_or(SessionRefusal::Invalid)?;
    if session.touch_due {
        repo::touch_session(db, session.id, config.idle_timeout.as_secs_f64()).await?;
    }
    let principal = if session.refresh_due {
        refresh(db, keys, config, &session).await?
    } else {
        verify_stored(keys, config, session.id, &session.idp_access_token).await?
    };
    let user = match users::authenticate(db, &principal).await {
        Ok(user) => user,
        Err(AppError::AccountDisabled) => {
            // Disabled since the session began: end all of their sessions.
            users::end_sessions(db, crate::users::model::UserId::from_uuid(session.user_id))
                .await?;
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
    let kind = Platform::parse(&session.kind).unwrap_or(Platform::Web);
    Ok(SessionUser {
        user,
        session_id: session.id,
        kind,
    })
}

/// The identity provider access token behind a session, for a call to
/// another service on the user's behalf (token exchange). Never log it.
///
/// # Errors
///
/// [`AppError::Unauthorized`] if the session is gone, or another
/// [`AppError`].
pub async fn stored_access_token(
    db: &PgPool,
    config: &SessionConfig,
    session_id: Uuid,
) -> Result<SecretString, AppError> {
    let sealed = repo::access_token(db, session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    crypto::open(&config.keys, session_id, Field::AccessToken, &sealed)
        .map_err(|_| AppError::Internal("session token cannot be opened"))
}

/// Checks a stored access token with the bearer rules. Until the identity
/// provider's keys have loaded, that cannot be done: `503`, never a
/// refusal that would end the session.
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
            KeyFailure::Rejected(_) => SessionRefusal::Invalid,
        })?;
    unverified
        .verify(&key, keys.config(), now())
        .map_err(|rejection| match rejection {
            Rejection::NoRole => SessionRefusal::NoRole,
            _ => SessionRefusal::Invalid,
        })
}
