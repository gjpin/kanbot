//! Refreshing a session's tokens at the identity provider, one request at
//! a time across replicas (a lease on the session row).

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use tracing::Instrument;
use uuid::Uuid;

use super::{
    KeyFailure, MAX_TOKEN_RESPONSE_BYTES, SessionRefusal, TokenResponse, key_for,
    logout::revoke_in_background, seal_tokens, session::verify_stored, stored_expiry,
    unverified_expiry,
};
use crate::{
    auth::{
        discovery::{FetchError, OAuthError},
        keys::KeyCache,
        token::{Rejection, now},
    },
    error::AppError,
    sessions::{
        config::SessionConfig,
        crypto::{self, Field},
        repo::{self, RefreshLease},
    },
};

/// How long a request waits for another one's refresh when its own
/// stored token has already expired, in steps of [`REFRESH_WAIT_STEP`].
const REFRESH_WAIT_STEPS: u32 = 20;
const REFRESH_WAIT_STEP: std::time::Duration = std::time::Duration::from_millis(100);

/// Why a refresh did not give new tokens.
enum RefreshFailure {
    /// The identity provider ended the grant (`invalid_grant`), or the
    /// refresh token cannot be opened: the session is over.
    Ended,
    /// The identity provider failed or refused for another reason
    /// (misconfiguration, outage): try again later.
    Failed,
}

/// Refreshes the session's tokens. One request takes the refresh lease
/// and calls the identity provider, holding no connection or row lock
/// meanwhile; the others use the stored token while it is valid, or wait
/// briefly for the new one. Roles are re-evaluated: the new token passes
/// the bearer rules or the session ends.
///
/// The lease, the call and storing its answer run in a task of their own,
/// so a request that is dropped meanwhile (the client went away, or the
/// request timed out) does not lose a rotated refresh token the identity
/// provider has already issued. The task is bounded by the identity
/// provider client's timeouts.
///
/// A session without a refresh token takes no lease: there is nothing to
/// refresh with.
pub(super) async fn refresh(
    db: &PgPool,
    keys: &Arc<KeyCache>,
    config: &Arc<SessionConfig>,
    session: &repo::ActiveSession,
) -> Result<crate::auth::token::Principal, SessionRefusal> {
    if session.refresh == repo::RefreshDue::WithoutRefreshToken {
        return without_refresh_token(db, keys, config, session).await;
    }
    let claimed = tokio::spawn(
        claim_and_refresh(
            db.clone(),
            Arc::clone(keys),
            Arc::clone(config),
            session.clone(),
        )
        .instrument(tracing::Span::current()),
    );
    match claimed.await {
        Ok(Some(refreshed)) => refreshed,
        Ok(None) => refreshed_elsewhere(db, keys, config, session).await,
        Err(error) => {
            tracing::error!(%error, session.id = %session.id, "session refresh task failed");
            Err(SessionRefusal::Error(AppError::Internal("session refresh")))
        }
    }
}

/// A due token that no refresh token can replace: it is used until it
/// fails (it has expired), and then the session is over.
async fn without_refresh_token(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    session: &repo::ActiveSession,
) -> Result<crate::auth::token::Principal, SessionRefusal> {
    let id = session.id;
    let verified = verify_stored(keys, config, id, &session.idp_access_token).await;
    if matches!(verified, Err(SessionRefusal::Invalid)) {
        repo::delete_session(db, id).await?;
        tracing::info!(session.id = %id, "session ended: token failed, no refresh token");
        return Err(SessionRefusal::Ended);
    }
    verified
}

/// Takes the refresh lease and refreshes; `None` if another request holds
/// the lease or has just refreshed.
async fn claim_and_refresh(
    db: PgPool,
    keys: Arc<KeyCache>,
    config: Arc<SessionConfig>,
    session: repo::ActiveSession,
) -> Option<Result<crate::auth::token::Principal, SessionRefusal>> {
    match repo::claim_refresh(&db, session.id).await {
        Ok(Some(claimed)) => Some(refresh_claimed(&db, &keys, &config, &session, claimed).await),
        Ok(None) => None,
        Err(error) => Some(Err(error.into())),
    }
}

/// The refresh, once this request holds the lease.
async fn refresh_claimed(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    session: &repo::ActiveSession,
    claimed: repo::ClaimedRefresh,
) -> Result<crate::auth::token::Principal, SessionRefusal> {
    let id = session.id;
    let lease = claimed.lease;
    match request_refresh(keys, config, id, &claimed.refresh_token).await {
        Ok((tokens, refresh_token)) => {
            let reseal = !crypto::sealed_with_current(&config.keys, &claimed.refresh_token);
            let kept_refresh = (tokens.refresh.is_none() && reseal).then_some(refresh_token);
            let refreshed = Refreshed {
                session_id: id,
                lease,
                tokens: &tokens,
                kept_refresh,
            };
            finish_refresh(db, keys, config, session, &refreshed).await
        }
        Err(RefreshFailure::Ended) => {
            repo::delete_session(db, id).await?;
            tracing::info!(session.id = %id, "session ended: refresh refused");
            Err(SessionRefusal::Ended)
        }
        Err(RefreshFailure::Failed) => {
            repo::release_refresh(db, id, lease).await?;
            // The stored token may still be valid for a few seconds.
            verify_stored(keys, config, id, &session.idp_access_token)
                .await
                .map_err(|refusal| match refusal {
                    SessionRefusal::Invalid => SessionRefusal::Error(AppError::Unavailable),
                    other => other,
                })
        }
    }
}

/// Another request holds the refresh lease, or has just refreshed: the
/// newest stored token, waiting a moment for it if the old one expired.
async fn refreshed_elsewhere(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    session: &repo::ActiveSession,
) -> Result<crate::auth::token::Principal, SessionRefusal> {
    let id = session.id;
    for step in 0..=REFRESH_WAIT_STEPS {
        if step > 0 {
            tokio::time::sleep(REFRESH_WAIT_STEP).await;
        }
        let sealed = repo::live_session_access_token(db, id)
            .await?
            .ok_or(SessionRefusal::Invalid)?;
        match verify_stored(keys, config, id, &sealed).await {
            // Expired, and the refresh is still running.
            Err(SessionRefusal::Invalid) if sealed == session.idp_access_token => {}
            other => return other,
        }
    }
    Err(SessionRefusal::Error(AppError::Unavailable))
}

/// The refresh token request. Holds no database connection.
async fn request_refresh(
    keys: &KeyCache,
    config: &SessionConfig,
    session_id: Uuid,
    sealed_refresh: &[u8],
) -> Result<(TokenResponse, SecretString), RefreshFailure> {
    let refresh_token = crypto::open(
        &config.keys,
        session_id,
        Field::RefreshToken,
        sealed_refresh,
    )
    .map_err(|_| RefreshFailure::Ended)?;
    let endpoint = keys
        .discovery()
        .and_then(|discovery| discovery.token_endpoint.clone())
        .ok_or(RefreshFailure::Failed)?;
    let refreshed = keys
        .client()
        .post_form(
            endpoint,
            &config.client_id,
            &config.client_secret,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.expose_secret()),
            ],
            MAX_TOKEN_RESPONSE_BYTES,
        )
        .await;
    match refreshed {
        Ok(tokens) => Ok((tokens, refresh_token)),
        // The identity provider ended the grant (sign-out, revocation,
        // expiry). So does kanbot. Any other refusal (a wrong client
        // secret, an outage) is not the user's: their session stays.
        Err(FetchError::Refused(_, OAuthError::InvalidGrant)) => Err(RefreshFailure::Ended),
        Err(error) => {
            tracing::warn!(%error, session.id = %session_id, "session refresh failed");
            Err(RefreshFailure::Failed)
        }
    }
}

/// The identity provider's answer to a refresh, to store.
struct Refreshed<'t> {
    session_id: Uuid,
    /// The lease the refresh ran under.
    lease: RefreshLease,
    tokens: &'t TokenResponse,
    /// The refresh token to store again when it was not rotated but is
    /// sealed with an old key.
    kept_refresh: Option<SecretString>,
}

/// Checks the refreshed tokens and stores them.
async fn finish_refresh(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    session: &repo::ActiveSession,
    refreshed: &Refreshed<'_>,
) -> Result<crate::auth::token::Principal, SessionRefusal> {
    let id = session.id;
    let tokens = refreshed.tokens;
    let principal = match key_for(keys, &tokens.access).await {
        Ok((unverified, key)) => unverified.verify(&key, keys.config(), now()),
        // The keys are not loaded, or not refreshed yet for a new key:
        // keep the new tokens (every use checks the access token) and try
        // again shortly. Dropping them could lose a rotated refresh token.
        Err(KeyFailure::NotLoaded | KeyFailure::Rejected(Rejection::UnknownKey)) => {
            let expires_at = unverified_expiry(&tokens.access).unwrap_or_else(now);
            store_refreshed(db, keys, config, refreshed, None, expires_at).await?;
            tracing::warn!(session.id = %id, "refreshed token cannot be checked yet");
            return Err(SessionRefusal::Error(AppError::Unavailable));
        }
        Err(KeyFailure::Rejected(rejection)) => Err(rejection),
    };
    let principal = match principal {
        Ok(principal) if principal.subject == session.user_subject => principal,
        Ok(_) => {
            repo::delete_session(db, id).await?;
            tracing::warn!(session.id = %id, "session ended: refreshed token is another user's");
            return Err(SessionRefusal::Invalid);
        }
        Err(rejection) => {
            repo::delete_session(db, id).await?;
            tracing::info!(session.id = %id, reason = rejection.reason(), "session ended: refreshed token refused");
            return Err(if rejection == Rejection::NoRole {
                SessionRefusal::NoRole
            } else {
                SessionRefusal::Ended
            });
        }
    };
    let id_token = verified_id_token(keys, config, tokens.id.as_deref()).await;
    store_refreshed(db, keys, config, refreshed, id_token, principal.expires_at).await?;
    tracing::info!(session.id = %id, "session refreshed");
    Ok(principal)
}

/// A refreshed ID token, if it verifies (`OpenID` Connect Core, section
/// 12.2). Otherwise the stored one stays: it only serves as the logout
/// hint.
async fn verified_id_token<'t>(
    keys: &KeyCache,
    config: &SessionConfig,
    id_token: Option<&'t str>,
) -> Option<&'t str> {
    let id_token = id_token?;
    let (unverified, key) = key_for(keys, id_token).await.ok()?;
    unverified
        .verify_id_token(&key, &keys.config().issuer, &config.client_id, now())
        .ok()
        .map(|_| id_token)
}

/// Seals and stores refreshed tokens, keeping the stored refresh and ID
/// tokens when there are no new ones, and gives the lease back.
///
/// Nothing is stored if the session ended meanwhile (signed out) or the
/// lease ran out and another request took it: a rotated refresh token is
/// then revoked, best effort, so that it does not outlive the session at
/// the identity provider. The request is refused: [`SessionRefusal::Invalid`]
/// for a session that is gone, `503` for one refreshed by another request.
async fn store_refreshed(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    refreshed: &Refreshed<'_>,
    id_token: Option<&str>,
    access_expires_at: u64,
) -> Result<(), SessionRefusal> {
    let session_id = refreshed.session_id;
    let tokens = refreshed.tokens;
    let refresh = match (tokens.refresh.as_deref(), &refreshed.kept_refresh) {
        (Some(rotated), _) => Some(rotated),
        (None, Some(kept)) => Some(kept.expose_secret()),
        (None, None) => None,
    };
    let sealed = seal_tokens(config, session_id, &tokens.access, refresh, id_token)
        .map_err(AppError::from)?;
    let stored = repo::store_refreshed(
        db,
        session_id,
        refreshed.lease,
        &repo::Refreshed {
            access_token: &sealed.access,
            refresh_token: sealed.refresh.as_deref(),
            id_token: sealed.id.as_deref(),
            access_expires_at: stored_expiry(access_expires_at),
        },
    )
    .await?;
    if stored {
        return Ok(());
    }
    // A refresh token that was not rotated is the stored one: whoever
    // ended the session revoked it, or another request uses it.
    if let Some(rotated) = tokens.refresh.as_deref() {
        revoke_in_background(
            keys,
            config,
            SecretString::from(rotated.to_owned()),
            session_id,
        );
    }
    if repo::live_session_access_token(db, session_id)
        .await?
        .is_some()
    {
        tracing::warn!(session.id = %session_id, "refresh outlasted its lease: not stored");
        Err(SessionRefusal::Error(AppError::Unavailable))
    } else {
        tracing::info!(session.id = %session_id, "session ended during its refresh: not stored");
        Err(SessionRefusal::Invalid)
    }
}
