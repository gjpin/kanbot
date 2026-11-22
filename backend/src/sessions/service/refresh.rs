//! Refreshing a session's tokens at the identity provider, one request at
//! a time across replicas (a lease on the session row).

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use super::{
    KeyFailure, MAX_TOKEN_RESPONSE_BYTES, SessionRefusal, TokenResponse, key_for, now,
    session::verify_stored, stored_expiry,
};
use crate::{
    auth::{
        discovery::{FetchError, OAuthError},
        keys::KeyCache,
        token::Rejection,
    },
    error::AppError,
    sessions::{
        config::SessionConfig,
        crypto::{self, Field},
        repo,
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
    /// No refresh token was issued: the stored token lasts until it
    /// expires.
    NoRefreshToken,
    /// The identity provider failed or refused for another reason
    /// (misconfiguration, outage): try again later.
    Failed,
}

/// Refreshes the session's tokens. One request takes the refresh lease
/// and calls the identity provider, holding no connection or row lock
/// meanwhile; the others use the stored token while it is valid, or wait
/// briefly for the new one. Roles are re-evaluated: the new token passes
/// the bearer rules or the session ends.
pub(super) async fn refresh(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    session: &repo::ActiveSession,
) -> Result<crate::auth::token::Principal, SessionRefusal> {
    let id = session.id;
    let Some(sealed_refresh) = repo::claim_refresh(db, id).await? else {
        return refreshed_elsewhere(db, keys, config, session).await;
    };
    let tokens = match sealed_refresh.as_deref() {
        Some(sealed) => request_refresh(keys, config, id, sealed).await,
        None => Err(RefreshFailure::NoRefreshToken),
    };
    match tokens {
        Ok((tokens, refresh_token)) => {
            let reseal = sealed_refresh
                .as_deref()
                .is_some_and(|sealed| !crypto::sealed_with_current(&config.keys, sealed));
            let kept_refresh = (tokens.refresh.is_none() && reseal).then_some(refresh_token);
            finish_refresh(db, keys, config, session, &tokens, kept_refresh).await
        }
        Err(RefreshFailure::Ended) => {
            repo::delete_session(db, id).await?;
            tracing::info!(session.id = %id, "session ended: refresh refused");
            Err(SessionRefusal::Ended)
        }
        Err(RefreshFailure::NoRefreshToken) => {
            repo::release_refresh(db, id).await?;
            verify_stored(keys, config, id, &session.idp_access_token).await
        }
        Err(RefreshFailure::Failed) => {
            repo::release_refresh(db, id).await?;
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
        let sealed = repo::stored_access_token(db, id)
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

/// Checks the refreshed tokens and stores them. `kept_refresh` is the
/// refresh token to store again when it was not rotated but is sealed with
/// an old key.
async fn finish_refresh(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    session: &repo::ActiveSession,
    tokens: &TokenResponse,
    kept_refresh: Option<SecretString>,
) -> Result<crate::auth::token::Principal, SessionRefusal> {
    let id = session.id;
    let principal = match key_for(keys, &tokens.access).await {
        Ok((unverified, key)) => unverified.verify(&key, keys.config(), now()),
        // The keys are not loaded, or not refreshed yet for a new key:
        // keep the new tokens (every use checks the access token) and try
        // again shortly. Dropping them could lose a rotated refresh token.
        Err(KeyFailure::NotLoaded | KeyFailure::Rejected(Rejection::UnknownKey)) => {
            let expires_at = unverified_expiry(&tokens.access).unwrap_or_else(now);
            store_refreshed(db, config, id, tokens, None, kept_refresh, expires_at).await?;
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
    store_refreshed(
        db,
        config,
        id,
        tokens,
        id_token,
        kept_refresh,
        principal.expires_at,
    )
    .await?;
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

/// The `exp` of a JWT, unverified: only to schedule the next refresh of a
/// token that every use still verifies.
fn unverified_expiry(token: &str) -> Option<u64> {
    #[derive(Deserialize)]
    struct Claims {
        exp: u64,
    }
    let payload = token.split('.').nth(1)?;
    let claims: Claims = serde_json::from_slice(&crate::base64::decode_url(payload)?).ok()?;
    Some(claims.exp)
}

/// Seals and stores refreshed tokens, keeping the stored refresh and ID
/// tokens when there are no new ones, and gives the lease back.
async fn store_refreshed(
    db: &PgPool,
    config: &SessionConfig,
    session_id: Uuid,
    tokens: &TokenResponse,
    id_token: Option<&str>,
    kept_refresh: Option<SecretString>,
    access_expires_at: u64,
) -> Result<(), AppError> {
    let seal = |field: Field, value: &str| {
        crypto::seal(
            &config.keys,
            session_id,
            field,
            &SecretString::from(value.to_owned()),
        )
    };
    let access = seal(Field::AccessToken, &tokens.access)?;
    let refresh = match (tokens.refresh.as_deref(), kept_refresh) {
        (Some(rotated), _) => Some(seal(Field::RefreshToken, rotated)?),
        (None, Some(kept)) => Some(seal(Field::RefreshToken, kept.expose_secret())?),
        (None, None) => None,
    };
    let id = id_token
        .map(|token| seal(Field::IdToken, token))
        .transpose()?;
    repo::store_refreshed(
        db,
        session_id,
        &access,
        refresh.as_deref(),
        id.as_deref(),
        stored_expiry(access_expires_at),
    )
    .await?;
    Ok(())
}
