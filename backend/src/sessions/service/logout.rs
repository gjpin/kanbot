//! Ending sessions: logout (with the identity provider's logout and token
//! revocation), and all of a disabled user's sessions.

use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::keys::KeyCache,
    error::AppError,
    sessions::{
        config::SessionConfig,
        crypto::{self, Field},
        model::Platform,
        repo,
    },
};

/// Ends a session. Returns the identity provider's logout URL (with
/// `id_token_hint` and `post_logout_redirect_uri`) for a web session when
/// discovery lists an `end_session_endpoint`, so the browser can end that
/// session too; native apps never open a browser to sign out. The refresh
/// token is revoked at the identity provider (RFC 7009) in the background
/// when discovery lists a `revocation_endpoint`: without it, an offline
/// session could outlive the sign-out there.
///
/// # Errors
///
/// A database error.
pub async fn logout(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    session_id: Uuid,
) -> Result<Option<Url>, AppError> {
    let Some(deleted) = repo::delete_session(db, session_id).await? else {
        return Ok(None);
    };
    tracing::info!(session.id = %session_id, "signed out");
    let discovery = keys.discovery();
    if let (Some(sealed), Some(endpoint)) = (
        deleted.idp_refresh_token.as_deref(),
        discovery
            .as_ref()
            .and_then(|discovery| discovery.revocation_endpoint.clone()),
    ) && let Ok(token) = crypto::open(&config.keys, session_id, Field::RefreshToken, sealed)
    {
        revoke_in_background(keys, config, endpoint, token, session_id);
    }
    if Platform::parse(&deleted.kind) == Some(Platform::Native) {
        return Ok(None);
    }
    let Some(mut url) = discovery.and_then(|discovery| discovery.end_session_endpoint.clone())
    else {
        return Ok(None);
    };
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("client_id", &config.client_id)
            .append_pair("post_logout_redirect_uri", &config.public_url.join(""));
        if let Some(id_token) = deleted
            .idp_id_token
            .and_then(|sealed| crypto::open(&config.keys, session_id, Field::IdToken, &sealed).ok())
        {
            query.append_pair("id_token_hint", id_token.expose_secret());
        }
    }
    Ok(Some(url))
}

/// Revokes `refresh_token` at `endpoint`, best effort: one call, bounded by
/// the identity provider client's timeouts, not awaited by the sign-out.
fn revoke_in_background(
    keys: &KeyCache,
    config: &SessionConfig,
    endpoint: Url,
    refresh_token: SecretString,
    session_id: Uuid,
) {
    let client = keys.client().clone();
    let client_id = config.client_id.clone();
    let client_secret = config.client_secret.clone();
    tokio::spawn(async move {
        let revoked = client
            .post_form_empty(
                endpoint,
                &client_id,
                &client_secret,
                &[
                    ("token", refresh_token.expose_secret()),
                    ("token_type_hint", "refresh_token"),
                ],
            )
            .await;
        if let Err(error) = revoked {
            tracing::info!(%error, session.id = %session_id, "refresh token not revoked");
        }
    });
}

/// Ends every session of `user` (disabled), on `db` (which may be a
/// transaction). Returns how many there were.
///
/// # Errors
///
/// A database error.
pub async fn end_user_sessions(
    db: &mut sqlx::PgConnection,
    user: crate::users::model::UserId,
) -> Result<u64, AppError> {
    Ok(repo::delete_user_sessions(db, user.as_uuid()).await?)
}
