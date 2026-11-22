//! Starting a sign-in: the login attempt and the identity provider's
//! authorization URL.

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
        model::LoginRequest,
        repo::{self, NewAttempt},
        secrets,
    },
};

/// Where to send the browser to sign in, and for the web app the value of
/// the cookie that binds the attempt to that browser.
pub struct LoginStart {
    pub authorization_url: Url,
    pub browser_binding: Option<SecretString>,
}

/// Records a new login attempt and builds the identity provider's
/// authorization URL: the authorization code flow with PKCE (S256), a state
/// and a nonce, all random, of which only hashes (and the encrypted
/// verifier) are stored.
///
/// # Errors
///
/// [`AppError::Unavailable`] until discovery has given the authorization
/// endpoint; [`AppError::Internal`] or a database error otherwise.
pub async fn start_login(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    request: &LoginRequest,
) -> Result<LoginStart, AppError> {
    let endpoint = keys
        .discovery()
        .and_then(|discovery| discovery.authorization_endpoint.clone())
        .ok_or(AppError::Unavailable)?;
    let state = secrets::issue("")?;
    let nonce = secrets::issue("")?;
    // 43 base64url characters: a valid PKCE verifier (RFC 7636).
    let verifier = secrets::issue("")?;
    let binding = match request {
        LoginRequest::Web => Some(secrets::issue("")?),
        LoginRequest::Native { .. } => None,
    };
    let id = Uuid::new_v4();
    let sealed_verifier = crypto::seal(&config.keys, id, Field::PkceVerifier, &verifier.value)?;
    let (redirect, challenge) = match request {
        LoginRequest::Web => (None, None),
        LoginRequest::Native {
            redirect,
            challenge,
        } => (Some(redirect.as_str()), Some(challenge.as_str())),
    };
    repo::insert_attempt(
        db,
        &NewAttempt {
            id,
            state_hash: &state.hash,
            nonce_hash: &nonce.hash,
            pkce_verifier: &sealed_verifier,
            platform: request.platform().as_str(),
            browser_binding_hash: binding.as_ref().map(|binding| binding.hash.as_slice()),
            app_redirect_uri: redirect,
            app_code_challenge: challenge,
        },
    )
    .await?;

    let mut authorization_url = endpoint;
    authorization_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &callback_url(config))
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", state.value.expose_secret())
        .append_pair("nonce", nonce.value.expose_secret())
        .append_pair("code_challenge", &secrets::pkce_challenge(&verifier.value))
        .append_pair("code_challenge_method", "S256");
    Ok(LoginStart {
        authorization_url,
        browser_binding: binding.map(|binding| binding.value),
    })
}

/// `<PUBLIC_URL>/auth/callback`: the only redirect URI registered at the
/// identity provider.
#[must_use]
pub fn callback_url(config: &SessionConfig) -> String {
    config.public_url.join("auth/callback")
}
