//! Business rules of the login flow and sessions.

use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{
        discovery::{FetchError, OAuthError},
        keys::{KeyCache, KeyLookup, VerifyingKey},
        token::{Rejection, UnverifiedToken},
    },
    error::AppError,
    sessions::{
        config::SessionConfig,
        crypto::{self, Field},
        model::{CodeChallenge, LoginRequest, Platform},
        repo::{self, NewAttempt, NewSession},
        secrets,
    },
    users::service as users,
};

/// Largest token endpoint response read, in bytes.
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

/// Where to send the browser to sign in, and for the web app the value of
/// the cookie that binds the attempt to that browser.
pub struct LoginStart {
    pub authorization_url: Url,
    pub browser_binding: Option<SecretString>,
}

impl From<secrets::NoRandomness> for AppError {
    fn from(_: secrets::NoRandomness) -> Self {
        Self::Internal("randomness")
    }
}

impl From<crypto::CryptoError> for AppError {
    fn from(_: crypto::CryptoError) -> Self {
        Self::Internal("crypto")
    }
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

/// Why a sign-in failed, as the stable `error` parameter of the redirect
/// back to the app. Never more detail than this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginError {
    /// The user declined at the identity provider, or is disabled here.
    AccessDenied,
    /// Anything else: an unknown or replayed state, a refused token, the
    /// identity provider failing.
    LoginFailed,
    /// The user signed in but has no kanbot role.
    NoRole,
}

impl LoginError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessDenied => "access_denied",
            Self::LoginFailed => "login_failed",
            Self::NoRole => "no_role",
        }
    }
}

/// Where the outcome of a sign-in goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// The web app (`<PUBLIC_URL>/`, or `<PUBLIC_URL>/login` on failure).
    Web,
    /// A native app's redirect URI.
    App(String),
}

/// How a sign-in ended.
pub enum LoginOutcome {
    /// A web session: its token goes into the session cookie.
    WebSession { token: SecretString },
    /// A native session waiting for its one-time code to be redeemed.
    NativeCode {
        redirect: String,
        code: SecretString,
    },
    Failed {
        destination: Destination,
        error: LoginError,
    },
}

/// What the identity provider sent back to the callback.
pub struct CallbackParams<'a> {
    pub state: Option<&'a str>,
    pub code: Option<&'a str>,
    /// The `error` parameter of an authorization error response.
    pub error: Option<&'a str>,
    /// The `iss` parameter (RFC 9207), when the identity provider sends
    /// it: it must be `OIDC_ISSUER`, against mix-up attacks.
    pub issuer: Option<&'a str>,
    /// Whether a parameter was sent more than once (one that was is
    /// `None`): the response is refused.
    pub repeated: bool,
}

/// A token endpoint's answer (RFC 6749, section 5.1).
#[derive(Deserialize)]
struct TokenResponse {
    #[serde(rename = "access_token")]
    access: String,
    #[serde(rename = "id_token")]
    id: Option<String>,
    #[serde(rename = "refresh_token")]
    refresh: Option<String>,
}

/// A refusal: the error the app sees, and the reason for the log.
type Refusal = (LoginError, &'static str);

const fn refused(reason: &'static str) -> Refusal {
    (LoginError::LoginFailed, reason)
}

/// Finishes a sign-in at `/auth/callback`: checks the state (and the
/// browser binding for the web), exchanges the code, validates the ID
/// token and the access token, records the user and creates the session.
///
/// # Errors
///
/// Only infrastructure failures (database, randomness, encryption) are
/// errors; every reason to refuse the sign-in is a [`LoginOutcome::Failed`].
pub async fn finish_login(
    db: &PgPool,
    keys: &KeyCache,
    config: &SessionConfig,
    params: &CallbackParams<'_>,
    browser_binding: Option<&str>,
) -> Result<LoginOutcome, AppError> {
    // Values without the shape of an issued one cannot match: no query
    // for them (a binding that cannot match is no binding).
    let Some(state_hash) = params.state.and_then(|state| secrets::presented("", state)) else {
        return Ok(failed(
            Destination::Web,
            refused("no state or a malformed one"),
        ));
    };
    let binding_hash = browser_binding.and_then(|binding| secrets::presented("", binding));
    let Some(attempt) = repo::consume_attempt(
        db,
        &state_hash,
        binding_hash.as_ref().map(<[u8; 32]>::as_slice),
    )
    .await?
    else {
        return Ok(failed(
            Destination::Web,
            refused("unknown, used or unbound state"),
        ));
    };
    let destination = attempt
        .app_redirect_uri
        .clone()
        .map_or(Destination::Web, Destination::App);
    if params.repeated {
        return Ok(failed(destination, refused("a repeated parameter")));
    }
    let principal = match authorize(keys, config, params, &attempt).await {
        Ok(principal) => principal,
        Err(refusal) => return Ok(failed(destination, refusal)),
    };
    let (tokens, principal) = principal;
    let user = match users::authenticate(db, &principal).await {
        Ok(user) => user,
        Err(AppError::AccountDisabled) => {
            return Ok(failed(
                destination,
                (LoginError::AccessDenied, "disabled user"),
            ));
        }
        Err(error) => return Err(error),
    };
    let platform = match destination {
        Destination::Web => Platform::Web,
        Destination::App(_) => Platform::Native,
    };
    let (session_id, session_token) = create_session(
        db,
        config,
        platform,
        user.id.as_uuid(),
        &tokens,
        principal.expires_at,
    )
    .await?;
    tracing::info!(
        user.id = %user.id.as_uuid(),
        session.id = %session_id,
        kind = platform.as_str(),
        "signed in"
    );
    match (
        session_token,
        attempt.app_redirect_uri,
        attempt.app_code_challenge,
    ) {
        (Some(token), _, _) => Ok(LoginOutcome::WebSession { token: token.value }),
        (None, Some(redirect), Some(challenge)) => {
            let code = secrets::issue(secrets::LOGIN_CODE)?;
            repo::insert_code(db, &code.hash, session_id, &challenge).await?;
            Ok(LoginOutcome::NativeCode {
                redirect,
                code: code.value,
            })
        }
        // The schema makes a native attempt carry both.
        (None, _, _) => Err(AppError::Internal("native attempt without redirect")),
    }
}

fn failed(destination: Destination, (error, reason): Refusal) -> LoginOutcome {
    tracing::info!(reason, error = error.as_str(), "sign-in refused");
    LoginOutcome::Failed { destination, error }
}

/// Exchanges the code and validates both tokens: the ID token was issued
/// to kanbot for this attempt's nonce, and the access token passes exactly
/// the bearer-token rules.
async fn authorize(
    keys: &KeyCache,
    config: &SessionConfig,
    params: &CallbackParams<'_>,
    attempt: &repo::Attempt,
) -> Result<(TokenResponse, crate::auth::token::Principal), Refusal> {
    if params
        .issuer
        .is_some_and(|issuer| issuer != keys.config().issuer.as_str())
    {
        return Err(refused("iss parameter from another issuer"));
    }
    if let Some(error) = params.error {
        let error = if error == "access_denied" {
            LoginError::AccessDenied
        } else {
            LoginError::LoginFailed
        };
        return Err((error, "the identity provider returned an error"));
    }
    let code = params.code.ok_or(refused("no code"))?;
    let tokens = exchange(keys, config, attempt, code).await?;
    let now = now();

    let id_token = tokens.id.as_deref().ok_or(refused("no ID token"))?;
    let (unverified, key) = key_for(keys, id_token)
        .await
        .map_err(|_| refused("ID token key unknown"))?;
    let claims = unverified
        .verify_id_token(&key, &keys.config().issuer, &config.client_id, now)
        .map_err(|_| refused("ID token refused"))?;
    let nonce_matches = claims
        .nonce
        .as_deref()
        .is_some_and(|nonce| secrets::hash(nonce).as_slice() == attempt.nonce_hash.as_slice());
    if !nonce_matches {
        return Err(refused("ID token nonce mismatch"));
    }

    let (unverified, key) = key_for(keys, &tokens.access)
        .await
        .map_err(|_| refused("access token key unknown"))?;
    match unverified.verify(&key, keys.config(), now) {
        Ok(principal) => Ok((tokens, principal)),
        Err(Rejection::NoRole) => Err((LoginError::NoRole, "no role")),
        Err(rejection) => {
            tracing::info!(
                reason = rejection.reason(),
                "access token refused at sign-in"
            );
            Err(refused("access token refused"))
        }
    }
}

/// The token request: the code, the callback URL and the PKCE verifier,
/// with the client's credentials.
async fn exchange(
    keys: &KeyCache,
    config: &SessionConfig,
    attempt: &repo::Attempt,
    code: &str,
) -> Result<TokenResponse, Refusal> {
    let verifier = crypto::open(
        &config.keys,
        attempt.id,
        Field::PkceVerifier,
        &attempt.pkce_verifier,
    )
    .map_err(|_| refused("verifier cannot be opened"))?;
    let endpoint = keys
        .discovery()
        .and_then(|discovery| discovery.token_endpoint.clone())
        .ok_or(refused("no token endpoint"))?;
    let callback = callback_url(config);
    keys.client()
        .post_form(
            endpoint,
            &config.client_id,
            &config.client_secret,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &callback),
                ("code_verifier", verifier.expose_secret()),
            ],
            MAX_TOKEN_RESPONSE_BYTES,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "token exchange failed");
            refused("token exchange failed")
        })
}

/// Stores the session with the sealed tokens. A web session gets its
/// token now; a native one when its code is redeemed.
async fn create_session(
    db: &PgPool,
    config: &SessionConfig,
    platform: Platform,
    user_id: Uuid,
    tokens: &TokenResponse,
    access_expires_at: u64,
) -> Result<(Uuid, Option<secrets::Issued>), AppError> {
    let session_id = Uuid::new_v4();
    let seal = |field: Field, value: &str| {
        crypto::seal(
            &config.keys,
            session_id,
            field,
            &SecretString::from(value.to_owned()),
        )
    };
    let access = seal(Field::AccessToken, &tokens.access)?;
    let refresh = tokens
        .refresh
        .as_deref()
        .map(|token| seal(Field::RefreshToken, token))
        .transpose()?;
    let id = tokens
        .id
        .as_deref()
        .map(|token| seal(Field::IdToken, token))
        .transpose()?;
    let session_token = match platform {
        Platform::Web => Some(secrets::issue(secrets::SESSION_TOKEN)?),
        Platform::Native => None,
    };
    repo::insert_session(
        db,
        &NewSession {
            id: session_id,
            token_hash: session_token.as_ref().map(|token| token.hash.as_slice()),
            user_id,
            kind: platform.as_str(),
            access_token: &access,
            refresh_token: refresh.as_deref(),
            id_token: id.as_deref(),
            access_expires_at: stored_expiry(access_expires_at),
            idle_seconds: config.idle_timeout.as_secs_f64(),
            absolute_seconds: config.absolute_timeout.as_secs_f64(),
        },
    )
    .await?;
    Ok((session_id, session_token))
}

/// A native app's session, handed over for its one-time code.
pub struct RedeemedSession {
    pub token: SecretString,
    /// The session's absolute expiry, RFC 3339 in UTC.
    pub expires_at: String,
}

/// Redeems a one-time code: it must be unused and unexpired, and
/// `verifier` must be the app's PKCE verifier (S256 of it equals the
/// challenge the app sent to `/auth/login`). The code is spent either way,
/// so an intercepted code is burnt by a wrong guess. The session's token
/// is created now and only returned here.
///
/// # Errors
///
/// [`AppError::BadRequest`] for any invalid, used or expired code or wrong
/// verifier, without saying which; database or internal errors otherwise.
pub async fn redeem_code(
    db: &PgPool,
    code: &str,
    verifier: &SecretString,
) -> Result<RedeemedSession, AppError> {
    let code_hash = secrets::presented(secrets::LOGIN_CODE, code).ok_or(AppError::BadRequest)?;
    let (session_id, challenge) = repo::consume_code(db, &code_hash)
        .await?
        .ok_or(AppError::BadRequest)?;
    let challenge_matches =
        CodeChallenge::parse(&challenge).is_some_and(|challenge| challenge.matches(verifier));
    if !challenge_matches {
        tracing::info!(session.id = %session_id, "one-time code redeemed with a wrong verifier");
        // The code is spent, so the session can never be handed over.
        repo::delete_session(db, session_id).await?;
        return Err(AppError::BadRequest);
    }
    let token = secrets::issue(secrets::SESSION_TOKEN)?;
    let expires_at = repo::activate_native_session(db, session_id, &token.hash)
        .await?
        .ok_or(AppError::BadRequest)?;
    tracing::info!(session.id = %session_id, "native session handed over");
    Ok(RedeemedSession {
        token: token.value,
        expires_at,
    })
}

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
async fn verify_stored(
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
async fn refresh(
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

/// The latest `exp` stored: Postgres timestamps end in year 294276, so a
/// larger one is cut (to the end of year 9999) rather than failing.
const MAX_STORED_EXPIRY: u64 = 253_402_300_799;

fn stored_expiry(exp: u64) -> i64 {
    i64::try_from(exp.min(MAX_STORED_EXPIRY)).unwrap_or(i64::MAX)
}

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

/// Rows deleted per statement by [`cleanup`].
pub const CLEANUP_BATCH: i64 = 1000;
/// How long one run may delete: short statements, but no limit on how
/// many fit, so cleanup keeps up with sign-ins started at the sign-in
/// routes' rate limit.
const CLEANUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
/// How often [`spawn_cleanup`] runs [`cleanup`].
const CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Deletes expired login attempts, one-time codes and sessions, `batch`
/// rows per statement, until a statement deletes fewer or `budget` has
/// passed. Returns how many rows went.
///
/// # Errors
///
/// A database error; what was deleted before it stays deleted.
pub async fn cleanup(
    db: &PgPool,
    batch: i64,
    budget: std::time::Duration,
) -> Result<u64, sqlx::Error> {
    let started = tokio::time::Instant::now();
    let mut deleted = 0_u64;
    for table in 0..3 {
        while started.elapsed() < budget {
            let count = match table {
                0 => repo::delete_expired_attempts(db, batch).await?,
                1 => repo::delete_expired_codes(db, batch).await?,
                _ => repo::delete_expired_sessions(db, batch).await?,
            };
            deleted = deleted.saturating_add(count);
            if count < u64::try_from(batch).unwrap_or(u64::MAX) {
                break;
            }
        }
    }
    Ok(deleted)
}

/// Runs [`cleanup`] every minute on the current Tokio runtime.
pub fn spawn_cleanup(db: PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            match cleanup(&db, CLEANUP_BATCH, CLEANUP_BUDGET).await {
                Ok(deleted) => tracing::debug!(
                    deleted = i64::try_from(deleted).unwrap_or(i64::MAX),
                    "expired sessions cleaned up"
                ),
                Err(error) => tracing::warn!(
                    error.type = crate::error::AppError::from(error).kind(),
                    "session cleanup failed"
                ),
            }
        }
    });
}

/// Why a token's key was not found.
enum KeyFailure {
    /// No keys have loaded yet: the token may well be valid.
    NotLoaded,
    Rejected(Rejection),
}

/// The token's key, refreshing the keys once for an unknown `kid`.
async fn key_for<'t>(
    keys: &KeyCache,
    token: &'t str,
) -> Result<(UnverifiedToken<'t>, std::sync::Arc<VerifyingKey>), KeyFailure> {
    let unverified = UnverifiedToken::parse(token).map_err(KeyFailure::Rejected)?;
    match keys.key(unverified.kid()).await {
        KeyLookup::Found(key) => Ok((unverified, key)),
        KeyLookup::Unknown => Err(KeyFailure::Rejected(Rejection::UnknownKey)),
        KeyLookup::NotLoaded => Err(KeyFailure::NotLoaded),
    }
}

/// Seconds since the Unix epoch; a clock before 1970 fails closed (see
/// `auth::middleware`).
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |since| since.as_secs())
}
