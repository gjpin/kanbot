//! Finishing a sign-in at `/auth/callback`: the state, the code exchange,
//! the tokens' checks, and the new session.

use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use uuid::Uuid;

use super::{
    MAX_TOKEN_RESPONSE_BYTES, TokenResponse, callback_url, key_for, seal_tokens, stored_expiry,
};
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
        repo::{self, NewSession},
        secrets,
    },
    users::service as users,
};

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
    let sealed = seal_tokens(
        config,
        session_id,
        &tokens.access,
        tokens.refresh.as_deref(),
        tokens.id.as_deref(),
    )?;
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
            access_token: &sealed.access,
            refresh_token: sealed.refresh.as_deref(),
            id_token: sealed.id.as_deref(),
            access_expires_at: stored_expiry(access_expires_at),
            idle_seconds: config.idle_timeout.as_secs_f64(),
            absolute_seconds: config.absolute_timeout.as_secs_f64(),
        },
    )
    .await?;
    Ok((session_id, session_token))
}
