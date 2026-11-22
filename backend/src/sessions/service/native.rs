//! Native apps: redeeming the one-time code for a session token.

use secrecy::SecretString;
use sqlx::PgPool;

use crate::{
    error::AppError,
    sessions::{model::CodeChallenge, repo, secrets},
};

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
