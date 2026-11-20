//! Database access for the login flow and sessions.

use sqlx::PgPool;
use uuid::Uuid;

/// A login attempt to store.
pub(super) struct NewAttempt<'a> {
    pub id: Uuid,
    pub state_hash: &'a [u8],
    pub nonce_hash: &'a [u8],
    pub pkce_verifier: &'a [u8],
    pub platform: &'static str,
    pub browser_binding_hash: Option<&'a [u8]>,
    pub app_redirect_uri: Option<&'a str>,
    pub app_code_challenge: Option<&'a str>,
}

/// How long a login attempt may take.
pub(super) const ATTEMPT_LIFETIME_SECONDS: f64 = 600.0;

#[tracing::instrument(skip_all)]
pub(super) async fn insert_attempt(
    db: &PgPool,
    attempt: &NewAttempt<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO login_attempts
           (id, state_hash, nonce_hash, pkce_verifier, platform, browser_binding_hash,
            app_redirect_uri, app_code_challenge, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))",
        attempt.id,
        attempt.state_hash,
        attempt.nonce_hash,
        attempt.pkce_verifier,
        attempt.platform,
        attempt.browser_binding_hash,
        attempt.app_redirect_uri,
        attempt.app_code_challenge,
        ATTEMPT_LIFETIME_SECONDS,
    )
    .execute(db)
    .await?;
    Ok(())
}
