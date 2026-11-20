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

/// A login attempt, as the callback needs it.
pub(super) struct Attempt {
    pub id: Uuid,
    pub nonce_hash: Vec<u8>,
    pub pkce_verifier: Vec<u8>,
    pub app_redirect_uri: Option<String>,
    pub app_code_challenge: Option<String>,
}

/// Marks the attempt with `state_hash` used and returns it, if it is
/// unused, unexpired, and either native or bound to the browser whose
/// login cookie hashes to `binding_hash`. One statement, so an attempt is
/// used at most once even under concurrent callbacks.
#[tracing::instrument(skip_all)]
pub(super) async fn consume_attempt(
    db: &PgPool,
    state_hash: &[u8],
    binding_hash: Option<&[u8]>,
) -> Result<Option<Attempt>, sqlx::Error> {
    sqlx::query_as!(
        Attempt,
        "UPDATE login_attempts SET used_at = now()
         WHERE state_hash = $1 AND used_at IS NULL AND expires_at > now()
           AND (platform = 'native' OR browser_binding_hash = $2)
         RETURNING id, nonce_hash, pkce_verifier, app_redirect_uri, app_code_challenge",
        state_hash,
        binding_hash,
    )
    .fetch_optional(db)
    .await
}

/// A session to store. The identity provider's tokens are sealed for
/// this session's ID.
pub(super) struct NewSession<'a> {
    pub id: Uuid,
    pub token_hash: Option<&'a [u8]>,
    pub user_id: Uuid,
    pub kind: &'static str,
    pub access_token: &'a [u8],
    pub refresh_token: Option<&'a [u8]>,
    pub id_token: Option<&'a [u8]>,
    /// The access token's `exp`, in seconds since the Unix epoch.
    pub access_expires_at: i64,
    pub idle_seconds: f64,
    pub absolute_seconds: f64,
}

#[tracing::instrument(skip_all, fields(session.id = %session.id))]
pub(super) async fn insert_session(
    db: &PgPool,
    session: &NewSession<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO sessions
           (id, token_hash, user_id, kind, idp_access_token, idp_refresh_token, idp_id_token,
            access_expires_at, idle_expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8::bigint),
                 now() + make_interval(secs => $9), now() + make_interval(secs => $10))",
        session.id,
        session.token_hash,
        session.user_id,
        session.kind,
        session.access_token,
        session.refresh_token,
        session.id_token,
        session.access_expires_at,
        session.idle_seconds,
        session.absolute_seconds,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// How long a native app has to redeem its one-time code.
pub(super) const CODE_LIFETIME_SECONDS: f64 = 60.0;

#[tracing::instrument(skip_all, fields(session.id = %session_id))]
pub(super) async fn insert_code(
    db: &PgPool,
    code_hash: &[u8],
    session_id: Uuid,
    app_code_challenge: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO login_codes (code_hash, session_id, app_code_challenge, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        code_hash,
        session_id,
        app_code_challenge,
        CODE_LIFETIME_SECONDS,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Marks the one-time code with `code_hash` used and returns its session
/// and PKCE challenge, if it is unused and unexpired. Single use, even
/// under concurrent redemptions.
#[tracing::instrument(skip_all)]
pub(super) async fn consume_code(
    db: &PgPool,
    code_hash: &[u8],
) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    let row = sqlx::query!(
        "UPDATE login_codes SET used_at = now()
         WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING session_id, app_code_challenge",
        code_hash,
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|row| (row.session_id, row.app_code_challenge)))
}

/// Gives a native session waiting for its token the token with
/// `token_hash`. Returns the session's absolute expiry (RFC 3339, UTC), or
/// `None` if there is no such waiting, unexpired session.
#[tracing::instrument(skip_all, fields(session.id = %session_id))]
pub(super) async fn activate_native_session(
    db: &PgPool,
    session_id: Uuid,
    token_hash: &[u8],
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"UPDATE sessions SET token_hash = $2, last_used_at = now()
           WHERE id = $1 AND kind = 'native' AND token_hash IS NULL
             AND absolute_expires_at > now()
           RETURNING to_char(absolute_expires_at AT TIME ZONE 'UTC',
                             'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "expires_at!""#,
        session_id,
        token_hash,
    )
    .fetch_optional(db)
    .await
}
