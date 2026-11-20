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

/// A live session found by its token.
pub(super) struct ActiveSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub kind: String,
    pub idp_access_token: Vec<u8>,
    /// The access token expires within the refresh window.
    pub refresh_due: bool,
    /// `last_used_at` is over a minute old.
    pub touch_due: bool,
}

/// How long before the identity provider's access token expires it is
/// refreshed.
pub(super) const REFRESH_WINDOW_SECONDS: f64 = 60.0;

#[tracing::instrument(skip_all)]
pub(super) async fn find_session(
    db: &PgPool,
    token_hash: &[u8],
) -> Result<Option<ActiveSession>, sqlx::Error> {
    sqlx::query_as!(
        ActiveSession,
        r#"SELECT id, user_id, kind, idp_access_token,
                  access_expires_at < now() + make_interval(secs => $2) AS "refresh_due!",
                  last_used_at < now() - interval '1 minute' AS "touch_due!"
           FROM sessions
           WHERE token_hash = $1 AND idle_expires_at > now() AND absolute_expires_at > now()"#,
        token_hash,
        REFRESH_WINDOW_SECONDS,
    )
    .fetch_optional(db)
    .await
}

/// Records use: `last_used_at` now, and the idle expiry moved forward (never
/// past the absolute one).
#[tracing::instrument(skip_all, fields(session.id = %id))]
pub(super) async fn touch_session(
    db: &PgPool,
    id: Uuid,
    idle_seconds: f64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE sessions
         SET last_used_at = now(),
             idle_expires_at = LEAST(now() + make_interval(secs => $2), absolute_expires_at)
         WHERE id = $1",
        id,
        idle_seconds,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// The tokens of a session locked for refreshing (`FOR UPDATE`), so
/// concurrent requests and instances never use one refresh token twice.
pub(super) struct LockedTokens {
    pub idp_access_token: Vec<u8>,
    pub idp_refresh_token: Option<Vec<u8>>,
    /// Still due: no one refreshed it while this request waited.
    pub refresh_due: bool,
}

pub(super) async fn lock_tokens(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<Option<LockedTokens>, sqlx::Error> {
    sqlx::query_as!(
        LockedTokens,
        r#"SELECT idp_access_token, idp_refresh_token,
                  access_expires_at < now() + make_interval(secs => $2) AS "refresh_due!"
           FROM sessions WHERE id = $1 FOR UPDATE"#,
        id,
        REFRESH_WINDOW_SECONDS,
    )
    .fetch_optional(tx)
    .await
}

/// Stores refreshed tokens. `None` keeps the stored value (an identity
/// provider that does not rotate refresh tokens, or sends no new ID token).
pub(super) async fn store_refreshed(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    access_token: &[u8],
    refresh_token: Option<&[u8]>,
    id_token: Option<&[u8]>,
    access_expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE sessions
         SET idp_access_token = $2,
             idp_refresh_token = COALESCE($3, idp_refresh_token),
             idp_id_token = COALESCE($4, idp_id_token),
             access_expires_at = to_timestamp($5::bigint)
         WHERE id = $1",
        id,
        access_token,
        refresh_token,
        id_token,
        access_expires_at,
    )
    .execute(tx)
    .await?;
    Ok(())
}

pub(super) async fn delete_session_in(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM sessions WHERE id = $1", id)
        .execute(tx)
        .await?;
    Ok(())
}

/// Deletes a session; returns its sealed ID token, if it existed.
#[tracing::instrument(skip_all, fields(session.id = %id))]
pub(super) async fn delete_session(
    db: &PgPool,
    id: Uuid,
) -> Result<Option<Option<Vec<u8>>>, sqlx::Error> {
    sqlx::query_scalar!(
        "DELETE FROM sessions WHERE id = $1 RETURNING idp_id_token",
        id
    )
    .fetch_optional(db)
    .await
}

/// Deletes up to `limit` expired login attempts; returns how many.
/// `SKIP LOCKED`: instances cleaning at the same time share the work.
pub(super) async fn delete_expired_attempts(db: &PgPool, limit: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM login_attempts WHERE id IN (
           SELECT id FROM login_attempts WHERE expires_at < now()
           LIMIT $1 FOR UPDATE SKIP LOCKED)",
        limit,
    )
    .execute(db)
    .await?
    .rows_affected())
}

/// Deletes up to `limit` expired one-time codes; returns how many.
pub(super) async fn delete_expired_codes(db: &PgPool, limit: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM login_codes WHERE code_hash IN (
           SELECT code_hash FROM login_codes WHERE expires_at < now()
           LIMIT $1 FOR UPDATE SKIP LOCKED)",
        limit,
    )
    .execute(db)
    .await?
    .rows_affected())
}

/// Deletes up to `limit` ended sessions: idle too long, past their
/// absolute lifetime, or native sessions whose code was never redeemed.
pub(super) async fn delete_expired_sessions(db: &PgPool, limit: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM sessions WHERE id IN (
           SELECT id FROM sessions
           WHERE idle_expires_at < now() OR absolute_expires_at < now()
              OR (token_hash IS NULL AND created_at < now() - make_interval(secs => $2))
           LIMIT $1 FOR UPDATE SKIP LOCKED)",
        limit,
        // A code lives a minute; leave a margin for a redemption in flight.
        CODE_LIFETIME_SECONDS * 5.0,
    )
    .execute(db)
    .await?
    .rows_affected())
}
