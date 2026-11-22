//! Database access for the login flow and sessions.

use sqlx::PgPool;
use uuid::Uuid;

use crate::sessions::model::ATTEMPT_LIFETIME;

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
        ATTEMPT_LIFETIME.as_secs_f64(),
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
#[derive(Clone)]
pub(super) struct ActiveSession {
    pub id: Uuid,
    pub user_id: Uuid,
    /// The user's subject, to check that refreshed tokens are still theirs.
    pub user_subject: String,
    pub kind: String,
    pub idp_access_token: Vec<u8>,
    /// The access token expires within the refresh window.
    pub refresh_due: bool,
    /// The idle expiry has fallen more than [`Idle::slack_seconds`] behind
    /// a full idle timeout (and is not at the absolute expiry).
    pub touch_due: bool,
}

/// The idle timeout, and how far the idle expiry may fall behind it before
/// a use moves it forward.
#[derive(Clone, Copy)]
pub(super) struct Idle {
    pub seconds: f64,
    pub slack_seconds: f64,
}

/// How long before the identity provider's access token expires it is
/// refreshed.
pub(super) const REFRESH_WINDOW_SECONDS: f64 = 60.0;

#[tracing::instrument(skip_all)]
pub(super) async fn find_session(
    db: &PgPool,
    token_hash: &[u8],
    idle: Idle,
) -> Result<Option<ActiveSession>, sqlx::Error> {
    sqlx::query_as!(
        ActiveSession,
        r#"SELECT s.id, s.user_id, u.subject AS user_subject, s.kind, s.idp_access_token,
                  s.access_expires_at < now() + make_interval(secs => $2) AS "refresh_due!",
                  s.idle_expires_at < LEAST(now() + make_interval(secs => $3)
                                              - make_interval(secs => $4),
                                            s.absolute_expires_at) AS "touch_due!"
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = $1 AND s.idle_expires_at > now()
             AND s.absolute_expires_at > now()"#,
        token_hash,
        REFRESH_WINDOW_SECONDS,
        idle.seconds,
        idle.slack_seconds,
    )
    .fetch_optional(db)
    .await
}

/// Records use: `last_used_at` now, and the idle expiry moved forward to a
/// full idle timeout (never past the absolute one). Only while it is due,
/// so concurrent requests that all found it due write once.
#[tracing::instrument(skip_all, fields(session.id = %id))]
pub(super) async fn touch_session(db: &PgPool, id: Uuid, idle: Idle) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE sessions
         SET last_used_at = now(),
             idle_expires_at = LEAST(now() + make_interval(secs => $2), absolute_expires_at)
         WHERE id = $1
           AND idle_expires_at < LEAST(now() + make_interval(secs => $2)
                                         - make_interval(secs => $3),
                                       absolute_expires_at)",
        id,
        idle.seconds,
        idle.slack_seconds,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// How long a refresh may take before another request may try: well over
/// the identity provider's timeouts (token endpoint, then keys).
pub(super) const REFRESH_LEASE_SECONDS: f64 = 30.0;

/// Takes the session's refresh lease, if its access token is still due and
/// no one else holds the lease. Returns the sealed refresh token (`None`
/// inside when there is none), or `None` when the lease was not taken.
#[tracing::instrument(skip_all, fields(session.id = %id))]
pub(super) async fn claim_refresh(
    db: &PgPool,
    id: Uuid,
) -> Result<Option<Option<Vec<u8>>>, sqlx::Error> {
    sqlx::query_scalar!(
        "UPDATE sessions SET refreshing_until = now() + make_interval(secs => $3)
         WHERE id = $1
           AND access_expires_at < now() + make_interval(secs => $2)
           AND (refreshing_until IS NULL OR refreshing_until < now())
         RETURNING idp_refresh_token",
        id,
        REFRESH_WINDOW_SECONDS,
        REFRESH_LEASE_SECONDS,
    )
    .fetch_optional(db)
    .await
}

/// Gives the refresh lease back without new tokens.
#[tracing::instrument(skip_all, fields(session.id = %id))]
pub(super) async fn release_refresh(db: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE sessions SET refreshing_until = NULL WHERE id = $1",
        id
    )
    .execute(db)
    .await?;
    Ok(())
}

/// The session's sealed identity provider access token, while the session
/// is live (neither idle too long nor past its absolute lifetime). The
/// token itself may have expired. `None` if the session is gone or over.
#[tracing::instrument(skip_all, fields(session.id = %id))]
pub(super) async fn live_session_access_token(
    db: &PgPool,
    id: Uuid,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT idp_access_token FROM sessions
         WHERE id = $1 AND idle_expires_at > now() AND absolute_expires_at > now()",
        id
    )
    .fetch_optional(db)
    .await
}

/// Stores refreshed tokens and gives the lease back. `None` keeps the
/// stored value (an identity provider that does not rotate refresh tokens,
/// or sends no new ID token).
#[tracing::instrument(skip_all, fields(session.id = %id))]
pub(super) async fn store_refreshed(
    db: &PgPool,
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
             access_expires_at = to_timestamp($5::bigint),
             refreshing_until = NULL
         WHERE id = $1",
        id,
        access_token,
        refresh_token,
        id_token,
        access_expires_at,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// What a deleted session leaves for signing out at the identity
/// provider.
pub(super) struct DeletedSession {
    pub kind: String,
    pub idp_id_token: Option<Vec<u8>>,
    pub idp_refresh_token: Option<Vec<u8>>,
}

/// Deletes a session; returns what it held, if it existed.
#[tracing::instrument(skip_all, fields(session.id = %id))]
pub(super) async fn delete_session(
    db: &PgPool,
    id: Uuid,
) -> Result<Option<DeletedSession>, sqlx::Error> {
    sqlx::query_as!(
        DeletedSession,
        "DELETE FROM sessions WHERE id = $1 RETURNING kind, idp_id_token, idp_refresh_token",
        id
    )
    .fetch_optional(db)
    .await
}

/// Deletes every session of the user; returns how many.
#[tracing::instrument(skip_all, fields(user.id = %user_id))]
pub(super) async fn delete_user_sessions(
    db: &mut sqlx::PgConnection,
    user_id: Uuid,
) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query!("DELETE FROM sessions WHERE user_id = $1", user_id)
            .execute(db)
            .await?
            .rows_affected(),
    )
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
