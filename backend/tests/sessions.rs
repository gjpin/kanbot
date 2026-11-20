//! Sessions and the login flow.

use sqlx::PgPool;
use uuid::Uuid;

async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, issuer, subject, platform_role) VALUES ($1, 'iss', $2, 'user')",
        id,
        id.to_string(),
    )
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_attempt(
    pool: &PgPool,
    platform: &str,
    binding: Option<&[u8]>,
    redirect: Option<&str>,
    challenge: Option<&str>,
) -> Result<(), sqlx::Error> {
    let state_hash = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO login_attempts
           (id, state_hash, nonce_hash, pkce_verifier, platform, browser_binding_hash,
            app_redirect_uri, app_code_challenge, expires_at)
         VALUES ($1, $2, 'n', 'v', $3, $4, $5, $6, now() + interval '10 minutes')",
        Uuid::new_v4(),
        state_hash.as_bytes().as_slice(),
        platform,
        binding,
        redirect,
        challenge,
    )
    .execute(pool)
    .await
    .map(|_| ())
}

#[sqlx::test]
async fn a_login_attempt_is_either_web_or_native(pool: PgPool) {
    insert_attempt(&pool, "web", Some(b"binding"), None, None)
        .await
        .unwrap();
    insert_attempt(&pool, "native", None, Some("app:/auth/done"), Some("c"))
        .await
        .unwrap();

    for (platform, binding, redirect, challenge) in [
        ("web", None, None, None),
        ("web", Some(&b"binding"[..]), Some("app:/auth/done"), None),
        ("native", None, Some("app:/auth/done"), None),
        ("native", None, None, Some("c")),
        (
            "native",
            Some(&b"binding"[..]),
            Some("app:/auth/done"),
            Some("c"),
        ),
        ("cli", None, None, None),
    ] {
        assert!(
            insert_attempt(&pool, platform, binding, redirect, challenge)
                .await
                .is_err(),
            "{platform} {binding:?} {redirect:?} {challenge:?}"
        );
    }
}

async fn insert_session(
    pool: &PgPool,
    user_id: Uuid,
    kind: &str,
    token_hash: Option<&[u8]>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO sessions
           (id, token_hash, user_id, kind, idp_access_token, access_expires_at,
            idle_expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, 'at', now(), now(), now())",
        id,
        token_hash,
        user_id,
        kind,
    )
    .execute(pool)
    .await
    .map(|_| id)
}

#[sqlx::test]
async fn only_native_sessions_may_wait_for_their_token(pool: PgPool) {
    let user_id = user(&pool).await;
    insert_session(&pool, user_id, "native", None)
        .await
        .unwrap();
    insert_session(&pool, user_id, "web", Some(b"hash-1"))
        .await
        .unwrap();
    assert!(insert_session(&pool, user_id, "web", None).await.is_err());
    assert!(
        insert_session(&pool, user_id, "native", Some(b"hash-1"))
            .await
            .is_err(),
        "token hashes are unique"
    );
    assert!(
        insert_session(&pool, user_id, "cli", Some(b"hash-2"))
            .await
            .is_err()
    );
}

#[sqlx::test]
async fn deleting_a_user_deletes_their_sessions_and_codes(pool: PgPool) {
    let user_id = user(&pool).await;
    let session = insert_session(&pool, user_id, "native", None)
        .await
        .unwrap();
    sqlx::query!(
        "INSERT INTO login_codes (code_hash, session_id, app_code_challenge, expires_at)
         VALUES ('code', $1, 'c', now())",
        session,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
        .execute(&pool)
        .await
        .unwrap();

    let left = sqlx::query_scalar!(
        r#"SELECT (SELECT count(*) FROM sessions) + (SELECT count(*) FROM login_codes) AS "n!""#
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}
