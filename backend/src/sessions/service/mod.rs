//! Business rules of the login flow and sessions, one responsibility per
//! module; what they share is here.

mod callback;
mod cleanup;
mod login;
mod logout;
mod native;
mod refresh;
mod session;

pub use callback::{CallbackParams, Destination, LoginError, LoginOutcome, finish_login};
pub use cleanup::{CLEANUP_BATCH, cleanup, spawn_cleanup};
pub use login::{LoginStart, callback_url, start_login};
pub use logout::{end_user_sessions, logout};
pub use native::{RedeemedSession, redeem_code};
pub use session::{
    IdentifiedSession, SessionRefusal, SessionUser, authenticate_session, identify_session,
    stored_access_token,
};

use secrecy::SecretString;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::{
        keys::{KeyCache, KeyLookup, VerifyingKey},
        token::{LEEWAY_SECONDS, Rejection, UnverifiedToken},
    },
    error::AppError,
    sessions::{
        config::SessionConfig,
        crypto::{self, Field},
        secrets,
    },
};

/// Largest token endpoint response read, in bytes.
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

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

/// The latest `exp` stored: Postgres timestamps end in year 294276, so a
/// larger one is cut (to the end of year 9999) rather than failing.
const MAX_STORED_EXPIRY: u64 = 253_402_300_799;

fn stored_expiry(exp: u64) -> i64 {
    i64::try_from(exp.min(MAX_STORED_EXPIRY)).unwrap_or(i64::MAX)
}

/// Why a token's key was not found.
enum KeyFailure {
    /// The key cannot be checked now (no keys have loaded yet, or too
    /// many requests wait for a refresh): the token may well be valid.
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
        KeyLookup::NotLoaded | KeyLookup::Busy => Err(KeyFailure::NotLoaded),
    }
}

/// A session's identity provider tokens, sealed for its row.
struct SealedTokens {
    access: Vec<u8>,
    refresh: Option<Vec<u8>>,
    id: Option<Vec<u8>>,
}

/// Seals the identity provider's tokens for the session `session_id`.
fn seal_tokens(
    config: &SessionConfig,
    session_id: Uuid,
    access: &str,
    refresh: Option<&str>,
    id: Option<&str>,
) -> Result<SealedTokens, crypto::CryptoError> {
    let seal = |field: Field, value: &str| {
        crypto::seal(
            &config.keys,
            session_id,
            field,
            &SecretString::from(value.to_owned()),
        )
    };
    Ok(SealedTokens {
        access: seal(Field::AccessToken, access)?,
        refresh: refresh
            .map(|token| seal(Field::RefreshToken, token))
            .transpose()?,
        id: id.map(|token| seal(Field::IdToken, token)).transpose()?,
    })
}

/// The `exp` of a JWT, unverified: only to schedule the next refresh of a
/// token that every use still verifies, or to tell that a token cannot
/// pass any more, whatever its key.
fn unverified_expiry(token: &str) -> Option<u64> {
    #[derive(Deserialize)]
    struct Claims {
        exp: u64,
    }
    let payload = token.split('.').nth(1)?;
    let claims: Claims = serde_json::from_slice(&crate::base64::decode_url(payload)?).ok()?;
    Some(claims.exp)
}

/// Whether the token has expired under the bearer rules' leeway, judging
/// by its unverified `exp` (no `exp`: expired).
fn expired(token: &str, now: u64) -> bool {
    unverified_expiry(token).is_none_or(|exp| exp.saturating_add(LEEWAY_SECONDS) < now)
}

#[cfg(test)]
mod tests {
    use super::expired;

    fn token(payload: &str) -> String {
        format!("e30.{}.c2ln", crate::base64::encode_url(payload.as_bytes()))
    }

    #[test]
    fn a_token_expires_once_past_the_leeway() {
        let token_at_1000 = token(r#"{"exp":1000}"#);
        assert!(!expired(&token_at_1000, 999));
        assert!(!expired(&token_at_1000, 1060));
        assert!(expired(&token_at_1000, 1061));
        assert!(expired(&token("{}"), 0), "no exp");
        assert!(expired("not a token", 0));
    }
}
