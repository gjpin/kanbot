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
pub use session::{SessionRefusal, SessionUser, authenticate_session, stored_access_token};

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::{
    auth::{
        keys::{KeyCache, KeyLookup, VerifyingKey},
        token::{Rejection, UnverifiedToken},
    },
    error::AppError,
    sessions::{crypto, secrets},
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

/// Seconds since the Unix epoch; a clock before 1970 fails closed (see
/// `auth::middleware`).
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |since| since.as_secs())
}
