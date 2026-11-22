//! Encryption of the secrets kanbot keeps for a session or login (the
//! identity provider's tokens, the PKCE verifier) with XChaCha20-Poly1305: 192-bit random
//! nonces, safe for any number of encryptions per key.
//!
//! A sealed value is `1 | key-id length | key id | nonce (24 bytes) |
//! ciphertext and tag`. The key ID lets older values be opened after a new
//! key takes over (`SESSION_ENCRYPTION_KEYS`). The associated data names
//! the row and the field, so a value cannot be moved to another session or
//! column.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use uuid::Uuid;

use crate::sessions::config::SessionKeys;

const VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;

/// Why a value could not be sealed or opened. Never says more.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("no randomness available")]
    Random,
    #[error("the value could not be sealed")]
    Seal,
    #[error("the value is malformed, forged, or sealed with an unknown key")]
    Open,
}

/// The fields that hold sealed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    PkceVerifier,
    AccessToken,
    RefreshToken,
    IdToken,
}

impl Field {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::PkceVerifier => b"login_attempts.pkce_verifier",
            Self::AccessToken => b"sessions.idp_access_token",
            Self::RefreshToken => b"sessions.idp_refresh_token",
            Self::IdToken => b"sessions.idp_id_token",
        }
    }
}

fn associated_data(row: Uuid, field: Field) -> Vec<u8> {
    let mut data = row.as_bytes().to_vec();
    data.extend_from_slice(field.label());
    data
}

/// Seals `plaintext` for `field` of row `row` with the current key.
///
/// # Errors
///
/// [`CryptoError`] if no randomness is available or encryption fails.
pub fn seal(
    keys: &SessionKeys,
    row: Uuid,
    field: Field,
    plaintext: &SecretString,
) -> Result<Vec<u8>, CryptoError> {
    let key = keys.current();
    let mut nonce = [0; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Random)?;
    let cipher = XChaCha20Poly1305::new(key.bytes().into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext.expose_secret().as_bytes(),
                aad: &associated_data(row, field),
            },
        )
        .map_err(|_| CryptoError::Seal)?;
    let id = key.id.as_str().as_bytes();
    let id_len = u8::try_from(id.len()).map_err(|_| CryptoError::Seal)?;
    let mut sealed = Vec::with_capacity(
        2_usize
            .saturating_add(id.len())
            .saturating_add(NONCE_BYTES)
            .saturating_add(ciphertext.len()),
    );
    sealed.push(VERSION);
    sealed.push(id_len);
    sealed.extend_from_slice(id);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Whether `sealed` was sealed with the current key, so it would survive
/// the older keys being retired.
#[must_use]
pub fn sealed_with_current(keys: &SessionKeys, sealed: &[u8]) -> bool {
    let id = keys.current().id.as_str().as_bytes();
    sealed.get(1).copied().map(usize::from) == Some(id.len())
        && sealed.get(2..2_usize.saturating_add(id.len())) == Some(id)
}

/// Opens a value sealed for `field` of row `row`, with whichever key
/// sealed it.
///
/// # Errors
///
/// [`CryptoError::Open`] if it is malformed, was sealed for another row or
/// field, was altered, or its key is no longer configured.
pub fn open(
    keys: &SessionKeys,
    row: Uuid,
    field: Field,
    sealed: &[u8],
) -> Result<SecretString, CryptoError> {
    let (&version, rest) = sealed.split_first().ok_or(CryptoError::Open)?;
    let (&id_len, rest) = rest.split_first().ok_or(CryptoError::Open)?;
    if version != VERSION {
        return Err(CryptoError::Open);
    }
    let (id, rest) = rest
        .split_at_checked(usize::from(id_len))
        .ok_or(CryptoError::Open)?;
    let (nonce, ciphertext) = rest
        .split_at_checked(NONCE_BYTES)
        .ok_or(CryptoError::Open)?;
    let id = std::str::from_utf8(id).map_err(|_| CryptoError::Open)?;
    let key = keys.get(id).ok_or(CryptoError::Open)?;
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| CryptoError::Open)?;
    let plaintext = SecretBox::new(Box::new(
        XChaCha20Poly1305::new(key.bytes().into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &associated_data(row, field),
                },
            )
            .map_err(|_| CryptoError::Open)?,
    ));
    String::from_utf8(plaintext.expose_secret().clone())
        .map(SecretString::from)
        .map_err(|_| CryptoError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const KEY_2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    fn keys(raw: &str) -> SessionKeys {
        SessionKeys::parse(raw).unwrap()
    }

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    #[test]
    fn round_trips_and_hides_the_plaintext() {
        let keys = keys(&format!("k1:{KEY_1}"));
        let row = Uuid::new_v4();
        let sealed = seal(&keys, row, Field::AccessToken, &secret("eyJ.token.sig")).unwrap();
        assert_eq!(sealed[0], VERSION);
        assert_eq!(&sealed[1..4], b"\x02k1");
        assert!(!sealed.windows(5).any(|w| w == b"eyJ.t"));
        let opened = open(&keys, row, Field::AccessToken, &sealed).unwrap();
        assert_eq!(opened.expose_secret(), "eyJ.token.sig");
    }

    #[test]
    fn each_seal_uses_a_new_nonce() {
        let keys = keys(&format!("k1:{KEY_1}"));
        let row = Uuid::new_v4();
        let a = seal(&keys, row, Field::IdToken, &secret("same")).unwrap();
        let b = seal(&keys, row, Field::IdToken, &secret("same")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn values_are_bound_to_their_row_and_field() {
        let keys = keys(&format!("k1:{KEY_1}"));
        let row = Uuid::new_v4();
        let sealed = seal(&keys, row, Field::RefreshToken, &secret("rt")).unwrap();
        assert!(open(&keys, Uuid::new_v4(), Field::RefreshToken, &sealed).is_err());
        assert!(open(&keys, row, Field::AccessToken, &sealed).is_err());
        assert!(open(&keys, row, Field::RefreshToken, &sealed).is_ok());
    }

    #[test]
    fn a_rotated_key_still_opens_older_values() {
        let old = keys(&format!("k1:{KEY_1}"));
        let row = Uuid::new_v4();
        let sealed_with_old = seal(&old, row, Field::AccessToken, &secret("at")).unwrap();

        let rotated = keys(&format!("k2:{KEY_2},k1:{KEY_1}"));
        let opened = open(&rotated, row, Field::AccessToken, &sealed_with_old).unwrap();
        assert_eq!(opened.expose_secret(), "at");
        let sealed_with_new = seal(&rotated, row, Field::AccessToken, &secret("at")).unwrap();
        assert_eq!(&sealed_with_new[1..4], b"\x02k2");

        // Once the old key is gone, its values cannot be opened.
        let only_new = keys(&format!("k2:{KEY_2}"));
        assert!(open(&only_new, row, Field::AccessToken, &sealed_with_old).is_err());
        assert!(open(&only_new, row, Field::AccessToken, &sealed_with_new).is_ok());
    }

    #[test]
    fn a_reused_key_id_with_another_key_cannot_open() {
        let row = Uuid::new_v4();
        let sealed = seal(
            &keys(&format!("k1:{KEY_1}")),
            row,
            Field::IdToken,
            &secret("x"),
        )
        .unwrap();
        assert!(open(&keys(&format!("k1:{KEY_2}")), row, Field::IdToken, &sealed).is_err());
    }

    #[test]
    fn altered_or_malformed_values_cannot_be_opened() {
        let keys = keys(&format!("k1:{KEY_1}"));
        let row = Uuid::new_v4();
        let sealed = seal(&keys, row, Field::PkceVerifier, &secret("verifier")).unwrap();
        for i in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[i] ^= 1;
            assert!(
                open(&keys, row, Field::PkceVerifier, &altered).is_err(),
                "byte {i}"
            );
        }
        for truncated in [0, 1, 2, 4, 27, sealed.len() - 1] {
            assert!(
                open(&keys, row, Field::PkceVerifier, &sealed[..truncated]).is_err(),
                "{truncated}"
            );
        }
    }
}
